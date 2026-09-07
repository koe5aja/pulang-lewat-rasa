#!/usr/bin/env python3
"""Server HTTP dan API Pemesanan Budaya Pulang Lewat Rasa — Gudeg KLA Yogyakarta."""

import hashlib
import hmac
from http import cookies
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import sys
import time
from datetime import date, datetime, timedelta
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "billing.db")
MENU_JSON_PATH = os.path.join(BASE_DIR, "billing_menu.json")

MAX_BODY_BYTES = 65_536
MAX_ITEMS = 12
MAX_QTY = 20
PHONE_RE = re.compile(r"^\+?[0-9][0-9 -]{8,15}$")

# Keamanan & Autentikasi
SALT_BYTES = 16
PBKDF2_ITERATIONS = 120_000
SESSION_EXPIRY_HOURS = 12
RATE_LIMIT_WINDOW = 600  # 10 menit
MAX_LOGIN_ATTEMPTS = 5

# Penyimpanan in-memory percobaan login: { ip_address: [timestamp, ...] }
login_attempts: dict[str, list[float]] = {}

# Konfigurasi tipe MIME
MIME_MAP = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".mp3": "audio/mpeg",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".webp": "image/webp",
    ".woff2": "font/woff2",
    ".woff": "font/woff",
    ".ttf": "font/ttf",
}

BLOCKED_EXTENSIONS = {".py", ".pyc", ".db", ".sqlite", ".sqlite3", ".db3", ".sh", ".log", ".bak"}
BLOCKED_DIRS = {"__pycache__", ".impeccable", ".git"}


class ValidationError(Exception):
    pass


def hash_password(password: str, salt: bytes = None) -> tuple[str, str]:
    """Hash password menggunakan PBKDF2-HMAC-SHA256 dengan salt acak 128-bit."""
    if salt is None:
        salt = secrets.token_bytes(SALT_BYTES)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return pwd_hash.hex(), salt.hex()


def verify_password(password: str, stored_hash: str, stored_salt: str) -> bool:
    """Verifikasi kecocokan password dengan proteksi timing attack."""
    try:
        salt = bytes.fromhex(stored_salt)
        expected_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS).hex()
        return hmac.compare_digest(expected_hash, stored_hash)
    except Exception:
        return False


def check_rate_limit(client_ip: str) -> bool:
    """Kembalikan True jika client_ip belum melebihi batas percobaan login."""
    now = time.time()
    attempts = [t for t in login_attempts.get(client_ip, []) if now - t < RATE_LIMIT_WINDOW]
    login_attempts[client_ip] = attempts
    return len(attempts) < MAX_LOGIN_ATTEMPTS


def record_failed_login(client_ip: str):
    """Catat percobaan login gagal dari client_ip."""
    now = time.time()
    if client_ip not in login_attempts:
        login_attempts[client_ip] = []
    login_attempts[client_ip].append(now)


def clear_login_attempts(client_ip: str):
    """Hapus riwayat percobaan gagal setelah login berhasil."""
    if client_ip in login_attempts:
        del login_attempts[client_ip]


def get_session_cookie(headers) -> str | None:
    """Ambil token admin_session dari cookie request."""
    cookie_header = headers.get("Cookie")
    if not cookie_header:
        return None
    c = cookies.SimpleCookie()
    try:
        c.load(cookie_header)
        if "admin_session" in c:
            return c["admin_session"].value
    except Exception:
        return None
    return None


def validate_admin_session(token: str | None) -> dict | None:
    """Validasi token sesi admin terhadap database."""
    if not token or not isinstance(token, str) or len(token) < 20:
        return None
    now_iso = datetime.now().isoformat()
    try:
        with sqlite3.connect(DB_PATH, timeout=5) as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT s.token, u.id, u.username, s.expires_at
                FROM admin_sessions s
                JOIN admin_users u ON s.user_id = u.id
                WHERE s.token = ? AND s.expires_at > ?
                """,
                (token, now_iso),
            )
            row = cur.fetchone()
            if row:
                return {"token": row[0], "user_id": row[1], "username": row[2]}
    except Exception:
        return None
    return None


def create_admin_session(user_id: int) -> str:
    """Buat token sesi baru dengan masa aktif terbatas."""
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.now() + timedelta(hours=SESSION_EXPIRY_HOURS)).isoformat()
    created_at = datetime.now().isoformat()
    with sqlite3.connect(DB_PATH, timeout=5) as conn:
        cur = conn.cursor()
        # Bersihkan sesi lama yang kadaluwarsa
        cur.execute("DELETE FROM admin_sessions WHERE expires_at <= ?", (created_at,))
        cur.execute(
            """
            INSERT INTO admin_sessions (token, user_id, expires_at, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (token, user_id, expires_at, created_at),
        )
        conn.commit()
    return token


def destroy_admin_session(token: str):
    """Hapus sesi admin dari database."""
    if not token:
        return
    try:
        with sqlite3.connect(DB_PATH, timeout=5) as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM admin_sessions WHERE token = ?", (token,))
            conn.commit()
    except Exception:
        pass


def sync_menu_json():
    """Selaraskan data menus dan packaging dari SQLite ke billing_menu.json."""
    try:
        with sqlite3.connect(DB_PATH, timeout=5) as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, name, region, price, unit, description, image FROM menus ORDER BY id ASC")
            menus = [
                {
                    "id": r[0],
                    "name": r[1],
                    "region": r[2],
                    "price": r[3],
                    "unit": r[4],
                    "description": r[5] or "",
                    "image": r[6] or "",
                }
                for r in cur.fetchall()
            ]
            cur.execute("SELECT id, name, price, description FROM packaging ORDER BY price ASC")
            packaging = [
                {"id": r[0], "name": r[1], "price": r[2], "description": r[3] or ""}
                for r in cur.fetchall()
            ]
            data = {"database_name": "billing.db", "menus": menus, "packaging": packaging}
            with open(MENU_JSON_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[Sync Warning] Gagal menyelaraskan {MENU_JSON_PATH}: {e}", file=sys.stderr)


def init_db():
    """Inisialisasi tabel SQLite otomatis dan seeding jika data masih kosong."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS menus (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    region TEXT NOT NULL,
                    price INTEGER NOT NULL,
                    unit TEXT NOT NULL,
                    description TEXT,
                    image TEXT
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS packaging (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    price INTEGER NOT NULL,
                    description TEXT
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS orders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    order_code TEXT UNIQUE NOT NULL,
                    customer_name TEXT NOT NULL,
                    contact TEXT NOT NULL,
                    items_json TEXT NOT NULL,
                    packaging_type TEXT NOT NULL,
                    packaging_price INTEGER NOT NULL,
                    subtotal INTEGER NOT NULL,
                    total_bill INTEGER NOT NULL,
                    arrival_date TEXT NOT NULL,
                    destination_address TEXT NOT NULL,
                    story TEXT,
                    status TEXT DEFAULT 'menunggu_konfirmasi',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS admin_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_login TEXT
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS admin_sessions (
                    token TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES admin_users(id) ON DELETE CASCADE
                )
                """
            )

            # Migrasi kolom status bila belum ada pada tabel orders lama
            cur.execute("PRAGMA table_info(orders)")
            columns = [col[1] for col in cur.fetchall()]
            if "status" not in columns:
                cur.execute("ALTER TABLE orders ADD COLUMN status TEXT DEFAULT 'menunggu_konfirmasi'")

            # Index performa
            cur.execute("CREATE INDEX IF NOT EXISTS idx_orders_code ON orders(order_code)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_orders_created ON orders(created_at)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_token ON admin_sessions(token)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires ON admin_sessions(expires_at)")

            # Inisialisasi akun admin default jika belum ada
            cur.execute("SELECT COUNT(*) FROM admin_users")
            if cur.fetchone()[0] == 0:
                default_user = "admin"
                default_pass = "GudegKLA#2026"
                p_hash, p_salt = hash_password(default_pass)
                now_str = datetime.now().isoformat()
                cur.execute(
                    """
                    INSERT INTO admin_users (username, password_hash, salt, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (default_user, p_hash, p_salt, now_str),
                )
                conn.commit()
                print(f"[Admin Init] Akun admin awal dibuat:")
                print(f"             Username : {default_user}")
                print(f"             Password : {default_pass}")
                print(f"             Harap segera ganti kata sandi ini melalui dasbor /admin.")

            # Seeding data menu jika kosong
            cur.execute("SELECT COUNT(*) FROM menus")
            menu_count = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM packaging")
            pack_count = cur.fetchone()[0]

            if (menu_count == 0 or pack_count == 0) and os.path.exists(MENU_JSON_PATH):
                with open(MENU_JSON_PATH, "r", encoding="utf-8") as f:
                    seed = json.load(f)
                if menu_count == 0:
                    for m in seed.get("menus", []):
                        cur.execute(
                            """
                            INSERT OR REPLACE INTO menus (id, name, region, price, unit, description, image)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                m["id"],
                                m["name"],
                                m["region"],
                                m["price"],
                                m["unit"],
                                m.get("description", ""),
                                m.get("image", ""),
                            ),
                        )
                if pack_count == 0:
                    for p in seed.get("packaging", []):
                        cur.execute(
                            """
                            INSERT OR REPLACE INTO packaging (id, name, price, description)
                            VALUES (?, ?, ?, ?)
                            """,
                            (p["id"], p["name"], p["price"], p.get("description", "")),
                        )
                conn.commit()
    except Exception as err:
        print(f"[DB Warning] Gagal menginisialisasi database: {err}", file=sys.stderr)


class PulangRasaHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)

    def log_message(self, format, *args):
        # Format log ringkas dan rapi
        sys.stderr.write(f"[{datetime.now().strftime('%H:%M:%S')}] {self.address_string()} - {format % args}\n")

    def send_security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Range, Authorization, X-Admin-Action, X-Requested-With")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def send_json(self, status_code, payload, set_cookie=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.send_security_headers()
        self.end_headers()
        self.wfile.write(body)

    def get_client_ip(self) -> str:
        forwarded = self.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.client_address[0]

    def require_admin(self) -> dict | None:
        token = get_session_cookie(self.headers)
        session = validate_admin_session(token)
        if not session:
            self.send_json(401, {"status": "error", "message": "Akses ditolak. Sesi admin belum masuk atau telah berakhir."})
            return None
        return session

    def check_admin_csrf(self) -> bool:
        csrf_header = self.headers.get("X-Admin-Action") or self.headers.get("X-Requested-With")
        if not csrf_header:
            self.send_json(403, {"status": "error", "message": "Permintaan ditolak: Header keamanan CSRF tidak valid."})
            return False
        return True

    def read_json_body(self) -> dict:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0 or content_length > MAX_BODY_BYTES:
            raise ValidationError("Ukuran data tidak valid.")
        raw = self.rfile.read(content_length).decode("utf-8")
        return json.loads(raw)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_security_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        # Rute Admin Web
        if path in ("/admin", "/admin/"):
            self.serve_static_file("admin.html")
            return

        # Health check
        if path == "/api/health":
            try:
                with sqlite3.connect(DB_PATH, timeout=2) as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT COUNT(*) FROM menus")
                    count = cur.fetchone()[0]
                self.send_json(200, {"status": "ok", "service": "pulang-lewat-rasa", "database": "healthy", "menus_count": count})
            except Exception as e:
                self.send_json(503, {"status": "error", "service": "pulang-lewat-rasa", "database": "unhealthy", "detail": str(e)})
            return

        # Menu listing API publik
        if path == "/api/billing/menu":
            try:
                with sqlite3.connect(DB_PATH, timeout=3) as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT id, name, region, price, unit, description, image FROM menus ORDER BY region, name")
                    menus = [
                        {"id": r[0], "name": r[1], "region": r[2], "price": r[3], "unit": r[4], "description": r[5], "image": r[6]}
                        for r in cur.fetchall()
                    ]
                    cur.execute("SELECT id, name, price, description FROM packaging ORDER BY price ASC")
                    packaging = [
                        {"id": r[0], "name": r[1], "price": r[2], "description": r[3]}
                        for r in cur.fetchall()
                    ]
                self.send_json(200, {"status": "success", "menus": menus, "packaging": packaging})
            except sqlite3.Error as e:
                self.send_json(503, {"status": "error", "message": "Daftar menu sedang tidak dapat dimuat. Silakan coba lagi.", "detail": str(e)})
            return

        # Order lookup API by order code
        if path == "/api/billing/order":
            order_code = (query.get("code") or [""])[0].strip()
            if not order_code:
                self.send_json(400, {"status": "error", "message": "Parameter kode pesanan (code) diperlukan."})
                return
            try:
                with sqlite3.connect(DB_PATH, timeout=3) as conn:
                    cur = conn.cursor()
                    cur.execute(
                        """
                        SELECT order_code, customer_name, contact, items_json, packaging_type,
                               packaging_price, subtotal, total_bill, arrival_date,
                               destination_address, story, status, created_at
                        FROM orders WHERE order_code = ?
                        """,
                        (order_code,),
                    )
                    row = cur.fetchone()
                if not row:
                    self.send_json(404, {"status": "error", "message": f"Pesanan dengan kode '{order_code}' tidak ditemukan."})
                    return
                order_data = {
                    "status": "success",
                    "order_code": row[0],
                    "customer_name": row[1],
                    "contact": row[2],
                    "items": json.loads(row[3]),
                    "packaging": {"name": row[4], "price": row[5]},
                    "subtotal": row[6],
                    "total_bill": row[7],
                    "arrival_date": row[8],
                    "destination_address": row[9],
                    "story": row[10],
                    "order_status": row[11],
                    "created_at": row[12],
                }
                self.send_json(200, order_data)
            except Exception as e:
                self.send_json(500, {"status": "error", "message": "Gagal mencari data pesanan.", "detail": str(e)})
            return

        # API Admin: Cek Sesi
        if path == "/api/admin/session":
            token = get_session_cookie(self.headers)
            session = validate_admin_session(token)
            if session:
                self.send_json(200, {"authenticated": True, "username": session["username"]})
            else:
                self.send_json(401, {"authenticated": False, "message": "Sesi belum masuk."})
            return

        # API Admin: Dashboard Ringkasan
        if path == "/api/admin/dashboard":
            if not self.require_admin():
                return
            try:
                with sqlite3.connect(DB_PATH, timeout=5) as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT COUNT(*) FROM orders")
                    total_orders = cur.fetchone()[0]
                    cur.execute("SELECT COUNT(*) FROM orders WHERE status = 'menunggu_konfirmasi'")
                    pending_orders = cur.fetchone()[0]
                    cur.execute("SELECT COUNT(*) FROM orders WHERE status = 'selesai'")
                    completed_orders = cur.fetchone()[0]
                    cur.execute("SELECT COALESCE(SUM(total_bill), 0) FROM orders WHERE status != 'dibatalkan'")
                    total_revenue = cur.fetchone()[0]
                    cur.execute("SELECT COUNT(*) FROM menus")
                    total_menus = cur.fetchone()[0]
                    cur.execute(
                        """
                        SELECT order_code, customer_name, contact, total_bill, status, created_at
                        FROM orders ORDER BY id DESC LIMIT 5
                        """
                    )
                    recent_orders = [
                        {
                            "order_code": r[0],
                            "customer_name": r[1],
                            "contact": r[2],
                            "total_bill": r[3],
                            "status": r[4],
                            "created_at": r[5],
                        }
                        for r in cur.fetchall()
                    ]
                self.send_json(
                    200,
                    {
                        "status": "success",
                        "total_orders": total_orders,
                        "pending_orders": pending_orders,
                        "completed_orders": completed_orders,
                        "total_revenue": total_revenue,
                        "total_menus": total_menus,
                        "recent_orders": recent_orders,
                    },
                )
            except Exception as e:
                self.send_json(500, {"status": "error", "message": "Gagal memuat ringkasan dasbor.", "detail": str(e)})
            return

        # API Admin: Daftar Menu
        if path == "/api/admin/menus":
            if not self.require_admin():
                return
            try:
                with sqlite3.connect(DB_PATH, timeout=3) as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT id, name, region, price, unit, description, image FROM menus ORDER BY id ASC")
                    menus = [
                        {
                            "id": r[0],
                            "name": r[1],
                            "region": r[2],
                            "price": r[3],
                            "unit": r[4],
                            "description": r[5] or "",
                            "image": r[6] or "",
                        }
                        for r in cur.fetchall()
                    ]
                self.send_json(200, {"status": "success", "menus": menus})
            except Exception as e:
                self.send_json(500, {"status": "error", "message": "Gagal memuat menu admin.", "detail": str(e)})
            return

        # API Admin: Daftar Wadah
        if path == "/api/admin/packaging":
            if not self.require_admin():
                return
            try:
                with sqlite3.connect(DB_PATH, timeout=3) as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT id, name, price, description FROM packaging ORDER BY price ASC")
                    packaging = [
                        {"id": r[0], "name": r[1], "price": r[2], "description": r[3] or ""}
                        for r in cur.fetchall()
                    ]
                self.send_json(200, {"status": "success", "packaging": packaging})
            except Exception as e:
                self.send_json(500, {"status": "error", "message": "Gagal memuat wadah admin.", "detail": str(e)})
            return

        # API Admin: Daftar Pesanan
        if path == "/api/admin/orders":
            if not self.require_admin():
                return
            status_filter = (query.get("status") or ["all"])[0].strip()
            limit = min(max(int((query.get("limit") or [50])[0]), 1), 100)
            offset = max(int((query.get("offset") or [0])[0]), 0)
            try:
                with sqlite3.connect(DB_PATH, timeout=5) as conn:
                    cur = conn.cursor()
                    if status_filter != "all":
                        cur.execute("SELECT COUNT(*) FROM orders WHERE status = ?", (status_filter,))
                        total_count = cur.fetchone()[0]
                        cur.execute(
                            """
                            SELECT id, order_code, customer_name, contact, items_json,
                                   packaging_type, packaging_price, subtotal, total_bill,
                                   arrival_date, destination_address, story, status, created_at
                            FROM orders WHERE status = ?
                            ORDER BY id DESC LIMIT ? OFFSET ?
                            """,
                            (status_filter, limit, offset),
                        )
                    else:
                        cur.execute("SELECT COUNT(*) FROM orders")
                        total_count = cur.fetchone()[0]
                        cur.execute(
                            """
                            SELECT id, order_code, customer_name, contact, items_json,
                                   packaging_type, packaging_price, subtotal, total_bill,
                                   arrival_date, destination_address, story, status, created_at
                            FROM orders
                            ORDER BY id DESC LIMIT ? OFFSET ?
                            """,
                            (limit, offset),
                        )

                    rows = cur.fetchall()
                    orders = []
                    for r in rows:
                        try:
                            items_data = json.loads(r[4])
                        except Exception:
                            items_data = []
                        orders.append(
                            {
                                "id": r[0],
                                "order_code": r[1],
                                "customer_name": r[2],
                                "contact": r[3],
                                "items": items_data,
                                "packaging_type": r[5],
                                "packaging_price": r[6],
                                "subtotal": r[7],
                                "total_bill": r[8],
                                "arrival_date": r[9],
                                "destination_address": r[10],
                                "story": r[11] or "",
                                "status": r[12],
                                "created_at": r[13],
                            }
                        )
                self.send_json(
                    200,
                    {"status": "success", "total": total_count, "limit": limit, "offset": offset, "orders": orders},
                )
            except Exception as e:
                self.send_json(500, {"status": "error", "message": "Gagal memuat data pesanan.", "detail": str(e)})
            return

        # Security check: Block direct access to sensitive files and directories
        clean_path = path.lstrip("/")
        parts = clean_path.split("/")
        _, ext = os.path.splitext(parts[-1].lower())

        if any(p.startswith(".") for p in parts) or any(p in BLOCKED_DIRS for p in parts) or ext in BLOCKED_EXTENSIONS:
            self.send_json(403, {"status": "error", "message": "Akses ke berkas ini ditolak demi keamanan."})
            return

        # Handle static files
        self.serve_static_file(clean_path)

    def serve_static_file(self, rel_path):
        """Menyajikan berkas statis dengan dukungan HTTP Range (RFC 7233) untuk audio streaming."""
        if not rel_path or rel_path == "/":
            rel_path = "index.html"

        full_path = os.path.normpath(os.path.join(BASE_DIR, rel_path))
        if not full_path.startswith(BASE_DIR):
            self.send_json(403, {"status": "error", "message": "Akses di luar direktori ditolak."})
            return

        if os.path.isdir(full_path):
            index_candidate = os.path.join(full_path, "index.html")
            if os.path.exists(index_candidate):
                full_path = index_candidate
            else:
                self.send_json(403, {"status": "error", "message": "Akses direktori ditolak."})
                return

        if not os.path.isfile(full_path):
            self.send_json(404, {"status": "error", "message": "Halaman atau berkas tidak ditemukan."})
            return

        _, ext = os.path.splitext(full_path)
        ext = ext.lower()
        content_type = MIME_MAP.get(ext, mimetypes.guess_type(full_path)[0] or "application/octet-stream")

        try:
            file_stat = os.stat(full_path)
            file_size = file_stat.st_size
            last_modified = self.date_time_string(file_stat.st_mtime)

            range_header = self.headers.get("Range")
            if range_header and range_header.startswith("bytes="):
                range_spec = range_header[6:].strip()
                start = 0
                end = file_size - 1

                if "-" in range_spec:
                    parts = range_spec.split("-", 1)
                    if parts[0].strip():
                        start = int(parts[0].strip())
                    if parts[1].strip():
                        end = int(parts[1].strip())
                else:
                    start = int(range_spec)

                start = max(0, min(start, file_size - 1))
                end = max(start, min(end, file_size - 1))
                content_length = end - start + 1

                self.send_response(206)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Range", f"bytes {start}-{end}/{file_size}")
                self.send_header("Content-Length", str(content_length))
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("Last-Modified", last_modified)
                self.send_security_headers()
                self.end_headers()

                with open(full_path, "rb") as f:
                    f.seek(start)
                    remaining = content_length
                    chunk_size = 65536
                    while remaining > 0:
                        read_bytes = min(remaining, chunk_size)
                        data = f.read(read_bytes)
                        if not data:
                            break
                        self.wfile.write(data)
                        remaining -= len(data)
            else:
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(file_size))
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("Last-Modified", last_modified)
                if ext in (".html", ".json"):
                    self.send_header("Cache-Control", "no-cache")
                else:
                    self.send_header("Cache-Control", "public, max-age=86400")
                self.send_security_headers()
                self.end_headers()

                with open(full_path, "rb") as f:
                    chunk_size = 65536
                    while True:
                        data = f.read(chunk_size)
                        if not data:
                            break
                        self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            print(f"[Serve Error] {rel_path}: {e}", file=sys.stderr)

    def validate_order(self, data, price_map, pack_map):
        if not isinstance(data, dict):
            raise ValidationError("Format data pesanan tidak valid.")

        name = str(data.get("customer_name", "")).strip()
        contact = str(data.get("contact", "")).strip()
        arrival = str(data.get("arrival_date", "")).strip()
        address = str(data.get("destination_address", "")).strip()
        story = str(data.get("story", "")).strip()
        items = data.get("items", [])
        packaging = str(data.get("packaging", "besek")).lower().strip()

        if not 2 <= len(name) <= 80:
            raise ValidationError("Nama pemesan harus terdiri dari 2 sampai 80 karakter.")
        if not PHONE_RE.fullmatch(contact):
            raise ValidationError("Nomor WhatsApp harus terdiri dari 9 sampai 16 digit dan boleh diawali tanda +.")
        if not 8 <= len(address) <= 240:
            raise ValidationError("Alamat tujuan harus terdiri dari 8 sampai 240 karakter.")
        if len(story) > 500:
            raise ValidationError("Catatan titipan rasa untuk dapur maksimal 500 karakter.")
        try:
            arrival_date = date.fromisoformat(arrival)
        except ValueError as exc:
            raise ValidationError("Format tanggal santap tidak valid (gunakan YYYY-MM-DD).") from exc
        if arrival_date < date.today() + timedelta(days=3):
            raise ValidationError("Tanggal santap minimal 3 hari dari hari ini agar dapur sempat menyiapkan bahan segar.")
        if not isinstance(items, list) or not 1 <= len(items) <= MAX_ITEMS:
            raise ValidationError(f"Pesanan harus memilih antara 1 sampai {MAX_ITEMS} hidangan.")
        if packaging not in pack_map:
            raise ValidationError("Pilihan wadah kemasan tidak valid.")

        calculated_items = []
        subtotal = 0
        seen = set()
        for raw in items:
            if not isinstance(raw, dict):
                raise ValidationError("Format baris hidangan tidak valid.")
            food_id = str(raw.get("id", "")).strip()
            if food_id not in price_map:
                raise ValidationError(f"Hidangan '{food_id}' tidak terdaftar atau sedang tidak tersedia.")
            if food_id in seen:
                raise ValidationError("Hidangan yang sama cukup dipilih satu kali. Tambahkan jumlah porsinya.")
            seen.add(food_id)

            try:
                qty = int(raw.get("qty", 1))
            except (ValueError, TypeError) as exc:
                raise ValidationError(f"Jumlah porsi untuk '{food_id}' harus berupa angka bulat.") from exc

            if not 1 <= qty <= MAX_QTY:
                raise ValidationError(f"Jumlah porsi untuk '{food_id}' harus antara 1 sampai {MAX_QTY}.")

            item_price = price_map[food_id]["price"]
            line_total = item_price * qty
            subtotal += line_total
            calculated_items.append({
                "id": food_id,
                "name": price_map[food_id]["name"],
                "region": price_map[food_id]["region"],
                "unit": price_map[food_id]["unit"],
                "price": item_price,
                "qty": qty,
                "total": line_total,
            })

        pack_info = pack_map[packaging]
        return {
            "customer_name": name,
            "contact": contact,
            "arrival_date": arrival,
            "destination_address": address,
            "story": story,
            "items": calculated_items,
            "packaging": {"id": packaging, **pack_info},
            "subtotal": subtotal,
            "total_bill": subtotal + pack_info["price"],
            "status": "menunggu_konfirmasi",
        }

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # ---------------------------------------------------------------------
        # 1. API Admin: Login
        # ---------------------------------------------------------------------
        if path == "/api/admin/login":
            client_ip = self.get_client_ip()
            if not check_rate_limit(client_ip):
                self.send_json(429, {"status": "error", "message": "Terlalu banyak percobaan masuk yang gagal. Silakan tunggu 10 menit demi keamanan."})
                return

            try:
                data = self.read_json_body()
                username = str(data.get("username", "")).strip()
                password = str(data.get("password", "")).strip()

                if not username or not password:
                    self.send_json(400, {"status": "error", "message": "Username dan kata sandi wajib diisi."})
                    return

                with sqlite3.connect(DB_PATH, timeout=5) as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT id, username, password_hash, salt FROM admin_users WHERE username = ?", (username,))
                    user = cur.fetchone()

                if not user or not verify_password(password, user[2], user[3]):
                    record_failed_login(client_ip)
                    time.sleep(0.4)  # Proteksi timing attack & penundaan brute-force
                    self.send_json(401, {"status": "error", "message": "Username atau kata sandi tidak cocok."})
                    return

                # Login berhasil
                clear_login_attempts(client_ip)
                user_id = user[0]
                token = create_admin_session(user_id)
                now_str = datetime.now().isoformat()
                with sqlite3.connect(DB_PATH, timeout=3) as conn:
                    cur = conn.cursor()
                    cur.execute("UPDATE admin_users SET last_login = ? WHERE id = ?", (now_str, user_id))
                    conn.commit()

                set_cookie = f"admin_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_EXPIRY_HOURS * 3600}"
                self.send_json(200, {"status": "success", "username": user[1], "message": "Login berhasil."}, set_cookie=set_cookie)
            except Exception as e:
                self.send_json(500, {"status": "error", "message": "Terjadi gangguan saat proses masuk.", "detail": str(e)})
            return

        # ---------------------------------------------------------------------
        # 2. API Admin: Logout
        # ---------------------------------------------------------------------
        if path == "/api/admin/logout":
            token = get_session_cookie(self.headers)
            destroy_admin_session(token)
            clear_cookie = "admin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
            self.send_json(200, {"status": "success", "message": "Logout berhasil."}, set_cookie=clear_cookie)
            return

        # ---------------------------------------------------------------------
        # 3. API Admin: Tambah Menu Baru
        # ---------------------------------------------------------------------
        if path == "/api/admin/menus/create":
            if not self.require_admin() or not self.check_admin_csrf():
                return
            try:
                data = self.read_json_body()
                m_id = str(data.get("id", "")).strip().lower()
                m_name = str(data.get("name", "")).strip()
                m_region = str(data.get("region", "")).strip()
                m_unit = str(data.get("unit", "")).strip()
                m_desc = str(data.get("description", "")).strip()
                m_img = str(data.get("image", "")).strip()

                try:
                    m_price = int(data.get("price", 0))
                except (ValueError, TypeError):
                    raise ValidationError("Harga menu harus berupa angka bulat positif.")

                if not re.fullmatch(r"^[a-z0-9-]+$", m_id) or not 2 <= len(m_id) <= 40:
                    raise ValidationError("ID Menu harus berupa huruf kecil, angka, dan tanda hubung (-) antara 2-40 karakter (contoh: gudeg-komplit).")
                if not 2 <= len(m_name) <= 80:
                    raise ValidationError("Nama hidangan harus antara 2-80 karakter.")
                if not 2 <= len(m_region) <= 50:
                    raise ValidationError("Wilayah tradisi harus antara 2-50 karakter.")
                if m_price <= 0:
                    raise ValidationError("Harga hidangan harus lebih besar dari 0.")
                if not 1 <= len(m_unit) <= 40:
                    raise ValidationError("Satuan porsi harus antara 1-40 karakter.")
                if len(m_desc) > 400:
                    raise ValidationError("Deskripsi maksimal 400 karakter.")
                if m_img and not re.fullmatch(r"^[a-zA-Z0-9_.-]+$", m_img):
                    raise ValidationError("Nama berkas foto tidak valid.")

                with sqlite3.connect(DB_PATH, timeout=5) as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT COUNT(*) FROM menus WHERE id = ?", (m_id,))
                    if cur.fetchone()[0] > 0:
                        raise ValidationError(f"Menu dengan ID '{m_id}' sudah ada. Gunakan ID lain.")
                    cur.execute(
                        """
                        INSERT INTO menus (id, name, region, price, unit, description, image)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (m_id, m_name, m_region, m_price, m_unit, m_desc, m_img or "gudeg-manggar.jpg"),
                    )
                    conn.commit()

                sync_menu_json()
                self.send_json(201, {"status": "success", "message": f"Menu '{m_name}' berhasil ditambahkan.", "id": m_id})
            except ValidationError as ve:
                self.send_json(400, {"status": "error", "message": str(ve)})
            except Exception as e:
                self.send_json(500, {"status": "error", "message": "Gagal menambahkan menu.", "detail": str(e)})
            return

        # ---------------------------------------------------------------------
        # 4. API Admin: Ubah Menu
        # ---------------------------------------------------------------------
        if path == "/api/admin/menus/update":
            if not self.require_admin() or not self.check_admin_csrf():
                return
            try:
                data = self.read_json_body()
                m_id = str(data.get("id", "")).strip().lower()
                m_name = str(data.get("name", "")).strip()
                m_region = str(data.get("region", "")).strip()
                m_unit = str(data.get("unit", "")).strip()
                m_desc = str(data.get("description", "")).strip()
                m_img = str(data.get("image", "")).strip()

                try:
                    m_price = int(data.get("price", 0))
                except (ValueError, TypeError):
                    raise ValidationError("Harga menu harus berupa angka bulat positif.")

                if not m_id:
                    raise ValidationError("ID Menu wajib disertakan.")
                if not 2 <= len(m_name) <= 80:
                    raise ValidationError("Nama hidangan harus antara 2-80 karakter.")
                if not 2 <= len(m_region) <= 50:
                    raise ValidationError("Wilayah tradisi harus antara 2-50 karakter.")
                if m_price <= 0:
                    raise ValidationError("Harga hidangan harus lebih besar dari 0.")
                if not 1 <= len(m_unit) <= 40:
                    raise ValidationError("Satuan porsi harus antara 1-40 karakter.")
                if len(m_desc) > 400:
                    raise ValidationError("Deskripsi maksimal 400 karakter.")
                if m_img and not re.fullmatch(r"^[a-zA-Z0-9_.-]+$", m_img):
                    raise ValidationError("Nama berkas foto tidak valid.")

                with sqlite3.connect(DB_PATH, timeout=5) as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT COUNT(*) FROM menus WHERE id = ?", (m_id,))
                    if cur.fetchone()[0] == 0:
                        raise ValidationError(f"Menu dengan ID '{m_id}' tidak ditemukan.")
                    cur.execute(
                        """
                        UPDATE menus SET name = ?, region = ?, price = ?, unit = ?, description = ?, image = ?
                        WHERE id = ?
                        """,
                        (m_name, m_region, m_price, m_unit, m_desc, m_img or "gudeg-manggar.jpg", m_id),
                    )
                    conn.commit()

                sync_menu_json()
                self.send_json(200, {"status": "success", "message": f"Menu '{m_name}' berhasil diperbarui."})
            except ValidationError as ve:
                self.send_json(400, {"status": "error", "message": str(ve)})
            except Exception as e:
                self.send_json(500, {"status": "error", "message": "Gagal memperbarui menu.", "detail": str(e)})
            return

        # ---------------------------------------------------------------------
        # 5. API Admin: Hapus Menu
        # ---------------------------------------------------------------------
        if path == "/api/admin/menus/delete":
            if not self.require_admin() or not self.check_admin_csrf():
                return
            try:
                data = self.read_json_body()
                m_id = str(data.get("id", "")).strip().lower()
                if not m_id:
                    raise ValidationError("ID Menu wajib disertakan.")

                with sqlite3.connect(DB_PATH, timeout=5) as conn:
                    cur = conn.cursor()
                    cur.execute("DELETE FROM menus WHERE id = ?", (m_id,))
                    conn.commit()

                sync_menu_json()
                self.send_json(200, {"status": "success", "message": f"Menu '{m_id}' berhasil dihapus."})
            except ValidationError as ve:
                self.send_json(400, {"status": "error", "message": str(ve)})
            except Exception as e:
                self.send_json(500, {"status": "error", "message": "Gagal menghapus menu.", "detail": str(e)})
            return

        # ---------------------------------------------------------------------
        # 6. API Admin: Update Wadah
        # ---------------------------------------------------------------------
        if path == "/api/admin/packaging/update":
            if not self.require_admin() or not self.check_admin_csrf():
                return
            try:
                data = self.read_json_body()
                p_id = str(data.get("id", "")).strip().lower()
                p_name = str(data.get("name", "")).strip()
                p_desc = str(data.get("description", "")).strip()
                try:
                    p_price = int(data.get("price", 0))
                except (ValueError, TypeError):
                    raise ValidationError("Biaya wadah harus berupa angka bulat non-negatif.")

                if not p_id or not p_name:
                    raise ValidationError("ID dan Nama wadah wajib diisi.")
                if p_price < 0:
                    raise ValidationError("Biaya wadah tidak boleh negatif.")

                with sqlite3.connect(DB_PATH, timeout=5) as conn:
                    cur = conn.cursor()
                    cur.execute(
                        """
                        UPDATE packaging SET name = ?, price = ?, description = ?
                        WHERE id = ?
                        """,
                        (p_name, p_price, p_desc, p_id),
                    )
                    conn.commit()

                sync_menu_json()
                self.send_json(200, {"status": "success", "message": f"Wadah '{p_name}' berhasil diperbarui."})
            except ValidationError as ve:
                self.send_json(400, {"status": "error", "message": str(ve)})
            except Exception as e:
                self.send_json(500, {"status": "error", "message": "Gagal memperbarui wadah.", "detail": str(e)})
            return

        # ---------------------------------------------------------------------
        # 7. API Admin: Update Status Pesanan
        # ---------------------------------------------------------------------
        if path == "/api/admin/orders/status":
            if not self.require_admin() or not self.check_admin_csrf():
                return
            try:
                data = self.read_json_body()
                code = str(data.get("order_code", "")).strip().upper()
                new_status = str(data.get("status", "")).strip().lower()
                allowed_statuses = {"menunggu_konfirmasi", "diterima", "disiapkan", "dikirim", "selesai", "dibatalkan"}

                if not code:
                    raise ValidationError("Kode pesanan wajib diisi.")
                if new_status not in allowed_statuses:
                    raise ValidationError("Status pesanan tidak valid.")

                with sqlite3.connect(DB_PATH, timeout=5) as conn:
                    cur = conn.cursor()
                    cur.execute("UPDATE orders SET status = ? WHERE order_code = ?", (new_status, code))
                    if cur.rowcount == 0:
                        raise ValidationError(f"Pesanan dengan kode '{code}' tidak ditemukan.")
                    conn.commit()

                self.send_json(200, {"status": "success", "message": f"Status pesanan {code} diubah menjadi '{new_status}'.", "order_code": code, "new_status": new_status})
            except ValidationError as ve:
                self.send_json(400, {"status": "error", "message": str(ve)})
            except Exception as e:
                self.send_json(500, {"status": "error", "message": "Gagal memperbarui status pesanan.", "detail": str(e)})
            return

        # ---------------------------------------------------------------------
        # 8. API Admin: Ganti Kata Sandi
        # ---------------------------------------------------------------------
        if path == "/api/admin/change-password":
            admin_sess = self.require_admin()
            if not admin_sess or not self.check_admin_csrf():
                return
            try:
                data = self.read_json_body()
                current_pwd = str(data.get("current_password", "")).strip()
                new_pwd = str(data.get("new_password", "")).strip()

                if not current_pwd or not new_pwd:
                    raise ValidationError("Kata sandi saat ini dan kata sandi baru wajib diisi.")
                if len(new_pwd) < 8:
                    raise ValidationError("Kata sandi baru minimal harus 8 karakter.")

                with sqlite3.connect(DB_PATH, timeout=5) as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT id, password_hash, salt FROM admin_users WHERE id = ?", (admin_sess["user_id"],))
                    user = cur.fetchone()

                    if not user or not verify_password(current_pwd, user[1], user[2]):
                        raise ValidationError("Kata sandi saat ini tidak cocok.")

                    new_hash, new_salt = hash_password(new_pwd)
                    cur.execute(
                        """
                        UPDATE admin_users SET password_hash = ?, salt = ?
                        WHERE id = ?
                        """,
                        (new_hash, new_salt, user[0]),
                    )
                    # Hapus sesi lain demi keamanan, pertahankan sesi yang sedang aktif
                    cur.execute("DELETE FROM admin_sessions WHERE user_id = ? AND token != ?", (user[0], admin_sess["token"]))
                    conn.commit()

                self.send_json(200, {"status": "success", "message": "Kata sandi berhasil diganti dengan aman."})
            except ValidationError as ve:
                self.send_json(400, {"status": "error", "message": str(ve)})
            except Exception as e:
                self.send_json(500, {"status": "error", "message": "Gagal mengganti kata sandi.", "detail": str(e)})
            return

        # ---------------------------------------------------------------------
        # 9. API Publik: Pemesanan Pelanggan (Slow-Order)
        # ---------------------------------------------------------------------
        if path == "/api/billing/order":
            try:
                content_length = int(self.headers.get("Content-Length", 0))
                if content_length <= 0 or content_length > MAX_BODY_BYTES:
                    raise ValidationError("Ukuran data pesanan tidak valid.")
                data = json.loads(self.rfile.read(content_length).decode("utf-8"))

                with sqlite3.connect(DB_PATH, timeout=5) as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT id, name, region, price, unit FROM menus")
                    price_map = {
                        r[0]: {"name": r[1], "region": r[2], "price": r[3], "unit": r[4]}
                        for r in cur.fetchall()
                    }
                    cur.execute("SELECT id, name, price FROM packaging")
                    pack_map = {r[0]: {"name": r[1], "price": r[2]} for r in cur.fetchall()}

                    order = self.validate_order(data, price_map, pack_map)

                    order_code = f"MATARAM-{secrets.randbelow(900000) + 100000}"
                    cur.execute(
                        """
                        INSERT INTO orders (
                            order_code, customer_name, contact, items_json,
                            packaging_type, packaging_price, subtotal, total_bill,
                            arrival_date, destination_address, story, status
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            order_code,
                            order["customer_name"],
                            order["contact"],
                            json.dumps(order["items"], ensure_ascii=False),
                            order["packaging"]["name"],
                            order["packaging"]["price"],
                            order["subtotal"],
                            order["total_bill"],
                            order["arrival_date"],
                            order["destination_address"],
                            order["story"],
                            order["status"],
                        ),
                    )
                    conn.commit()

                order_response = {
                    "status": "success",
                    "order_code": order_code,
                    "created_at": datetime.now().isoformat(),
                    **order,
                }
                self.send_json(201, order_response)
            except ValidationError as exc:
                self.send_json(400, {"status": "error", "message": str(exc)})
            except (json.JSONDecodeError, UnicodeDecodeError):
                self.send_json(400, {"status": "error", "message": "Format data JSON pesanan tidak dapat dibaca."})
            except sqlite3.Error as exc:
                self.send_json(503, {"status": "error", "message": "Dapur sedang mengalami kendala penyimpanan. Data Anda belum terkirim. Silakan coba lagi.", "detail": str(exc)})
            except Exception as exc:
                self.send_json(500, {"status": "error", "message": "Pesanan belum dapat diproses karena terjadi gangguan sistem.", "detail": str(exc)})
            return

        self.send_json(404, {"status": "error", "message": "Endpoint API tidak ditemukan."})


def run(port=4174):
    init_db()
    server_address = ("0.0.0.0", port)
    HTTPServer.allow_reuse_address = True
    httpd = HTTPServer(server_address, PulangRasaHandler)
    print(f"[Gudeg KLA — Pulang Lewat Rasa] Server aktif di: http://127.0.0.1:{port}/")
    print(f"[Gudeg KLA] Halaman Admin: http://127.0.0.1:{port}/admin")
    print(f"[Gudeg KLA] Dapur: Jl. Teratai 1, Perumnas Klender, Jakarta Timur")
    print(f"[Gudeg KLA] Hotline WhatsApp: 085171506967 (Pembayaran QR CODE)")
    print(f"[Gudeg KLA] Database SQLite: {DB_PATH}")
    print("[Gudeg KLA] Keamanan berkas aktif, Range streaming audio aktif, Admin API aktif.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[Gudeg KLA] Menghentikan server...")
        httpd.server_close()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", sys.argv[1] if len(sys.argv) > 1 else 4174))
    run(port)
