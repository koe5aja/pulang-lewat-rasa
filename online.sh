#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${1:-4174}"
CLOUDFLARED="/home/kus/.local/bin/cloudflared"

if [ ! -f "$CLOUDFLARED" ]; then
  mkdir -p /home/kus/.local/bin
  echo "Mengunduh Cloudflare Tunnel resmi (gratis)..."
  curl -sL "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64" -o "$CLOUDFLARED"
  chmod +x "$CLOUDFLARED"
fi

echo "========================================================================="
echo "   GUDEG KLA: PULANG LEWAT RASA — ONLINE GRATIS (TANPA DOMAIN & HOSTING)"
echo "========================================================================="

# Jalankan server lokal jika belum berjalan
if ! ss -ltn "sport = :${PORT}" 2>/dev/null | grep -q LISTEN; then
  echo "Memulai server lokal pada port ${PORT}..."
  cd "$BASE_DIR"
  python3 server.py "$PORT" &
  SERVER_PID=$!
  sleep 1
else
  echo "Server lokal sudah aktif di port ${PORT}."
  SERVER_PID=""
fi

cleanup() {
  echo -e "\n\nMenghentikan tunnel online..."
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
  fi
  exit 0
}
trap cleanup SIGINT SIGTERM

echo "Menghubungkan ke jaringan publik Cloudflare (100% Gratis & Aman)..."
echo "Menyiapkan URL HTTPS publik..."

"$CLOUDFLARED" tunnel --url "http://127.0.0.1:${PORT}"
