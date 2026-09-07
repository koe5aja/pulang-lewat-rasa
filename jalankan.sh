#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${1:-4174}"

while :; do
  if ! ss -ltn "sport = :${PORT}" 2>/dev/null | grep -q LISTEN; then
    break
  fi
  PORT=$((PORT + 1))
done

echo "Pulang Lewat Rasa berjalan di: http://127.0.0.1:${PORT}/"
echo "Database billing SQLite aktif: ${BASE_DIR}/billing.db"
echo "Tekan Ctrl+C untuk menghentikan server."
cd "$BASE_DIR"
exec python3 server.py "$PORT"
