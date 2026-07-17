#!/usr/bin/env bash
# oauth2-proxy v7+ attend un secret 16/24/32 octets (AES).
# Génération : 32 octets aléatoires, encodés en base64 URL-safe sans padding
# (compatible pkg/encryption.SecretBytes → base64.RawURLEncoding côté Go).
set -euo pipefail

_py() {
  python3 - "$@"
}

cmd_gen() {
  _py - <<'PY'
import base64
import os

print(base64.urlsafe_b64encode(os.urandom(32)).decode(), end="")
PY
}

cmd_valid() {
  local file="${1:-}"
  if [[ -z "$file" || ! -s "$file" ]]; then
    return 1
  fi
  _py "$file" <<'PY'
import base64
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
raw = path.read_text().strip()
if not raw:
    sys.exit(1)

# openssl rand -base64 32 produit du base64 standard (+/) : rejeté par Go RawURLEncoding.
if any(ch in raw for ch in "+/"):
    sys.exit(1)

# Miroir oauth2-proxy SecretBytes : RawURLEncoding, padding '=' retiré.
try:
    decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    if len(decoded) in (16, 24, 32):
        sys.exit(0)
except Exception:
    pass

# Secret brut ASCII 16/24/32 octets (rare).
if len(raw.encode()) in (16, 24, 32):
    sys.exit(0)

sys.exit(1)
PY
}

case "${1:-gen}" in
  gen) cmd_gen ;;
  valid) cmd_valid "${2:-}" ;;
  *)
    echo "Usage: $0 gen|valid <file>" >&2
    exit 2
    ;;
esac
