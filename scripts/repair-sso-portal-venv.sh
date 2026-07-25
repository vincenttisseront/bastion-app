#!/usr/bin/env bash
# repair-sso-portal-venv.sh — répare un venv /opt/sso-portal corrompu (ImportError fastapi).
#
# Usage sur vmdmz-reverse01 :
#   sudo bash repair-sso-portal-venv.sh
#   sudo REBUILD=1 bash repair-sso-portal-venv.sh   # recréer le venv entièrement

set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/sso-portal}"
VENV="${INSTALL_DIR}/venv"
USER="${SSO_PORTAL_USER:-sso-portal}"
REBUILD="${REBUILD:-0}"

log() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Exécuter en root (sudo)."

PIP_DEPS=(
  "fastapi>=0.137.1"
  "uvicorn[standard]>=0.49.0"
  "httpx>=0.28.1"
  "pydantic[email]>=2.13.4"
  "pydantic-settings>=2.14.2"
  "PyJWT>=2.13.0"
  "cryptography>=49.0.0"
  "sqlalchemy>=2.0.51"
  "jinja2>=3.1.6"
  "python-multipart>=0.0.32"
  "bcrypt>=5.0.0"
  "pyyaml>=6.0.3"
  "email-validator>=2.3.0"
  "pandas>=2.2"
  "reportlab>=4.2"
  "alembic>=1.14.0"
  "apscheduler>=3.10.4"
)

log "=== Diagnostic fastapi ==="
if [[ -x "${VENV}/bin/python3" ]]; then
  sudo -u "$USER" env PYTHONPATH="$INSTALL_DIR" "${VENV}/bin/python3" -c \
    "import fastapi; from fastapi import FastAPI; print('fastapi OK', fastapi.__file__)" \
    2>&1 || true
else
  log "venv absent ou python3 manquant"
fi

if [[ "$REBUILD" == "1" ]]; then
  log "=== Suppression venv (REBUILD=1) ==="
  rm -rf "$VENV"
fi

if [[ ! -x "${VENV}/bin/python3" ]]; then
  log "=== Création venv ==="
  python3 -m venv "$VENV"
  chown -R "$USER:$USER" "$VENV"
fi

log "=== Nettoyage ombres PYTHONPATH + métadonnées pip ==="
rm -rf "${INSTALL_DIR}/fastapi" "${INSTALL_DIR}/pydantic" \
       "${INSTALL_DIR}/fastapi.py" "${INSTALL_DIR}/pydantic.py" \
       "${INSTALL_DIR}"/*.egg-info "${INSTALL_DIR}/bastion_app"*.dist-info 2>/dev/null || true
rm -rf "${VENV}"/lib/python*/site-packages/bastion_app*.dist-info \
       "${VENV}"/lib/python*/site-packages/__editable__*.pth \
       "${VENV}"/lib/python*/site-packages/__editable__*.py \
       "${VENV}"/lib/python*/site-packages/bastion_app*.pth 2>/dev/null || true

log "=== Réinstallation pip (--force-reinstall, user ${USER}) ==="
sudo -u "$USER" "${VENV}/bin/pip" install --upgrade pip
sudo -u "$USER" "${VENV}/bin/pip" install --force-reinstall --no-cache-dir "${PIP_DEPS[@]}"

chown -R "$USER:$USER" "$VENV"

log "=== Vérification fastapi/pydantic (sans PYTHONPATH) ==="
sudo -u "$USER" "${VENV}/bin/python3" -c \
  "import fastapi; from fastapi import FastAPI; import pydantic; from pydantic import AliasChoices; print('deps OK', fastapi.__file__)"

log "=== Vérification import ==="
sudo -u "$USER" env PYTHONPATH="$INSTALL_DIR" bash -c \
  "cd '$INSTALL_DIR' && '$VENV/bin/python3' -c \"from fastapi import FastAPI; import app.main; print('import ok')\""

log "=== Restart sso-portal ==="
systemctl restart sso-portal
sleep 2
curl -sf "http://127.0.0.1:8000/api/health" && echo "" || die "healthcheck KO"

log "Terminé."
