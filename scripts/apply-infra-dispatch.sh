#!/usr/bin/env bash
# Exécuté en root par systemd (path unit) — lit apply-infra.request, écrit status + log.
set -euo pipefail

DATA_DIR="${SSO_PORTAL_DATA_DIR:-/var/lib/sso-portal}"
REQUEST="$DATA_DIR/apply-infra.request"
STATUS_FILE="$DATA_DIR/apply-infra.status"
LOG_FILE="$DATA_DIR/apply-infra.log"
INSTALL_DIR="${SSO_PORTAL_INSTALL_DIR:-/opt/sso-portal}"
APPLY_SCRIPT="$INSTALL_DIR/scripts/apply-infrastructure.sh"
PORTAL_USER="${SSO_PORTAL_USER:-sso-portal}"

finish() {
  local code="$1"
  local status="$2"
  local msg="$3"
  printf '%s\n' "$status" >"$STATUS_FILE"
  printf '%s\n' "$msg" >"$LOG_FILE"
  chown "$PORTAL_USER:$PORTAL_USER" "$STATUS_FILE" "$LOG_FILE" 2>/dev/null || true
  chmod 640 "$STATUS_FILE" "$LOG_FILE"
  rm -f "$REQUEST"
  exit "$code"
}

# Attente courte : évite la course si PathModified déclenche le service pendant un replace atomique.
for _ in 1 2 3 4 5 6 7 8 9 10; do
  [[ -f "$REQUEST" ]] && break
  sleep 0.1
done
if [[ ! -f "$REQUEST" ]]; then
  finish 1 error "Fichier requête absent ($REQUEST)."
fi

EXPORT_DIR="$(tr -d '\r\n' <"$REQUEST")"
if [[ -z "$EXPORT_DIR" ]]; then
  finish 1 error "Chemin export vide dans $REQUEST."
fi
if [[ ! -d "$EXPORT_DIR" ]]; then
  finish 1 error "Répertoire export introuvable: $EXPORT_DIR"
fi
if [[ ! -x "$APPLY_SCRIPT" ]]; then
  finish 1 error "Script apply absent ou non exécutable: $APPLY_SCRIPT"
fi

LOG_TMP="$(mktemp)"
if "$APPLY_SCRIPT" "$EXPORT_DIR" >"$LOG_TMP" 2>&1; then
  finish 0 ok "Infrastructure appliquée avec succès."
else
  rc=$?
  finish "$rc" error "$(cat "$LOG_TMP")"
fi
