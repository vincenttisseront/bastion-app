#!/usr/bin/env bash
# Exécuté en root par systemd (path unit) sur docker01 —
# lit apply-infra.request, lance apply-infra-docker.sh, écrit status + log.
set -euo pipefail

DATA_DIR="${SSO_PORTAL_DATA_DIR:-/tools/portal/data}"
REQUEST="$DATA_DIR/apply-infra.request"
STATUS_FILE="$DATA_DIR/apply-infra.status"
LOG_FILE="$DATA_DIR/apply-infra.log"
COMPOSE_DIR="${BASTION_COMPOSE_DIR:-${SSO_PORTAL_COMPOSE_DIR:-/tools/portal}}"
APPLY_SCRIPT="${APPLY_INFRA_DOCKER_SCRIPT:-$COMPOSE_DIR/scripts/apply-infra-docker.sh}"

finish() {
  local code="$1"
  local status="$2"
  local msg="$3"
  printf '%s\n' "$status" >"$STATUS_FILE"
  printf '%s\n' "$msg" >"$LOG_FILE"
  chmod 640 "$STATUS_FILE" "$LOG_FILE" 2>/dev/null || true
  rm -f "$REQUEST"
  exit "$code"
}

# Attente courte : évite la course PathChanged pendant un replace atomique.
for _ in 1 2 3 4 5 6 7 8 9 10; do
  [[ -f "$REQUEST" ]] && break
  sleep 0.1
done
if [[ ! -f "$REQUEST" ]]; then
  finish 1 error "Fichier requête absent ($REQUEST)."
fi

EXPORT_DIR="$(head -1 "$REQUEST" | tr -d '\r\n' | sed 's/#.*//')"
EXPORT_DIR="$(echo "$EXPORT_DIR" | xargs)"
if [[ -z "$EXPORT_DIR" ]]; then
  # Contenu container path → chemin hôte data/exports
  EXPORT_DIR="$DATA_DIR/exports"
fi
# Si le chemin vient du conteneur (/var/lib/sso-portal/exports) mais DATA_DIR
# hôte est /tools/portal/data, utiliser le mount hôte.
if [[ ! -d "$EXPORT_DIR" && -d "$DATA_DIR/exports" ]]; then
  EXPORT_DIR="$DATA_DIR/exports"
fi
if [[ ! -d "$EXPORT_DIR" ]]; then
  finish 1 error "Répertoire export introuvable: $EXPORT_DIR (data=$DATA_DIR)"
fi
if [[ ! -x "$APPLY_SCRIPT" ]]; then
  if [[ -f "$APPLY_SCRIPT" ]]; then
    chmod +x "$APPLY_SCRIPT" || true
  fi
fi
if [[ ! -x "$APPLY_SCRIPT" ]]; then
  finish 1 error "Script apply absent ou non exécutable: $APPLY_SCRIPT"
fi

LOG_TMP="$(mktemp)"
if "$APPLY_SCRIPT" "$EXPORT_DIR" "$COMPOSE_DIR" >"$LOG_TMP" 2>&1; then
  {
    cat "$LOG_TMP"
    echo "Infrastructure Docker appliquée avec succès."
  } >"${LOG_TMP}.ok"
  finish 0 ok "$(cat "${LOG_TMP}.ok")"
else
  rc=$?
  finish "$rc" error "$(cat "$LOG_TMP")"
fi
