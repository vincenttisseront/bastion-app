#!/usr/bin/env bash
# restore-transfer-nginx-awx.sh
#
# Restaure la config nginx transfer EXACTEMENT comme awx-playbook
# (roles/nginx_reverse_proxy_dmz) — sans patch expérimental.
#
# Usage sur vmdmz-reverse01 :
#   sudo bash restore-transfer-nginx-awx.sh
#
# Sources (dans l'ordre) :
#   1. AWX_PLAYBOOK_DIR/roles/nginx_reverse_proxy_dmz/...
#   2. Répertoire nginx/reference-from-awx/ du dépôt bastion-app (à côté du script)
#
# Variables :
#   AWX_PLAYBOOK_DIR=/chemin/vers/awx-playbook
#   NO_RELOAD=1

set -euo pipefail

VHOST_DEST="${VHOST_DEST:-/etc/nginx/conf.d/vhost_transfer_crushftp.conf}"
MAP_DEST="${MAP_DEST:-/etc/nginx/includes/transfer-crushftp.map.conf}"
NGINX_CONF="${NGINX_CONF:-/etc/nginx/nginx.conf}"
NO_RELOAD="${NO_RELOAD:-0}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASTION_REF="${SCRIPT_DIR}/../nginx/reference-from-awx"
AWX_PLAYBOOK_DIR="${AWX_PLAYBOOK_DIR:-}"

log() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Exécuter en root (sudo)."

resolve_src() {
  local awx_rel="$1"
  local ref_name="$2"
  if [[ -n "$AWX_PLAYBOOK_DIR" && -f "${AWX_PLAYBOOK_DIR}/${awx_rel}" ]]; then
    printf '%s\n' "${AWX_PLAYBOOK_DIR}/${awx_rel}"
    return 0
  fi
  local local_guess
  for local_guess in \
    "${SCRIPT_DIR}/../../awx-playbook/${awx_rel}" \
    "${HOME}/awx-playbook/${awx_rel}" \
    "/opt/awx-playbook/${awx_rel}"; do
    if [[ -f "$local_guess" ]]; then
      printf '%s\n' "$local_guess"
      return 0
    fi
  done
  if [[ -f "${BASTION_REF}/${ref_name}" ]]; then
    printf '%s\n' "${BASTION_REF}/${ref_name}"
    return 0
  fi
  return 1
}

MAP_SRC="$(resolve_src "roles/nginx_reverse_proxy_dmz/files/transfer-crushftp.map.conf" "transfer-crushftp.map.conf")" \
  || die "transfer-crushftp.map.conf introuvable (AWX_PLAYBOOK_DIR ou bastion-app/nginx/reference-from-awx/)"

VHOST_TEMPLATE="$(resolve_src "roles/nginx_reverse_proxy_dmz/templates/vhost_transfer_crushftp.conf.j2" "")" || true
VHOST_STATIC="${BASTION_REF}/vhost_transfer_crushftp.conf"

TS="$(date +%Y%m%d%H%M%S)"
mkdir -p "$(dirname "$MAP_DEST")" "$(dirname "$VHOST_DEST")"

[[ -f "$VHOST_DEST" ]] && cp -a "$VHOST_DEST" "${VHOST_DEST}.backup.${TS}"
[[ -f "$MAP_DEST" ]] && cp -a "$MAP_DEST" "${MAP_DEST}.backup.${TS}"

log "=== Restauration transfer nginx (référence AWX) ==="
log "Map source  : $MAP_SRC"
cp -a "$MAP_SRC" "$MAP_DEST"
log "Map déployé : $MAP_DEST"

if [[ -n "${VHOST_TEMPLATE:-}" && -f "$VHOST_TEMPLATE" ]] && command -v ansible >/dev/null 2>&1; then
  log "Vhost source: $VHOST_TEMPLATE (rendu ansible)"
  ansible localhost -m template -a "src=${VHOST_TEMPLATE} dest=${VHOST_DEST}" \
    -e "transfer_domain=transfer.ar-systems.fr" \
    -e "transfer_backend_ip=172.24.0.106" \
    -e "transfer_backend=https://172.24.0.106" \
    -e "ssl_certificate_path=/etc/letsencrypt/live/ar-systems.fr/fullchain.pem" \
    -e "ssl_certificate_key=/etc/letsencrypt/live/ar-systems.fr/privkey.pem" \
    -e "ansible_managed=restored by restore-transfer-nginx-awx.sh" >/dev/null
elif [[ -f "$VHOST_STATIC" ]]; then
  log "Vhost source: $VHOST_STATIC"
  cp -a "$VHOST_STATIC" "$VHOST_DEST"
else
  die "vhost_transfer_crushftp introuvable (template AWX ou ${VHOST_STATIC})"
fi
log "Vhost déployé: $VHOST_DEST"

if [[ -f "$NGINX_CONF" ]] && ! grep -q 'transfer-crushftp.map.conf' "$NGINX_CONF"; then
  log "ATTENTION: $NGINX_CONF n'inclut pas transfer-crushftp.map.conf"
  log "  Attendu dans bloc http {} : include /etc/nginx/includes/transfer-crushftp.map.conf;"
  log "  → Relancer le playbook AWX 'App – Nginx reverse' ou ajouter l'include manuellement."
fi

log ""
log "=== nginx -t ==="
if ! nginx -t; then
  log "ÉCHEC — restaurer les backups *.backup.${TS}"
  die "nginx -t invalide"
fi

if [[ "$NO_RELOAD" != "1" ]]; then
  systemctl reload nginx
  log "nginx rechargé."
fi

log ""
log "=== Tests ==="
curl -sk "https://172.24.0.106/WebInterface/new-ui/" -H "Host: 172.24.0.106" \
  -o /tmp/transfer-direct.bin -w "direct size=%{size_download}\n" --max-time 35 || true
curl -sk "https://transfer.ar-systems.fr/WebInterface/new-ui/" \
  --resolve transfer.ar-systems.fr:443:127.0.0.1 \
  -o /tmp/transfer-proxy.bin -w "proxy size=%{size_download}\n" --max-time 35 || true
ls -la /tmp/transfer-direct.bin /tmp/transfer-proxy.bin 2>/dev/null || true

log ""
log "Terminé. Source de vérité : awx-playbook roles/nginx_reverse_proxy_dmz"
log "Ne pas utiliser fix-transfer-nginx-reneg.sh (patch expérimental)."
