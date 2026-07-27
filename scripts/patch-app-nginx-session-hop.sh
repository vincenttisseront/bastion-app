#!/usr/bin/env bash
# patch-app-nginx-session-hop.sh
#
# Injecte location = /.bastion/session-cookies dans un vhost app (Dolibarr, etc.)
# pour battre `location ~ /\. { deny all; }` — requis pour le hop cookies Bastion.
#
# Usage sur vmdmz-reverse01 :
#   sudo VHOST_DEST=/etc/nginx/conf.d/vhost_dolibarr.conf \
#        SMOKE_URL=https://dolibarr.ar-systems.fr/.bastion/session-cookies \
#        bash scripts/patch-app-nginx-session-hop.sh
#
# Variables :
#   VHOST_DEST   (obligatoire) chemin du vhost nginx
#   SMOKE_URL    (obligatoire) URL de smoke GET
#   TRAEFIK_UPSTREAM=https://172.24.0.110
#   PORTAL_HOST=portal.ar-systems.fr
#   NO_RELOAD=1

set -euo pipefail

VHOST_DEST="${VHOST_DEST:-}"
SMOKE_URL="${SMOKE_URL:-}"
TRAEFIK_UPSTREAM="${TRAEFIK_UPSTREAM:-https://172.24.0.110}"
PORTAL_HOST="${PORTAL_HOST:-portal.ar-systems.fr}"
NO_RELOAD="${NO_RELOAD:-0}"

log() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Exécuter en root (sudo)."
[[ -n "$VHOST_DEST" ]] || die "VHOST_DEST requis (ex: /etc/nginx/conf.d/vhost_dolibarr.conf)"
[[ -n "$SMOKE_URL" ]] || die "SMOKE_URL requis (ex: https://dolibarr.ar-systems.fr/.bastion/session-cookies)"
[[ -f "$VHOST_DEST" ]] || die "Vhost introuvable: $VHOST_DEST"
command -v python3 >/dev/null 2>&1 || die "python3 requis"

MARKER="location = /.bastion/session-cookies"
if grep -qF "$MARKER" "$VHOST_DEST"; then
  log "Déjà présent ($MARKER) dans $VHOST_DEST — rien à injecter."
else
  TS="$(date +%Y%m%d%H%M%S)"
  BACKUP="${VHOST_DEST}.bak.sessionhop.${TS}"
  cp -a "$VHOST_DEST" "$BACKUP"
  log "Backup: $BACKUP"

  export VHOST_DEST TRAEFIK_UPSTREAM PORTAL_HOST
  python3 <<'PY'
import os
import re
import sys

path = os.environ["VHOST_DEST"]
upstream = os.environ["TRAEFIK_UPSTREAM"].rstrip("/")
portal = os.environ["PORTAL_HOST"]

block = f"""
    # Cookie hop (host-only target session cookies) — exact = beats location ~ /\\. deny
    # Traefik Host=portal; browser URL stays app FQDN → host-only cookies.
    # CRITICAL: do NOT add `internal;` — browser navigates here via a real 302.
    location = /.bastion/session-cookies {{
        auth_request off;
        proxy_pass {upstream}/api/internal/session-cookie-hop;
        proxy_ssl_verify off;
        proxy_http_version 1.1;
        proxy_set_header Host {portal};
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header Cookie $http_cookie;
        proxy_pass_request_body off;
    }}
""".rstrip("\n") + "\n\n"

text = open(path, encoding="utf-8").read()
if "location = /.bastion/session-cookies" in text:
    print("already present", file=sys.stderr)
    sys.exit(0)

deny_re = re.compile(r"(^[ \t]*location\s+~\s+/\\\.\s*\{)", re.M)
m = deny_re.search(text)
if m:
    text = text[: m.start()] + block + text[m.start() :]
else:
    loc_root = re.compile(
        r"(location\s+=\s+/\s*\{.*?^\s*\}\s*\n)",
        re.M | re.S,
    )
    m2 = loc_root.search(text)
    if not m2:
        print("ERROR: impossible de trouver `location ~ /\\.` ni `location = /`", file=sys.stderr)
        sys.exit(2)
    text = text[: m2.end()] + "\n" + block + text[m2.end() :]

open(path, "w", encoding="utf-8", newline="\n").write(text)
print(f"Injecté dans {path}")
PY
fi

log ""
log "=== nginx -t ==="
if ! nginx -t; then
  die "nginx -t invalide — restaurer le .bak.sessionhop.* le plus récent"
fi

if [[ "$NO_RELOAD" != "1" ]]; then
  systemctl reload nginx
  log "nginx rechargé."
fi

log ""
log "=== Smoke $SMOKE_URL ==="
status="$(curl -skI --max-time 15 "$SMOKE_URL" | awk 'BEGIN{IGNORECASE=1} /^HTTP\//{print $2; exit}')"
log "HTTP $status"
if [[ "$status" == "403" ]]; then
  die "Toujours 403 — location non prise en compte (mauvais fichier? conf.d non inclus?)"
fi
if [[ "$status" == "404" ]]; then
  die "404 — mauvais vhost ou fichier non chargé"
fi
if [[ "$status" != "302" && "$status" != "301" ]]; then
  log "ATTENTION: attendu 302 (token hop absent), obtenu $status — vérifier proxy Traefik/bastion."
else
  log "OK: hop atteint (redirect sans cookie hop)."
fi

log ""
log "Ensuite: hard refresh portail, rouvrir l'app, vérifier DOLSESSID_* / PHPSESSID sur le FQDN app."
