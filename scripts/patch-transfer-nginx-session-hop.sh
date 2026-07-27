#!/usr/bin/env bash
# patch-transfer-nginx-session-hop.sh
#
# Injecte les location = /.bastion/session-cookies (+ alias crush-session)
# dans le vhost transfer live — nécessaire pour battre `location ~ /\. { deny all; }`.
#
# Usage sur vmdmz-reverse01 :
#   sudo bash patch-transfer-nginx-session-hop.sh
#   # ou depuis le dépôt :
#   sudo bash /chemin/vers/bastion-app/scripts/patch-transfer-nginx-session-hop.sh
#
# Variables :
#   VHOST_DEST=/etc/nginx/conf.d/vhost_transfer_crushftp.conf
#   TRAEFIK_UPSTREAM=https://172.24.0.110
#   PORTAL_HOST=portal.ar-systems.fr
#   NO_RELOAD=1
#   SMOKE_URL=https://transfer.ar-systems.fr/.bastion/session-cookies

set -euo pipefail

VHOST_DEST="${VHOST_DEST:-/etc/nginx/conf.d/vhost_transfer_crushftp.conf}"
TRAEFIK_UPSTREAM="${TRAEFIK_UPSTREAM:-https://172.24.0.110}"
PORTAL_HOST="${PORTAL_HOST:-portal.ar-systems.fr}"
NO_RELOAD="${NO_RELOAD:-0}"
SMOKE_URL="${SMOKE_URL:-https://transfer.ar-systems.fr/.bastion/session-cookies}"

log() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Exécuter en root (sudo)."
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
    # Traefik Host=portal; browser URL stays transfer.* → host-only cookies.
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
    location = /.bastion/crush-session {{
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

# Prefer insert just before the dotfiles deny (must stay after exact = locations).
deny_re = re.compile(r"(^[ \t]*location\s+~\s+/\\\.\s*\{)", re.M)
m = deny_re.search(text)
if m:
    text = text[: m.start()] + block + text[m.start() :]
else:
    # Fallback: after first `location = / { ... }`
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
# shellcheck disable=SC2086
status="$(curl -skI --max-time 15 "$SMOKE_URL" | awk 'BEGIN{IGNORECASE=1} /^HTTP\//{print $2; exit}')"
log "HTTP $status"
if [[ "$status" == "403" ]]; then
  die "Toujours 403 — location non prise en compte (mauvais fichier? conf.d non inclus?)"
fi
if [[ "$status" != "302" && "$status" != "301" ]]; then
  log "ATTENTION: attendu 302 (token hop absent), obtenu $status — vérifier proxy Traefik/bastion."
else
  log "OK: plus de 403 (hop atteint ou redirect)."
fi

log ""
log "Ensuite: purge CrushAuth/currentAuth Domain=.ar-systems.fr puis open Transfer depuis le portail."
