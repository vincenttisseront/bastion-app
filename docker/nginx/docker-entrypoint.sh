#!/usr/bin/env bash
# Render snippets that need secrets, sync App exports, then start nginx + export watcher.
set -euo pipefail

export PORTAL_INTERNAL_TOKEN="${PORTAL_INTERNAL_TOKEN:-}"
export PORTAL_DOMAIN="${PORTAL_DOMAIN:-portal.ar-systems.fr}"
export SSO_PORTAL_DEFAULT_REALM_SLUG="${SSO_PORTAL_DEFAULT_REALM_SLUG:-ar-systems}"
export EXPORTS_DIR="${EXPORTS_DIR:-/var/lib/sso-portal/exports}"

if [[ -z "${PORTAL_INTERNAL_TOKEN}" ]]; then
  echo "WARN: PORTAL_INTERNAL_TOKEN empty — FastAPI internal auth may fail" >&2
fi

# Ensure exports include exists (empty stub if missing).
# exports/ is often :ro in the nginx container — only write when the FS allows it.
mkdir -p "$EXPORTS_DIR" 2>/dev/null || true
if [[ ! -f "$EXPORTS_DIR/nginx-portal-realms.conf" ]]; then
  echo "# no secondary realms yet" > "$EXPORTS_DIR/nginx-portal-realms.conf" 2>/dev/null \
    || echo "WARN: exports/nginx-portal-realms.conf missing and exports is read-only" >&2
fi

/sync-exports-to-confd.sh

if [[ ! -d /var/log/nginx/apps ]]; then
  echo "ERROR: /var/log/nginx/apps missing — Accès apps requires shared nginx-logs volume" >&2
fi

envsubst '${PORTAL_INTERNAL_TOKEN}' \
  < /etc/nginx/templates-portal/proxy_portal_trusted_internal.conf.template \
  > /etc/nginx/snippets/proxy_portal_trusted_internal.conf

envsubst '${PORTAL_DOMAIN} ${SSO_PORTAL_DEFAULT_REALM_SLUG}' \
  < /etc/nginx/templates-portal/vhost_sso_portal.conf.template \
  > /etc/nginx/conf.d/vhost_sso_portal.conf

# Fail fast if vhost render did not produce a listener (avoids "running" with no :8080)
if ! grep -qE 'listen[[:space:]]+0\.0\.0\.0:8080([[:space:]]+default_server)?' \
  /etc/nginx/conf.d/vhost_sso_portal.conf; then
  echo "ERROR: rendered vhost missing listen 0.0.0.0:8080" >&2
  cat /etc/nginx/conf.d/vhost_sso_portal.conf >&2 || true
  exit 1
fi
if ! grep -qE 'listen[[:space:]]+0\.0\.0\.0:8080[[:space:]]+default_server' \
  /etc/nginx/conf.d/vhost_sso_portal.conf; then
  echo "ERROR: portal vhost must be default_server on :8080 (else subdomain/public_proxy steal loopback health)" >&2
  exit 1
fi

nginx -t

# Watch App catalogue exports → conf.d + reload (approve/edit without apply-infra-docker).
if [[ "${BASTION_EXPORTS_WATCH:-1}" != "0" ]]; then
  /watch-exports-reload.sh &
fi

exec "$@"
