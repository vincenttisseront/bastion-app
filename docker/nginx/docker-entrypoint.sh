#!/usr/bin/env bash
# Render snippets that need secrets, then start nginx.
set -euo pipefail

export PORTAL_INTERNAL_TOKEN="${PORTAL_INTERNAL_TOKEN:-}"
export PORTAL_DOMAIN="${PORTAL_DOMAIN:-portal.ar-systems.fr}"
export SSO_PORTAL_DEFAULT_REALM_SLUG="${SSO_PORTAL_DEFAULT_REALM_SLUG:-ar-systems}"

if [[ -z "${PORTAL_INTERNAL_TOKEN}" ]]; then
  echo "WARN: PORTAL_INTERNAL_TOKEN empty — FastAPI internal auth may fail" >&2
fi

# Ensure exports include exists (empty stub if missing)
mkdir -p /var/lib/sso-portal/exports
if [[ ! -f /var/lib/sso-portal/exports/nginx-portal-realms.conf ]]; then
  echo "# no secondary realms yet" > /var/lib/sso-portal/exports/nginx-portal-realms.conf
fi

envsubst '${PORTAL_INTERNAL_TOKEN}' \
  < /etc/nginx/templates-portal/proxy_portal_trusted_internal.conf.template \
  > /etc/nginx/snippets/proxy_portal_trusted_internal.conf

envsubst '${PORTAL_DOMAIN} ${SSO_PORTAL_DEFAULT_REALM_SLUG}' \
  < /etc/nginx/templates-portal/vhost_sso_portal.conf.template \
  > /etc/nginx/conf.d/vhost_sso_portal.conf

# Fail fast if vhost render did not produce a listener (avoids "running" with no :8080)
if ! grep -qE 'listen[[:space:]]+0\.0\.0\.0:8080' /etc/nginx/conf.d/vhost_sso_portal.conf; then
  echo "ERROR: rendered vhost missing listen 0.0.0.0:8080" >&2
  cat /etc/nginx/conf.d/vhost_sso_portal.conf >&2 || true
  exit 1
fi

nginx -t
exec "$@"
