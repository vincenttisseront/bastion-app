#!/usr/bin/env bash
# Render snippets that need secrets, sync App exports, then start nginx + export watcher.
set -euo pipefail

export PORTAL_INTERNAL_TOKEN="${PORTAL_INTERNAL_TOKEN:-}"
export PORTAL_DOMAIN="${PORTAL_DOMAIN:-portal.ar-systems.fr}"
export SSO_PORTAL_DEFAULT_REALM_SLUG="${SSO_PORTAL_DEFAULT_REALM_SLUG:-ar-systems}"
export EXPORTS_DIR="${EXPORTS_DIR:-/var/lib/sso-portal/exports}"

# Portal + auth_request open many FDs. Docker default soft=1024 → accept4 EMFILE
# and clients see bare "403 Forbidden / nginx". Compose sets ulimits.nofile=65535;
# raise soft to hard here so a forgotten recreate still recovers when hard allows.
if soft=$(ulimit -n 2>/dev/null); then
  hard=$(ulimit -H -n 2>/dev/null || echo "$soft")
  if [[ "$hard" =~ ^[0-9]+$ ]] && [[ "$soft" =~ ^[0-9]+$ ]] && [[ "$soft" -lt "$hard" ]]; then
    ulimit -n "$hard" 2>/dev/null || true
    soft=$(ulimit -n 2>/dev/null || echo "$soft")
  fi
  echo "INFO: nginx process nofile soft=${soft} hard=${hard}"
  if [[ "$soft" =~ ^[0-9]+$ ]] && [[ "$soft" -lt 4096 ]]; then
    echo "ERROR: nofile soft=${soft} < 4096 — expect intermittent bare nginx 403 (EMFILE)." >&2
    echo "ERROR: set docker-compose ulimits.nofile soft/hard 65535 and recreate bastion-nginx." >&2
    if [[ "${BASTION_REQUIRE_HIGH_NOFILE:-1}" != "0" ]]; then
      exit 1
    fi
  fi
fi

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

# ModSecurity audit log (same volume as per-app access/error logs).
mkdir -p /var/log/nginx/apps /tmp/modsecurity/data /tmp/modsecurity/tmp /tmp/modsecurity/upload
touch /var/log/nginx/apps/modsec_audit.log
chown -R nginx:nginx /tmp/modsecurity /var/log/nginx/apps/modsec_audit.log 2>/dev/null || true
chmod 0640 /var/log/nginx/apps/modsec_audit.log 2>/dev/null || true

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
/export-waf-snapshot.sh || echo "WARN: export-waf-snapshot failed" >&2

# Daily logrotate + snapshot WAF toutes les 5 min (crond Alpine).
# Le crontab Alpine n'exécute pas /etc/periodic/5min sans ligne */5.
if [[ "${BASTION_MODSEC_LOGROTATE:-1}" != "0" ]] && command -v crond >/dev/null 2>&1; then
  mkdir -p /etc/periodic/daily
  cat > /etc/periodic/daily/modsecurity-logrotate <<'EOF'
#!/bin/sh
/usr/sbin/logrotate -f /etc/logrotate.d/modsecurity >/dev/null 2>&1 || true
EOF
  chmod +x /etc/periodic/daily/modsecurity-logrotate
  mkdir -p /etc/periodic/5min
  cat > /etc/periodic/5min/waf-snapshot <<'EOF'
#!/bin/sh
/export-waf-snapshot.sh >/dev/null 2>&1 || true
EOF
  chmod +x /etc/periodic/5min/waf-snapshot
  if ! grep -qF 'run-parts /etc/periodic/5min' /etc/crontabs/root 2>/dev/null; then
    echo '*/5 * * * * run-parts /etc/periodic/5min' >> /etc/crontabs/root
  fi
  crond -b -l 8 || echo "WARN: crond failed to start — modsec logrotate / waf-snapshot inactive" >&2
fi

# Watch App catalogue exports → conf.d + reload (approve/edit without apply-infra-docker).
if [[ "${BASTION_EXPORTS_WATCH:-1}" != "0" ]]; then
  /watch-exports-reload.sh &
fi

exec "$@"
