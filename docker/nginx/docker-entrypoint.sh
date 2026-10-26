#!/usr/bin/env bash
# Render snippets that need secrets, sync App exports, then start nginx + export watcher.
set -euo pipefail

export PORTAL_INTERNAL_TOKEN="${PORTAL_INTERNAL_TOKEN:-}"
export PORTAL_DOMAIN="${PORTAL_DOMAIN:-portal.example.com}"
export SSO_PORTAL_DEFAULT_REALM_SLUG="${SSO_PORTAL_DEFAULT_REALM_SLUG:-default}"
export EXPORTS_DIR="${EXPORTS_DIR:-/var/lib/sso-portal/exports}"
export BASTION_NGINX_SEED="${BASTION_NGINX_SEED:-/usr/share/bastion-nginx/seed}"

echo "INFO: bastion-nginx entrypoint uid=$(id -u) gid=$(id -g)"

# When compose mounts empty tmpfs over conf.d/snippets/includes/generated, restore defaults.
# Non-root: never ``cp -a`` (BusyBox fails preserving root ownership → set -e abort).
# Note: with cap_drop ALL, uid 0 loses DAC_OVERRIDE — tmpfs must be mode 0777 (see compose)
# or seed/write fails even as "root".
_seed_nginx_writable_dirs() {
  local name dest seed err
  for name in conf.d snippets includes; do
    dest="/etc/nginx/${name}"
    seed="${BASTION_NGINX_SEED}/${name}"
    mkdir -p "$dest" 2>/dev/null || true
    if [[ -d "$seed" ]] && [[ ! -f "${dest}/.bastion-seeded" ]]; then
      # -r not -a: drop ownership/mode preserve (uid 101 cannot chown root-owned seed).
      err="$(cp -rf "${seed}/." "${dest}/" 2>&1)" && touch "${dest}/.bastion-seeded" 2>/dev/null || true
      if [[ -n "${err}" ]]; then
        echo "WARN: could not seed ${dest} from ${seed}: ${err}" >&2
      fi
    fi
  done
  # WAF overlays written by sync-exports (read_only rootfs needs tmpfs here).
  dest="/etc/nginx/modsecurity/generated"
  seed="${BASTION_NGINX_SEED}/generated"
  mkdir -p "$dest" 2>/dev/null || true
  if [[ -d "$seed" ]] && [[ ! -f "${dest}/.bastion-seeded" ]]; then
    err="$(cp -rf "${seed}/." "${dest}/" 2>&1)" && touch "${dest}/.bastion-seeded" 2>/dev/null || true
    if [[ -n "${err}" ]]; then
      echo "WARN: could not seed ${dest} from ${seed}: ${err}" >&2
    fi
  fi
  mkdir -p /tmp/modsecurity/data /tmp/modsecurity/tmp /tmp/modsecurity/upload \
    /var/cache/nginx /var/run /etc/nginx/ssl-local 2>/dev/null || true
}

_seed_nginx_writable_dirs

# DB / setup-wizard override (written by bastion-app as exports/bastion-site.env)
if [[ -f "${EXPORTS_DIR}/bastion-site.env" ]]; then
  # shellcheck disable=SC1090
  set -a
  # Prefer file values over compose defaults when present.
  # shellcheck disable=SC1091
  . "${EXPORTS_DIR}/bastion-site.env"
  set +a
  export PORTAL_DOMAIN="${PORTAL_DOMAIN:-portal.example.com}"
  export SSO_PORTAL_DEFAULT_REALM_SLUG="${SSO_PORTAL_DEFAULT_REALM_SLUG:-default}"
fi

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

# exports/ is often :ro — never require a write there. Realms mirror lives under
# includes/ (tmpfs); sync-exports copies from exports when present.
mkdir -p "$EXPORTS_DIR" /etc/nginx/includes 2>/dev/null || true
if [[ ! -f /etc/nginx/includes/nginx-portal-realms.conf ]]; then
  if ! echo "# no secondary realms yet" > /etc/nginx/includes/nginx-portal-realms.conf 2>/dev/null; then
    echo "WARN: cannot write nginx-portal-realms.conf (uid=$(id -u)) — tmpfs includes must be mode 0777 under cap_drop ALL" >&2
  fi
fi

/sync-exports-to-confd.sh

if [[ ! -d /var/log/nginx/apps ]]; then
  echo "ERROR: /var/log/nginx/apps missing — Accès apps requires shared nginx-logs volume" >&2
fi

mkdir -p /tmp/modsecurity/data /tmp/modsecurity/tmp /tmp/modsecurity/upload 2>/dev/null || true
mkdir -p /var/log/nginx/apps 2>/dev/null || true
chown -R nginx:nginx /tmp/modsecurity 2>/dev/null || true

# conf.d/snippets tmpfs must be writable (compose mode=0777 when cap_drop ALL).
if ! envsubst '${PORTAL_INTERNAL_TOKEN}' \
  < /etc/nginx/templates-portal/proxy_portal_trusted_internal.conf.template \
  > /etc/nginx/snippets/proxy_portal_trusted_internal.conf; then
  echo "ERROR: cannot write snippets/ (uid=$(id -u)) — tmpfs mode must be 0777 under cap_drop ALL" >&2
  exit 1
fi

if ! envsubst '${SSO_PORTAL_DEFAULT_REALM_SLUG}' \
  < /etc/nginx/templates-portal/nginx-portal-core-realm-oauth2.conf.template \
  > /etc/nginx/snippets/nginx-portal-core-realm-oauth2.conf; then
  echo "ERROR: cannot write oauth2 snippet (uid=$(id -u))" >&2
  exit 1
fi

if ! envsubst '${PORTAL_DOMAIN} ${SSO_PORTAL_DEFAULT_REALM_SLUG}' \
  < /etc/nginx/templates-portal/vhost_sso_portal.conf.template \
  > /etc/nginx/conf.d/vhost_sso_portal.conf; then
  echo "ERROR: cannot write vhost_sso_portal.conf (uid=$(id -u)) — conf.d tmpfs not writable" >&2
  exit 1
fi

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

# Under cap_drop ALL, root has no CAP_CHOWN. Running ``nginx -t`` as uid 0 makes
# the master try chown(.../client_temp, 101) → emerg Operation not permitted.
# Create cache dirs + test + final exec as nginx whenever we will drop privileges.
_drop_to_nginx=0
if [[ "$(id -u)" -eq 0 ]] && command -v su-exec >/dev/null 2>&1 \
  && [[ "${BASTION_NGINX_KEEP_ROOT:-0}" != "1" ]]; then
  _drop_to_nginx=1
fi

_nginx_as_worker() {
  if [[ "${_drop_to_nginx}" -eq 1 ]]; then
    su-exec nginx:nginx "$@"
  else
    "$@"
  fi
}

# Probe once: cap_drop ALL without SETUID/SETGID → setgroups EPERM.
if [[ "${_drop_to_nginx}" -eq 1 ]]; then
  if ! su-exec nginx:nginx true 2>/tmp/bastion-suexec.err; then
    echo "ERROR: su-exec nginx failed — compose must cap_add SETUID+SETGID under cap_drop ALL" >&2
    cat /tmp/bastion-suexec.err >&2 || true
    exit 1
  fi
fi

_nginx_as_worker mkdir -p \
  /var/cache/nginx/client_temp \
  /var/cache/nginx/proxy_temp \
  /var/cache/nginx/fastcgi_temp \
  /var/cache/nginx/uwsgi_temp \
  /var/cache/nginx/scgi_temp \
  /var/run

# access_log under apps/ must be openable by uid 101 (else nginx -t fails → no :8080).
/fix-nginx-logs.sh

_nginx_as_worker nginx -t
/export-waf-snapshot.sh || echo "WARN: export-waf-snapshot failed" >&2

# Daily logrotate + snapshot WAF toutes les 5 min (crond Alpine).
# Needs a writable /etc (not compose read_only) + root. Otherwise watch / app aggregator cover it.
_rootfs_writable=0
if touch /etc/.bastion-rw-probe 2>/dev/null; then
  rm -f /etc/.bastion-rw-probe 2>/dev/null || true
  _rootfs_writable=1
fi
if [[ "$(id -u)" -eq 0 ]] \
  && [[ "${_rootfs_writable}" -eq 1 ]] \
  && [[ "${BASTION_MODSEC_LOGROTATE:-1}" != "0" ]] \
  && command -v crond >/dev/null 2>&1; then
  mkdir -p /etc/periodic/daily /etc/periodic/5min
  cat > /etc/periodic/daily/modsecurity-logrotate <<'EOF'
#!/bin/sh
/usr/sbin/logrotate -f /etc/logrotate.d/modsecurity >/dev/null 2>&1 || true
EOF
  chmod +x /etc/periodic/daily/modsecurity-logrotate
  cat > /etc/periodic/5min/waf-snapshot <<'EOF'
#!/bin/sh
/export-waf-snapshot.sh >/dev/null 2>&1 || true
EOF
  chmod +x /etc/periodic/5min/waf-snapshot
  if ! grep -qF 'run-parts /etc/periodic/5min' /etc/crontabs/root 2>/dev/null; then
    echo '*/5 * * * * run-parts /etc/periodic/5min' >> /etc/crontabs/root
  fi
  crond -b -l 8 || echo "WARN: crond failed to start — modsec logrotate / waf-snapshot inactive" >&2
elif [[ "${_rootfs_writable}" -eq 0 ]]; then
  echo "INFO: read_only rootfs — crond/logrotate skipped (snapshots via watch / bastion-app)"
elif [[ "$(id -u)" -ne 0 ]]; then
  echo "INFO: non-root runtime — crond skipped (snapshots via watch / bastion-app aggregator)"
fi

# Watch App catalogue exports → conf.d + reload (approve/edit without apply-infra-docker).
# Keep the watcher as root when we started as root so ACME renewals (root:600 PEM)
# can be re-mirrored into ssl-local; nginx workers still run as uid 101.
if [[ "${BASTION_EXPORTS_WATCH:-1}" != "0" ]]; then
  /watch-exports-reload.sh &
fi

if [[ "${_drop_to_nginx}" -eq 1 ]]; then
  echo "INFO: dropping privileges to nginx after cert mirror / conf render"
  exec su-exec nginx:nginx "$@"
fi
exec "$@"
