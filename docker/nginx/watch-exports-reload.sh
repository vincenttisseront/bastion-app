#!/usr/bin/env bash
# Poll bastion-app exports + ACME certs; sync conf.d and reload nginx on change.
set -euo pipefail

EXPORTS="${EXPORTS_DIR:-/var/lib/sso-portal/exports}"
CERTS="${CERTS_DIR:-/etc/nginx/ssl}"
INTERVAL="${BASTION_EXPORTS_WATCH_INTERVAL:-2}"
SYNC="${SYNC_EXPORTS_SCRIPT:-/sync-exports-to-confd.sh}"

fingerprint() {
  {
    for f in \
      nginx-known-hosts.map \
      nginx-public-proxy-apps.conf \
      nginx-subdomain-apps.conf \
      nginx-infra-proxy-apps.conf \
      nginx-mta-sts.conf \
      acme-domains.json
    do
      if [[ -f "$EXPORTS/$f" ]]; then
        stat -c '%Y %s %n' "$EXPORTS/$f" 2>/dev/null || ls -lL "$EXPORTS/$f"
      else
        echo "missing $f"
      fi
    done
    if [[ -d "$EXPORTS/modsecurity" ]]; then
      find "$EXPORTS/modsecurity" -type f -exec stat -c '%Y %s %n' {} \; 2>/dev/null | sort || true
    fi
    for f in waf-ip-allow.conf waf-ip-deny.conf nginx-portal-rate-limits.conf modsecurity-portal-switch.conf modsecurity-subdomain-switch.conf modsecurity-public-switch.conf; do
      if [[ -f "$EXPORTS/$f" ]]; then
        stat -c '%Y %s %n' "$EXPORTS/$f" 2>/dev/null || ls -lL "$EXPORTS/$f"
      else
        echo "missing $f"
      fi
    done
    if [[ -d "$CERTS" ]]; then
      find "$CERTS" -type f \( -name 'fullchain.pem' -o -name 'privkey.pem' \) \
        -exec stat -c '%Y %s %n' {} \; 2>/dev/null | sort || true
    fi
  } | cksum | awk '{print $1}'
}

LAST="$(fingerprint || echo none)"
echo "bastion-nginx: watching $EXPORTS + $CERTS (every ${INTERVAL}s)"

while true; do
  sleep "$INTERVAL" || true
  CUR="$(fingerprint || echo none)"
  if [[ "$CUR" == "$LAST" ]]; then
    continue
  fi
  echo "bastion-nginx: exports/certs changed (fp $LAST → $CUR) — sync + reload"
  # nginx -t as root under cap_drop ALL tries chown(client_temp,101) → fail;
  # master already runs as uid 101 — test/reload as nginx when su-exec exists.
  _test_reload() {
    if [[ "$(id -u)" -eq 0 ]] && command -v su-exec >/dev/null 2>&1; then
      su-exec nginx:nginx nginx -t && su-exec nginx:nginx nginx -s reload
    else
      nginx -t && nginx -s reload
    fi
  }
  if "$SYNC" && /fix-nginx-logs.sh && _test_reload; then
    LAST="$CUR"
    # Skip second nginx -t — _test_reload already validated (OOM under mem_limit).
    BASTION_SNAPSHOT_SKIP_NGINX_T=1 /export-waf-snapshot.sh \
      || echo "bastion-nginx: WARN export-waf-snapshot failed" >&2
    echo "bastion-nginx: reload ok — public_proxy TLS servers:"
    grep -E '^\s*server_name\s+' /etc/nginx/conf.d/nginx-acme-tls.conf 2>/dev/null \
      | sed 's/^/  /' || echo "  (none)"
  else
    echo "bastion-nginx: WARN sync/reload failed — will retry" >&2
  fi
done
