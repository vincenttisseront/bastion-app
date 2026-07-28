#!/usr/bin/env bash
# Poll bastion-app exports and reload nginx when App catalogue nginx files change.
# Needed because entrypoint only syncs at container start; approve/edit writes
# exports/ without docker exec.
set -euo pipefail

EXPORTS="${EXPORTS_DIR:-/var/lib/sso-portal/exports}"
INTERVAL="${BASTION_EXPORTS_WATCH_INTERVAL:-2}"
SYNC="${SYNC_EXPORTS_SCRIPT:-/sync-exports-to-confd.sh}"

fingerprint() {
  # mtime+size of catalogue files that affect routing / unknown-host map
  {
    for f in \
      nginx-known-hosts.map \
      nginx-public-proxy-apps.conf \
      nginx-subdomain-apps.conf \
      nginx-infra-proxy-apps.conf
    do
      if [[ -f "$EXPORTS/$f" ]]; then
        # busybox/alpine: stat -c; fall back to ls
        stat -c '%Y %s %n' "$EXPORTS/$f" 2>/dev/null \
          || ls -lL "$EXPORTS/$f"
      else
        echo "missing $f"
      fi
    done
  } | cksum | awk '{print $1}'
}

LAST="$(fingerprint || echo none)"
echo "bastion-nginx: watching $EXPORTS for catalogue changes (every ${INTERVAL}s)"

while true; do
  sleep "$INTERVAL" || true
  CUR="$(fingerprint || echo none)"
  if [[ "$CUR" == "$LAST" ]]; then
    continue
  fi
  echo "bastion-nginx: catalogue exports changed (fp $LAST → $CUR) — sync + reload"
  if "$SYNC" && nginx -t && nginx -s reload; then
    LAST="$CUR"
    # Surface which app conf files are live (helps ops correlate Admin → Apps).
    echo "bastion-nginx: reload ok — public_proxy servers:"
    grep -E '^\s*server_name\s+' /etc/nginx/conf.d/nginx-public-proxy-apps.conf 2>/dev/null \
      | sed 's/^/  /' || echo "  (none)"
    echo "bastion-nginx: reload ok — subdomain_proxy servers:"
    grep -E '^\s*server_name\s+' /etc/nginx/conf.d/nginx-subdomain-apps.conf 2>/dev/null \
      | sed 's/^/  /' || echo "  (none)"
  else
    echo "bastion-nginx: WARN sync/reload failed — will retry" >&2
  fi
done
