#!/usr/bin/env bash
# Poll bastion-app exports + ACME certs; sync conf.d and reload nginx on change.
#
# Debounced: a bastion-app restart rewrites several export files over a few
# seconds, and each `nginx -t` + reload holds one more full config copy in the
# container memcg until old workers exit. Back-to-back reloads used to stack
# copies past mem_limit (OOM → container restart → every vhost down). So:
#   - reload only once the fingerprint has not moved for SETTLE seconds;
#   - never start two reloads less than MIN_INTERVAL seconds apart (boot and
#     failed attempts count, so a broken export is not retried every poll);
#   - a change that never settles is still applied after MAX_DEFER seconds.
# With worker_shutdown_timeout 30s (nginx.conf) at most ~3 config generations
# coexist (lingering old workers + current + the next nginx -t / reload).
# Keep MIN_INTERVAL well under the 30s Admin → WAF → Réactiver polls
# (waf_reactivation.wait_for_*_engine_mode), or arming rolls back.
set -euo pipefail

EXPORTS="${EXPORTS_DIR:-/var/lib/sso-portal/exports}"
CERTS="${CERTS_DIR:-/etc/nginx/ssl}"
INTERVAL="${BASTION_EXPORTS_WATCH_INTERVAL:-2}"
SETTLE="${BASTION_EXPORTS_WATCH_SETTLE:-5}"
MIN_INTERVAL="${BASTION_RELOAD_MIN_INTERVAL:-15}"
MAX_DEFER="${BASTION_EXPORTS_WATCH_MAX_DEFER:-60}"
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

# nginx -t as root under cap_drop ALL tries chown(client_temp,101) → fail;
# master already runs as uid 101 — test/reload as nginx when su-exec exists.
_test_reload() {
  if [[ "$(id -u)" -eq 0 ]] && command -v su-exec >/dev/null 2>&1; then
    su-exec nginx:nginx nginx -t && su-exec nginx:nginx nginx -s reload
  else
    nginx -t && nginx -s reload
  fi
}

# Returns 0 once nginx runs the new config.
apply_changes() {
  "$SYNC" && /fix-nginx-logs.sh && _test_reload
}

after_reload() {
  # Snapshot reads conf files only (no nginx -T — OOM under mem_limit).
  /export-waf-snapshot.sh \
    || echo "bastion-nginx: WARN export-waf-snapshot failed" >&2
  echo "bastion-nginx: reload ok — public_proxy TLS servers:"
  grep -E '^\s*server_name\s+' /etc/nginx/conf.d/nginx-acme-tls.conf 2>/dev/null \
    | sed 's/^/  /' || echo "  (none)"
}

APPLIED=""       # fingerprint nginx currently runs with
SEEN=""          # last fingerprint observed
SEEN_AT=0        # epoch second SEEN was first observed
PENDING_SINCE="" # epoch second of the first unapplied change ("" = none)
LAST_RELOAD_AT=0 # last config load attempt (boot counts as one)

# $1 = fingerprint nginx was started with, $2 = now (epoch seconds).
watch_init() {
  APPLIED="$1"
  SEEN="$1"
  SEEN_AT="$2"
  PENDING_SINCE=""
  LAST_RELOAD_AT="$2"
}

# One poll: fingerprint $1 observed at epoch second $2. Reloads at most once.
watch_step() {
  local cur="$1" now="$2"
  if [[ "$cur" != "$SEEN" ]]; then
    SEEN="$cur"
    SEEN_AT="$now"
    if [[ "$cur" == "$APPLIED" ]]; then
      PENDING_SINCE=""
    elif [[ -z "$PENDING_SINCE" ]]; then
      PENDING_SINCE="$now"
      echo "bastion-nginx: exports/certs changed (fp $APPLIED → $cur) — reload once stable ${SETTLE}s"
    fi
  fi
  if [[ -z "$PENDING_SINCE" ]]; then
    return 0
  fi
  if (( now - SEEN_AT < SETTLE && now - PENDING_SINCE < MAX_DEFER )); then
    return 0
  fi
  if (( now - LAST_RELOAD_AT < MIN_INTERVAL )); then
    return 0
  fi
  LAST_RELOAD_AT="$now"
  echo "bastion-nginx: exports/certs settled (fp $APPLIED → $cur) — sync + reload"
  if apply_changes; then
    APPLIED="$cur"
    PENDING_SINCE=""
    after_reload
  else
    echo "bastion-nginx: WARN sync/reload failed — retry in ${MIN_INTERVAL}s" >&2
  fi
  return 0
}

watch_main() {
  watch_init "$(fingerprint || echo none)" "$(date +%s)"
  echo "bastion-nginx: watching $EXPORTS + $CERTS (every ${INTERVAL}s, settle ${SETTLE}s, min ${MIN_INTERVAL}s between reloads)"
  while true; do
    sleep "$INTERVAL" || true
    watch_step "$(fingerprint || echo none)" "$(date +%s)"
  done
}

# Sourced by tests (functions only); executed by the entrypoint.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  watch_main
fi
