#!/usr/bin/env sh
# acme-companion entrypoint: reconcile once, install cron, run crond + periodic reconcile.
set -eu

CERTS="${CERTS_DIR:-/certs}"
EXPORTS="${EXPORTS_DIR:-/exports}"
INTERVAL="${ACME_RECONCILE_INTERVAL:-300}"

mkdir -p "$CERTS" /acme.sh

echo "acme-companion: initial reconcile"
/bin/sh /reconcile-certs.sh || echo "acme-companion: WARN initial reconcile failed" >&2

# Renewals: acme.sh cron (2×/day). Also re-run reconcile periodically for new FQDNs.
if command -v acme.sh >/dev/null 2>&1; then
  acme.sh --install-cronjob 2>/dev/null || true
elif [ -x /root/.acme.sh/acme.sh ]; then
  /root/.acme.sh/acme.sh --install-cronjob 2>/dev/null || true
fi

(
  while true; do
    sleep "$INTERVAL" || true
    # Admin UI sentinel → immediate reconcile
    if [ -f "${CERTS}/.reconcile_request" ]; then
      rm -f "${CERTS}/.reconcile_request" 2>/dev/null || true
      echo "acme-companion: reconcile_request received"
      /bin/sh /reconcile-certs.sh || true
      continue
    fi
    /bin/sh /reconcile-certs.sh || true
  done
) &

# Prefer crond if present (acme.sh renewals); else keep container alive via reconcile loop.
if command -v crond >/dev/null 2>&1; then
  exec crond -f -l 2
fi

echo "acme-companion: no crond — foreground reconcile loop only"
while true; do
  sleep "$INTERVAL" || true
  /bin/sh /reconcile-certs.sh || true
done
