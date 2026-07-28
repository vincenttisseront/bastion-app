#!/usr/bin/env sh
# acme-companion entrypoint: reconcile once, install cron, watch Admin sentinel.
set -eu

CERTS="${CERTS_DIR:-/certs}"
EXPORTS="${EXPORTS_DIR:-/exports}"
INTERVAL="${ACME_RECONCILE_INTERVAL:-300}"
POLL="${ACME_SENTINEL_POLL_SECONDS:-5}"

mkdir -p "$CERTS" /acme.sh

echo "acme-companion: initial reconcile"
/bin/sh /reconcile-certs.sh || echo "acme-companion: WARN initial reconcile failed" >&2

if command -v acme.sh >/dev/null 2>&1; then
  acme.sh --install-cronjob 2>/dev/null || true
elif [ -x /root/.acme.sh/acme.sh ]; then
  /root/.acme.sh/acme.sh --install-cronjob 2>/dev/null || true
fi

# Fast loop: Admin → ACME writes certs/.reconcile_request; pick it up in seconds.
# Full reconcile also runs every INTERVAL (renewals / drift).
(
  elapsed=0
  while true; do
    sleep "$POLL" || true
    elapsed=$((elapsed + POLL))
    if [ -f "${CERTS}/.reconcile_request" ]; then
      rm -f "${CERTS}/.reconcile_request" 2>/dev/null || true
      echo "acme-companion: reconcile_request from Admin UI"
      /bin/sh /reconcile-certs.sh || true
      elapsed=0
      continue
    fi
    if [ "$elapsed" -ge "$INTERVAL" ]; then
      echo "acme-companion: periodic reconcile"
      /bin/sh /reconcile-certs.sh || true
      elapsed=0
    fi
  done
) &

if command -v crond >/dev/null 2>&1; then
  exec crond -f -l 2
fi

echo "acme-companion: no crond — foreground poll loop"
elapsed=0
while true; do
  sleep "$POLL" || true
  elapsed=$((elapsed + POLL))
  if [ -f "${CERTS}/.reconcile_request" ]; then
    rm -f "${CERTS}/.reconcile_request" 2>/dev/null || true
    /bin/sh /reconcile-certs.sh || true
    elapsed=0
    continue
  fi
  if [ "$elapsed" -ge "$INTERVAL" ]; then
    /bin/sh /reconcile-certs.sh || true
    elapsed=0
  fi
done
