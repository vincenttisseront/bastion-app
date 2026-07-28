#!/usr/bin/env sh
# Issue / renew / prune LE certs for public_proxy FQDNs listed in acme-domains.json.
# DNS-01 via acme.sh (default dns_cf / Cloudflare). Reload via sentinel (no docker.sock).
set -eu

CERTS="${CERTS_DIR:-/certs}"
EXPORTS="${EXPORTS_DIR:-/exports}"
MANIFEST="${EXPORTS}/acme-domains.json"
DNS_API="${ACME_DNS_API:-dns_cf}"
# letsencrypt | letsencrypt_test (staging)
ACME_CA="${ACME_CA:-letsencrypt}"
ACME_BIN="${ACME_BIN:-}"

# Admin → ACME writes exports/acme-runtime.env (CF_Token, ACME_CA, …)
RUNTIME_ENV="${EXPORTS}/acme-runtime.env"
if [ -f "$RUNTIME_ENV" ]; then
  # shellcheck disable=SC1090
  set -a
  # Prefer runtime env from bastion-app over stale process env for CF_* / ACME_*
  # shellcheck disable=SC1091
  . "$RUNTIME_ENV"
  set +a
fi

DNS_API="${ACME_DNS_API:-$DNS_API}"
ACME_CA="${ACME_CA:-$ACME_CA}"

if [ "${ACME_ENABLED:-1}" = "0" ]; then
  echo "reconcile-certs: ACME_ENABLED=0 — skip"
  exit 0
fi

if [ -z "$ACME_BIN" ]; then
  if command -v acme.sh >/dev/null 2>&1; then
    ACME_BIN="$(command -v acme.sh)"
  elif [ -x /root/.acme.sh/acme.sh ]; then
    ACME_BIN=/root/.acme.sh/acme.sh
  else
    echo "reconcile-certs: acme.sh not found" >&2
    exit 1
  fi
fi

mkdir -p "$CERTS"

if [ ! -f "$MANIFEST" ]; then
  echo "reconcile-certs: no $MANIFEST yet — skip"
  exit 0
fi

list_fqdns() {
  if command -v jq >/dev/null 2>&1; then
    jq -r '.domains[].fqdn // empty' "$MANIFEST"
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print('\n'.join(x['fqdn'] for x in d.get('domains',[]) if x.get('fqdn')))" "$MANIFEST"
  else
    grep -oE '"fqdn"[[:space:]]*:[[:space:]]*"[^"]+"' "$MANIFEST" | sed 's/.*"\([^"]*\)"$/\1/'
  fi
}

has_cf_creds() {
  [ -n "${CF_Token:-}" ] || [ -n "${CF_Token_Write:-}" ] || [ -n "${CF_Key:-}" ]
}

issue_or_placeholder() {
  fqdn="$1"
  dest="$CERTS/$fqdn"
  mkdir -p "$dest"

  if [ -f "$dest/fullchain.pem" ] && [ -f "$dest/privkey.pem" ]; then
    if has_cf_creds; then
      "$ACME_BIN" --renew -d "$fqdn" 2>/dev/null || true
      "$ACME_BIN" --install-cert -d "$fqdn" \
        --key-file "$dest/privkey.pem" \
        --fullchain-file "$dest/fullchain.pem" \
        --reloadcmd "touch $CERTS/.reload_nginx" 2>/dev/null || true
    fi
    return 0
  fi

  if ! has_cf_creds; then
    echo "reconcile-certs: no Cloudflare creds — self-signed placeholder for $fqdn"
    if command -v openssl >/dev/null 2>&1; then
      openssl req -x509 -nodes -newkey rsa:2048 -days 7 \
        -keyout "$dest/privkey.pem" \
        -out "$dest/fullchain.pem" \
        -subj "/CN=$fqdn" 2>/dev/null
      touch "$CERTS/.reload_nginx"
      return 0
    fi
    echo "reconcile-certs: openssl missing — cannot placeholder $fqdn" >&2
    return 1
  fi

  echo "reconcile-certs: issuing $fqdn via $DNS_API (CA=$ACME_CA)"
  ISSUE_ARGS="--issue --dns $DNS_API -d $fqdn"
  if [ "$ACME_CA" = "letsencrypt_test" ] || [ "$ACME_CA" = "staging" ]; then
    ISSUE_ARGS="$ISSUE_ARGS --staging"
  fi
  # shellcheck disable=SC2086
  if ! "$ACME_BIN" $ISSUE_ARGS; then
    echo "reconcile-certs: issue failed for $fqdn" >&2
    return 1
  fi
  "$ACME_BIN" --install-cert -d "$fqdn" \
    --key-file "$dest/privkey.pem" \
    --fullchain-file "$dest/fullchain.pem" \
    --reloadcmd "touch $CERTS/.reload_nginx"
  touch "$CERTS/.reload_nginx"
}

KEEP="$(mktemp)"
trap 'rm -f "$KEEP"' EXIT

list_fqdns > "$KEEP"

while IFS= read -r fqdn; do
  [ -n "$fqdn" ] || continue
  issue_or_placeholder "$fqdn" || true
done < "$KEEP"

for dir in "$CERTS"/*; do
  [ -d "$dir" ] || continue
  base="$(basename "$dir")"
  case "$base" in
    .*|lost+found) continue ;;
  esac
  if ! grep -qxF "$base" "$KEEP" 2>/dev/null; then
    echo "reconcile-certs: pruning orphan $base"
    rm -rf "$dir"
    "$ACME_BIN" --remove -d "$base" 2>/dev/null || true
    touch "$CERTS/.reload_nginx"
  fi
done

echo "reconcile-certs: done"
