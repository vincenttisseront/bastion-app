#!/bin/sh
# Issue / renew certs for every FQDN in /certs/acme-domains.json (DNS-01 via Cloudflare).
# Logs: /certs/acme-reconcile.log + /certs/acme-last-run.json (lu par Admin → ACME).
# No docker.sock required from bastion-app — triggered by /certs/.reconcile_request.
set -eu

CERTS="${ACME_CERTS_DIR:-${CERTS_DIR:-/certs}}"
EXPORTS="${EXPORTS_DIR:-/exports}"
DOMAINS_JSON="${ACME_DOMAINS_JSON:-$CERTS/acme-domains.json}"
# Prefer shared export under /exports (Admin write), fallback to certs copy.
if [ -f "$EXPORTS/acme-domains.json" ]; then
  DOMAINS_JSON="$EXPORTS/acme-domains.json"
fi
ACME_HOME="${ACME_HOME:-/acme.sh}"
if [ -x "$ACME_HOME/acme.sh" ]; then
  ACME_BIN="$ACME_HOME/acme.sh"
elif command -v acme.sh >/dev/null 2>&1; then
  ACME_BIN="$(command -v acme.sh)"
elif [ -x /root/.acme.sh/acme.sh ]; then
  ACME_BIN=/root/.acme.sh/acme.sh
else
  ACME_BIN="${ACME_BIN:-$ACME_HOME/acme.sh}"
fi
DNS_API="${ACME_DNS_API:-dns_cf}"
ACME_CA="${ACME_CA:-letsencrypt}"
LOG="${ACME_RECONCILE_LOG:-$CERTS/acme-reconcile.log}"
LAST_JSON="${ACME_LAST_RUN_JSON:-$CERTS/acme-last-run.json}"
MAX_LOG_BYTES="${ACME_LOG_MAX_BYTES:-1048576}"

mkdir -p "$CERTS"
: >"$CERTS/.reconcile_running"

# Admin UI writes exports/acme-runtime.env (CF_Token Fernet → plain for sidecar).
RUNTIME_ENV="${ACME_RUNTIME_ENV:-$EXPORTS/acme-runtime.env}"
if [ -f "$RUNTIME_ENV" ]; then
  # shellcheck disable=SC1090
  set -a
  . "$RUNTIME_ENV"
  set +a
fi
# Re-read after sourcing (Admin may override ACME_CA / DNS_API)
DNS_API="${ACME_DNS_API:-$DNS_API}"
ACME_CA="${ACME_CA:-$ACME_CA}"

log() {
  # shellcheck disable=SC2039
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
  line="[$ts] $*"
  echo "$line"
  echo "$line" >>"$LOG"
}

rotate_log_if_needed() {
  if [ -f "$LOG" ]; then
    sz=$(wc -c <"$LOG" 2>/dev/null || echo 0)
    if [ "$sz" -gt "$MAX_LOG_BYTES" ]; then
      tail -c "$((MAX_LOG_BYTES / 2))" "$LOG" >"$LOG.tmp" 2>/dev/null || true
      mv "$LOG.tmp" "$LOG" 2>/dev/null || true
    fi
  fi
}

write_last_run() {
  status="$1"
  message="$2"
  ok_count="$3"
  fail_count="$4"
  finished="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
  # JSON minimal sans dépendance python (échappement basique)
  msg_esc=$(printf '%s' "$message" | sed 's/\\/\\\\/g; s/"/\\"/g')
  cat >"$LAST_JSON" <<EOF
{"finished_at":"$finished","status":"$status","message":"$msg_esc","ok":$ok_count,"failed":$fail_count}
EOF
}

has_cf_creds() {
  [ -n "${CF_Token:-}" ] || [ -n "${CF_Token_Write:-}" ] || {
    [ -n "${CF_Email:-}" ] && [ -n "${CF_Key:-}" ]
  }
}

list_fqdns() {
  if [ ! -f "$DOMAINS_JSON" ]; then
    log "WARN no $DOMAINS_JSON — nothing to do"
    return 0
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$DOMAINS_JSON" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    data = json.load(f)
for d in data.get("domains") or []:
    fqdn = (d.get("fqdn") or "").strip().lower()
    if fqdn:
        print(fqdn)
PY
    return 0
  fi
  grep -oE '"fqdn"[[:space:]]*:[[:space:]]*"[^"]+"' "$DOMAINS_JSON" \
    | sed -E 's/.*"([^"]+)"/\1/' | tr '[:upper:]' '[:lower:]'
}

issue_or_placeholder() {
  fqdn="$1"
  dest="$CERTS/$fqdn"
  mkdir -p "$dest"

  if [ -f "$dest/fullchain.pem" ] && [ -f "$dest/privkey.pem" ]; then
    if openssl x509 -in "$dest/fullchain.pem" -noout -checkend 2592000 >/dev/null 2>&1; then
      log "OK $fqdn — cert valid >30d, skip"
      return 0
    fi
    log "RENEW $fqdn — expires within 30d"
    if has_cf_creds; then
      out="$(mktemp)"
      # shellcheck disable=SC2086
      set +e
      "$ACME_BIN" --renew -d "$fqdn" --force >"$out" 2>&1
      rc=$?
      set -e
      cat "$out" >>"$LOG"
      cat "$out"
      rm -f "$out"
      if [ "$rc" -eq 0 ]; then
        "$ACME_BIN" --install-cert -d "$fqdn" \
          --key-file "$dest/privkey.pem" \
          --fullchain-file "$dest/fullchain.pem" \
          --reloadcmd "touch $CERTS/.reload_nginx" >>"$LOG" 2>&1 || true
        touch "$CERTS/.reload_nginx"
        log "OK $fqdn — renewed"
        return 0
      fi
      log "ERROR $fqdn — renew failed (rc=$rc)"
      return 1
    fi
  fi

  if ! has_cf_creds; then
    log "WARN $fqdn — no Cloudflare token → self-signed placeholder (DNS-01 impossible)"
    if command -v openssl >/dev/null 2>&1; then
      openssl req -x509 -nodes -newkey rsa:2048 -days 7 \
        -keyout "$dest/privkey.pem" \
        -out "$dest/fullchain.pem" \
        -subj "/CN=$fqdn" 2>>"$LOG"
      touch "$CERTS/.reload_nginx"
      return 0
    fi
    log "ERROR $fqdn — openssl missing"
    return 1
  fi

  log "ISSUE $fqdn via DNS-01 ($DNS_API) CA=$ACME_CA — acme.sh crée/supprime _acme-challenge TXT via API CF (pas de record manuel)"
  ISSUE_ARGS="--issue --dns $DNS_API -d $fqdn"
  if [ "$ACME_CA" = "letsencrypt_test" ] || [ "$ACME_CA" = "staging" ]; then
    ISSUE_ARGS="$ISSUE_ARGS --staging"
  fi
  out="$(mktemp)"
  # shellcheck disable=SC2086
  set +e
  "$ACME_BIN" $ISSUE_ARGS >"$out" 2>&1
  rc=$?
  set -e
  cat "$out" >>"$LOG"
  cat "$out"
  rm -f "$out"
  if [ "$rc" -ne 0 ]; then
    log "ERROR $fqdn — issue failed rc=$rc (vérifier Zone DNS Edit sur CF + domaine dans la zone)"
    return 1
  fi
  "$ACME_BIN" --install-cert -d "$fqdn" \
    --key-file "$dest/privkey.pem" \
    --fullchain-file "$dest/fullchain.pem" \
    --reloadcmd "touch $CERTS/.reload_nginx" >>"$LOG" 2>&1
  touch "$CERTS/.reload_nginx"
  log "OK $fqdn — issued + installed"
}

rotate_log_if_needed
log "========== reconcile start =========="

if [ "${ACME_ENABLED:-1}" = "0" ]; then
  log "ACME_ENABLED=0 — skip issue/renew"
  write_last_run "skipped" "ACME désactivé (ACME_ENABLED=0)" 0 0
  rm -f "$CERTS/.reconcile_running"
  exit 0
fi

if has_cf_creds; then
  log "Cloudflare credentials: present (DNS-01 automatique — pas de record TXT manuel)"
else
  log "Cloudflare credentials: ABSENT — placeholders only"
fi

ok_n=0
fail_n=0
KEEP="$(mktemp)"
trap 'rm -f "$KEEP" "$CERTS/.reconcile_running"' EXIT

list_fqdns > "$KEEP"
n_domains=$(grep -c . "$KEEP" 2>/dev/null || echo 0)
log "domains in manifest: $n_domains"

while IFS= read -r fqdn; do
  [ -n "$fqdn" ] || continue
  if issue_or_placeholder "$fqdn"; then
    ok_n=$((ok_n + 1))
  else
    fail_n=$((fail_n + 1))
  fi
done < "$KEEP"

for dir in "$CERTS"/*; do
  [ -d "$dir" ] || continue
  base="$(basename "$dir")"
  case "$base" in
    .*|lost+found) continue ;;
  esac
  if ! grep -qxF "$base" "$KEEP" 2>/dev/null; then
    log "prune orphan $base"
    rm -rf "$dir"
    "$ACME_BIN" --remove -d "$base" 2>>"$LOG" || true
    touch "$CERTS/.reload_nginx"
  fi
done

if [ "$fail_n" -gt 0 ]; then
  st="error"
  msg="Reconcile terminé avec $fail_n échec(s), $ok_n ok — voir logs ACME."
else
  st="ok"
  msg="Reconcile OK — $ok_n domaine(s)."
fi
write_last_run "$st" "$msg" "$ok_n" "$fail_n"
log "========== reconcile done status=$st ok=$ok_n failed=$fail_n =========="
rm -f "$CERTS/.reconcile_running"
