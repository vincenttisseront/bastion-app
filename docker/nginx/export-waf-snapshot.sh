#!/usr/bin/env bash
# Write nginx effective WAF/security-headers snapshot for bastion-app (read-only consumer).
# Runs inside bastion-nginx after nginx -t / reload — never uses docker.sock on the app side.
set -euo pipefail

OUT="${NGINX_WAF_SNAPSHOT_PATH:-/var/log/nginx/apps/nginx-waf-snapshot.json}"
TMP="${OUT}.tmp.$$"
MODSEC="/etc/nginx/modsecurity"
NGINX_T="$(mktemp)"
trap 'rm -f "$NGINX_T" "$TMP"' EXIT

mkdir -p "$(dirname "$OUT")"
chmod 0777 "$(dirname "$OUT")" 2>/dev/null || true

nginx -T >"$NGINX_T" 2>/dev/null || true
nginx_t_ok=false
if nginx -t >/dev/null 2>&1; then
  nginx_t_ok=true
fi

nginx_t_excerpt="$(grep -Ei 'modsecurity|SecRuleEngine|modsecurity_rules' "$NGINX_T" | head -200 || true)"

last_sec_rule_engine() {
  echo "$1" | grep -E '^[[:space:]]*SecRuleEngine[[:space:]]' | tail -1 \
    | sed -E 's/.*SecRuleEngine[[:space:]]+(Off|On|DetectionOnly).*/\1/I'
}

normalize_mode() {
  case "$(echo "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    off) echo "off" ;;
    on) echo "on" ;;
    detectiononly) echo "detection_only" ;;
    "") echo "" ;;
    *) echo "$(echo "$1" | tr '[:upper:]' '[:lower:]')" ;;
  esac
}

parse_threshold() {
  echo "$1" | grep -oE 'inbound_anomaly_score_threshold=[0-9]+' | tail -1 | cut -d= -f2
}

family_json() {
  local fam="$1"
  local main="${MODSEC}/main-${fam}.conf"
  local combined=""
  local engine_gen=false
  local crs_gen=false
  local engine_source=""
  local overlay=""

  if [[ ! -f "$main" ]]; then
    jq -n --arg fam "$fam" '{family:$fam, error:"main conf missing"}'
    return
  fi

  # Authoritative ModSecurity mode overlay (last Include in main-*.conf).
  case "$fam" in
    portal) overlay="${MODSEC}/generated/engine-mode-generated.conf" ;;
    subdomain) overlay="${MODSEC}/generated/engine-subdomain-mode-generated.conf" ;;
    *) overlay="" ;;
  esac

  while IFS= read -r inc; do
    [[ -z "$inc" ]] && continue
    # Match portal engine-mode-generated and subdomain engine-*-mode-generated.
    if [[ "$inc" == *engine-mode-generated* || "$inc" == *engine-*-mode-generated* ]]; then
      engine_gen=true
    fi
    if [[ "$inc" == *crs-setup-generated* ]]; then crs_gen=true; fi
    if [[ -f "$inc" ]]; then
      combined+="$(cat "$inc")"$'\n'
      if [[ "$inc" == *engine-* ]] && [[ "$inc" != *generated* ]]; then
        engine_source="$inc"
      fi
    fi
  done < <(
    grep -E '^[[:space:]]*Include[[:space:]]+' "$main" \
      | sed -E 's/^[[:space:]]*Include[[:space:]]+([^[:space:]#;]+).*/\1/'
  )

  local raw_mode static_mode threshold threshold_source
  # Prefer the generated overlay file when present (avoids stale/mis-ordered cats).
  if [[ -n "$overlay" && -f "$overlay" ]]; then
    raw_mode="$(last_sec_rule_engine "$(cat "$overlay")")"
    engine_gen=true
    engine_source="$overlay"
  else
    raw_mode="$(last_sec_rule_engine "$combined")"
  fi
  static_mode="$(last_sec_rule_engine "$(cat "${MODSEC}/engine-${fam}.conf" 2>/dev/null || echo '')")"
  threshold="$(parse_threshold "$(cat "${MODSEC}/crs-setup.conf" 2>/dev/null || echo '')")"
  threshold_source="crs-setup.conf (statique)"

  if [[ "$crs_gen" == true && -f "${MODSEC}/generated/crs-setup-generated.conf" ]]; then
    local t2
    t2="$(parse_threshold "$(cat "${MODSEC}/generated/crs-setup-generated.conf")")"
    if [[ -n "$t2" ]]; then
      threshold="$t2"
      threshold_source="crs-setup-generated.conf"
    fi
  fi

  local mode_norm static_norm thr_json
  mode_norm="$(normalize_mode "$raw_mode")"
  static_norm="$(normalize_mode "$static_mode")"
  if [[ -n "$threshold" ]]; then
    thr_json="$threshold"
  else
    thr_json="null"
  fi

  jq -n \
    --arg fam "$fam" \
    --arg main "$main" \
    --arg engine_file "${MODSEC}/engine-${fam}.conf" \
    --arg mode "$mode_norm" \
    --arg static "$static_norm" \
    --arg engine_source "$engine_source" \
    --argjson threshold "$thr_json" \
    --arg threshold_source "$threshold_source" \
    --argjson engine_gen "$engine_gen" \
    --argjson crs_gen "$crs_gen" \
    '{
      family: $fam,
      main_conf: $main,
      engine_file: $engine_file,
      sec_rule_engine: (if $mode == "" then null else $mode end),
      sec_rule_engine_static: (if $static == "" then null else $static end),
      engine_source: (if $engine_source == "" then null else $engine_source end),
      anomaly_threshold: (if $threshold == null then null else $threshold end),
      anomaly_source: $threshold_source,
      engine_mode_generated_loaded: $engine_gen,
      crs_setup_generated_loaded: $crs_gen
    }'
}

headers_json='[]'
if [[ -f /etc/nginx/includes/security-headers.conf ]]; then
  headers_json="$(
    grep -E '^[[:space:]]*add_header[[:space:]]+' /etc/nginx/includes/security-headers.conf \
      | sed -E 's/^[[:space:]]*add_header[[:space:]]+([^[:space:]]+)[[:space:]]+"([^"]*)"[[:space:]]+always;/{"name":"\1","value":"\2"}/' \
      | jq -s '.' 2>/dev/null || echo '[]'
  )"
fi

portal_tpl="$(cat /etc/nginx/templates-portal/vhost_sso_portal.conf.template 2>/dev/null || echo '')"
acme_sync="$(cat /sync-acme-tls.sh 2>/dev/null || echo '')"
included_on_443=false
if grep -q 'security-headers.conf' <<<"$acme_sync"; then included_on_443=true; fi
no_dup_8080=false
if grep -qE 'Do not re-add|security-headers' <<<"$portal_tpl"; then no_dup_8080=true; fi

portal_json="$(family_json portal)"
subdomain_json="$(family_json subdomain)"
public_json="$(family_json public)"

generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
nginx_version="$(nginx -v 2>&1 | sed 's/^nginx version: //')"
image_tag="${BASTION_NGINX_IMAGE_TAG:-unknown}"

jq -n \
  --argjson schema_version 1 \
  --arg generated_at "$generated_at" \
  --arg nginx_version "$nginx_version" \
  --arg image_tag "$image_tag" \
  --argjson nginx_t_ok "$nginx_t_ok" \
  --arg nginx_t_excerpt "$nginx_t_excerpt" \
  --argjson portal "$portal_json" \
  --argjson subdomain "$subdomain_json" \
  --argjson public "$public_json" \
  --argjson security_headers "$headers_json" \
  --arg security_headers_path "/etc/nginx/includes/security-headers.conf" \
  --argjson included_on_443 "$included_on_443" \
  --argjson no_duplicate_8080 "$no_dup_8080" \
  '
  def fam_mode(f): (f | type) as $t | if $t == "object" then f.sec_rule_engine else null end;
  def fam_thr(f): (f | type) as $t | if $t == "object" then f.anomaly_threshold else null end;
  def fam_flag(f; key): (f | type) as $t | if $t == "object" then (f[key] // false) else false end;
  ([$portal, $subdomain, $public]) as $fs |
  ([$fs[] | fam_mode(.)] | map(select(. != null)) | unique) as $modes |
  ([$fs[] | fam_thr(.)] | map(select(. != null)) | unique) as $thrs |
  {
    schema_version: $schema_version,
    generated_at: $generated_at,
    nginx_version: $nginx_version,
    image_tag: $image_tag,
    nginx_t_ok: $nginx_t_ok,
    nginx_t_excerpt: $nginx_t_excerpt,
    families: {
      portal: $portal,
      subdomain: $subdomain,
      public: $public
    },
    aggregate_mode: (
      if ($modes | length) == 0 then null
      elif ($modes | length) == 1 then $modes[0]
      else "mixed" end
    ),
    aggregate_threshold: (
      if ($thrs | length) == 0 then null
      elif ($thrs | length) == 1 then $thrs[0]
      else "mixed" end
    ),
    engine_mode_generated_loaded: ([$fs[] | fam_flag(.; "engine_mode_generated_loaded")] | any),
    crs_setup_generated_loaded: ([$fs[] | fam_flag(.; "crs_setup_generated_loaded")] | any),
    security_headers: {
      path: $security_headers_path,
      headers: $security_headers,
      included_on_443: $included_on_443,
      no_duplicate_8080: $no_duplicate_8080
    }
  }
  ' >"$TMP"

mv "$TMP" "$OUT"
chmod 644 "$OUT" 2>/dev/null || true
