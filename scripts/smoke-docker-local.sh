#!/usr/bin/env bash
# smoke-docker-local.sh — smoke contre stack Docker local
# Sans Traefik : utilise docker-compose.publish.yml (127.0.0.1:8080)
# Prérequis : Docker Engine + compose
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v docker >/dev/null 2>&1; then
  echo "SKIP: docker non installé sur cette machine" >&2
  exit 0
fi

mkdir -p data/sso-portal/exports
[[ -f .env ]] || cp .env.example .env
[[ -f docker/oauth2-core/oauth2-proxy.cfg ]] \
  || cp docker/oauth2-core/oauth2-proxy.cfg.example docker/oauth2-core/oauth2-proxy.cfg
[[ -f .env.oauth2-core ]] || touch .env.oauth2-core
[[ -f data/sso-portal/exports/nginx-portal-realms.conf ]] \
  || echo "# stub" > data/sso-portal/exports/nginx-portal-realms.conf

grep -q 'OAUTH2_PROXY_NETWORK_MODE' .env \
  || printf '\nOAUTH2_PROXY_NETWORK_MODE=docker\nOAUTH2_PROXY_DEFAULT_URL=http://oauth2-proxy-core:4180\nDATABASE_URL=sqlite:////var/lib/sso-portal/portal.db\nEXPORTS_DIR=/var/lib/sso-portal/exports\n' >> .env

export SSO_PORTAL_DATA_DIR="${SSO_PORTAL_DATA_DIR:-$ROOT/data/sso-portal}"
export PORTAL_DOMAIN="${PORTAL_DOMAIN:-portal.ar-systems.fr}"

# Réseau Traefik attendu par compose (external vpcbr)
docker network inspect vpcbr >/dev/null 2>&1 || docker network create vpcbr

COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.publish.yml)

echo "=== docker compose build ==="
"${COMPOSE[@]}" build

echo "=== docker compose up (publish profile local) ==="
"${COMPOSE[@]}" up -d --remove-orphans

echo "=== wait /api/health ==="
ok=0
for _ in $(seq 1 40); do
  if curl -fsS http://127.0.0.1:8000/api/health | grep -q '"status":"ok"'; then
    ok=1
    break
  fi
  sleep 2
done
[[ "$ok" -eq 1 ]] || { echo "FAIL: bastion-app health"; "${COMPOSE[@]}" logs bastion-app | tail -80; exit 1; }

echo "=== health JSON ==="
curl -fsS http://127.0.0.1:8000/api/health
echo

echo "=== nginx loopback :8080 /api/health ==="
curl -fsS -H "Host: ${PORTAL_DOMAIN}" "http://127.0.0.1:8080/api/health"
echo

echo "=== subdomain-auth (expect non-500) ==="
code="$(curl -s -o /dev/null -w '%{http_code}' \
  -H 'X-Original-Host: transfer.ar-systems.fr' \
  -H 'X-Real-IP: 8.8.8.8' \
  http://127.0.0.1:8000/internal/subdomain-auth || true)"
echo "subdomain-auth HTTP $code"
[[ "$code" != "500" ]] || { echo "FAIL: subdomain-auth 500"; exit 1; }

echo "=== oauth2-proxy-core /oauth2/start (best-effort) ==="
curl -s -o /dev/null -w 'oauth2/start HTTP %{http_code}\n' \
  http://127.0.0.1:4180/oauth2/start || true

echo "=== apply-infra-docker ==="
bash scripts/apply-infra-docker.sh "$SSO_PORTAL_DATA_DIR/exports" "$ROOT" || true

echo "OK — smoke Docker local terminé"
echo "Prod docker01 : sans publish.yml — entrée Traefik https://172.24.0.110 Host=${PORTAL_DOMAIN}"
