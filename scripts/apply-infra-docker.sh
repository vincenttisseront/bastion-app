#!/usr/bin/env bash
# apply-infra-docker.sh — régénère docker-compose.override.yml depuis les exports portail
# et applique les realms secondaires (1 conteneur oauth2-proxy par realm).
#
# Usage:
#   scripts/apply-infra-docker.sh [EXPORT_DIR] [COMPOSE_DIR]
#
# Variables:
#   OAUTH2_PROXY_IMAGE_TAG  (default v7.7.1)
#   COMPOSE_PROJECT_NAME    (default bastion)
#   CORE_REALM_SLUG         (default ar-systems)
set -euo pipefail

EXPORT_DIR="${1:-/var/lib/sso-portal/exports}"
COMPOSE_DIR="${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
OVERRIDE="${COMPOSE_DIR}/docker-compose.override.yml"
IMAGE_TAG="${OAUTH2_PROXY_IMAGE_TAG:-v7.7.1}"
CORE_REALM_SLUG="${PORTAL_DEFAULT_REALM_SLUG:-${SSO_PORTAL_DEFAULT_REALM_SLUG:-ar-systems}}"

if [[ ! -d "$EXPORT_DIR" ]]; then
  echo "Répertoire export introuvable: $EXPORT_DIR" >&2
  exit 1
fi

shopt -s nullglob

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

{
  echo "# Généré par apply-infra-docker.sh — ne pas éditer à la main"
  echo "# Source: $EXPORT_DIR"
  echo "services:"
} > "$tmp"

found=0
for slug_dir in "$EXPORT_DIR"/oauth2/*/; do
  slug="$(basename "$slug_dir")"
  if [[ "$slug" == "core-admin" || "$slug" == "$CORE_REALM_SLUG" ]]; then
    echo "Ignoré (core) : oauth2/$slug" >&2
    continue
  fi
  cfg="$slug_dir/oauth2-proxy.cfg"
  if [[ ! -f "$cfg" ]]; then
    # Fallback flat export
    flat="$EXPORT_DIR/oauth2-proxy-${slug}.conf"
    if [[ -f "$flat" ]]; then
      mkdir -p "$slug_dir"
      cp "$flat" "$cfg"
    else
      echo "Config manquante pour realm $slug" >&2
      continue
    fi
  fi

  # Host publish port: prefer DB export port from http_address, else skip publish
  host_port="$(grep -E '^\s*http_address\s*=' "$cfg" | head -1 | sed -E 's/.*:([0-9]+)[" ].*/\1/' || true)"
  if [[ -z "$host_port" || "$host_port" == "4180" ]]; then
    # docker mode configs listen on 4180 inside container — publish via manifest if present
    if [[ -f "$EXPORT_DIR/infrastructure-manifest.json" ]]; then
      host_port="$(python3 - "$slug" "$EXPORT_DIR/infrastructure-manifest.json" <<'PY' 2>/dev/null || true
import json, sys
slug, path = sys.argv[1], sys.argv[2]
data = json.load(open(path, encoding="utf-8"))
for r in data.get("realms", []):
    if r.get("slug") == slug:
        print(r.get("oauth2_proxy_port", ""))
        break
PY
)"
    fi
  fi
  if [[ -z "${host_port:-}" ]]; then
    host_port=0
  fi

  found=1
  {
    echo "  oauth2-proxy-${slug}:"
    echo "    image: quay.io/oauth2-proxy/oauth2-proxy:${IMAGE_TAG}"
    echo "    command:"
    echo "      - --config=/etc/oauth2-proxy/oauth2-proxy.cfg"
    echo "    volumes:"
    echo "      - ${EXPORT_DIR}/oauth2/${slug}:/etc/oauth2-proxy:ro"
    echo "    networks:"
    echo "      - bastion_net"
    echo "    restart: unless-stopped"
    if [[ "$host_port" =~ ^[0-9]+$ ]] && [[ "$host_port" -gt 0 ]]; then
      echo "    ports:"
      echo "      - \"127.0.0.1:${host_port}:4180\""
    fi
  } >> "$tmp"
done

if [[ "$found" -eq 0 ]]; then
  # Compose requires at least one key under services or empty override with comment-only fails
  {
    echo "# Généré par apply-infra-docker.sh — aucun realm secondaire"
    echo "services: {}"
  } > "$tmp"
fi

mv "$tmp" "$OVERRIDE"
trap - EXIT
echo "Écrit: $OVERRIDE"

cd "$COMPOSE_DIR"
if command -v docker >/dev/null 2>&1; then
  docker compose -f docker-compose.yml -f docker-compose.override.yml up -d --remove-orphans
  # Reload nginx to pick up nginx-portal-realms.conf updates
  docker compose exec -T nginx nginx -s reload 2>/dev/null \
    || docker compose restart nginx
else
  echo "docker indisponible — override écrit, compose up ignoré" >&2
fi

echo "Infrastructure Docker appliquée depuis $EXPORT_DIR"
