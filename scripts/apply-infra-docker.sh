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
    echo "      - vpcbr"
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

# ── Purge marker (bastion-app DELETE → exports/systemd/purge-units.list) ──
# Même format que scripts/apply-infrastructure.sh (bare-metal systemd).
# Ici : stop/rm du service compose oauth2-proxy-<slug>, puis truncate du marqueur.
PURGE_LIST="$EXPORT_DIR/systemd/purge-units.list"
if [[ -f "$PURGE_LIST" ]]; then
  echo "Consommation purge-units.list…"
  while IFS= read -r unit || [[ -n "$unit" ]]; do
    unit="${unit%%#*}"
    unit="$(echo "$unit" | tr -d '[:space:]')"
    [[ -z "$unit" ]] && continue
    if [[ "$unit" =~ ^oauth2-proxy-portal-(.+)\.service$ ]]; then
      slug="${BASH_REMATCH[1]}"
      echo "  purge docker: oauth2-proxy-${slug} (marker $unit)"
      if command -v docker >/dev/null 2>&1; then
        (
          cd "$COMPOSE_DIR"
          docker compose -f docker-compose.yml -f docker-compose.override.yml \
            stop "oauth2-proxy-${slug}" 2>/dev/null || true
          docker compose -f docker-compose.yml -f docker-compose.override.yml \
            rm -f "oauth2-proxy-${slug}" 2>/dev/null || true
        )
      fi
    else
      echo "  entrée purge ignorée (format inattendu): $unit" >&2
    fi
  done < "$PURGE_LIST"
  : > "$PURGE_LIST"
  echo "purge-units.list vidé"
fi

# ── Core realm (ar-systems) : cfg depuis DB export → volume oauth2-proxy-core ──
# Source of truth = RealmConfig en base ; le fichier docker/oauth2-core n'est qu'un miroir.
CORE_CFG_SRC="${EXPORT_DIR}/oauth2/${CORE_REALM_SLUG}/oauth2-proxy.cfg"
CORE_CFG_DST="${COMPOSE_DIR}/docker/oauth2-core/oauth2-proxy.cfg"
if [[ -f "$CORE_CFG_SRC" ]]; then
  mkdir -p "$(dirname "$CORE_CFG_DST")"
  cp -a "$CORE_CFG_SRC" "$CORE_CFG_DST"
  chmod 644 "$CORE_CFG_DST"
  chmod 755 "$(dirname "$CORE_CFG_DST")"
  echo "Sync oauth2-proxy-core cfg depuis DB export: $CORE_CFG_SRC → $CORE_CFG_DST"
else
  echo "WARN: export core absent ($CORE_CFG_SRC) — oauth2-proxy-core non synchronisé (Admin → Realms + Apply infra)" >&2
fi

cd "$COMPOSE_DIR"
if command -v docker >/dev/null 2>&1; then
  docker compose -f docker-compose.yml -f docker-compose.override.yml up -d --remove-orphans
  if [[ -f "$CORE_CFG_SRC" ]]; then
    docker compose up -d --force-recreate --no-deps oauth2-proxy-core
  fi
  # Refresh nginx conf.d copies from exports (entrypoint only runs on container start)
  docker compose exec -T nginx sh -c '
    if [ -f /var/lib/sso-portal/exports/nginx-subdomain-apps.conf ]; then
      cp -a /var/lib/sso-portal/exports/nginx-subdomain-apps.conf \
        /etc/nginx/conf.d/nginx-subdomain-apps.conf
    fi
    if [ -f /var/lib/sso-portal/exports/nginx-public-proxy-apps.conf ]; then
      cp -a /var/lib/sso-portal/exports/nginx-public-proxy-apps.conf \
        /etc/nginx/conf.d/nginx-public-proxy-apps.conf
    fi
    if [ -f /var/lib/sso-portal/exports/nginx-infra-proxy-apps.conf ]; then
      cp -a /var/lib/sso-portal/exports/nginx-infra-proxy-apps.conf \
        /etc/nginx/conf.d/nginx-infra-proxy-apps.conf
    fi
    MAP_SRC=/var/lib/sso-portal/exports/nginx-known-hosts.map
    PORTAL_DOMAIN_EFF="${PORTAL_DOMAIN:-portal.ar-systems.fr}"
    # exports/ is :ro — never write MAP_SRC here; bastion-app owns that file.
    {
      echo "# Regenerated by apply-infra-docker.sh"
      echo "map \$host \$bastion_unknown_host {"
      echo "    default 1;"
      echo "    127.0.0.1 0;"
      echo "    localhost 0;"
      echo "    ${PORTAL_DOMAIN_EFF} 0;"
      if [ -f "$MAP_SRC" ]; then
        grep -E '^[A-Za-z0-9][A-Za-z0-9.-]*[[:space:]]+0[[:space:]]*;[[:space:]]*$' "$MAP_SRC" || true
      fi
      echo "}"
    } > /etc/nginx/conf.d/00-known-hosts-map.conf
    nginx -t && nginx -s reload
  ' 2>/dev/null || docker compose restart nginx
else
  echo "docker indisponible — override écrit, compose up ignoré" >&2
fi

echo "Infrastructure Docker appliquée depuis $EXPORT_DIR"
