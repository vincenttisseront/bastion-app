#!/usr/bin/env bash
# Applique les exports générés par le portail SSO (oauth2-proxy + nginx + systemd).
set -euo pipefail

EXPORT_DIR="${1:-/var/lib/sso-portal/exports}"
OAUTH2_BASE="/etc/oauth2-proxy-portal"
NGINX_REALMS="/var/lib/sso-portal/exports/nginx-portal-realms.conf"
NGINX_VHOST="/etc/nginx/conf.d/vhost_sso_portal.conf"
OAUTH2_SECRET_GEN="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/oauth2-cookie-secret.sh"

if [[ ! -d "$EXPORT_DIR" ]]; then
  echo "Répertoire export introuvable: $EXPORT_DIR" >&2
  exit 1
fi

shopt -s nullglob

CORE_REALM_SLUG="${PORTAL_DEFAULT_REALM_SLUG:-ar-systems}"
for slug_dir in "$EXPORT_DIR"/oauth2/*/; do
  slug="$(basename "$slug_dir")"
  if [[ "$slug" == "core-admin" || "$slug" == "$CORE_REALM_SLUG" ]]; then
    echo "Ignoré (Ansible statique / core) : oauth2/$slug" >&2
    continue
  fi
  target_dir="$OAUTH2_BASE/$slug"
  mkdir -p "$target_dir"
  cfg_src="$slug_dir/oauth2-proxy.cfg"
  cfg_tmp="$(mktemp)"
  cp "$cfg_src" "$cfg_tmp"

  # Flux SSO : oauth2-proxy /start (login_hint OIDC standard, config legacy .cfg)
  rm -f "$target_dir/oauth2-proxy.alpha.yaml"

  if [[ ! -s "$target_dir/cookie_secret" ]] || grep -qE '[+/]' "$target_dir/cookie_secret" || ! bash "$OAUTH2_SECRET_GEN" valid "$target_dir/cookie_secret"; then
    bash "$OAUTH2_SECRET_GEN" gen > "$target_dir/cookie_secret"
    chown oauth2-proxy-portal:oauth2-proxy-portal "$target_dir/cookie_secret"
    chmod 640 "$target_dir/cookie_secret"
  fi

  # cookie_secret inline ; client_secret via client_secret_file sur disque
  sed -i '/cookie_csrf_per_request/d' "$cfg_tmp"

  if [[ ! -s "$target_dir/client_secret" ]]; then
    echo "client_secret manquant pour realm $slug ($target_dir/client_secret)" >&2
    exit 1
  fi

  if grep -q 'cookie_secret   = "GENERATE_ON_APPLY"' "$cfg_tmp" && [[ -s "$target_dir/cookie_secret" ]]; then
    cookie_secret="$(tr -d '\n' < "$target_dir/cookie_secret")"
    sed -i "s|cookie_secret   = \"GENERATE_ON_APPLY\"|cookie_secret   = \"${cookie_secret}\"|" "$cfg_tmp"
  fi

  install -o oauth2-proxy-portal -g oauth2-proxy-portal -m 640 \
    "$cfg_tmp" "$target_dir/oauth2-proxy.cfg"
  rm -f "$cfg_tmp"

  if ! timeout 3 /usr/local/bin/oauth2-proxy \
      --config="$target_dir/oauth2-proxy.cfg" \
      --http-address=127.0.0.1:0 >/dev/null 2>&1; then
    echo "Config oauth2-proxy invalide pour realm $slug" >&2
    timeout 3 /usr/local/bin/oauth2-proxy \
      --config="$target_dir/oauth2-proxy.cfg" \
      --http-address=127.0.0.1:0 2>&1 | tail -20 >&2 || true
    exit 1
  fi

  unit_src="$EXPORT_DIR/systemd/oauth2-proxy-portal-${slug}.service"
  if [[ -f "$unit_src" ]]; then
    install -m 644 "$unit_src" "/etc/systemd/system/oauth2-proxy-portal-${slug}.service"
    systemctl daemon-reload
    systemctl enable "oauth2-proxy-portal-${slug}.service"
    if ! systemctl restart "oauth2-proxy-portal-${slug}.service"; then
      echo "Échec restart oauth2-proxy-portal-${slug}" >&2
      journalctl -u "oauth2-proxy-portal-${slug}" -n 30 --no-pager >&2 || true
      exit 1
    fi
    if ! systemctl is-active --quiet "oauth2-proxy-portal-${slug}.service"; then
      echo "Service oauth2-proxy-portal-${slug} inactif après restart" >&2
      journalctl -u "oauth2-proxy-portal-${slug}" -n 30 --no-pager >&2 || true
      exit 1
    fi
  fi
done

if [[ -f "$NGINX_REALMS" ]]; then
  if nginx -t; then
    systemctl reload nginx
  else
    echo "nginx -t a échoué — oauth2-proxy appliqué, reload nginx ignoré" >&2
    exit 1
  fi
fi

echo "Infrastructure appliquée depuis $EXPORT_DIR"
