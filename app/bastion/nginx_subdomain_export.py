"""Generate front-nginx server blocks for subdomain_proxy apps from App DB.

Target architecture: Traefik/edge terminates TLS → bastion-nginx:8080 (Host-based)
→ upstream app. Session cookie hop is always included (product-agnostic).

DMZ reverse01 is transitional; these exports are the source of truth for front nginx.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.access_modes import normalize_access_mode
from app.models import App
from app.sso_settings import Settings

_SAFE_SLUG = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")


def iter_subdomain_proxy_apps(db: Session) -> list[App]:
    """Enabled apps with subdomain_proxy + public_fqdn (ordered by slug)."""
    apps = db.query(App).filter_by(enabled=True).order_by(App.slug).all()
    out: list[App] = []
    for app in apps:
        if normalize_access_mode(app.access_mode) != "subdomain_proxy":
            continue
        if not (app.public_fqdn or "").strip():
            continue
        out.append(app)
    return out


def _upstream_host(upstream_url: str) -> str:
    host = urlparse((upstream_url or "").strip()).hostname
    return host or "127.0.0.1"


def _nginx_escape(value: str) -> str:
    """Minimal escaping for nginx string contexts (quotes / backslash)."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def subdomain_app_inventory_entry(app: App, settings: Settings) -> dict[str, Any]:
    fqdn = (app.public_fqdn or "").strip()
    realm = (app.realm_slug or "").strip() or settings.sso_portal_default_realm_slug
    return {
        "slug": app.slug,
        "label": app.label,
        "public_fqdn": fqdn,
        "upstream_url": (app.upstream_url or "").rstrip("/") + "/",
        "upstream_host": _upstream_host(app.upstream_url or ""),
        "realm_slug": realm,
        "access_mode": "subdomain_proxy",
        "session_cookie_hop": True,
        "hop_path": "/.bastion/session-cookies",
        "allow_activesync": bool(getattr(app, "allow_activesync", False)),
    }


def _activesync_locations(slug: str, upstream_host_esc: str, fqdn_esc: str) -> list[str]:
    """Locations that skip browser SSO redirect; require Basic or SSO via activesync-auth."""
    return [
        "    # Mobile ActiveSync / Autodiscover (allow_activesync=true)",
        "    location ~* ^/Microsoft-Server-ActiveSync {",
        "        auth_request /internal/activesync-auth;",
        f"        error_page 401 = @activesync_unauthorized_{slug};",
        "",
        "        proxy_pass $app_upstream;",
        "        proxy_redirect off;",
        "        proxy_http_version 1.1;",
        "        # WebSocket-friendly reverse proxy (Teleport uses ws/wss endpoints)",
        "        proxy_set_header Upgrade $http_upgrade;",
        "        proxy_set_header Connection $http_connection;",
        "        proxy_read_timeout 3600s;",
        "        proxy_send_timeout 3600s;",
        "        proxy_set_header Host $host;",
        "        proxy_set_header X-Real-IP $remote_addr;",
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "        proxy_set_header X-Forwarded-Proto $bastion_forwarded_proto;",
        "        proxy_set_header Authorization $http_authorization;",
        "        proxy_pass_request_headers on;",
        "",
        "        auth_request_set $auth_user $upstream_http_x_auth_user;",
        "        auth_request_set $auth_app $upstream_http_x_auth_app;",
        "        auth_request_set $auth_source $upstream_http_x_auth_source;",
        "        proxy_set_header X-Auth-User $auth_user;",
        "        proxy_set_header X-Auth-App $auth_app;",
        "        proxy_set_header X-Auth-Source $auth_source;",
        "    }",
        "",
        "    location ~* ^/(AutoDiscover|autodiscover)/ {",
        "        auth_request /internal/activesync-auth;",
        f"        error_page 401 = @activesync_unauthorized_{slug};",
        "",
        "        proxy_pass $app_upstream;",
        "        proxy_redirect off;",
        "        proxy_http_version 1.1;",
        "        # WebSocket-friendly reverse proxy (Teleport uses ws/wss endpoints)",
        "        proxy_set_header Upgrade $http_upgrade;",
        "        proxy_set_header Connection $http_connection;",
        "        proxy_read_timeout 3600s;",
        "        proxy_send_timeout 3600s;",
        "        proxy_set_header Host $host;",
        "        proxy_set_header X-Real-IP $remote_addr;",
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "        proxy_set_header X-Forwarded-Proto $bastion_forwarded_proto;",
        "        proxy_set_header Authorization $http_authorization;",
        "",
        "        auth_request_set $auth_user $upstream_http_x_auth_user;",
        "        auth_request_set $auth_app $upstream_http_x_auth_app;",
        "        auth_request_set $auth_source $upstream_http_x_auth_source;",
        "        proxy_set_header X-Auth-User $auth_user;",
        "        proxy_set_header X-Auth-App $auth_app;",
        "        proxy_set_header X-Auth-Source $auth_source;",
        "    }",
        "",
        f"    location @activesync_unauthorized_{slug} {{",
        '        add_header WWW-Authenticate \'Basic realm="ActiveSync"\' always;',
        "        default_type text/plain;",
        "        return 401 \"ActiveSync authentication required\\n\";",
        "    }",
        "",
    ]


def generate_subdomain_server_block(app: App, settings: Settings) -> str:
    """One HTTP server{} for front nginx (TLS offloaded). Includes hop + auth_request."""
    fqdn = (app.public_fqdn or "").strip()
    slug = app.slug
    if not _SAFE_SLUG.match(slug):
        raise ValueError(f"unsafe app slug for nginx: {slug!r}")
    upstream = (app.upstream_url or "").strip().rstrip("/")
    if not upstream:
        raise ValueError(f"app {slug}: upstream_url required")
    upstream_host = _upstream_host(upstream)
    portal = (settings.portal_domain or "portal.ar-systems.fr").strip()
    realm = (app.realm_slug or "").strip() or settings.sso_portal_default_realm_slug
    upstream_esc = _nginx_escape(upstream)
    fqdn_esc = _nginx_escape(fqdn)
    portal_esc = _nginx_escape(portal)
    upstream_host_esc = _nginx_escape(upstream_host)
    allow_eas = bool(getattr(app, "allow_activesync", False))

    lines = [
        f"# [{slug}] subdomain_proxy — {fqdn} (generated from App DB)",
        "server {",
        "    listen 0.0.0.0:8080;",
        f"    server_name {fqdn_esc};",
        "",
        "    absolute_redirect off;",
        "    port_in_redirect off;",
        "",
        f"    access_log /var/log/nginx/apps/{slug}.access.log app;",
        f"    error_log  /var/log/nginx/apps/{slug}.error.log warn;",
        "",
        "    set $bastion_app_upstream bastion-app:8000;",
        f'    set $app_upstream "{upstream_esc}";',
        "",
        "    include /etc/nginx/snippets/subdomain_auth_common.conf;",
        "",
        "    # Cookie hop — exact = beats any location ~ /\\. deny; never internal;",
        "    location = /.bastion/session-cookies {",
        "        auth_request off;",
        "        proxy_pass http://$bastion_app_upstream/api/internal/session-cookie-hop;",
        "        proxy_http_version 1.1;",
        f"        proxy_set_header Host {portal_esc};",
        "        proxy_set_header X-Real-IP $remote_addr;",
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "        proxy_set_header X-Forwarded-Proto $bastion_forwarded_proto;",
        "        proxy_set_header X-Forwarded-Host $host;",
        "        proxy_set_header Cookie $http_cookie;",
        "        proxy_pass_request_body off;",
        "    }",
        "",
    ]
    if allow_eas:
        lines.extend(_activesync_locations(slug, upstream_host_esc, fqdn_esc))
    lines.extend(
        [
            "    location / {",
            "        auth_request /internal/subdomain-auth;",
            f"        error_page 401 = @portal_redirect_{slug};",
            "",
            "        proxy_pass $app_upstream;",
            "        proxy_redirect off;",
            "        proxy_http_version 1.1;",
            # Needed for ws/wss endpoints (e.g. Teleport terminal streaming).
            "        proxy_set_header Upgrade $http_upgrade;",
            "        proxy_set_header Connection $http_connection;",
            "        proxy_read_timeout 3600s;",
            "        proxy_send_timeout 3600s;",
            "        proxy_set_header Host $host;",
            "        proxy_set_header X-Real-IP $remote_addr;",
            "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
            "        proxy_set_header X-Forwarded-Proto $bastion_forwarded_proto;",
            "        proxy_cookie_path / /;",
            f"        proxy_cookie_domain {upstream_host_esc} {fqdn_esc};",
            "",
            "        auth_request_set $auth_user $upstream_http_x_auth_user;",
            "        auth_request_set $auth_app $upstream_http_x_auth_app;",
            "        proxy_set_header X-Auth-User $auth_user;",
            "        proxy_set_header X-Auth-App $auth_app;",
            "    }",
            "",
            f"    location @portal_redirect_{slug} {{",
            # oauth2-proxy rejects absolute URLs in rd= (validator.go whitelist).
            # Pass only the relative URI so the redirect is always accepted.
            f"        return 302 https://{portal_esc}/oauth2/{_nginx_escape(realm)}/start"
            "?rd=$request_uri;",
            "    }",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def generate_subdomain_apps_nginx(db: Session, settings: Settings) -> str:
    """Full nginx conf for all subdomain_proxy apps (front nginx include)."""
    header = [
        "# Generated by bastion-app — subdomain apps from App DB",
        "# Consumed by bastion-nginx (front). Product-agnostic: hop on every FQDN.",
        "# Do not edit by hand; Admin → Apps (exports + bastion-nginx reload auto).",
        "",
    ]
    blocks: list[str] = []
    for app in iter_subdomain_proxy_apps(db):
        blocks.append(generate_subdomain_server_block(app, settings))
    if not blocks:
        header.append("# (no enabled subdomain_proxy apps)")
        header.append("")
    return "\n".join(header + blocks)


def generate_subdomain_apps_inventory(db: Session, settings: Settings) -> dict[str, Any]:
    """JSON inventory for Traefik/edge routing during DMZ transition."""
    apps = iter_subdomain_proxy_apps(db)
    return {
        "portal_domain": settings.portal_domain,
        "hop_path": "/.bastion/session-cookies",
        "applications": [subdomain_app_inventory_entry(app, settings) for app in apps],
    }


def write_subdomain_apps_exports(db: Session, settings: Settings) -> dict[str, str]:
    """Write nginx conf + inventory under EXPORTS_DIR; prune stale per-app files."""
    exports_path = Path(settings.exports_dir)
    exports_path.mkdir(parents=True, exist_ok=True)
    conf_path = exports_path / "nginx-subdomain-apps.conf"
    inventory_path = exports_path / "subdomain-apps-inventory.json"
    per_app_dir = exports_path / "nginx-subdomain-apps"
    per_app_dir.mkdir(parents=True, exist_ok=True)

    conf_path.write_text(generate_subdomain_apps_nginx(db, settings), encoding="utf-8")
    inventory = generate_subdomain_apps_inventory(db, settings)
    inventory_path.write_text(
        json.dumps(inventory, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    keep: set[str] = set()
    for app in iter_subdomain_proxy_apps(db):
        name = f"{app.slug}.conf"
        keep.add(name)
        (per_app_dir / name).write_text(
            generate_subdomain_server_block(app, settings), encoding="utf-8"
        )
    for stale in per_app_dir.glob("*.conf"):
        if stale.name not in keep:
            stale.unlink(missing_ok=True)

    return {
        "nginx_subdomain_apps_conf": str(conf_path),
        "subdomain_apps_inventory": str(inventory_path),
        "nginx_subdomain_apps_dir": str(per_app_dir),
    }
