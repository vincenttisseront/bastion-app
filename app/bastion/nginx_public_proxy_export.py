"""Generate front-nginx server blocks for public_proxy apps (no bastion auth).

Target: Traefik/edge terminates TLS → bastion-nginx:8080 (Host-based) → upstream.
Deliberately no auth_request, oauth2-proxy, hop, or FastAPI /internal/* dependency.
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


def iter_public_proxy_apps(db: Session) -> list[App]:
    """Enabled apps with public_proxy + public_fqdn (ordered by slug)."""
    apps = db.query(App).filter_by(enabled=True).order_by(App.slug).all()
    out: list[App] = []
    for app in apps:
        if normalize_access_mode(app.access_mode) != "public_proxy":
            continue
        if not (app.public_fqdn or "").strip():
            continue
        out.append(app)
    return out


def _upstream_host(upstream_url: str) -> str:
    host = urlparse((upstream_url or "").strip()).hostname
    return host or "127.0.0.1"


def _nginx_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def public_proxy_inventory_entry(app: App) -> dict[str, Any]:
    fqdn = (app.public_fqdn or "").strip()
    return {
        "slug": app.slug,
        "label": app.label,
        "public_fqdn": fqdn,
        "upstream_url": (app.upstream_url or "").rstrip("/") + "/",
        "upstream_host": _upstream_host(app.upstream_url or ""),
        "access_mode": "public_proxy",
        "bastion_auth": False,
    }


def generate_public_proxy_server_block(app: App) -> str:
    """One HTTP server{} for front nginx — transparent proxy, no auth."""
    fqdn = (app.public_fqdn or "").strip()
    slug = app.slug
    if not _SAFE_SLUG.match(slug):
        raise ValueError(f"unsafe app slug for nginx: {slug!r}")
    upstream = (app.upstream_url or "").strip().rstrip("/")
    if not upstream:
        raise ValueError(f"app {slug}: upstream_url required")
    upstream_esc = _nginx_escape(upstream)
    fqdn_esc = _nginx_escape(fqdn)

    lines = [
        f"# [{slug}] public_proxy — {fqdn} (no bastion auth; generated from App DB)",
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
        f'    set $app_upstream "{upstream_esc}";',
        "",
        "    # Optional health probe — no auth",
        "    location = /healthz {",
        "        access_log off;",
        "        proxy_pass $app_upstream/;",
        "        proxy_redirect off;",
        "        proxy_set_header Host $host;",
        "        # Keep websocket headers consistent (harmless for /healthz)",
        "        proxy_http_version 1.1;",
        "        proxy_set_header Upgrade $http_upgrade;",
        "        proxy_set_header Connection $http_connection;",
        "        proxy_read_timeout 3600s;",
        "        proxy_send_timeout 3600s;",
        "    }",
        "",
        "    # Teleport terminal streaming /connect/ws uses a websocket upgrade; be strict",
        "    location ~* ^/v1/webapi/.*?/connect/ws$ {",
        "        proxy_pass $app_upstream;",
        "        proxy_redirect off;",
        "        proxy_http_version 1.1;",
        "        proxy_set_header Upgrade $http_upgrade;",
        "        proxy_set_header Connection \"upgrade\";",
        "        proxy_read_timeout 3600s;",
        "        proxy_send_timeout 3600s;",
        "        proxy_set_header Host $host;",
        "        proxy_set_header X-Real-IP $remote_addr;",
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "        proxy_set_header X-Forwarded-Proto $bastion_forwarded_proto;",
        "        proxy_set_header X-Forwarded-Host $host;",
        "    }",
        "",
        "    # Main route — transparent proxy, no bastion authentication",
        "    location / {",
        "        proxy_pass $app_upstream;",
        "        proxy_redirect off;",
        "        proxy_http_version 1.1;",
        "        # Needed for ws/wss endpoints (e.g. Teleport terminal streaming)",
        "        proxy_set_header Upgrade $http_upgrade;",
        "        proxy_set_header Connection $http_connection;",
        "        proxy_read_timeout 3600s;",
        "        proxy_send_timeout 3600s;",
        "        proxy_set_header Host $host;",
        "        proxy_set_header X-Real-IP $remote_addr;",
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "        proxy_set_header X-Forwarded-Proto $bastion_forwarded_proto;",
        "        proxy_set_header X-Forwarded-Host $host;",
        "    }",
        "}",
        "",
    ]
    return "\n".join(lines)


def generate_public_proxy_apps_nginx(db: Session) -> str:
    """Full nginx conf for all public_proxy apps (front nginx include)."""
    header = [
        "# Generated by bastion-app — public_proxy apps from App DB",
        "# No bastion authentication (SSO / RBAC / FastAPI internal). Do not edit by hand.",
        "",
    ]
    blocks: list[str] = []
    for app in iter_public_proxy_apps(db):
        blocks.append(generate_public_proxy_server_block(app))
    if not blocks:
        header.append("# (no enabled public_proxy apps)")
        header.append("")
    return "\n".join(header + blocks)


def generate_public_proxy_apps_inventory(db: Session) -> dict[str, Any]:
    apps = iter_public_proxy_apps(db)
    return {
        "bastion_auth": False,
        "applications": [public_proxy_inventory_entry(app) for app in apps],
    }


def write_public_proxy_apps_exports(db: Session, settings: Settings) -> dict[str, str]:
    """Write nginx conf + inventory under EXPORTS_DIR; prune stale per-app files."""
    exports_path = Path(settings.exports_dir)
    exports_path.mkdir(parents=True, exist_ok=True)
    conf_path = exports_path / "nginx-public-proxy-apps.conf"
    inventory_path = exports_path / "public-proxy-apps-inventory.json"
    per_app_dir = exports_path / "nginx-public-proxy-apps"
    per_app_dir.mkdir(parents=True, exist_ok=True)

    conf_path.write_text(generate_public_proxy_apps_nginx(db), encoding="utf-8")
    inventory = generate_public_proxy_apps_inventory(db)
    inventory_path.write_text(
        json.dumps(inventory, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    keep: set[str] = set()
    for app in iter_public_proxy_apps(db):
        name = f"{app.slug}.conf"
        keep.add(name)
        (per_app_dir / name).write_text(
            generate_public_proxy_server_block(app), encoding="utf-8"
        )
    for stale in per_app_dir.glob("*.conf"):
        if stale.name not in keep:
            stale.unlink(missing_ok=True)

    return {
        "nginx_public_proxy_apps_conf": str(conf_path),
        "public_proxy_apps_inventory": str(inventory_path),
        "nginx_public_proxy_apps_dir": str(per_app_dir),
    }
