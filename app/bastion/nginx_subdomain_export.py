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
from app.bastion.upstream_proxy import upstream_origin
from app.bastion.upstream_tls import (
    nginx_proxy_ssl_verify_directive,
    resolve_upstream_tls_verify,
)
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


# auth_request_set — surface FastAPI X-Auth-Error in access logs (no-session,
# no-app-for-host, native-session-rejected). Host = literal $bastion_vhost_fqdn;
# Cookie = $bastion_auth_cookie rebuilt from $bastion_pass_* in location /.
_AUTH_REQUEST_DIAG_LINES = (
    "        auth_request_set $bastion_auth_err $upstream_http_x_auth_error;",
)

# Capture + rebuild client Cookie in location / (rewrite) BEFORE auth_request.
# Do NOT also set these at server{} — server rewrite re-runs on the auth
# subrequest and overwrites a good capture with a filtered/empty $http_cookie
# (HAR ae=no-session:ck=72:x=0). Location-/ sets do not re-run for the
# internal auth location, so the parent capture survives.
#
# Rebuild Cookie as bastion_session=<JWT>; <full parent jar> so auth_request
# always sees the JWT even when a CrushFTP Cookie filter later inherits into
# the subrequest and leaves $http_cookie as CrushAuth-only (ck=72). Snippet
# uses $bastion_pass_session / $bastion_auth_cookie DIRECTLY — no map fallback
# to filtered $http_cookie.
_AUTH_COOKIE_CAPTURE_LINES = (
    "        # Parent capture — survives auth_request (do not mirror at server{}).",
    "        set $bastion_pass_cookie $http_cookie;",
    "        set $bastion_pass_session $cookie_bastion_session;",
    '        set $bastion_auth_cookie '
    '"bastion_session=$bastion_pass_session; $bastion_pass_cookie";',
)


def _activesync_locations(
    slug: str,
    upstream_host_esc: str,
    fqdn_esc: str,
    *,
    upstream_is_https: bool = False,
    upstream_tls_verify: bool = False,
) -> list[str]:
    """Locations that skip browser SSO redirect; require Basic or SSO via activesync-auth.

    EAS uses long-lived Ping (often 15–30 min) and large Sync bodies — buffering off,
    high body limit, and no WebSocket Connection rewrite (would break keep-alive Ping).
    """
    ssl_lines: list[str] = []
    if upstream_is_https:
        ssl_lines = [
            "        proxy_ssl_server_name on;",
            nginx_proxy_ssl_verify_directive(upstream_tls_verify),
        ]
    return [
        "    # Mobile ActiveSync / Autodiscover (allow_activesync=true)",
        "    # Ping heartbeat needs read timeout >> default 60s (iOS often 900–1800s).",
        "    location ~* ^/Microsoft-Server-ActiveSync {",
        *_AUTH_COOKIE_CAPTURE_LINES,
        "        auth_request /internal/activesync-auth;",
        *_AUTH_REQUEST_DIAG_LINES,
        f"        error_page 401 = @activesync_unauthorized_{slug};",
        "",
        "        client_max_body_size 64m;",
        "        proxy_pass $app_upstream;",
        "        proxy_redirect off;",
        "        proxy_http_version 1.1;",
        "        proxy_buffering off;",
        "        proxy_request_buffering off;",
        "        proxy_read_timeout 3600s;",
        "        proxy_send_timeout 3600s;",
        "        proxy_connect_timeout 60s;",
        *ssl_lines,
        "        proxy_set_header Host $host;",
        "        proxy_set_header X-Real-IP $remote_addr;",
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "        proxy_set_header X-Forwarded-Proto $bastion_forwarded_proto;",
        "        # Upstream (grommunio) validates Basic; auth_request only gates access.",
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
        *_AUTH_COOKIE_CAPTURE_LINES,
        "        auth_request /internal/activesync-auth;",
        *_AUTH_REQUEST_DIAG_LINES,
        f"        error_page 401 = @activesync_unauthorized_{slug};",
        "",
        "        client_max_body_size 1m;",
        "        proxy_pass $app_upstream;",
        "        proxy_redirect off;",
        "        proxy_http_version 1.1;",
        "        proxy_buffering off;",
        "        proxy_request_buffering off;",
        "        proxy_read_timeout 120s;",
        "        proxy_send_timeout 120s;",
        *ssl_lines,
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


def _is_crushftp_app(app: App) -> bool:
    driver = (getattr(app, "robotic_driver", None) or "").strip().lower()
    provision = (getattr(app, "provisioning_driver", None) or "").strip().lower()
    return driver == "crushftp" or provision == "crushftp"


def generate_subdomain_server_block(app: App, settings: Settings) -> str:
    """One HTTP server{} for front nginx (TLS offloaded). Includes hop + auth_request."""
    fqdn = (app.public_fqdn or "").strip()
    slug = app.slug
    if not _SAFE_SLUG.match(slug):
        raise ValueError(f"unsafe app slug for nginx: {slug!r}")
    raw_upstream = (app.upstream_url or "").strip()
    if not raw_upstream:
        raise ValueError(f"app {slug}: upstream_url required")
    # Origin only — path in upstream_url is ignored (avoids /web ↔ /web/ 301 loops).
    origin = upstream_origin(raw_upstream)
    upstream_host = _upstream_host(raw_upstream)
    portal = (settings.portal_domain or "portal.ar-systems.fr").strip()
    origin_esc = _nginx_escape(origin)
    fqdn_esc = _nginx_escape(fqdn)
    portal_esc = _nginx_escape(portal)
    upstream_host_esc = _nginx_escape(upstream_host)
    allow_eas = bool(getattr(app, "allow_activesync", False))
    crushftp = _is_crushftp_app(app)
    upstream_is_https = origin.lower().startswith("https://")
    tls_verify = resolve_upstream_tls_verify(app)
    ssl_lines: list[str] = []
    if upstream_is_https:
        ssl_lines = [
            "        proxy_ssl_server_name on;",
            nginx_proxy_ssl_verify_directive(tls_verify),
        ]
        if crushftp:
            # CrushFTP often negotiates poorly with default openssl defaults.
            ssl_lines.insert(0, "        proxy_ssl_protocols TLSv1.2 TLSv1.3;")
            ssl_lines.append("        proxy_ssl_session_reuse off;")

    # CrushFTP: forward ONLY CrushAuth + currentAuth. Never bastion_session /
    # oauth2 JWTs (header too large → 502, or CrushFTP drops the session and
    # Absolute-redirects to the upstream IP login page).
    # CRITICAL: put that Cookie filter in @app_upstream_* only — never in the
    # same location as auth_request (inherits → HAR ae=no-session:ck=72:x=0).
    if crushftp:
        cookie_lines = [
            '        set $bastion_upstream_cookie '
            '"CrushAuth=$cookie_CrushAuth; currentAuth=$cookie_currentAuth";',
            "        proxy_set_header Cookie $bastion_upstream_cookie;",
        ]
        # Robotic login + browser must share the same reverse IP or CrushFTP
        # invalidates CrushAuth (dedicated transfer vhost contract).
        real_ip_line = "        proxy_set_header X-Real-IP $server_addr;"
        xff_line = "        proxy_set_header X-Forwarded-For $server_addr;"
        # CrushFTP often emits Absolute Location: http(s)://<upstream-ip>/...
        # With proxy_redirect off the browser leaves the SSO vhost (IP login).
        upstream_host_re = re.escape(upstream_host)
        redirect_lines = [
            f"        proxy_redirect http://{upstream_host_esc}/ "
            f"https://{fqdn_esc}/;",
            f"        proxy_redirect https://{upstream_host_esc}/ "
            f"https://{fqdn_esc}/;",
            f"        proxy_redirect ~^https?://{upstream_host_re}(?::\\d+)?(/.*)$ "
            f"https://{fqdn_esc}$1;",
        ]
    else:
        cookie_lines = ["        proxy_set_header Cookie $http_cookie;"]
        real_ip_line = "        proxy_set_header X-Real-IP $remote_addr;"
        xff_line = "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;"
        redirect_lines = ["        proxy_redirect off;"]

    named_upstream = f"@app_upstream_{slug}"
    auth_request_set_user_lines = [
        "        auth_request_set $auth_user $upstream_http_x_auth_user;",
        "        auth_request_set $auth_app $upstream_http_x_auth_app;",
    ]
    proxy_auth_header_lines = [
        "        proxy_set_header X-Auth-User $auth_user;",
        "        proxy_set_header X-Auth-App $auth_app;",
    ]
    proxy_body_lines = [
        f"        proxy_pass $app_upstream;",
        *redirect_lines,
        "        proxy_http_version 1.1;",
        # Needed for ws/wss endpoints (e.g. Teleport terminal streaming).
        "        proxy_set_header Upgrade $http_upgrade;",
        "        proxy_set_header Connection $http_connection;",
        "        proxy_connect_timeout 60s;",
        "        proxy_read_timeout 3600s;",
        "        proxy_send_timeout 3600s;",
        *ssl_lines,
        "        proxy_set_header Host $host;",
        real_ip_line,
        xff_line,
        "        proxy_set_header X-Forwarded-Proto $bastion_forwarded_proto;",
        *cookie_lines,
        "        proxy_cookie_path / /;",
        f"        proxy_cookie_domain {upstream_host_esc} {fqdn_esc};",
        *(
            ["        proxy_hide_header WWW-Authenticate;"]
            if crushftp
            else []
        ),
        "",
        *proxy_auth_header_lines,
    ]

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
        f'    set $app_upstream "{origin_esc}";',
        # Literal FQDN — re-set on auth_request rewrite; never empty like $host
        # can be on the subrequest (HAR: portal OK, Transfer 401 no-app).
        f'    set $bastion_vhost_fqdn "{fqdn_esc}";',
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
    if crushftp:
        # CrushFTP aborts TLS on directory URLs; force the explicit index file.
        lines.extend(
            [
                "    location = /WebInterface/new-ui {",
                "        return 302 /WebInterface/new-ui/index.html;",
                "    }",
                "    location = /WebInterface/new-ui/ {",
                "        return 302 /WebInterface/new-ui/index.html;",
                "    }",
                "    location = / {",
                "        return 302 /WebInterface/new-ui/index.html;",
                "    }",
                "",
            ]
        )
    if allow_eas:
        lines.extend(
            _activesync_locations(
                slug,
                upstream_host_esc,
                fqdn_esc,
                upstream_is_https=upstream_is_https,
                upstream_tls_verify=tls_verify,
            )
        )
    if crushftp:
        # Auth gate only — CrushFTP Cookie filter is in the named location below.
        location_slash = [
            "    location / {",
            *_AUTH_COOKIE_CAPTURE_LINES,
            "        auth_request /internal/subdomain-auth;",
            *_AUTH_REQUEST_DIAG_LINES,
            *auth_request_set_user_lines,
            f"        error_page 401 = @portal_redirect_{slug};",
            # Do not map CrushFTP/upstream 401 through @portal_redirect.
            "        proxy_intercept_errors off;",
            "",
            "        # Hand off AFTER auth — filtered Cookie must not share this location",
            "        # with auth_request (inherits proxy_set_header -> ck=72 / x=0).",
            f"        try_files /nonexistent {named_upstream};",
            "    }",
            "",
            f"    location {named_upstream} {{",
            *proxy_body_lines,
            "    }",
        ]
    else:
        location_slash = [
            "    location / {",
            # Capture Cookie here (parent) — $http_cookie is empty on auth
            # subrequest (HAR ae=no-session). Host stays literal $bastion_vhost_fqdn.
            *_AUTH_COOKIE_CAPTURE_LINES,
            "        auth_request /internal/subdomain-auth;",
            *_AUTH_REQUEST_DIAG_LINES,
            *auth_request_set_user_lines,
            f"        error_page 401 = @portal_redirect_{slug};",
            "        proxy_intercept_errors off;",
            "",
            *proxy_body_lines,
            "    }",
        ]

    lines.extend(location_slash)
    lines.extend(
        [
            "",
            f"    location @portal_redirect_{slug} {{",
            # Native bastion_session cutover: send browsers to /auth/login
            # (auth_request off on portal) — NOT bare /login which falls through
            # location / → portal_auth_check → bounce-back loop when subdomain
            # auth_request still returns 401.
            # bastion_sub=1: login must NOT bounce back to this Host (HAR loop when
            # auth_request 401 despite a valid bastion_session — stale nginx snippet).
            # ae=$bastion_auth_err: surface FastAPI X-Auth-Error in the next HAR
            # (no-session / no-app-for-host / native-session-rejected).
            f"        return 302 https://{portal_esc}/auth/login"
            "?rd=https://$host$request_uri&bastion_sub=1&ae=$bastion_auth_err;",
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
