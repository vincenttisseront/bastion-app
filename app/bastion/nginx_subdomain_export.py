"""Generate front-nginx server blocks for subdomain_proxy apps from App DB.

Target architecture: Traefik/edge terminates TLS → bastion-nginx:8080 (Host-based)
→ upstream app. Session cookie hop is always included (product-agnostic).
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
    "        auth_request_set $bastion_auth_app $upstream_http_x_auth_app;",
)

# Capture client Cookie in location / BEFORE auth_request.
# Do not also set these at server{} — rewrite on auth would wipe them.
# Snapshot from $cookie_bastion_session + $http_cookie. Keep auth_request,
# error_page 401 and proxy in the same location / (no if{}, no circular maps).
_AUTH_COOKIE_CAPTURE_LINES = (
    "        # Snapshot from cookie module — no if{} / map cycle / 418 gate.",
    "        set $bastion_pass_session $cookie_bastion_session;",
    "        set $bastion_pass_cookie $http_cookie;",
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
    CRS is off on these locations only: WBXML POST bodies trip SQLi/XSS rules.
    Subdomain WAF stays armed for other paths.
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
        "        # WBXML Sync/Ping — CRS false positives; subdomain WAF stays on elsewhere.",
        "        modsecurity off;",
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
        "        modsecurity off;",
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
        "        modsecurity off;",
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


def _is_teleport_app(app: App) -> bool:
    from app.bastion.teleport_agent_paths import is_teleport_app

    return is_teleport_app(app)


def _teleport_agent_proxy_lines(
    *,
    ssl_lines: list[str],
    forwarded_ip_lines: list[str],
    cookie_lines: list[str],
    redirect_lines: list[str],
    fqdn_esc: str,
    upstream_host_esc: str,
) -> list[str]:
    """Direct upstream proxy — no auth_request, no trusted-header injection."""
    return [
        "        proxy_pass $app_upstream;",
        *redirect_lines,
        "        proxy_http_version 1.1;",
        "        proxy_buffering off;",
        "        proxy_request_buffering off;",
        "        proxy_buffer_size 128k;",
        "        proxy_buffers 8 128k;",
        "        proxy_busy_buffers_size 256k;",
        "        proxy_set_header Upgrade $http_upgrade;",
        "        proxy_set_header Connection $connection_upgrade;",
        "        proxy_connect_timeout 60s;",
        "        proxy_read_timeout 3600s;",
        "        proxy_send_timeout 3600s;",
        *ssl_lines,
        "        proxy_set_header Host $host;",
        *forwarded_ip_lines,
        "        proxy_set_header X-Forwarded-Proto $bastion_forwarded_proto;",
        *cookie_lines,
        "        proxy_cookie_path / /;",
        f"        proxy_cookie_domain {upstream_host_esc} {fqdn_esc};",
        "",
    ]


def _teleport_agent_locations(
    slug: str,
    *,
    ssl_lines: list[str],
    forwarded_ip_lines: list[str],
    cookie_lines: list[str],
    redirect_lines: list[str],
    fqdn_esc: str,
    upstream_host_esc: str,
) -> list[str]:
    """Agent/reverse-tunnel paths — bypass portal SSO (Teleport handles auth)."""
    proxy = _teleport_agent_proxy_lines(
        ssl_lines=ssl_lines,
        forwarded_ip_lines=forwarded_ip_lines,
        cookie_lines=cookie_lines,
        redirect_lines=redirect_lines,
        fqdn_esc=fqdn_esc,
        upstream_host_esc=upstream_host_esc,
    )
    blocks: list[str] = [
        "    # Teleport agents — reverse tunnel / TLS-routing (no portal SSO).",
    ]
    for path in ("/webapi/find", "/webapi/ping", "/webapi/connectionupgrade"):
        blocks.extend(
            [
                f"    location = {path} {{",
                "        auth_request off;",
                "        modsecurity off;",
                *proxy,
                "    }",
                "",
            ]
        )
    blocks.extend(
        [
            "    location ^~ /webapi/host/ {",
            "        auth_request off;",
            "        modsecurity off;",
            *proxy,
            "    }",
            "",
            "    location ~* ^/v[12]/webapi/.+/connect/ws {",
            "        auth_request off;",
            "        modsecurity off;",
            *proxy,
            "    }",
            "",
        ]
    )
    del slug  # reserved for future per-app tuning
    return blocks


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
    # same location as auth_request (inherited proxy_set_header starves the jar).
    if crushftp:
        cookie_lines = [
            '        set $bastion_upstream_cookie '
            '"CrushAuth=$cookie_CrushAuth; currentAuth=$cookie_currentAuth";',
            "        proxy_set_header Cookie $bastion_upstream_cookie;",
        ]
        # Robotic login + browser must present the SAME IP to CrushFTP or it
        # invalidates CrushAuth (session IP lock):
        #   "User session invalidated due to IP change" in CrushFTP.log.
        # The robotic login reaches CrushFTP directly (TCP source = docker
        # host NAT, no forwarded headers), while browser traffic traverses
        # the DMZ reverse proxy which ADDS X-Forwarded-For: <client-ip>.
        # Simply omitting proxy_set_header here is NOT enough: nginx then
        # forwards the inbound X-Forwarded-For/X-Real-IP unchanged and
        # CrushFTP trusts it → two different IPs for the same CrushAuth →
        # 302 login.html + cookie wipe loop. Explicitly BLANK the headers
        # (empty value removes them) so CrushFTP only ever sees the TCP
        # source IP, identical for both paths.
        forwarded_ip_lines = [
            '        proxy_set_header X-Real-IP "";',
            '        proxy_set_header X-Forwarded-For "";',
        ]
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
        forwarded_ip_lines = [
            "        proxy_set_header X-Real-IP $remote_addr;",
            "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        ]
        redirect_lines = ["        proxy_redirect off;"]

    named_upstream = f"@app_upstream_{slug}"
    # Prefer X-Auth-Request-Email — same $upstream_http_x_auth_request_* vars the
    # portal already uses successfully with auth_request_set. Short X-Auth-Email
    # is still returned by FastAPI for clients that read it directly.
    auth_request_set_user_lines = [
        "        auth_request_set $auth_user $upstream_http_x_auth_user;",
        "        auth_request_set $auth_app $upstream_http_x_auth_app;",
        "        auth_request_set $auth_email $upstream_http_x_auth_request_email;",
        "        auth_request_set $auth_preferred $upstream_http_x_auth_preferred_username;",
        "        auth_request_set $auth_display $upstream_http_x_auth_display_name;",
        "        auth_request_set $auth_groups $upstream_http_x_auth_groups;",
        "        auth_request_set $auth_source $upstream_http_x_auth_source;",
    ]
    # Identity from auth_request only (never $http_*) — trusted-header SSO for
    # upstreams (Open WebUI WEBUI_AUTH_TRUSTED_*, Authelia-style apps, …).
    proxy_auth_header_lines = [
        "        proxy_set_header X-Auth-User $auth_user;",
        "        proxy_set_header X-Auth-App $auth_app;",
        "        proxy_set_header X-Auth-Email $auth_email;",
        "        proxy_set_header X-Auth-Preferred-Username $auth_preferred;",
        "        proxy_set_header X-Auth-Display-Name $auth_display;",
        "        proxy_set_header X-Auth-Groups $auth_groups;",
        "        proxy_set_header X-Auth-Source $auth_source;",
        "        proxy_set_header X-Forwarded-Email $auth_email;",
        "        proxy_set_header X-Forwarded-User $auth_display;",
        "        proxy_set_header X-Forwarded-Preferred-Username $auth_preferred;",
        "        proxy_set_header X-Forwarded-Groups $auth_groups;",
    ]
    proxy_body_lines = [
        f"        proxy_pass $app_upstream;",
        *redirect_lines,
        "        proxy_http_version 1.1;",
        "        # Stream transfers both ways — with buffering on, nginx spools the",
        "        # whole upload to client_body_temp before forwarding (a 2G file",
        "        # would fill the container disk and CrushFTP sees nothing for",
        "        # minutes). Same directives as the legacy hand-written vhost.",
        "        proxy_buffering off;",
        "        proxy_request_buffering off;",
        # Response-header buffers (independent of proxy_buffering): Immich/oauth
        # Set-Cookie jars blow the default 4k/8k → 502 "upstream sent too big header".
        "        proxy_buffer_size 128k;",
        "        proxy_buffers 8 128k;",
        "        proxy_busy_buffers_size 256k;",
        # Needed for ws/wss (Immich socket.io, Teleport, …). Use the http{} map
        # $connection_upgrade — raw $http_connection is empty on HTTP/2 hops.
        "        proxy_set_header Upgrade $http_upgrade;",
        "        proxy_set_header Connection $connection_upgrade;",
        "        proxy_connect_timeout 60s;",
        "        proxy_read_timeout 3600s;",
        "        proxy_send_timeout 3600s;",
        *ssl_lines,
        "        proxy_set_header Host $host;",
        *forwarded_ip_lines,
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
        "    include /etc/nginx/snippets/modsecurity-subdomain.conf;",
        "",
        "    absolute_redirect off;",
        "    port_in_redirect off;",
        "",
        f"    access_log /var/log/nginx/apps/{slug}.access.log app;",
        f"    error_log  /var/log/nginx/apps/{slug}.error.log warn;",
        "",
        "    # Empty defaults for log_format app (nginx 1.30+) before auth_request_set.",
        '    set $bastion_auth_err "";',
        '    set $bastion_auth_app "";',
        '    set $auth_email "";',
        '    set $auth_user "";',
        '    set $auth_app "";',
        '    set $auth_source "";',
        '    set $auth_preferred "";',
        '    set $auth_display "";',
        '    set $auth_groups "";',
        "",
        "    # Uploads — nginx default client_max_body_size is 1m: bigger bodies get",
        "    # 413 BEFORE reaching the app. CrushFTP symptom: transfer stalls while",
        "    # CrushFTP.log only shows getSessionTimeout keepalives (session counter",
        "    # draining) because the upload POST never arrives.",
        f"    client_max_body_size {'2G' if crushftp else '64m'};",
        "",
        "    set $bastion_app_upstream bastion-app:8000;",
        f'    set $app_upstream "{origin_esc}";',
        # Literal FQDN — re-set on auth_request rewrite; never empty like $host
        # can be on the subrequest.
        f'    set $bastion_vhost_fqdn "{fqdn_esc}";',
        "",
        "    include /etc/nginx/snippets/subdomain_auth_common.conf;",
        "",
        "    # Cookie hop — exact = beats any location ~ /\\. deny; never internal;",
        "    location = /.bastion/session-cookies {",
        "        auth_request off;",
        "        modsecurity off;",
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
        "    location = /.bastion/sso-session-mirror {",
        "        auth_request off;",
        "        modsecurity off;",
        "        proxy_pass http://$bastion_app_upstream/api/internal/sso-session-mirror;",
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
        "    # Edge liveness — must not depend on app upstream (smoke / monitoring).",
        "    location = /healthz {",
        "        modsecurity off;",
        "        access_log off;",
        "        default_type text/plain;",
        "        return 200 'ok\\n';",
        "    }",
        "",
        "    # Never run auth_request on /auth/login here — 401 would 302 to",
        "    # /auth/login?rd=… on this Host and nest until the URL explodes.",
        "    location = /auth/login {",
        "        auth_request off;",
        "        modsecurity off;",
        f"        return 302 https://{portal_esc}/auth/login;",
        "    }",
        "    location = /login {",
        "        auth_request off;",
        "        modsecurity off;",
        f"        return 302 https://{portal_esc}/auth/login;",
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
    if _is_teleport_app(app):
        lines.extend(
            _teleport_agent_locations(
                slug,
                ssl_lines=ssl_lines,
                forwarded_ip_lines=forwarded_ip_lines,
                cookie_lines=cookie_lines,
                redirect_lines=redirect_lines,
                fqdn_esc=fqdn_esc,
                upstream_host_esc=upstream_host_esc,
            )
        )
    if crushftp:
        # Auth gate only — CrushFTP Cookie filter is in the named location below.
        location_slash = [
            "    location / {",
            "        modsecurity off;",
            *_AUTH_COOKIE_CAPTURE_LINES,
            "        auth_request /internal/subdomain-auth;",
            *_AUTH_REQUEST_DIAG_LINES,
            *auth_request_set_user_lines,
            f"        error_page 401 403 503 = @portal_redirect_{slug};",
            # Do not map CrushFTP/upstream 401 through @portal_redirect.
            "        proxy_intercept_errors off;",
            "",
            "        # Hand off AFTER auth — filtered Cookie must not share this location",
            "        # with auth_request (inherited proxy_set_header would starve the jar).",
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
            "        # SPA/API: CRS breaks grommunio.js responses and POST bodies.",
            "        modsecurity off;",
            # Capture Cookie here (parent) — auth + proxy in same location.
            # Do NOT use return 418 → named gate: nested error_page breaks
            # @portal_redirect.
            *_AUTH_COOKIE_CAPTURE_LINES,
            "        auth_request /internal/subdomain-auth;",
            *_AUTH_REQUEST_DIAG_LINES,
            *auth_request_set_user_lines,
            f"        error_page 401 403 503 = @portal_redirect_{slug};",
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
            # fetch()/XHR (Sec-Fetch-Mode: cors): stay on this Host with 401 — a 302
            # to portal /auth/login triggers cross-origin CORS preflight (405).
            "        if ($bastion_unauth_return_401 = 1) {",
            "            return 401;",
            "        }",
            # Portal session OK but upstream robotic cookie missing — vault impersonate
            # (same path as catalogue tile) instead of the upstream login page.
            "        if ($bastion_auth_err = no-app-session) {",
            f"            return 302 https://{portal_esc}/api/internal/impersonate/{slug};",
            "        }",
            # Native bastion_session cutover: send browsers to /auth/login
            # (auth_request off on portal) — NOT bare /login which falls through
            # location / → portal_auth_check → bounce-back loop when subdomain
            # auth_request still returns 401.
            # bastion_sub=1: login must NOT bounce back to this Host.
            # ae=$bastion_auth_err: surface FastAPI X-Auth-Error for diagnostics.
            # Literal vhost FQDN (set above) — never raw $host from the request.
            f"        return 302 https://{portal_esc}/auth/login"
            "?rd=https://$bastion_vhost_fqdn$request_uri&bastion_sub=1&ae=$bastion_auth_err;",
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
