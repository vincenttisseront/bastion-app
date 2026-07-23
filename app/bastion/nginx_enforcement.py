"""Nginx fragment generation for vault robotic drivers."""

from __future__ import annotations

from app.access_modes import PROXY_ACCESS_MODES, normalize_access_mode
from app.bastion.bastion_fields import normalize_auth_mode
from app.models import App


def _resolved_driver(app: App) -> str:
    mode = normalize_auth_mode(app.auth_mode)
    if mode in ("generic_basic_auth", "generic_wsse"):
        return mode
    return (app.robotic_driver or "").strip().lower()


def basic_auth_auth_request_lines(app: App) -> list[str]:
    """
    auth_request + proxy_set_header Authorization for generic_basic_auth apps.

    Only valid for subdomain_proxy / legacy_path_proxy — not sso_gate.
    """
    mode = normalize_access_mode(app.access_mode)
    if mode not in PROXY_ACCESS_MODES:
        return []
    if _resolved_driver(app) != "generic_basic_auth":
        return []
    slug = app.slug
    lines = [
        f"    # [{slug}] generic_basic_auth — robotic Authorization via auth_request",
        f"    auth_request /internal/basic-auth-header/{slug};",
        "    auth_request_set $robotic_auth $upstream_http_x_robotic_authorization;",
        "    proxy_set_header Authorization $robotic_auth;",
    ]
    return lines


def wsse_auth_request_lines(app: App) -> list[str]:
    """
    auth_request + X-WSSE / Authorization for generic_wsse apps.

    Header is regenerated on every auth_request (nonce + Created) — never cached.
    Only valid for subdomain_proxy / legacy_path_proxy — not sso_gate.
    """
    mode = normalize_access_mode(app.access_mode)
    if mode not in PROXY_ACCESS_MODES:
        return []
    if _resolved_driver(app) != "generic_wsse":
        return []
    slug = app.slug
    lines = [
        f"    # [{slug}] generic_wsse — X-WSSE UsernameToken via auth_request (fresh each request)",
        f"    auth_request /internal/wsse-header/{slug};",
        "    auth_request_set $wsse_auth $upstream_http_x_wsse_authorization;",
        "    proxy_set_header X-WSSE $wsse_auth;",
        '    proxy_set_header Authorization \'WSSE profile="UsernameToken"\';',
    ]
    return lines


def robotic_auth_request_lines(app: App) -> list[str]:
    """Basic Auth or WSSE auth_request fragments for the app's vault driver."""
    return basic_auth_auth_request_lines(app) or wsse_auth_request_lines(app)


def proxy_location_lines(app: App) -> list[str]:
    """Full proxy location block including header-injection enforcement when applicable."""
    mode = normalize_access_mode(app.access_mode)
    lines: list[str] = []
    if mode == "subdomain_proxy" and app.public_fqdn:
        lines.append(f"# [{app.slug}] subdomain_proxy — {app.public_fqdn.strip()}")
        lines.append("server {")
        lines.append(f"    server_name {app.public_fqdn.strip()};")
        lines.append(f"    # proxy_pass {app.upstream_url};")
        lines.extend(robotic_auth_request_lines(app))
        lines.append("    # include snippets/subdomain_auth_common.conf;")
        lines.append("}")
        lines.append("")
    elif mode == "legacy_path_proxy":
        lines.append(f"# [{app.slug}] legacy_path_proxy")
        lines.append(f"location /proxy/{app.slug}/ {{")
        lines.append(f"    proxy_pass {app.upstream_url};")
        lines.extend(robotic_auth_request_lines(app))
        lines.append("    # auth_request /internal/oauth2-auth;")
        lines.append("}")
        lines.append("")
    return lines
