"""Target-app session cookie Path/Domain helpers (robotic / vault injection).

Two cookie categories must stay distinct:

1. **Portal SSO cookie** (oauth2-proxy / ``_kc_portal_*``) — may use
   ``Domain=<shared parent>`` for cross-subdomain SSO. That logic lives outside
   this module and must not be reused for category 2.

2. **Target session cookies** injected after robotic login — by default
   **host-only** (no ``Domain``), matching what the target app itself would set.
   Opt-in ``wide_domain`` exists for exceptional apps that need a parent Domain.
"""

from __future__ import annotations

import logging
import re
from typing import Literal
from urllib.parse import urlparse

from fastapi import Response

logger = logging.getLogger(__name__)

# CrushFTP cookie names (key filter only — Domain rules are scope-based, not driver-based).
CRUSHFTP_COOKIE_KEYS = ("CrushAuth", "currentAuth")

COOKIE_SCOPE_HOST_ONLY = "host_only"
COOKIE_SCOPE_WIDE_DOMAIN = "wide_domain"
INJECTED_COOKIE_SCOPES = (COOKIE_SCOPE_HOST_ONLY, COOKIE_SCOPE_WIDE_DOMAIN)
INJECTED_COOKIE_SCOPE_LABELS = {
    COOKIE_SCOPE_HOST_ONLY: "Host-only (recommandé)",
    COOKIE_SCOPE_WIDE_DOMAIN: "Domaine parent large (exception)",
}

CookieScope = Literal["host_only", "wide_domain"]

_HOST_PORT_RE = re.compile(r"^(.+):(\d+)$")


def normalize_hostname(value: str | None) -> str:
    """
    Extract a bare hostname from a FQDN, URL, or host:port string.

    Used before shared-parent comparison and cookie Domain= computation so that
    ``https://webmail.ar-systems.fr/`` or ``webmail.ar-systems.fr:443`` still
    resolve to the same parent as ``portal.ar-systems.fr``.
    """
    raw = (value or "").strip().lower()
    if not raw:
        return ""
    if "://" in raw or "/" in raw or "?" in raw or "#" in raw:
        parsed = urlparse(raw if "://" in raw else f"//{raw}", scheme="")
        host = (parsed.hostname or "").strip(".")
        if host:
            return host
    raw = raw.strip(".")
    match = _HOST_PORT_RE.match(raw)
    if match and match.group(1).count(":") == 0:
        # host:port (not IPv6)
        return match.group(1).strip(".")
    # Bracketed IPv6 with optional port — urlparse handles best via // prefix
    if raw.startswith("["):
        parsed = urlparse(f"//{raw}")
        return (parsed.hostname or "").strip(".")
    return raw


def shared_parent_domain(fqdn: str, portal_domain: str) -> str | None:
    """
    Return the shortest common parent domain of two hostnames, or None.

    Used for portal SSO cross-subdomain cookies and for the rare
    ``injected_cookie_scope=wide_domain`` opt-in — not the default for target
    session cookies.
    """
    fqdn_labels = normalize_hostname(fqdn).split(".")
    portal_labels = normalize_hostname(portal_domain).split(".")
    if (
        not fqdn_labels
        or not portal_labels
        or "" in fqdn_labels
        or "" in portal_labels
    ):
        return None
    common: list[str] = []
    for a, b in zip(reversed(fqdn_labels), reversed(portal_labels)):
        if a != b:
            break
        common.append(a)
    if len(common) < 2:
        return None
    return ".".join(reversed(common))


def portal_sso_cookie_domain(portal_domain: str) -> str | None:
    """
    Parent domain for oauth2-proxy ``cookie_domains`` / ``whitelist_domains``.

    ``portal.ar-systems.fr`` → ``ar-systems.fr`` so subdomain apps
    (``webmail.ar-systems.fr``, …) receive ``_oauth2_proxy`` on auth_request.
    Two-label portal hosts stay host-only (return None).
    """
    labels = [p for p in normalize_hostname(portal_domain).split(".") if p]
    if len(labels) < 3:
        return None
    return ".".join(labels[1:])


def normalize_injected_cookie_scope(value: str | None) -> CookieScope:
    raw = (value or "").strip().lower()
    if raw == COOKIE_SCOPE_WIDE_DOMAIN:
        return COOKIE_SCOPE_WIDE_DOMAIN
    return COOKIE_SCOPE_HOST_ONLY


def cookie_path_and_domain(
    mode: Literal["subdomain", "legacy"],
    slug: str,
    fqdn: str | None,
    portal_domain: str = "",
    *,
    scope: str | None = COOKIE_SCOPE_HOST_ONLY,
) -> tuple[str, str | None]:
    """
    Compute Path and Domain for **target** session cookies.

    Default scope ``host_only`` → no Domain (app-managed clears work).
    ``wide_domain`` (subdomain only) → Domain=shared parent with portal.
    Legacy mode is always host-only with Path=/proxy/{slug}/.
    """
    normalized = normalize_injected_cookie_scope(scope)
    if mode == "subdomain":
        path = "/"
        if normalized == COOKIE_SCOPE_WIDE_DOMAIN:
            fqdn_clean = (fqdn or "").strip()
            if not fqdn_clean:
                return path, None
            shared = shared_parent_domain(fqdn_clean, portal_domain or "")
            if shared is None:
                logger.warning(
                    "No shared parent domain between app FQDN %r and portal %r — "
                    "wide_domain cookies cannot be set; falling back to host-only",
                    fqdn_clean,
                    portal_domain,
                )
                return path, None
            return path, shared
        return path, None
    return f"/proxy/{slug}/", None


def needs_session_cookie_hop(
    mode: Literal["subdomain", "legacy"],
    fqdn: str | None,
    *,
    scope: str | None = COOKIE_SCOPE_HOST_ONLY,
) -> bool:
    """
    True when target cookies must be set via a hop on the app FQDN.

    Portal responses cannot set host-only cookies for another host; subdomain +
    host_only therefore requires ``https://{fqdn}/.bastion/session-cookies``.
    """
    if mode != "subdomain":
        return False
    if normalize_injected_cookie_scope(scope) != COOKIE_SCOPE_HOST_ONLY:
        return False
    return bool((fqdn or "").strip())


def cookie_should_be_httponly(key: str) -> bool:
    # Apps that expose a CSRF/c2f token via JS (e.g. CrushFTP currentAuth) need
    # a readable cookie — keyed by cookie name, not by driver.
    return key != "currentAuth"


def inject_target_session_cookies(
    response: Response,
    cookies: dict[str, str],
    mode: Literal["subdomain", "legacy"],
    slug: str,
    fqdn: str | None,
    *,
    portal_domain: str = "",
    scope: str | None = COOKIE_SCOPE_HOST_ONLY,
    cookie_keys: tuple[str, ...] | None = None,
) -> None:
    """
    Set target-app session cookies on a FastAPI response.

    Default: host-only (no Domain). Does not apply portal SSO Domain rules.
    """
    path, domain = cookie_path_and_domain(
        mode, slug, fqdn, portal_domain=portal_domain, scope=scope
    )
    keys = cookie_keys if cookie_keys is not None else tuple(cookies.keys())
    if not keys:
        keys = tuple(cookies.keys())

    for key in keys:
        value = cookies.get(key)
        if not value:
            continue
        kwargs: dict = {
            "key": key,
            "value": value,
            "path": path,
            "httponly": cookie_should_be_httponly(key),
            "secure": True,
            "samesite": "lax",
        }
        if domain:
            kwargs["domain"] = domain
        response.set_cookie(**kwargs)


# Backward-compatible aliases
build_response_cookies = inject_target_session_cookies


def build_crushftp_response_cookies(
    response: Response,
    cookies: dict[str, str],
    mode: Literal["subdomain", "legacy"],
    slug: str,
    fqdn: str | None,
    *,
    portal_domain: str = "",
    scope: str | None = COOKIE_SCOPE_HOST_ONLY,
) -> None:
    """Inject CrushFTP session cookie names via the shared helper."""
    inject_target_session_cookies(
        response,
        cookies,
        mode,
        slug,
        fqdn,
        portal_domain=portal_domain,
        scope=scope,
        cookie_keys=CRUSHFTP_COOKIE_KEYS,
    )
