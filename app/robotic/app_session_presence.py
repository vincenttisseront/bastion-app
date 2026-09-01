"""Detect upstream session cookies on subdomain requests (cookie-SSO drivers)."""

from __future__ import annotations

import re

from app.access_modes import uses_cookie_impersonation
from app.models import App

_TELEPORT_SESSION_RE = re.compile(
    r"(?:^|;\s*)(?:__Host-session|__Secure-session)=([^;]+)",
    re.IGNORECASE,
)
_CRUSHAUTH_RE = re.compile(r"(?:^|;\s*)CrushAuth=([^;]+)", re.IGNORECASE)


def has_app_session_cookie(app: App, cookie_header: str) -> bool:
    """
    True when the browser already carries upstream session cookies for this app.

    Cookie-impersonation drivers without a recognizable session cookie should
    trigger ``no-app-session`` in subdomain auth (nginx → impersonate or login).
    """
    if not uses_cookie_impersonation(app):
        return True

    raw = cookie_header or ""
    driver = (getattr(app, "robotic_driver", None) or "").strip().lower()

    if driver == "teleport":
        match = _TELEPORT_SESSION_RE.search(raw)
        return bool(match and match.group(1).strip())

    if driver == "crushftp":
        match = _CRUSHAUTH_RE.search(raw)
        return bool(match and match.group(1).strip())

    # generic_form: cookie names vary per upstream — presence check is driver-specific
    # and not enforced here (vault impersonation still runs from the catalogue).
    return True
