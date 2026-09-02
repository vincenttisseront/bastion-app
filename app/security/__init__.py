"""Security helpers: internal token auth + identity binding."""

from __future__ import annotations

import secrets

from fastapi import Depends, HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.sso_settings import Settings, get_settings

bearer = HTTPBearer()
bearer_optional = HTTPBearer(auto_error=False)


def nginx_identity_trusted(request: Request, settings: Settings) -> bool:
    """True when the request carries the shared Nginx→app internal token.

    SDD-001: MUST NOT trust X-Email / X-Groups / … without a valid
    ``X-Portal-Internal-Token`` (or Bearer) matching ``vault_portal_internal_token``.
    Empty/unconfigured token → fail closed (never trust identity headers).
    """
    expected = (settings.vault_portal_internal_token or "").strip()
    if not expected:
        return False
    header = (request.headers.get("x-portal-internal-token") or "").strip()
    if header and secrets.compare_digest(header, expected):
        return True
    auth = (request.headers.get("authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token and secrets.compare_digest(token, expected):
            return True
    return False


def require_internal_token(
    credentials: HTTPAuthorizationCredentials = Security(bearer),
    settings: Settings = Depends(get_settings),
) -> str:
    if not settings.vault_portal_internal_token:
        raise HTTPException(status_code=503, detail="Internal token not configured")
    if credentials.credentials != settings.vault_portal_internal_token:
        raise HTTPException(status_code=403, detail="Invalid internal token")
    return credentials.credentials


def require_nginx_internal_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_optional),
    settings: Settings = Depends(get_settings),
) -> str:
    """Bearer *or* X-Portal-Internal-Token (nginx trusted_internal snippet)."""
    expected = (settings.vault_portal_internal_token or "").strip()
    if not expected:
        raise HTTPException(status_code=503, detail="Internal token not configured")
    if credentials is not None and credentials.credentials == expected:
        return expected
    header = (request.headers.get("x-portal-internal-token") or "").strip()
    if header == expected:
        return expected
    raise HTTPException(status_code=403, detail="Invalid internal token")
