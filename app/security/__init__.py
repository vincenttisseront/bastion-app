"""Security helpers: internal token auth + identity binding."""

from fastapi import Depends, HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.sso_settings import Settings, get_settings

bearer = HTTPBearer()
bearer_optional = HTTPBearer(auto_error=False)


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
