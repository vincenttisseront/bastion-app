"""Internal token authentication for admin/machine-to-machine routes."""

from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.sso_settings import Settings, get_settings

bearer = HTTPBearer()


def require_internal_token(
    credentials: HTTPAuthorizationCredentials = Security(bearer),
    settings: Settings = Depends(get_settings),
) -> str:
    if not settings.vault_portal_internal_token:
        raise HTTPException(status_code=503, detail="Internal token not configured")
    if credentials.credentials != settings.vault_portal_internal_token:
        raise HTTPException(status_code=403, detail="Invalid internal token")
    return credentials.credentials
