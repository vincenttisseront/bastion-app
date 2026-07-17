"""User identity from Nginx-injected headers and break-glass cookie."""

from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.breakglass import COOKIE_NAME, validate_breakglass_cookie
from app.database import get_db
from app.rbac.effective_access_service import user_has_portal_admin_role
from app.sso_settings import Settings, get_settings


@dataclass
class UserContext:
    email: str
    username: str
    groups: list[str]
    realm_slug: str
    auth_source: str
    is_admin: bool
    keycloak_user_id: str | None = None

    @property
    def display_name(self) -> str:
        return self.username or self.email

    @property
    def is_breakglass(self) -> bool:
        return self.auth_source == "breakglass"


def _parse_groups(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [g.strip() for g in raw.split(",") if g.strip()]


def _is_admin_via_groups(groups: list[str], auth_source: str, settings: Settings) -> bool:
    if auth_source == "breakglass":
        return True
    admin_groups = settings.portal_admin_groups
    return any(g in admin_groups for g in groups)


def get_user_context(request: Request, settings: Settings | None = None) -> UserContext | None:
    settings = settings or get_settings()
    email = request.headers.get("X-Email", "").strip()
    username = (
        request.headers.get("X-Preferred-Username", "").strip()
        or request.headers.get("X-User", "").strip()
        or email
    )
    # Prefer explicit subject UUID when Nginx/oauth2-proxy forwards it.
    keycloak_user_id = request.headers.get("X-User-Id", "").strip() or None
    groups = _parse_groups(request.headers.get("X-Groups"))
    realm_slug = request.headers.get(
        "X-Portal-Realm-Slug", settings.sso_portal_default_realm_slug
    )
    auth_source = request.headers.get("X-Portal-Auth-Source", "sso")

    if not email and not username:
        bg_cookie = request.cookies.get(COOKIE_NAME)
        if bg_cookie and validate_breakglass_cookie(bg_cookie, settings.vault_portal_internal_token):
            try:
                payload = jwt.decode(
                    bg_cookie, settings.vault_portal_internal_token, algorithms=["HS256"]
                )
                username = payload.get("sub", "breakglass")
                email = f"{username}@breakglass.local"
                auth_source = "breakglass"
                groups = list(settings.portal_admin_groups)
                keycloak_user_id = None
            except jwt.PyJWTError:
                return None
        else:
            return None

    if not email:
        email = username

    # Fallback: X-User holding a Keycloak subject (not an email).
    if not keycloak_user_id:
        x_user = request.headers.get("X-User", "").strip()
        if x_user and x_user != email and "@" not in x_user:
            keycloak_user_id = x_user

    is_admin = _is_admin_via_groups(groups, auth_source, settings)
    return UserContext(
        email=email,
        username=username,
        groups=groups,
        realm_slug=realm_slug,
        auth_source=auth_source,
        is_admin=is_admin,
        keycloak_user_id=keycloak_user_id,
    )


def is_portal_admin(
    user: UserContext,
    db: Session | None = None,
    settings: Settings | None = None,
) -> bool:
    """Admin if portal_admin_groups / break-glass, or AccessGrant system_role=portal_admin."""
    if user.is_admin:
        return True
    if db is None:
        return False
    settings = settings or get_settings()
    return user_has_portal_admin_role(
        db,
        keycloak_user_id=user.keycloak_user_id,
        group_names=user.groups,
    )


def require_user(request: Request) -> UserContext:
    user = get_user_context(request)
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def require_admin(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> UserContext:
    """Require portal admin. Non-admins get 403 (HTML handler redirects to /apps)."""
    user = require_user(request)
    if is_portal_admin(user, db, settings):
        user.is_admin = True
        return user
    raise HTTPException(status_code=403, detail="Admin access required")

