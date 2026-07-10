"""User identity from Nginx-injected headers and break-glass cookie."""

from dataclasses import dataclass

import jwt
from fastapi import HTTPException, Request

from app.breakglass import COOKIE_NAME, validate_breakglass_cookie
from app.sso_settings import Settings, get_settings


@dataclass
class UserContext:
    email: str
    username: str
    groups: list[str]
    realm_slug: str
    auth_source: str
    is_admin: bool

    @property
    def display_name(self) -> str:
        return self.username or self.email


def _parse_groups(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [g.strip() for g in raw.split(",") if g.strip()]


def _is_admin_user(groups: list[str], auth_source: str, settings: Settings) -> bool:
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
            except jwt.PyJWTError:
                return None
        else:
            return None

    if not email:
        email = username

    is_admin = _is_admin_user(groups, auth_source, settings)
    return UserContext(
        email=email,
        username=username,
        groups=groups,
        realm_slug=realm_slug,
        auth_source=auth_source,
        is_admin=is_admin,
    )


def require_user(request: Request) -> UserContext:
    user = get_user_context(request)
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def require_admin(request: Request) -> UserContext:
    user = require_user(request)
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user
