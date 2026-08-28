"""User identity from Nginx-injected headers and break-glass cookie."""

from __future__ import annotations

import re
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.breakglass import (
    COOKIE_NAME,
    decode_breakglass_token_with_fallback,
    validate_breakglass_cookie,
)
from app.database import get_db
from app.rbac.effective_access_service import user_has_portal_admin_role
from app.rbac.user_identity import (
    format_identity_first_name,
    format_identity_last_name,
    parse_identity_from_username,
)
from app.sso_settings import Settings, get_settings

# Keycloak subject UUIDs must never be shown as a display name.
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def looks_like_uuid(value: str | None) -> bool:
    if not value:
        return False
    return bool(_UUID_RE.match(value.strip()))


def _human_label(*candidates: str | None) -> str | None:
    for raw in candidates:
        if not raw:
            continue
        text = raw.strip()
        if text and not looks_like_uuid(text):
            return text
    return None


@dataclass
class UserContext:
    email: str
    username: str
    groups: list[str]
    realm_slug: str
    auth_source: str
    is_admin: bool
    keycloak_user_id: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    identity_first_name: str | None = None
    identity_last_name: str | None = None

    @property
    def display_name(self) -> str:
        first = (self.identity_first_name or "").strip()
        last = (self.identity_last_name or "").strip()
        if first and last:
            return f"{first} {last}"
        if first or last:
            return first or last
        return _human_label(self.given_name, self.username, self.email) or (
            self.email or self.username or "?"
        )

    @property
    def is_breakglass(self) -> bool:
        return self.auth_source == "breakglass"

    @property
    def first_name(self) -> str:
        """Prénom for greetings — OIDC given_name, else email local-part."""
        if self.given_name and self.given_name.strip() and not looks_like_uuid(self.given_name):
            return self.given_name.strip()
        local = (self.email or self.username or "").split("@", 1)[0].strip()
        if not local or looks_like_uuid(local):
            return self.display_name
        token = local.replace("_", ".").replace("-", ".").split(".", 1)[0]
        if not token:
            return self.display_name
        return token[:1].upper() + token[1:]

    @property
    def initials(self) -> str:
        """Two-letter avatar initials from identity or display name / email."""
        first = (self.identity_first_name or "").strip()
        last = (self.identity_last_name or "").strip()
        if first and last:
            return (first[0] + last[0]).upper()
        source = self.display_name
        if source == "?" or looks_like_uuid(source):
            source = (self.email or self.username or "?").strip()
        if "@" in source:
            source = source.split("@", 1)[0]
        parts = [p for p in source.replace("_", ".").replace("-", ".").split(".") if p]
        if len(parts) >= 2:
            return (parts[0][0] + parts[1][0]).upper()
        if parts:
            token = parts[0]
            return (token[:2] if len(token) >= 2 else token[:1]).upper()
        return "?"


def _normalize_group_name(raw: str) -> str:
    """Keycloak may send path-style claims (/portal-admins); compare on leaf name."""
    name = raw.strip()
    if "/" in name:
        name = name.rstrip("/").rsplit("/", 1)[-1]
    return name


def _parse_groups(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [_normalize_group_name(g) for g in raw.split(",") if g.strip()]


def parse_groups_header(raw: str | None) -> list[str]:
    """Public alias for OIDC ``groups`` claim / X-Groups header parsing."""
    return _parse_groups(raw)


def _is_admin_via_groups(groups: list[str], auth_source: str, settings: Settings) -> bool:
    if auth_source == "breakglass":
        return True
    admin_groups = {_normalize_group_name(g) for g in settings.portal_admin_groups}
    return any(g in admin_groups for g in groups)


def _bastion_identity_names(
    db: Session, user: UserContext
) -> tuple[str | None, str | None]:
    from app.models import BastionAccount, RealmConfig

    base = db.query(BastionAccount.first_name, BastionAccount.last_name)
    if user.keycloak_user_id:
        row = (
            base.filter(BastionAccount.keycloak_user_id == user.keycloak_user_id)
            .order_by(BastionAccount.updated_at.desc())
            .first()
        )
        if row and (row[0] or row[1]):
            return (row[0] or None, row[1] or None)

    if user.username and user.realm_slug:
        realm_id = (
            db.query(RealmConfig.id).filter(RealmConfig.slug == user.realm_slug).scalar()
        )
        if realm_id:
            row = (
                base.filter(
                    BastionAccount.realm_id == realm_id,
                    BastionAccount.username == user.username,
                )
                .order_by(BastionAccount.updated_at.desc())
                .first()
            )
            if row and (row[0] or row[1]):
                return (row[0] or None, row[1] or None)
    return None, None


def _resolve_identity_names(user: UserContext, db: Session | None) -> None:
    """Fill ``identity_first_name`` / ``identity_last_name`` for portal display."""
    first: str | None = None
    last: str | None = None

    if db is not None:
        first, last = _bastion_identity_names(db, user)

    if not first and user.given_name and not looks_like_uuid(user.given_name):
        first = format_identity_first_name(user.given_name)
    if not last and user.family_name and not looks_like_uuid(user.family_name):
        last = format_identity_last_name(user.family_name)

    if not first or not last:
        parsed = parse_identity_from_username(user.username)
        if parsed:
            first = first or parsed[0]
            last = last or parsed[1]

    user.identity_first_name = (first or "").strip() or None
    user.identity_last_name = (last or "").strip() or None


def _display_cache_for_user(db: Session, keycloak_user_id: str | None) -> str | None:
    if not keycloak_user_id:
        return None
    from app.models import AccessGrant

    row = (
        db.query(AccessGrant.user_display_cache)
        .filter(
            AccessGrant.subject_type == "user",
            AccessGrant.keycloak_user_id == keycloak_user_id,
            AccessGrant.user_display_cache.is_not(None),
            AccessGrant.user_display_cache != "",
        )
        .order_by(AccessGrant.granted_at.desc())
        .first()
    )
    if not row:
        return None
    label = (row[0] or "").strip()
    return label if label and not looks_like_uuid(label) else None


def enrich_user_identity(user: UserContext, db: Session | None) -> UserContext:
    """Prefer human labels over Keycloak subject UUIDs; fill from grant cache if needed."""
    if db is None:
        _resolve_identity_names(user, None)
        return user

    cache = _display_cache_for_user(db, user.keycloak_user_id)
    if looks_like_uuid(user.username):
        user.username = _human_label(cache, user.email, user.given_name) or user.username
    if looks_like_uuid(user.email):
        user.email = _human_label(cache, user.username, user.given_name) or user.email
    if cache and looks_like_uuid(user.username) and looks_like_uuid(user.email):
        user.username = cache
    _resolve_identity_names(user, db)
    return user


BREAKGLASS_EMAIL_DOMAIN = "breakglass.local"


def is_breakglass_email(email: str | None) -> bool:
    """Synthetic break-glass identities use ``user@breakglass.local``."""
    text = (email or "").strip().lower()
    return text.endswith(f"@{BREAKGLASS_EMAIL_DOMAIN}")


def _realm_from_bastion_session(
    request: Request,
    settings: Settings,
    db: Session | None,
) -> str:
    """Realm claim from native ``bastion_session`` JWT (cookie portal_realm_slug retired)."""
    if db is None:
        return ""
    try:
        from app.auth import extract_oidc_session_cookie_raw
        from app.oidc_bff import validate_oidc_session_cookie
    except Exception:
        return ""
    raw = extract_oidc_session_cookie_raw(request, settings)
    if not raw:
        return ""
    claims = validate_oidc_session_cookie(raw, db=db, settings=settings)
    if claims is None:
        return ""
    return (claims.realm or "").strip()


def _resolve_portal_realm_slug(
    request: Request,
    settings: Settings,
    db: Session | None,
) -> str:
    """Prefer non-empty nginx header, then JWT realm, then portal default.

    Empty ``X-Portal-Realm-Slug`` (missing ``portal_realm_slug`` cookie) must not
    win over the default via ``dict.get`` — nginx always sends the header.
    """
    header = (request.headers.get("X-Portal-Realm-Slug") or "").strip()
    if header:
        return header
    from_jwt = _realm_from_bastion_session(request, settings, db)
    if from_jwt:
        return from_jwt
    return (settings.sso_portal_default_realm_slug or "").strip() or "ar-systems"


def get_user_context(
    request: Request,
    settings: Settings | None = None,
    db: Session | None = None,
) -> UserContext | None:
    settings = settings or get_settings()
    email = request.headers.get("X-Email", "").strip()
    preferred = request.headers.get("X-Preferred-Username", "").strip()
    x_user = request.headers.get("X-User", "").strip()
    # Never treat a Keycloak subject UUID as the login name.
    username = _human_label(preferred, x_user, email) or preferred or x_user or email
    # Prefer explicit subject UUID when Nginx/oauth2-proxy forwards it.
    keycloak_user_id = request.headers.get("X-User-Id", "").strip() or None
    groups = _parse_groups(request.headers.get("X-Groups"))
    realm_slug = _resolve_portal_realm_slug(request, settings, db)
    auth_source = request.headers.get("X-Portal-Auth-Source", "sso")
    given_name = (
        request.headers.get("X-Given-Name", "").strip()
        or request.headers.get("X-Auth-Request-Given-Name", "").strip()
        or None
    )
    family_name = (
        request.headers.get("X-Family-Name", "").strip()
        or request.headers.get("X-Auth-Request-Family-Name", "").strip()
        or None
    )

    if not email and not username:
        bg_cookie = request.cookies.get(COOKIE_NAME)
        if bg_cookie and validate_breakglass_cookie(
            bg_cookie, db=db, settings=settings
        ):
            payload, _fb = decode_breakglass_token_with_fallback(
                bg_cookie, settings, db=db
            )
            if not payload:
                return None
            username = payload.get("sub", "breakglass")
            email = f"{username}@{BREAKGLASS_EMAIL_DOMAIN}"
            auth_source = "breakglass"
            groups = list(settings.portal_admin_groups)
            keycloak_user_id = None
        else:
            return None

    if not email:
        email = username

    # Break-glass is emergency local auth — never attribute to an SSO realm.
    if auth_source == "breakglass" or is_breakglass_email(email):
        auth_source = "breakglass"
        realm_slug = ""
        keycloak_user_id = None

    # Fallback: X-User / X-User-Id holding a Keycloak subject (not an email).
    if not keycloak_user_id:
        for candidate in (request.headers.get("X-User-Id", ""), x_user):
            cand = (candidate or "").strip()
            if cand and looks_like_uuid(cand):
                keycloak_user_id = cand
                break
            if cand and cand != email and "@" not in cand and not preferred:
                # Legacy: X-User sometimes carried the subject when preferred was absent.
                keycloak_user_id = cand
                break

    is_admin = _is_admin_via_groups(groups, auth_source, settings)
    user = UserContext(
        email=email,
        username=username,
        groups=groups,
        realm_slug=realm_slug,
        auth_source=auth_source,
        is_admin=is_admin,
        keycloak_user_id=keycloak_user_id,
        given_name=given_name,
        family_name=family_name,
    )
    if db is not None:
        if not user.is_admin and user_has_portal_admin_role(
            db,
            keycloak_user_id=user.keycloak_user_id,
            group_names=user.groups,
        ):
            user.is_admin = True
        enrich_user_identity(user, db)
    return user


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


def require_user(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> UserContext:
    user = get_user_context(request, settings, db=db)
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


async def require_user_enriched(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> UserContext:
    """Like require_user, but fills email from Keycloak when X-Email is missing/short."""
    user = require_user(request, db=db, settings=settings)
    if user.is_breakglass or not user.keycloak_user_id:
        return user
    from app.rbac.oidc_email import looks_like_email, resolve_user_email

    if looks_like_email(user.email):
        return user
    resolved = await resolve_user_email(db, settings, user)
    if looks_like_email(resolved):
        user.email = resolved
    return user


def require_admin(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> UserContext:
    """Require portal admin. Non-admins get 403 (HTML handler redirects to /apps)."""
    user = require_user(request, db=db, settings=settings)
    if is_portal_admin(user, db, settings):
        user.is_admin = True
        enrich_user_identity(user, db)
        return user
    raise HTTPException(status_code=403, detail="Admin access required")
