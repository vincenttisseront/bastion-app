"""identite_utilisateur — keep the typed password for one portal session.

Opt-in per application (``App.identity_password_session_cache``). The secret is
split so that no single store is enough to recover it:

* the database row holds ``AES-GCM(key, password)`` only;
* the browser holds a random 32-byte value in an ``HttpOnly`` / ``Secure`` /
  ``SameSite=Strict`` host-only cookie (never sent to app subdomains);
* ``key = HMAC(portal signing secret, cookie value)``.

A database dump, a stolen cookie or a leaked signing secret alone decrypt
nothing. The associated data binds each ciphertext to its handle, application,
portal identity and login name, so a row cannot be replayed for someone else.

Rows are deleted at portal logout, admin disconnect, upstream rejection, when
the user opts out, or once ``expires_at`` passes. The password itself is never
logged or returned to the browser.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import logging
import os
import secrets
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Request, Response
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app import re_safe
from app.bastion.bastion_fields import normalize_credential_mode
from app.models import App, IdentityPasswordCache, utcnow
from app.sso_settings import Settings
from app.web.csrf import portal_signing_secret

logger = logging.getLogger(__name__)

COOKIE_NAME = "bastion_idpw"
# Host-only on the portal FQDN: no Domain attribute, so app subdomains (and the
# upstreams behind them) never receive it.
_COOKIE_FLAGS = {"httponly": True, "secure": True, "samesite": "strict", "path": "/"}

_SIGNING_PURPOSE = "identity-password-cache"
_AAD_VERSION = "v1"
_NONCE_BYTES = 12
_SECRET_BYTES = 32
_MIN_TTL_SECONDS = 300

_HANDLE_RE = re_safe.compile(r"^[A-Za-z0-9_-]{32}$")
_SECRET_RE = re_safe.compile(r"^[A-Za-z0-9_-]{43}$")


@dataclass(frozen=True)
class CacheCookie:
    """Browser half of the split secret: public handle + key material."""

    handle: str
    secret: bytes

    def value(self) -> str:
        return f"{self.handle}.{_b64e(self.secret)}"


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def new_cookie() -> CacheCookie:
    return CacheCookie(handle=secrets.token_urlsafe(24), secret=os.urandom(_SECRET_BYTES))


def parse_cookie(raw: str | None) -> CacheCookie | None:
    handle, sep, secret_text = (raw or "").strip().partition(".")
    if not sep or not _HANDLE_RE.match(handle) or not _SECRET_RE.match(secret_text):
        return None
    try:
        secret = _b64d(secret_text)
    except (binascii.Error, ValueError):
        return None
    if len(secret) != _SECRET_BYTES:
        return None
    return CacheCookie(handle=handle, secret=secret)


def cookie_from_request(request: Request) -> CacheCookie | None:
    return parse_cookie(request.cookies.get(COOKIE_NAME))


def set_cache_cookie(response: Response, cookie: CacheCookie) -> None:
    # No Max-Age: a browser-session cookie. The server-side expires_at is the
    # authoritative lifetime; closing the browser simply drops the key half.
    response.set_cookie(key=COOKIE_NAME, value=cookie.value(), **_COOKIE_FLAGS)


def clear_cache_cookie(response: Response) -> None:
    response.delete_cookie(key=COOKIE_NAME, **_COOKIE_FLAGS)


def identity_user_key(user) -> str:
    """Portal identity a cache row belongs to (same key as the identity throttle)."""
    return (
        getattr(user, "keycloak_user_id", None)
        or getattr(user, "email", None)
        or getattr(user, "username", None)
        or "unknown"
    )


def is_enabled_for(app: App | None) -> bool:
    if app is None:
        return False
    if normalize_credential_mode(getattr(app, "credential_mode", None)) != "identite_utilisateur":
        return False
    return bool(getattr(app, "identity_password_session_cache", False))


def ttl_seconds(settings: Settings) -> int:
    ttl = int(getattr(settings, "identity_password_cache_ttl", 0) or 0)
    session_cap = int(getattr(settings, "oidc_session_max_age", 0) or 0)
    if session_cap > 0:
        ttl = min(ttl, session_cap)
    return max(_MIN_TTL_SECONDS, ttl)


def _derive_key(settings: Settings, cookie: CacheCookie) -> bytes:
    server = portal_signing_secret(settings, purpose=_SIGNING_PURPOSE).encode()
    return hmac.new(server, cookie.secret, hashlib.sha256).digest()


def _aad(*, handle: str, app_id: int, user_key: str, login_username: str) -> bytes:
    return "|".join((_AAD_VERSION, handle, str(app_id), user_key, login_username)).encode()


def _encrypt(key: bytes, password: str, aad: bytes) -> str:
    nonce = os.urandom(_NONCE_BYTES)
    return _b64e(nonce + AESGCM(key).encrypt(nonce, password.encode("utf-8"), aad))


def _decrypt(key: bytes, blob: str, aad: bytes) -> str | None:
    try:
        raw = _b64d(blob)
    except (binascii.Error, ValueError):
        return None
    if len(raw) <= _NONCE_BYTES:
        return None
    try:
        plain = AESGCM(key).decrypt(raw[:_NONCE_BYTES], raw[_NONCE_BYTES:], aad)
    except InvalidTag:
        return None
    return plain.decode("utf-8", errors="strict")


def _row(db: Session, cookie: CacheCookie, app_id: int) -> IdentityPasswordCache | None:
    return (
        db.query(IdentityPasswordCache)
        .filter_by(handle=cookie.handle, application_id=app_id)
        .first()
    )


def purge_expired(db: Session, *, now: datetime | None = None) -> int:
    """Delete expired rows (any user). Caller commits."""
    moment = now or utcnow()
    count = (
        db.query(IdentityPasswordCache)
        .filter(IdentityPasswordCache.expires_at <= moment)
        .delete(synchronize_session=False)
    )
    return int(count or 0)


def remember_password(
    db: Session,
    settings: Settings,
    *,
    cookie: CacheCookie | None,
    app: App,
    user_key: str,
    user_email: str | None,
    login_username: str,
    password: str,
    now: datetime | None = None,
) -> CacheCookie:
    """Encrypt and store ``password`` for this browser + app. Returns the cookie to set."""
    moment = now or utcnow()
    cookie = cookie or new_cookie()
    purge_expired(db, now=moment)
    blob = _encrypt(
        _derive_key(settings, cookie),
        password,
        _aad(
            handle=cookie.handle,
            app_id=app.id,
            user_key=user_key,
            login_username=login_username,
        ),
    )
    row = _row(db, cookie, app.id)
    if row is None:
        row = IdentityPasswordCache(handle=cookie.handle, application_id=app.id)
        db.add(row)
    row.user_key = user_key
    row.user_email = (user_email or "").strip().lower() or None
    row.login_username = login_username
    row.ciphertext = blob
    row.created_at = moment
    row.expires_at = moment + timedelta(seconds=ttl_seconds(settings))
    row.last_used_at = None
    db.commit()
    return cookie


def recall_password(
    db: Session,
    settings: Settings,
    *,
    cookie: CacheCookie | None,
    app: App,
    user_key: str,
    login_username: str,
    now: datetime | None = None,
) -> str | None:
    """Decrypt the cached password, or ``None`` (and drop any unusable row)."""
    if cookie is None:
        return None
    row = _row(db, cookie, app.id)
    if row is None:
        return None
    moment = now or utcnow()
    password: str | None = None
    if (
        row.expires_at > moment
        and hmac.compare_digest(row.user_key or "", user_key or "")
        and hmac.compare_digest(row.login_username or "", login_username or "")
    ):
        password = _decrypt(
            _derive_key(settings, cookie),
            row.ciphertext,
            _aad(
                handle=cookie.handle,
                app_id=app.id,
                user_key=user_key,
                login_username=login_username,
            ),
        )
    if password is None:
        db.delete(row)
    else:
        row.last_used_at = moment
    db.commit()
    return password


def cached_app_ids(
    db: Session,
    *,
    cookie: CacheCookie | None,
    user_key: str,
    app_ids: Iterable[int],
    now: datetime | None = None,
) -> set[int]:
    """Apps for which this browser has a live cache row (no decryption)."""
    ids = [int(i) for i in app_ids]
    if cookie is None or not ids or not user_key:
        return set()
    rows = (
        db.query(IdentityPasswordCache.application_id)
        .filter(
            IdentityPasswordCache.handle == cookie.handle,
            IdentityPasswordCache.user_key == user_key,
            IdentityPasswordCache.application_id.in_(ids),
            IdentityPasswordCache.expires_at > (now or utcnow()),
        )
        .all()
    )
    return {int(r[0]) for r in rows}


def forget(db: Session, *, cookie: CacheCookie | None, app_id: int | None = None) -> int:
    """Delete this browser's rows (one app, or all of them). Commits."""
    if cookie is None:
        return 0
    query = db.query(IdentityPasswordCache).filter(
        IdentityPasswordCache.handle == cookie.handle
    )
    if app_id is not None:
        query = query.filter(IdentityPasswordCache.application_id == app_id)
    try:
        count = int(query.delete(synchronize_session=False) or 0)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("identity password cache: forget failed")
        return 0
    return count


def forget_request_cache(db: Session, request: Request, response: Response) -> int:
    """Portal logout: drop this browser's rows and expire the cookie."""
    clear_cache_cookie(response)
    return forget(db, cookie=cookie_from_request(request))


def forget_app(db: Session, app_id: int) -> int:
    """Drop every row of one application (cache switched off). Caller commits."""
    count = (
        db.query(IdentityPasswordCache)
        .filter(IdentityPasswordCache.application_id == app_id)
        .delete(synchronize_session=False)
    )
    return int(count or 0)


def forget_if_disabled(db: Session, app: App) -> int:
    """After an app edit: no cache rows may outlive the opt-in. Caller commits."""
    if app is None or app.id is None or is_enabled_for(app):
        return 0
    return forget_app(db, app.id)


def forget_for_identity(
    db: Session,
    *,
    keycloak_subs: Iterable[str] | None = None,
    emails: Iterable[str] | None = None,
) -> int:
    """Admin disconnect: drop every row of an identity, all browsers. Caller commits."""
    subs = {s.strip() for s in (keycloak_subs or ()) if s and s.strip()}
    mails = {e.strip().lower() for e in (emails or ()) if e and e.strip()}
    matches = []
    if subs:
        matches.append(IdentityPasswordCache.user_key.in_(subs))
    if mails:
        matches.append(func.lower(IdentityPasswordCache.user_key).in_(mails))
        matches.append(IdentityPasswordCache.user_email.in_(mails))
    if not matches:
        return 0
    count = (
        db.query(IdentityPasswordCache)
        .filter(or_(*matches))
        .delete(synchronize_session=False)
    )
    return int(count or 0)
