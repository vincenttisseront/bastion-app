"""Headless OIDC authorization-code + PKCE against Keycloak (server-side only).

Supports a two-step password → OTP flow without browser redirects: intermediate
Keycloak cookie jar is stored Fernet-encrypted in ``OidcLoginAttempt``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from urllib.parse import parse_qs, urljoin, urlparse
from uuid import uuid4

import httpx
import jwt
from bs4 import BeautifulSoup
from sqlalchemy.orm import Session

from app.models import OidcLoginAttempt, utcnow
from app.secret_crypto import decrypt_secret, encrypt_secret
from app.sso_settings import Settings, get_settings

logger = logging.getLogger(__name__)

_HTTP_TIMEOUT = httpx.Timeout(5.0, connect=5.0)
_AUTH_PATH = "/realms/{realm}/protocol/openid-connect/auth"
_TOKEN_PATH = "/realms/{realm}/protocol/openid-connect/token"

ATTEMPT_TTL_SECONDS = 180
MAX_OTP_FAILURES = 3
_OTP_FORM_ID = "kc-otp-login-form"

# Interactive flows we still refuse (OTP is handled separately).
_UNSUPPORTED_FORM_IDS = frozenset(
    {
        "kc-webauthn-login-form",
        "kc-select-credential-form",
        "kc-passwd-update-form",
    }
)


class OidcBffError(Exception):
    """Base error for headless OIDC BFF login."""


class OidcBffConfigError(OidcBffError):
    """Missing or invalid BFF/Keycloak settings."""


class InvalidCredentialsError(OidcBffError):
    """Keycloak rejected username/password (or expired attempt — generic)."""


class InvalidOtpError(OidcBffError):
    """Keycloak rejected the OTP code."""


class UnsupportedAuthFlowError(OidcBffError):
    """Required-action / WebAuthn / interactive step — not handled by headless BFF."""


@dataclass(frozen=True, slots=True)
class OidcTokenResult:
    access_token: str
    refresh_token: str | None
    id_token: str
    expires_in: int
    sub: str
    preferred_username: str | None
    claims: dict[str, Any]


@dataclass(frozen=True, slots=True)
class LoginStepResult:
    status: Literal["success", "otp_required"]
    tokens: OidcTokenResult | None = None
    attempt_id: str | None = None


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _require_bff_config(
    *,
    base: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
) -> tuple[str, str, str, str]:
    base = (base or "").strip().rstrip("/")
    client_id = (client_id or "").strip()
    client_secret = (client_secret or "").strip()
    redirect_uri = (redirect_uri or "").strip()
    missing = [
        name
        for name, val in (
            ("keycloak_base_url", base),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", redirect_uri),
        )
        if not val
    ]
    if missing:
        raise OidcBffConfigError(
            "OIDC BFF config incomplete: " + ", ".join(missing)
        )
    return base, client_id, client_secret, redirect_uri


def _extract_form_by_id(html: str, form_id: str) -> tuple[str, dict[str, str]]:
    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form", id=form_id)
    if form is None:
        raise OidcBffError(f"Formulaire Keycloak introuvable ({form_id})")
    action = (form.get("action") or "").strip()
    if not action:
        raise OidcBffError(f"Attribut action manquant sur {form_id}")
    fields: dict[str, str] = {}
    for inp in form.find_all("input"):
        name = inp.get("name")
        if not name:
            continue
        itype = (inp.get("type") or "text").lower()
        if itype in {"submit", "button", "image"}:
            continue
        fields[name] = inp.get("value") or ""
    return action, fields


def _extract_login_form(html: str) -> tuple[str, dict[str, str]]:
    return _extract_form_by_id(html, "kc-form-login")


def _extract_otp_form(html: str) -> tuple[str, dict[str, str]] | None:
    soup = BeautifulSoup(html, "html.parser")
    if soup.find("form", id=_OTP_FORM_ID) is None:
        return None
    return _extract_form_by_id(html, _OTP_FORM_ID)


def _html_indicates_invalid_credentials(html: str) -> bool:
    lower = html.lower()
    markers = (
        "invalid username or password",
        "invalid user credentials",
        "nom d'utilisateur ou mot de passe invalide",
        "identifiants invalides",
        "kc-feedback-text",
        'class="alert-error"',
        "pf-m-danger",
    )
    if any(m in lower for m in markers):
        soup = BeautifulSoup(html, "html.parser")
        feedback = soup.find(id="input-error") or soup.find(class_="kc-feedback-text")
        if feedback is not None:
            return True
        if "alert-error" in lower or "pf-m-danger" in lower:
            return True
        if "invalid" in lower and "password" in lower:
            return True
    return False


def _html_indicates_unsupported_flow(html: str) -> str | None:
    soup = BeautifulSoup(html, "html.parser")
    for form_id in _UNSUPPORTED_FORM_IDS:
        if soup.find("form", id=form_id) is not None:
            return f"étape interactive Keycloak détectée ({form_id})"
    if "login-actions/required-action" in html:
        return "required action Keycloak (mise à jour mot de passe / profil / …)"
    if soup.find(id="kc-totp-secret-key") is not None:
        return "configuration TOTP requise"
    title = soup.find("title")
    if title and "update password" in title.get_text(" ", strip=True).lower():
        return "required action: update password"
    return None


def _location_has_auth_code(location: str) -> str | None:
    parsed = urlparse(location)
    code = (parse_qs(parsed.query).get("code") or [None])[0]
    return code


def _location_state(location: str) -> str | None:
    parsed = urlparse(location)
    return (parse_qs(parsed.query).get("state") or [None])[0]


def _decode_id_token_claims(id_token: str) -> dict[str, Any]:
    return jwt.decode(
        id_token,
        options={
            "verify_signature": False,
            "verify_aud": False,
            "verify_exp": False,
        },
    )


def _serialize_cookies(client: httpx.AsyncClient) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for cookie in client.cookies.jar:
        out.append(
            {
                "name": cookie.name,
                "value": cookie.value,
                "domain": cookie.domain or "",
                "path": cookie.path or "/",
            }
        )
    return out


def _restore_cookies(client: httpx.AsyncClient, cookies: list[dict[str, str]]) -> None:
    for item in cookies:
        name = item.get("name") or ""
        value = item.get("value") or ""
        if not name:
            continue
        domain = (item.get("domain") or "").strip() or None
        path = (item.get("path") or "/").strip() or "/"
        client.cookies.set(name, value, domain=domain, path=path)


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def purge_expired_oidc_login_attempts(db: Session) -> int:
    """Delete expired intermediate login attempts (lazy purge)."""
    now = utcnow()
    # SQLite may return naive datetimes — compare in Python for safety.
    expired_ids = [
        row.attempt_id
        for row in db.query(OidcLoginAttempt).all()
        if _as_utc(row.expires_at) <= now
    ]
    if not expired_ids:
        return 0
    count = (
        db.query(OidcLoginAttempt)
        .filter(OidcLoginAttempt.attempt_id.in_(expired_ids))
        .delete(synchronize_session=False)
    )
    db.flush()
    return int(count or 0)


def _resolve_bff_creds(
    realm: str,
    *,
    settings: Settings,
    keycloak_base_url: str | None,
    client_id: str | None,
    client_secret: str | None,
    redirect_uri: str | None,
    db: Session | None,
) -> tuple[str, str, str, str, str]:
    """Return (base, client_id, client_secret, redirect_uri, keycloak_realm)."""
    keycloak_realm = realm
    if not all([keycloak_base_url, client_id, client_secret, redirect_uri]):
        if db is None:
            raise OidcBffConfigError(
                f"OIDC natif non configuré pour le realm '{realm}'"
            )
        from app.oidc_bff_config_service import get_oidc_bff_config

        cfg = get_oidc_bff_config(db, realm, settings)
        if cfg is None:
            raise OidcBffConfigError(
                f"OIDC natif non configuré pour le realm '{realm}'"
            )
        keycloak_base_url = cfg.keycloak_base_url
        client_id = cfg.client_id
        client_secret = cfg.client_secret
        redirect_uri = cfg.redirect_uri
        keycloak_realm = cfg.keycloak_realm or realm

    base, client_id, client_secret, redirect_uri = _require_bff_config(
        base=keycloak_base_url or "",
        client_id=client_id or "",
        client_secret=client_secret or "",
        redirect_uri=redirect_uri or "",
    )
    return base, client_id, client_secret, redirect_uri, keycloak_realm


async def _exchange_code_for_tokens(
    client: httpx.AsyncClient,
    *,
    token_url: str,
    code: str,
    redirect_uri: str,
    code_verifier: str,
    client_id: str,
    client_secret: str,
    realm: str,
) -> OidcTokenResult:
    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    try:
        token_resp = await client.post(
            token_url,
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    except httpx.HTTPError as exc:
        logger.warning("oidc_bff token POST failed realm=%s err=%s", realm, type(exc).__name__)
        raise OidcBffError("Impossible de joindre Keycloak (token)") from exc

    if token_resp.status_code != 200:
        logger.warning(
            "oidc_bff token exchange rejected realm=%s status=%s",
            realm,
            token_resp.status_code,
        )
        raise OidcBffError(
            f"Échange code→token refusé par Keycloak (HTTP {token_resp.status_code})"
        )

    try:
        payload = token_resp.json()
    except ValueError as exc:
        raise OidcBffError("Réponse token Keycloak non JSON") from exc

    access_token = payload.get("access_token")
    id_token = payload.get("id_token")
    if not access_token or not id_token:
        raise OidcBffError("Réponse token Keycloak incomplète (access_token/id_token)")

    claims = _decode_id_token_claims(id_token)
    sub = str(claims.get("sub") or "").strip()
    if not sub:
        raise OidcBffError("id_token sans claim sub")

    preferred = claims.get("preferred_username")
    if preferred is not None:
        preferred = str(preferred).strip() or None

    expires_in = int(payload.get("expires_in") or 0)
    refresh = payload.get("refresh_token")
    if refresh is not None:
        refresh = str(refresh)

    logger.info("oidc_bff headless_login ok realm=%s sub=%s", realm, sub)
    return OidcTokenResult(
        access_token=str(access_token),
        refresh_token=refresh,
        id_token=str(id_token),
        expires_in=expires_in,
        sub=sub,
        preferred_username=preferred,
        claims=claims,
    )


def _absolute_action_url(action: str, base: str) -> str:
    if action.startswith("http://") or action.startswith("https://"):
        return action
    return urljoin(base.rstrip("/") + "/", action)


async def start_headless_login(
    realm: str,
    username: str,
    password: str,
    *,
    settings: Settings | None = None,
    keycloak_base_url: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
    redirect_uri: str | None = None,
    db: Session | None = None,
) -> LoginStepResult:
    """Authorize + submit password. Returns tokens or ``otp_required`` + attempt_id."""
    settings = settings or get_settings()
    realm = (realm or "").strip()
    username = (username or "").strip()
    if not realm or not username or password is None or password == "":
        raise InvalidCredentialsError("Identifiants incomplets")
    if db is None:
        raise OidcBffConfigError("db session required for headless login")

    purge_expired_oidc_login_attempts(db)

    base, client_id, client_secret, redirect_uri, keycloak_realm = _resolve_bff_creds(
        realm,
        settings=settings,
        keycloak_base_url=keycloak_base_url,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        db=db,
    )
    code_verifier, code_challenge = _pkce_pair()
    state = secrets.token_urlsafe(24)

    auth_url = f"{base}{_AUTH_PATH.format(realm=keycloak_realm)}"
    token_url = f"{base}{_TOKEN_PATH.format(realm=keycloak_realm)}"
    auth_params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid profile email",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }

    logger.info(
        "oidc_bff headless_login start realm=%s username=%s",
        realm,
        username,
    )

    async with httpx.AsyncClient(
        timeout=_HTTP_TIMEOUT,
        follow_redirects=False,
        headers={"User-Agent": "bastion-oidc-bff/1.0"},
    ) as client:
        login_html = await _fetch_login_html(client, auth_url, auth_params)
        unsupported = _html_indicates_unsupported_flow(login_html)
        if unsupported:
            raise UnsupportedAuthFlowError(
                f"Flux Keycloak non supporté en headless: {unsupported}"
            )

        action, form_fields = _extract_login_form(login_html)
        action_url = _absolute_action_url(action, base)
        form_fields["username"] = username
        form_fields["password"] = password

        try:
            post_resp = await client.post(
                action_url,
                data=form_fields,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except httpx.HTTPError as exc:
            logger.warning("oidc_bff login POST failed realm=%s err=%s", realm, type(exc).__name__)
            raise OidcBffError("Impossible de joindre Keycloak (login)") from exc

        outcome = await _interpret_post_password_response(
            client, post_resp, expected_state=state, base=base
        )
        if outcome[0] == "code":
            tokens = await _exchange_code_for_tokens(
                client,
                token_url=token_url,
                code=outcome[1],
                redirect_uri=redirect_uri,
                code_verifier=code_verifier,
                client_id=client_id,
                client_secret=client_secret,
                realm=realm,
            )
            return LoginStepResult(status="success", tokens=tokens)

        # otp_required — outcome[1] is OTP HTML
        otp_parsed = _extract_otp_form(outcome[1])
        if otp_parsed is None:
            raise UnsupportedAuthFlowError(
                "Flux Keycloak non supporté en headless: OTP attendu mais formulaire absent"
            )
        otp_action, otp_fields = otp_parsed
        attempt_id = str(uuid4())
        cookies_json = json.dumps(_serialize_cookies(client), separators=(",", ":"))
        form_json = json.dumps(
            {"action": otp_action, "fields": otp_fields},
            separators=(",", ":"),
        )
        now = utcnow()
        row = OidcLoginAttempt(
            attempt_id=attempt_id,
            realm=realm,
            username=username,
            keycloak_cookies_encrypted=encrypt_secret(cookies_json, settings),
            otp_form_encrypted=encrypt_secret(form_json, settings),
            code_verifier=code_verifier,
            state=state,
            keycloak_base_url=base,
            keycloak_realm=keycloak_realm,
            client_id=client_id,
            redirect_uri=redirect_uri,
            otp_failures=0,
            created_at=now,
            expires_at=now + timedelta(seconds=ATTEMPT_TTL_SECONDS),
        )
        db.add(row)
        db.flush()
        return LoginStepResult(status="otp_required", attempt_id=attempt_id)


async def submit_headless_otp(
    attempt_id: str,
    otp_code: str,
    *,
    settings: Settings | None = None,
    db: Session | None = None,
) -> LoginStepResult:
    """Complete an OTP step for a stored ``OidcLoginAttempt`` (single-use on success)."""
    settings = settings or get_settings()
    if db is None:
        raise OidcBffConfigError("db session required for OTP submit")
    attempt_id = (attempt_id or "").strip()
    otp_code = (otp_code or "").strip()
    if not attempt_id or not otp_code:
        raise InvalidCredentialsError("Identifiants incomplets")

    purge_expired_oidc_login_attempts(db)

    row = db.query(OidcLoginAttempt).filter_by(attempt_id=attempt_id).first()
    now = utcnow()
    if row is None or _as_utc(row.expires_at) <= now:
        if row is not None:
            db.delete(row)
            db.flush()
        # No enumeration: same generic failure as bad password.
        raise InvalidCredentialsError("Identifiants invalides")

    try:
        cookies = json.loads(decrypt_secret(row.keycloak_cookies_encrypted, settings))
        form_blob = json.loads(decrypt_secret(row.otp_form_encrypted, settings))
    except (ValueError, json.JSONDecodeError, TypeError):
        db.delete(row)
        db.flush()
        raise InvalidCredentialsError("Identifiants invalides") from None

    if not isinstance(cookies, list) or not isinstance(form_blob, dict):
        db.delete(row)
        db.flush()
        raise InvalidCredentialsError("Identifiants invalides")

    otp_action = str(form_blob.get("action") or "")
    otp_fields = form_blob.get("fields")
    if not otp_action or not isinstance(otp_fields, dict):
        db.delete(row)
        db.flush()
        raise InvalidCredentialsError("Identifiants invalides")

    fields = {str(k): str(v) for k, v in otp_fields.items()}
    # Keycloak TOTP field is usually ``otp``.
    fields["otp"] = otp_code
    if "totp" in fields:
        fields["totp"] = otp_code

    # Reload client secret from realm config (never stored on the attempt row).
    from app.oidc_bff_config_service import get_oidc_bff_config

    cfg = get_oidc_bff_config(db, row.realm, settings)
    if cfg is None:
        db.delete(row)
        db.flush()
        raise OidcBffConfigError(
            f"OIDC natif non configuré pour le realm '{row.realm}'"
        )

    token_url = f"{row.keycloak_base_url}{_TOKEN_PATH.format(realm=row.keycloak_realm)}"
    action_url = _absolute_action_url(otp_action, row.keycloak_base_url)

    async with httpx.AsyncClient(
        timeout=_HTTP_TIMEOUT,
        follow_redirects=False,
        headers={"User-Agent": "bastion-oidc-bff/1.0"},
    ) as client:
        _restore_cookies(client, cookies)
        try:
            post_resp = await client.post(
                action_url,
                data=fields,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except httpx.HTTPError as exc:
            logger.warning(
                "oidc_bff otp POST failed realm=%s err=%s",
                row.realm,
                type(exc).__name__,
            )
            raise OidcBffError("Impossible de joindre Keycloak (otp)") from exc

        try:
            outcome = await _interpret_post_password_response(
                client, post_resp, expected_state=row.state, base=row.keycloak_base_url
            )
        except InvalidCredentialsError:
            row.otp_failures = int(row.otp_failures or 0) + 1
            if row.otp_failures >= MAX_OTP_FAILURES:
                db.delete(row)
                db.flush()
            else:
                # Refresh OTP form if Keycloak redisplayed it.
                if post_resp.status_code == 200 and _extract_otp_form(post_resp.text):
                    otp_parsed = _extract_otp_form(post_resp.text)
                    assert otp_parsed is not None
                    new_action, new_fields = otp_parsed
                    form_json = json.dumps(
                        {"action": new_action, "fields": new_fields},
                        separators=(",", ":"),
                    )
                    row.otp_form_encrypted = encrypt_secret(form_json, settings)
                    row.keycloak_cookies_encrypted = encrypt_secret(
                        json.dumps(_serialize_cookies(client), separators=(",", ":")),
                        settings,
                    )
                db.flush()
            raise InvalidOtpError("OTP invalide") from None
        except UnsupportedAuthFlowError:
            db.delete(row)
            db.flush()
            raise

        if outcome[0] != "code":
            # Still on OTP form after submit → bad OTP
            row.otp_failures = int(row.otp_failures or 0) + 1
            if outcome[0] == "otp":
                otp_parsed = _extract_otp_form(outcome[1])
                if otp_parsed is not None:
                    new_action, new_fields = otp_parsed
                    form_json = json.dumps(
                        {"action": new_action, "fields": new_fields},
                        separators=(",", ":"),
                    )
                    row.otp_form_encrypted = encrypt_secret(form_json, settings)
                    row.keycloak_cookies_encrypted = encrypt_secret(
                        json.dumps(_serialize_cookies(client), separators=(",", ":")),
                        settings,
                    )
            if row.otp_failures >= MAX_OTP_FAILURES:
                db.delete(row)
                db.flush()
            else:
                db.flush()
            raise InvalidOtpError("OTP invalide")

        tokens = await _exchange_code_for_tokens(
            client,
            token_url=token_url,
            code=outcome[1],
            redirect_uri=row.redirect_uri,
            code_verifier=row.code_verifier,
            client_id=cfg.client_id,
            client_secret=cfg.client_secret,
            realm=row.realm,
        )

    db.delete(row)
    db.flush()
    return LoginStepResult(status="success", tokens=tokens)


async def perform_headless_login(
    realm: str,
    username: str,
    password: str,
    *,
    settings: Settings | None = None,
    keycloak_base_url: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
    redirect_uri: str | None = None,
    db: Any | None = None,
) -> OidcTokenResult:
    """Backward-compatible single-shot login (no OTP). Prefer ``start_headless_login``."""
    # Unit tests pass explicit creds without db — support that path.
    settings = settings or get_settings()
    if db is None and all([keycloak_base_url, client_id, client_secret, redirect_uri]):
        return await _perform_headless_login_no_db(
            realm,
            username,
            password,
            settings=settings,
            keycloak_base_url=keycloak_base_url or "",
            client_id=client_id or "",
            client_secret=client_secret or "",
            redirect_uri=redirect_uri or "",
        )
    result = await start_headless_login(
        realm,
        username,
        password,
        settings=settings,
        keycloak_base_url=keycloak_base_url,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        db=db,
    )
    if result.status == "success" and result.tokens is not None:
        return result.tokens
    raise UnsupportedAuthFlowError(
        "Flux Keycloak non supporté en headless: étape interactive Keycloak détectée "
        f"({_OTP_FORM_ID})"
    )


async def _perform_headless_login_no_db(
    realm: str,
    username: str,
    password: str,
    *,
    settings: Settings,
    keycloak_base_url: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
) -> OidcTokenResult:
    """Unit-test helper: password-only flow without persisting OTP attempts."""
    realm = (realm or "").strip()
    username = (username or "").strip()
    if not realm or not username or password is None or password == "":
        raise InvalidCredentialsError("Identifiants incomplets")
    base, client_id, client_secret, redirect_uri = _require_bff_config(
        base=keycloak_base_url,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
    )
    keycloak_realm = realm
    code_verifier, code_challenge = _pkce_pair()
    state = secrets.token_urlsafe(24)
    auth_url = f"{base}{_AUTH_PATH.format(realm=keycloak_realm)}"
    token_url = f"{base}{_TOKEN_PATH.format(realm=keycloak_realm)}"
    auth_params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid profile email",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    async with httpx.AsyncClient(
        timeout=_HTTP_TIMEOUT,
        follow_redirects=False,
        headers={"User-Agent": "bastion-oidc-bff/1.0"},
    ) as client:
        login_html = await _fetch_login_html(client, auth_url, auth_params)
        unsupported = _html_indicates_unsupported_flow(login_html)
        if unsupported:
            raise UnsupportedAuthFlowError(
                f"Flux Keycloak non supporté en headless: {unsupported}"
            )
        if _extract_otp_form(login_html) is not None:
            raise UnsupportedAuthFlowError(
                f"Flux Keycloak non supporté en headless: étape interactive Keycloak "
                f"détectée ({_OTP_FORM_ID})"
            )
        action, form_fields = _extract_login_form(login_html)
        action_url = _absolute_action_url(action, base)
        form_fields["username"] = username
        form_fields["password"] = password
        try:
            post_resp = await client.post(
                action_url,
                data=form_fields,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except httpx.HTTPError as exc:
            raise OidcBffError("Impossible de joindre Keycloak (login)") from exc
        outcome = await _interpret_post_password_response(
            client, post_resp, expected_state=state, base=base
        )
        if outcome[0] != "code":
            raise UnsupportedAuthFlowError(
                f"Flux Keycloak non supporté en headless: étape interactive Keycloak "
                f"détectée ({_OTP_FORM_ID})"
            )
        return await _exchange_code_for_tokens(
            client,
            token_url=token_url,
            code=outcome[1],
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
            client_id=client_id,
            client_secret=client_secret,
            realm=realm,
        )


async def _fetch_login_html(
    client: httpx.AsyncClient,
    auth_url: str,
    auth_params: dict[str, str],
) -> str:
    """GET /auth and follow Keycloak redirects until the login HTML is returned."""
    url: str | httpx.URL = auth_url
    params: dict[str, str] | None = auth_params
    for _ in range(8):
        try:
            resp = await client.get(url, params=params)
        except httpx.HTTPError as exc:
            logger.warning("oidc_bff auth GET failed err=%s", type(exc).__name__)
            raise OidcBffError("Impossible de joindre Keycloak (auth)") from exc
        params = None
        if resp.status_code in {301, 302, 303, 307, 308}:
            location = resp.headers.get("location") or ""
            if not location:
                raise OidcBffError("Redirect Keycloak sans Location")
            if _location_has_auth_code(location):
                raise OidcBffError(
                    "Code OIDC reçu avant soumission du formulaire — flux inattendu"
                )
            if "login-actions/required-action" in location:
                raise UnsupportedAuthFlowError(
                    "Flux Keycloak non supporté en headless: required action"
                )
            url = urljoin(str(resp.url), location)
            continue
        if resp.status_code != 200:
            raise OidcBffError(
                f"Keycloak auth HTTP {resp.status_code} inattendu"
            )
        text = resp.text
        if "kc-form-login" in text:
            return text
        unsupported = _html_indicates_unsupported_flow(text)
        if unsupported:
            raise UnsupportedAuthFlowError(
                f"Flux Keycloak non supporté en headless: {unsupported}"
            )
        raise OidcBffError("Page Keycloak sans formulaire de login")
    raise OidcBffError("Trop de redirections Keycloak avant le formulaire de login")


async def _interpret_post_password_response(
    client: httpx.AsyncClient,
    resp: httpx.Response,
    *,
    expected_state: str,
    base: str,
) -> tuple[Literal["code", "otp"], str]:
    """Return ``('code', auth_code)`` or ``('otp', html)``."""
    if resp.status_code in {301, 302, 303, 307, 308}:
        location = resp.headers.get("location") or ""
        if not location:
            raise OidcBffError("Redirect post-login sans Location")
        if "login-actions/required-action" in location:
            raise UnsupportedAuthFlowError(
                "Flux Keycloak non supporté en headless: required action après login"
            )
        code = _location_has_auth_code(location)
        if code:
            returned_state = _location_state(location)
            if returned_state is not None and returned_state != expected_state:
                raise OidcBffError("State OIDC mismatch après login Keycloak")
            return ("code", code)
        # Interactive step redirect — follow GET to inspect HTML (OTP vs other).
        if "login-actions/" in location:
            next_url = urljoin(str(resp.url), location)
            try:
                follow = await client.get(next_url)
            except httpx.HTTPError as exc:
                raise OidcBffError("Impossible de joindre Keycloak (follow)") from exc
            if follow.status_code == 200:
                html = follow.text
                if _extract_otp_form(html) is not None:
                    return ("otp", html)
                unsupported = _html_indicates_unsupported_flow(html)
                if unsupported:
                    raise UnsupportedAuthFlowError(
                        f"Flux Keycloak non supporté en headless: {unsupported}"
                    )
            raise UnsupportedAuthFlowError(
                "Flux Keycloak non supporté en headless: étape interactive après login"
            )
        raise OidcBffError("Redirect post-login sans code OIDC dans Location")

    if resp.status_code == 200:
        html = resp.text
        if _extract_otp_form(html) is not None:
            return ("otp", html)
        unsupported = _html_indicates_unsupported_flow(html)
        if unsupported:
            raise UnsupportedAuthFlowError(
                f"Flux Keycloak non supporté en headless: {unsupported}"
            )
        if "kc-form-login" in html:
            raise InvalidCredentialsError("Identifiants Keycloak invalides")
        if _html_indicates_invalid_credentials(html):
            raise InvalidCredentialsError("Identifiants Keycloak invalides")
        raise OidcBffError(
            "Réponse login Keycloak inattendue (HTTP 200, pas de code)"
        )

    raise OidcBffError(f"Login Keycloak HTTP {resp.status_code} inattendu")
