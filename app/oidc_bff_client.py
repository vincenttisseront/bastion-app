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
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse
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
_DISCOVERY_PATH = "/realms/{realm}/.well-known/openid-configuration"
_ALLOWED_JWT_ALGS = frozenset({"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"})

ATTEMPT_TTL_SECONDS = 300
MAX_OTP_FAILURES = 3
_OTP_FORM_ID = "kc-otp-login-form"
_TOTP_SETUP_FORM_ID = "kc-totp-settings-form"

# Interactive flows we still refuse (OTP verify + TOTP enrollment are handled).
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
    """Keycloak rejected the OTP code (login or TOTP enrollment)."""


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
    groups: tuple[str, ...] = ()
    email: str | None = None


@dataclass(frozen=True, slots=True)
class LoginStepResult:
    status: Literal["success", "otp_required", "totp_setup_required"]
    tokens: OidcTokenResult | None = None
    attempt_id: str | None = None
    totp_secret_display: str | None = None
    qr_data_url: str | None = None


@dataclass(frozen=True, slots=True)
class _TotpSetupParsed:
    action: str
    fields: dict[str, str]
    totp_secret: str
    secret_display: str
    qr_data_url: str | None


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


def _extract_totp_setup(html: str) -> _TotpSetupParsed | None:
    """Parse Keycloak CONFIGURE_TOTP page (``kc-totp-settings-form``)."""
    soup = BeautifulSoup(html or "", "html.parser")
    form = soup.find("form", id=_TOTP_SETUP_FORM_ID)
    if form is None:
        # Some themes omit the id — fall back to a form that posts totpSecret.
        for candidate in soup.find_all("form"):
            if candidate.find("input", attrs={"name": "totpSecret"}):
                form = candidate
                break
    if form is None:
        return None

    action = (form.get("action") or "").strip()
    if not action:
        return None
    fields: dict[str, str] = {}
    for inp in form.find_all("input"):
        name = inp.get("name")
        if not name:
            continue
        itype = (inp.get("type") or "text").lower()
        if itype in {"submit", "button", "image"}:
            continue
        fields[name] = inp.get("value") or ""

    totp_secret = (fields.get("totpSecret") or "").strip()
    secret_el = soup.find(id="kc-totp-secret-key")
    secret_display = ""
    if secret_el is not None:
        secret_display = " ".join(secret_el.get_text(" ", strip=True).split())
    if not secret_display and totp_secret:
        # Manual-friendly groups of 4 (Keycloak style).
        compact = totp_secret.replace(" ", "")
        secret_display = " ".join(
            compact[i : i + 4] for i in range(0, len(compact), 4)
        )

    qr_data_url: str | None = None
    img = soup.find(id="kc-totp-secret-qr-code")
    if img is not None:
        src = (img.get("src") or "").strip()
        if src.startswith("data:image/"):
            qr_data_url = src

    if not totp_secret and not secret_display and not qr_data_url:
        return None
    if not totp_secret and secret_display:
        totp_secret = secret_display.replace(" ", "")
        fields["totpSecret"] = totp_secret

    return _TotpSetupParsed(
        action=action,
        fields=fields,
        totp_secret=totp_secret,
        secret_display=secret_display or totp_secret,
        qr_data_url=qr_data_url,
    )


def _classify_post_auth_html(html: str) -> Literal["otp", "totp_setup"] | None:
    if _extract_otp_form(html) is not None:
        return "otp"
    if _extract_totp_setup(html) is not None:
        return "totp_setup"
    return None


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
    # TOTP enrollment is handled by the BFF — do not classify as unsupported.
    if _extract_totp_setup(html) is not None:
        return None
    if "login-actions/required-action" in (html or ""):
        return "required action Keycloak (mise à jour mot de passe / profil / …)"
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


async def _load_oidc_verification_material(
    client: httpx.AsyncClient,
    *,
    base: str,
    keycloak_realm: str,
) -> tuple[str, dict[str, Any]]:
    """Return ``(issuer, jwks)`` from Keycloak discovery + JWKS endpoints."""
    discovery_url = (
        f"{base.rstrip('/')}{_DISCOVERY_PATH.format(realm=keycloak_realm)}"
    )
    try:
        disc_resp = await client.get(discovery_url)
    except httpx.HTTPError as exc:
        raise OidcBffError("Impossible de joindre Keycloak (discovery)") from exc
    if disc_resp.status_code != 200:
        raise OidcBffError(f"Discovery Keycloak HTTP {disc_resp.status_code}")
    try:
        disc = disc_resp.json()
    except ValueError as exc:
        raise OidcBffError("Discovery Keycloak non JSON") from exc
    if not isinstance(disc, dict):
        raise OidcBffError("Discovery Keycloak invalide")
    issuer = str(disc.get("issuer") or "").strip().rstrip("/")
    jwks_uri = str(disc.get("jwks_uri") or "").strip()
    if not issuer or not jwks_uri:
        raise OidcBffError("Discovery Keycloak incomplète (issuer/jwks_uri)")
    try:
        jwks_resp = await client.get(jwks_uri)
    except httpx.HTTPError as exc:
        raise OidcBffError("Impossible de joindre Keycloak (jwks)") from exc
    if jwks_resp.status_code != 200:
        raise OidcBffError(f"JWKS Keycloak HTTP {jwks_resp.status_code}")
    try:
        jwks = jwks_resp.json()
    except ValueError as exc:
        raise OidcBffError("JWKS Keycloak non JSON") from exc
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise OidcBffError("JWKS Keycloak invalide")
    return issuer, jwks


def _jwk_to_key(jwk: dict[str, Any]) -> Any:
    """Build a PyJWT verification key from a JWK dict (RSA or EC)."""
    raw = json.dumps(jwk)
    kty = str(jwk.get("kty") or "").upper()
    if kty == "EC":
        return jwt.algorithms.ECAlgorithm.from_jwk(raw)
    # Default / RSA
    return jwt.algorithms.RSAAlgorithm.from_jwk(raw)


def _verify_oidc_jwt(
    token: str,
    *,
    jwks: dict[str, Any],
    issuer: str,
    audience: str | None = None,
) -> dict[str, Any]:
    """Verify JWT signature + standard claims against Keycloak JWKS."""
    raw = (token or "").strip()
    if not raw or raw.count(".") != 2:
        raise OidcBffError("JWT OIDC illisible")
    try:
        header = jwt.get_unverified_header(raw)
    except jwt.PyJWTError as exc:
        raise OidcBffError("JWT OIDC illisible") from exc
    alg = str(header.get("alg") or "")
    if alg not in _ALLOWED_JWT_ALGS:
        raise OidcBffError(f"Algorithme JWT refusé ({alg or 'missing'})")
    kid = header.get("kid")
    keys = [k for k in (jwks.get("keys") or []) if isinstance(k, dict)]
    jwk: dict[str, Any] | None = None
    if kid:
        jwk = next((k for k in keys if k.get("kid") == kid), None)
    if jwk is None and len(keys) == 1:
        jwk = keys[0]
    if jwk is None:
        raise OidcBffError("Clé de signature JWT introuvable dans JWKS")
    try:
        key = _jwk_to_key(jwk)
    except (ValueError, TypeError, jwt.PyJWTError) as exc:
        raise OidcBffError("JWK Keycloak non supportée") from exc

    decode_kwargs: dict[str, Any] = {
        "algorithms": [alg],
        "issuer": issuer,
        "options": {
            "require": ["exp", "iss", "sub"],
            "verify_aud": audience is not None,
        },
    }
    if audience is not None:
        decode_kwargs["audience"] = audience
    try:
        payload = jwt.decode(raw, key, **decode_kwargs)
    except jwt.PyJWTError as exc:
        raise OidcBffError("JWT Keycloak invalide (signature/claims)") from exc
    if not isinstance(payload, dict):
        raise OidcBffError("JWT Keycloak invalide")
    return payload


def _try_verify_jwt_claims(
    token: str | None,
    *,
    jwks: dict[str, Any],
    issuer: str,
) -> dict[str, Any]:
    """Best-effort verified decode — access tokens may carry the groups claim."""
    raw = (token or "").strip()
    if not raw or raw.count(".") != 2:
        return {}
    try:
        # Access tokens often use a different ``aud`` than the BFF client_id.
        return _verify_oidc_jwt(raw, jwks=jwks, issuer=issuer, audience=None)
    except OidcBffError:
        return {}


def _leaf_group_name(raw: str) -> str:
    """Keycloak may emit path-style groups (/foo/bar); portal RBAC matches leaf names."""
    name = (raw or "").strip()
    if "/" in name:
        name = name.rstrip("/").rsplit("/", 1)[-1]
    return name


def extract_groups_from_oidc_claims(*claim_dicts: dict[str, Any] | None) -> tuple[str, ...]:
    """Collect unique group leaf names from one or more OIDC claim maps.

    Accepts ``groups`` as a JSON array (Keycloak mapper) or a comma-separated string
    (oauth2-proxy style). Paths are reduced to their leaf segment for RBAC parity.
    """
    out: list[str] = []
    seen: set[str] = set()
    for claims in claim_dicts:
        if not claims:
            continue
        raw = claims.get("groups")
        items: list[str] = []
        if isinstance(raw, list):
            items = [str(x).strip() for x in raw if str(x).strip()]
        elif isinstance(raw, str):
            items = [part.strip() for part in raw.split(",") if part.strip()]
        for item in items:
            leaf = _leaf_group_name(item)
            if not leaf:
                continue
            key = leaf.casefold()
            if key in seen:
                continue
            seen.add(key)
            out.append(leaf)
    return tuple(out)


def _email_from_claims(claims: dict[str, Any]) -> str | None:
    email = claims.get("email")
    if email is None:
        return None
    text = str(email).strip()
    return text or None


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
        from app.oidc_bff_config_service import get_headless_oidc_config

        cfg = get_headless_oidc_config(db, realm, settings)
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
    keycloak_base_url: str,
    keycloak_realm: str,
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
        logger.warning(
            "oidc_bff code exchange transport failed realm=%s err=%s",
            realm,
            type(exc).__name__,
        )
        raise OidcBffError("Impossible de joindre Keycloak (token)") from exc

    if token_resp.status_code != 200:
        logger.warning(
            "oidc_bff code exchange rejected realm=%s status=%s",
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

    issuer, jwks = await _load_oidc_verification_material(
        client, base=keycloak_base_url, keycloak_realm=keycloak_realm
    )
    claims = _verify_oidc_jwt(
        str(id_token),
        jwks=jwks,
        issuer=issuer,
        audience=client_id,
    )
    sub = str(claims.get("sub") or "").strip()
    if not sub:
        raise OidcBffError("id_token sans claim sub")

    preferred = claims.get("preferred_username")
    if preferred is not None:
        preferred = str(preferred).strip() or None

    access_claims = _try_verify_jwt_claims(
        str(access_token), jwks=jwks, issuer=issuer
    )
    groups = extract_groups_from_oidc_claims(claims, access_claims)
    email = _email_from_claims(claims) or _email_from_claims(access_claims)

    expires_in = int(payload.get("expires_in") or 0)
    refresh = payload.get("refresh_token")
    if refresh is not None:
        refresh = str(refresh)

    logger.info(
        "oidc_bff headless_login ok realm=%s sub=%s groups=%d",
        realm,
        sub,
        len(groups),
    )
    return OidcTokenResult(
        access_token=str(access_token),
        refresh_token=refresh,
        id_token=str(id_token),
        expires_in=expires_in,
        sub=sub,
        preferred_username=preferred,
        claims=claims,
        groups=groups,
        email=email,
    )


def _origin_of(url: str) -> str:
    parsed = urlparse((url or "").strip())
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def _safe_url_for_log(url: str) -> str:
    """Origin + path only (no query — may contain code / session_code)."""
    raw = (url or "").strip()
    if not raw:
        return "-"
    parsed = urlparse(raw)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"[:240]
    return (parsed.path or raw.split("?", 1)[0])[:240]


def _set_cookie_names(resp: httpx.Response) -> str:
    names: list[str] = []
    get_list = getattr(resp.headers, "get_list", None)
    values = get_list("set-cookie") if callable(get_list) else None
    if not values:
        single = resp.headers.get("set-cookie")
        values = [single] if single else []
    for raw in values:
        name = (raw or "").split("=", 1)[0].strip()
        if name and name not in names:
            names.append(name)
    return ",".join(names) if names else "-"


def _html_diag_flags(html: str) -> str:
    """Compact HTML signals for logs (never includes secrets)."""
    text = html or ""
    flags: list[str] = []
    if "kc-form-login" in text:
        flags.append("kc-form-login")
    if _OTP_FORM_ID in text:
        flags.append("kc-otp")
    if _TOTP_SETUP_FORM_ID in text or "kc-totp-secret" in text:
        flags.append("kc-totp-setup")
    if any(fid in text for fid in _UNSUPPORTED_FORM_IDS):
        flags.append("unsupported-form")
    if _html_indicates_invalid_credentials(text):
        flags.append("invalid_creds")
    unsupported = _html_indicates_unsupported_flow(text)
    if unsupported:
        flags.append(f"flow:{unsupported}")
    hint = _keycloak_http_error_hint(text)
    if hint:
        flags.append(f"hint={hint}")
    try:
        soup = BeautifulSoup(text, "html.parser")
        title = soup.find("title")
        if title:
            title_text = " ".join(title.get_text(" ", strip=True).split())[:80]
            if title_text:
                flags.append(f"title={title_text}")
    except Exception:
        pass
    return "|".join(flags) if flags else "-"


def _log_keycloak_http(phase: str, resp: httpx.Response, **extra: Any) -> None:
    """INFO-level Keycloak hop diagnostics (status / URL / Location / cookies / HTML)."""
    location = resp.headers.get("location") or ""
    extra_s = " ".join(f"{k}={v}" for k, v in extra.items() if v is not None)
    body_flags = "-"
    ctype = (resp.headers.get("content-type") or "").lower()
    if "text/html" in ctype or "application/xhtml" in ctype or (
        resp.status_code == 200 and not location
    ):
        try:
            body_flags = _html_diag_flags(resp.text or "")
        except Exception:
            body_flags = "html_read_error"
    logger.info(
        "oidc_bff kc_http phase=%s status=%s url=%s location=%s set_cookie=%s html=%s%s",
        phase,
        resp.status_code,
        _safe_url_for_log(str(resp.url)),
        _safe_url_for_log(location) if location else "-",
        _set_cookie_names(resp),
        body_flags,
        f" {extra_s}" if extra_s else "",
    )


def _absolute_action_url(action: str, base: str) -> str:
    """Resolve a form/redirect URL onto ``base`` (the host that holds AUTH cookies).

    Keycloak may embed a different hostname in form ``action`` / ``Location``.
    Cookie jars are host-scoped: always POST/GET on the same origin that served
    the login HTML (``session_base``), not necessarily the configured internal
    ``oidc_keycloak_base_url``.
    """
    base = (base or "").strip().rstrip("/")
    action = (action or "").strip()
    if not action:
        return action
    if not (action.startswith("http://") or action.startswith("https://")):
        abs_action = urljoin(base + "/", action.lstrip("/"))
    else:
        abs_action = action
    if not base:
        return abs_action
    parsed = urlparse(abs_action)
    base_parsed = urlparse(base)
    if not base_parsed.netloc or "/realms/" not in (parsed.path or ""):
        return abs_action
    if (
        parsed.scheme == base_parsed.scheme
        and parsed.netloc == base_parsed.netloc
    ):
        return abs_action
    return urlunparse(
        (
            base_parsed.scheme,
            base_parsed.netloc,
            parsed.path,
            "",
            parsed.query,
            "",
        )
    )


def _keycloak_http_error_hint(html: str) -> str | None:
    """Best-effort hint from Keycloak error HTML (never log secrets)."""
    lower = (html or "").lower()
    if "cookie" in lower and (
        "not found" in lower or "introuvable" in lower or "cookie_not_found" in lower
    ):
        return "cookie session Keycloak manquant (URL frontend vs base BFF)"
    if "expired" in lower and ("code" in lower or "session" in lower):
        return "session_code Keycloak expiré"
    if "we are sorry" in lower or "nous sommes désolés" in lower:
        return (
            "page d'erreur Keycloak "
            "(souvent cookie AUTH_SESSION_ID / hostname frontend vs interne)"
        )
    # Login theme redisplays (title "Sign in to …") are not error pages — skip
    # them here; callers classify kc-form-login via InvalidCredentialsError.
    try:
        soup = BeautifulSoup(html or "", "html.parser")
        title = soup.find("title")
        if title:
            title_text = " ".join(title.get_text(" ", strip=True).split())
            folded = title_text.casefold()
            if not title_text:
                return None
            if (
                folded.startswith("sign in")
                or folded in {"connexion", "log in"}
                or "kc-form-login" in lower
            ):
                return None
            return f"page d'erreur Keycloak ({title_text[:80]})"
    except Exception:
        pass
    return None


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
        "oidc_bff headless_login start realm=%s kc_realm=%s username=%s "
        "auth_base=%s redirect_uri=%s",
        realm,
        keycloak_realm,
        username,
        _safe_url_for_log(base),
        _safe_url_for_log(redirect_uri),
    )

    async with httpx.AsyncClient(
        timeout=_HTTP_TIMEOUT,
        follow_redirects=False,
        headers={"User-Agent": "bastion-oidc-bff/1.0"},
    ) as client:
        login_html, session_base = await _fetch_login_html(
            client, auth_url, auth_params, base=base
        )
        logger.info(
            "oidc_bff headless_login form_ready realm=%s session_base=%s html=%s",
            realm,
            session_base,
            _html_diag_flags(login_html),
        )
        unsupported = _html_indicates_unsupported_flow(login_html)
        if unsupported:
            raise UnsupportedAuthFlowError(
                f"Flux Keycloak non supporté en headless: {unsupported}"
            )

        action, form_fields = _extract_login_form(login_html)
        # Post on the origin that set AUTH_SESSION_ID (may be public frontend).
        action_url = _absolute_action_url(action, session_base)
        form_fields["username"] = username
        form_fields["password"] = password

        logger.info(
            "oidc_bff headless_login post_password realm=%s action=%s field_names=%s",
            realm,
            _safe_url_for_log(action_url),
            ",".join(sorted(form_fields.keys())),
        )
        try:
            post_resp = await client.post(
                action_url,
                data=form_fields,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except httpx.HTTPError as exc:
            logger.warning("oidc_bff login POST failed realm=%s err=%s", realm, type(exc).__name__)
            raise OidcBffError("Impossible de joindre Keycloak (login)") from exc

        _log_keycloak_http("login_post", post_resp, realm=realm, username=username)
        try:
            outcome = await _interpret_post_password_response(
                client, post_resp, expected_state=state, base=session_base
            )
        except InvalidCredentialsError:
            logger.warning(
                "oidc_bff headless_login invalid_credentials realm=%s username=%s "
                "status=%s location=%s html=%s",
                realm,
                username,
                post_resp.status_code,
                _safe_url_for_log(post_resp.headers.get("location") or ""),
                _html_diag_flags(post_resp.text or ""),
            )
            raise
        if outcome[0] == "code":
            logger.info(
                "oidc_bff headless_login got_code realm=%s username=%s",
                realm,
                username,
            )
            tokens = await _exchange_code_for_tokens(
                client,
                token_url=token_url,
                code=outcome[1],
                redirect_uri=redirect_uri,
                code_verifier=code_verifier,
                client_id=client_id,
                client_secret=client_secret,
                realm=realm,
                keycloak_base_url=base,
                keycloak_realm=keycloak_realm,
            )
            return LoginStepResult(status="success", tokens=tokens)

        # totp_setup or otp_required
        if outcome[0] == "totp_setup":
            setup = _extract_totp_setup(outcome[1])
            if setup is None:
                raise UnsupportedAuthFlowError(
                    "Flux Keycloak non supporté en headless: configuration TOTP attendue "
                    "mais formulaire absent"
                )
            attempt_id = str(uuid4())
            cookies_json = json.dumps(_serialize_cookies(client), separators=(",", ":"))
            form_json = json.dumps(
                {
                    "kind": "totp_setup",
                    "action": setup.action,
                    "fields": setup.fields,
                    "secret_display": setup.secret_display,
                    "qr_data_url": setup.qr_data_url,
                },
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
                keycloak_base_url=session_base,
                keycloak_realm=keycloak_realm,
                client_id=client_id,
                redirect_uri=redirect_uri,
                otp_failures=0,
                created_at=now,
                expires_at=now + timedelta(seconds=ATTEMPT_TTL_SECONDS),
            )
            db.add(row)
            db.flush()
            logger.info(
                "oidc_bff headless_login totp_setup_required realm=%s username=%s "
                "attempt_id=%s has_qr=%s",
                realm,
                username,
                attempt_id,
                bool(setup.qr_data_url),
            )
            return LoginStepResult(
                status="totp_setup_required",
                attempt_id=attempt_id,
                totp_secret_display=setup.secret_display,
                qr_data_url=setup.qr_data_url,
            )

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
            {"kind": "otp", "action": otp_action, "fields": otp_fields},
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
            # Keep session_base so OTP POSTs hit the same host as AUTH cookies.
            keycloak_base_url=session_base,
            keycloak_realm=keycloak_realm,
            client_id=client_id,
            redirect_uri=redirect_uri,
            otp_failures=0,
            created_at=now,
            expires_at=now + timedelta(seconds=ATTEMPT_TTL_SECONDS),
        )
        db.add(row)
        db.flush()
        logger.info(
            "oidc_bff headless_login otp_required realm=%s username=%s attempt_id=%s",
            realm,
            username,
            attempt_id,
        )
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

    kind = str(form_blob.get("kind") or "otp").strip() or "otp"
    fields = {str(k): str(v) for k, v in otp_fields.items()}
    if kind == "totp_setup":
        fields["totp"] = otp_code
        if not (fields.get("totpSecret") or "").strip():
            db.delete(row)
            db.flush()
            raise InvalidCredentialsError("Identifiants invalides")
        fields["userLabel"] = (fields.get("userLabel") or "").strip() or "Bastion"
    else:
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

        _log_keycloak_http(
            "totp_setup_post" if kind == "totp_setup" else "otp_post",
            post_resp,
            realm=row.realm,
            attempt_id=row.attempt_id,
        )
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
                if post_resp.status_code == 200:
                    _refresh_attempt_form_from_html(
                        row, client, post_resp.text or "", settings=settings, kind=kind
                    )
                db.flush()
            raise InvalidOtpError("OTP invalide") from None
        except UnsupportedAuthFlowError:
            db.delete(row)
            db.flush()
            raise

        if outcome[0] == "totp_setup":
            row.otp_failures = int(row.otp_failures or 0) + 1
            if row.otp_failures >= MAX_OTP_FAILURES:
                db.delete(row)
                db.flush()
            else:
                _refresh_attempt_form_from_html(
                    row, client, outcome[1], settings=settings, kind="totp_setup"
                )
                db.flush()
            raise InvalidOtpError("OTP invalide")

        if outcome[0] == "otp":
            otp_parsed = _extract_otp_form(outcome[1])
            if otp_parsed is None:
                row.otp_failures = int(row.otp_failures or 0) + 1
                if row.otp_failures >= MAX_OTP_FAILURES:
                    db.delete(row)
                db.flush()
                raise InvalidOtpError("OTP invalide")
            new_action, new_fields = otp_parsed
            form_json = json.dumps(
                {"kind": "otp", "action": new_action, "fields": new_fields},
                separators=(",", ":"),
            )
            row.otp_form_encrypted = encrypt_secret(form_json, settings)
            row.keycloak_cookies_encrypted = encrypt_secret(
                json.dumps(_serialize_cookies(client), separators=(",", ":")),
                settings,
            )
            if kind == "totp_setup":
                row.otp_failures = 0
                db.flush()
                return LoginStepResult(
                    status="otp_required", attempt_id=row.attempt_id
                )
            row.otp_failures = int(row.otp_failures or 0) + 1
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
            keycloak_base_url=row.keycloak_base_url,
            keycloak_realm=row.keycloak_realm,
        )

    db.delete(row)
    db.flush()
    return LoginStepResult(status="success", tokens=tokens)


def _refresh_attempt_form_from_html(
    row: OidcLoginAttempt,
    client: httpx.AsyncClient,
    html: str,
    *,
    settings: Settings,
    kind: str,
) -> None:
    if kind == "totp_setup":
        setup = _extract_totp_setup(html)
        if setup is None:
            return
        form_json = json.dumps(
            {
                "kind": "totp_setup",
                "action": setup.action,
                "fields": setup.fields,
                "secret_display": setup.secret_display,
                "qr_data_url": setup.qr_data_url,
            },
            separators=(",", ":"),
        )
    else:
        otp_parsed = _extract_otp_form(html)
        if otp_parsed is None:
            return
        new_action, new_fields = otp_parsed
        form_json = json.dumps(
            {"kind": "otp", "action": new_action, "fields": new_fields},
            separators=(",", ":"),
        )
    row.otp_form_encrypted = encrypt_secret(form_json, settings)
    row.keycloak_cookies_encrypted = encrypt_secret(
        json.dumps(_serialize_cookies(client), separators=(",", ":")),
        settings,
    )


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
        f"({result.status})"
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
        login_html, session_base = await _fetch_login_html(
            client, auth_url, auth_params, base=base
        )
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
        action_url = _absolute_action_url(action, session_base)
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
            client, post_resp, expected_state=state, base=session_base
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
            keycloak_base_url=base,
            keycloak_realm=keycloak_realm,
        )


async def _fetch_login_html(
    client: httpx.AsyncClient,
    auth_url: str,
    auth_params: dict[str, str],
    *,
    base: str,
) -> tuple[str, str]:
    """GET /auth, follow Keycloak redirects, return ``(html, session_base)``.

    ``session_base`` is the origin of the final login HTML (where AUTH cookies
    live). Do **not** force redirects back onto the configured internal base —
    Keycloak hostname-strict often creates the auth session on the public
    frontend URL.
    """
    url: str | httpx.URL = auth_url
    params: dict[str, str] | None = auth_params
    for hop in range(8):
        try:
            resp = await client.get(url, params=params)
        except httpx.HTTPError as exc:
            logger.warning("oidc_bff auth GET failed err=%s", type(exc).__name__)
            raise OidcBffError("Impossible de joindre Keycloak (auth)") from exc
        params = None
        _log_keycloak_http("auth_get", resp, hop=hop)
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
        session_base = _origin_of(str(resp.url)) or base
        if "kc-form-login" in text:
            logger.info(
                "oidc_bff auth_get login_form session_base=%s html=%s",
                session_base,
                _html_diag_flags(text),
            )
            return text, session_base
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
) -> tuple[Literal["code", "otp", "totp_setup"], str]:
    """Return ``('code', auth_code)``, ``('otp', html)`` or ``('totp_setup', html)``.

    ``base`` is the session origin (cookie host), used when following redirects.
    """
    if resp.status_code in {301, 302, 303, 307, 308}:
        location = resp.headers.get("location") or ""
        if not location:
            raise OidcBffError("Redirect post-login sans Location")
        code = _location_has_auth_code(location)
        if code:
            returned_state = _location_state(location)
            if returned_state is not None and returned_state != expected_state:
                raise OidcBffError("State OIDC mismatch après login Keycloak")
            logger.info(
                "oidc_bff post_password outcome=code status=%s location=%s",
                resp.status_code,
                _safe_url_for_log(location),
            )
            return ("code", code)
        # Interactive step / required-action — follow on the auth-cookie host.
        if "login-actions/" in location:
            next_url = _absolute_action_url(urljoin(str(resp.url), location), base)
            logger.info(
                "oidc_bff post_password follow_login_action status=%s next=%s",
                resp.status_code,
                _safe_url_for_log(next_url),
            )
            try:
                follow = await client.get(next_url)
            except httpx.HTTPError as exc:
                raise OidcBffError("Impossible de joindre Keycloak (follow)") from exc
            _log_keycloak_http("login_follow", follow)
            if follow.status_code in {301, 302, 303, 307, 308}:
                return await _interpret_post_password_response(
                    client, follow, expected_state=expected_state, base=base
                )
            if follow.status_code == 200:
                html = follow.text
                kind = _classify_post_auth_html(html)
                if kind == "otp":
                    logger.info("oidc_bff post_password outcome=otp via=follow")
                    return ("otp", html)
                if kind == "totp_setup":
                    logger.info("oidc_bff post_password outcome=totp_setup via=follow")
                    return ("totp_setup", html)
                unsupported = _html_indicates_unsupported_flow(html)
                if unsupported:
                    raise UnsupportedAuthFlowError(
                        f"Flux Keycloak non supporté en headless: {unsupported}"
                    )
            raise UnsupportedAuthFlowError(
                "Flux Keycloak non supporté en headless: étape interactive après login"
            )
        logger.warning(
            "oidc_bff post_password redirect_without_code status=%s location=%s",
            resp.status_code,
            _safe_url_for_log(location),
        )
        raise OidcBffError("Redirect post-login sans code OIDC dans Location")

    if resp.status_code == 200:
        html = resp.text
        kind = _classify_post_auth_html(html)
        if kind == "otp":
            logger.info(
                "oidc_bff post_password outcome=otp status=200 html=%s",
                _html_diag_flags(html),
            )
            return ("otp", html)
        if kind == "totp_setup":
            logger.info(
                "oidc_bff post_password outcome=totp_setup status=200 html=%s",
                _html_diag_flags(html),
            )
            return ("totp_setup", html)
        unsupported = _html_indicates_unsupported_flow(html)
        if unsupported:
            logger.warning(
                "oidc_bff post_password unsupported status=200 flow=%s html=%s",
                unsupported,
                _html_diag_flags(html),
            )
            raise UnsupportedAuthFlowError(
                f"Flux Keycloak non supporté en headless: {unsupported}"
            )
        if "kc-form-login" in html:
            logger.warning(
                "oidc_bff post_password invalid_credentials status=200 html=%s",
                _html_diag_flags(html),
            )
            raise InvalidCredentialsError("Identifiants Keycloak invalides")
        if _html_indicates_invalid_credentials(html):
            logger.warning(
                "oidc_bff post_password invalid_credentials status=200 html=%s",
                _html_diag_flags(html),
            )
            raise InvalidCredentialsError("Identifiants Keycloak invalides")
        logger.warning(
            "oidc_bff post_password unexpected_200 html=%s",
            _html_diag_flags(html),
        )
        raise OidcBffError(
            "Réponse login Keycloak inattendue (HTTP 200, pas de code)"
        )

    if resp.status_code == 400:
        html = resp.text or ""
        kind = _classify_post_auth_html(html)
        if kind == "totp_setup":
            return ("totp_setup", html)
        if kind == "otp":
            return ("otp", html)
        if "kc-form-login" in html:
            logger.warning(
                "oidc_bff post_password invalid_credentials status=400 html=%s",
                _html_diag_flags(html),
            )
            raise InvalidCredentialsError("Identifiants Keycloak invalides")
        if _html_indicates_invalid_credentials(html):
            logger.warning(
                "oidc_bff post_password invalid_credentials status=400 html=%s",
                _html_diag_flags(html),
            )
            raise InvalidCredentialsError("Identifiants Keycloak invalides")

    hint = _keycloak_http_error_hint(resp.text or "")
    logger.warning(
        "oidc_bff login unexpected status=%s location=%s set_cookie=%s html=%s hint=%s",
        resp.status_code,
        _safe_url_for_log(resp.headers.get("location") or ""),
        _set_cookie_names(resp),
        _html_diag_flags(resp.text or ""),
        hint or "-",
    )
    detail = f"Login Keycloak HTTP {resp.status_code} inattendu"
    if hint:
        detail = f"{detail}: {hint}"
    raise OidcBffError(detail)


async def verify_keycloak_password(
    db: Any,
    *,
    realm_slug: str,
    username: str,
    password: str,
    settings: Settings | None = None,
) -> None:
    """Verify credentials via headless KC login without issuing a portal session."""
    settings = settings or get_settings()
    result = await start_headless_login(
        (realm_slug or "").strip(),
        (username or "").strip(),
        password,
        settings=settings,
        db=db,
    )
    if result.status in ("success", "otp_required", "totp_setup_required"):
        return
    raise InvalidCredentialsError("Identifiants Keycloak invalides")
