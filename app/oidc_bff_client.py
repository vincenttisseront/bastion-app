"""Headless OIDC authorization-code + PKCE against Keycloak (server-side only).

The browser never talks to Keycloak: bastion GETs the login form, POSTs credentials,
captures the ``code`` from the 302 ``Location``, then exchanges it for tokens.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

import httpx
import jwt
from bs4 import BeautifulSoup

from app.sso_settings import Settings, get_settings

logger = logging.getLogger(__name__)

_HTTP_TIMEOUT = httpx.Timeout(5.0, connect=5.0)
_AUTH_PATH = "/realms/{realm}/protocol/openid-connect/auth"
_TOKEN_PATH = "/realms/{realm}/protocol/openid-connect/token"

# Keycloak HTML markers for flows we refuse to automate.
_MFA_FORM_IDS = frozenset(
    {
        "kc-otp-login-form",
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
    """Keycloak rejected username/password."""


class UnsupportedAuthFlowError(OidcBffError):
    """MFA / required-action / interactive step — not handled by headless BFF."""


@dataclass(frozen=True, slots=True)
class OidcTokenResult:
    access_token: str
    refresh_token: str | None
    id_token: str
    expires_in: int
    sub: str
    preferred_username: str | None
    claims: dict[str, Any]


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


def _extract_login_form(html: str) -> tuple[str, dict[str, str]]:
    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form", id="kc-form-login")
    if form is None:
        raise OidcBffError("Formulaire de login Keycloak introuvable (kc-form-login)")
    action = (form.get("action") or "").strip()
    if not action:
        raise OidcBffError("Attribut action manquant sur kc-form-login")
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
        # Prefer structured feedback when present
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
    for form_id in _MFA_FORM_IDS:
        if soup.find("form", id=form_id) is not None:
            return f"étape interactive Keycloak détectée ({form_id})"
    # Generic required-action pages
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
    # Token just obtained from trusted internal Keycloak — extract claims only.
    return jwt.decode(
        id_token,
        options={
            "verify_signature": False,
            "verify_aud": False,
            "verify_exp": False,
        },
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
    """Run authorization-code + PKCE headlessly against internal Keycloak.

    Prefer explicit BFF credentials (from ``get_oidc_bff_config``). When ``db`` is
    provided and credentials are omitted, loads per-realm config from SQLite.
    """
    settings = settings or get_settings()
    realm = (realm or "").strip()
    username = (username or "").strip()
    if not realm or not username or password is None or password == "":
        raise InvalidCredentialsError("Identifiants incomplets")

    # Bastion slug (session/audit) vs Keycloak path segment (may differ in casing).
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
        # 1) Fetch login form (follow redirects internally until HTML login page).
        login_html = await _fetch_login_html(client, auth_url, auth_params)
        unsupported = _html_indicates_unsupported_flow(login_html)
        if unsupported:
            raise UnsupportedAuthFlowError(
                f"Flux Keycloak non supporté en headless: {unsupported}"
            )

        action, form_fields = _extract_login_form(login_html)
        action_url = urljoin(str(client.base_url or base) + "/", action)
        if action.startswith("http://") or action.startswith("https://"):
            action_url = action

        form_fields["username"] = username
        form_fields["password"] = password

        # 2) Submit credentials — do not follow redirect (need Location?code=).
        try:
            post_resp = await client.post(
                action_url,
                data=form_fields,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except httpx.HTTPError as exc:
            logger.warning("oidc_bff login POST failed realm=%s err=%s", realm, type(exc).__name__)
            raise OidcBffError("Impossible de joindre Keycloak (login)") from exc

        code = _handle_login_response(post_resp, expected_state=state)

        # 3) Token exchange
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


async def _fetch_login_html(
    client: httpx.AsyncClient,
    auth_url: str,
    auth_params: dict[str, str],
) -> str:
    """GET /auth and follow Keycloak redirects until the login HTML is returned."""
    url: str | httpx.URL = auth_url
    params: dict[str, str] | None = auth_params
    # Bound redirect loops (auth → login page).
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


def _handle_login_response(resp: httpx.Response, *, expected_state: str) -> str:
    if resp.status_code in {301, 302, 303, 307, 308}:
        location = resp.headers.get("location") or ""
        if not location:
            raise OidcBffError("Redirect post-login sans Location")
        if "login-actions/required-action" in location:
            raise UnsupportedAuthFlowError(
                "Flux Keycloak non supporté en headless: required action après login"
            )
        # OTP / webauthn execution redirects stay on Keycloak hosts without code=
        if "login-actions/" in location and not _location_has_auth_code(location):
            raise UnsupportedAuthFlowError(
                "Flux Keycloak non supporté en headless: étape interactive après login"
            )
        code = _location_has_auth_code(location)
        if not code:
            raise OidcBffError(
                "Redirect post-login sans code OIDC dans Location"
            )
        returned_state = _location_state(location)
        if returned_state is not None and returned_state != expected_state:
            raise OidcBffError("State OIDC mismatch après login Keycloak")
        return code

    if resp.status_code == 200:
        html = resp.text
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
            f"Réponse login Keycloak inattendue (HTTP 200, pas de code)"
        )

    raise OidcBffError(f"Login Keycloak HTTP {resp.status_code} inattendu")
