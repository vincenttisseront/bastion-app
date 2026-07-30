"""Robotic SSO impersonation — vault decrypt + driver login + session cookies."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Literal

from sqlalchemy.orm import Session

from app.access_modes import PROXY_ACCESS_MODES, normalize_access_mode
from app.audit import log_action
from app.bastion.bastion_fields import normalize_credential_mode
from app.bastion.drivers.base import RoboticLoginError
from app.bastion.drivers.crushftp import CrushFTPDriver
from app.bastion.drivers.generic import (
    DriverAuthRejectedError,
    DriverUpstreamError,
    generic_basic_auth_header,
    generic_form_login,
    generic_wsse_header,
)
from app.bastion.upstream_tls import resolve_upstream_tls_verify
from app.models import App
from app.robotic.robotic_session_cookies import normalize_injected_cookie_scope
from app.sso_settings import Settings
from app.vault.app_credential_service import (
    CredentialDecryptError,
    CredentialNotFoundError,
    EncryptionNotConfiguredError,
)
from app.vault.user_app_credential_service import (
    CredentialSource,
    ResolvedCredential,
    resolve_credential,
)

logger = logging.getLogger(__name__)


def _injected_cookie_scope(app: App) -> str:
    return normalize_injected_cookie_scope(getattr(app, "injected_cookie_scope", None))


class ImpersonationError(Exception):
    """Impersonation failed — messages must never include secrets or full cookies."""


class ImpersonationCredentialRequiredError(ImpersonationError):
    """individual_required mode and no per-user vault override."""

    error_code = "credential_required"
    user_message = (
        "Cette application nécessite un credential individuel. "
        "Contactez votre administrateur."
    )


class ImpersonationPasswordRequiredError(ImpersonationError):
    """App is identite_utilisateur — password must be collected via open-with-identity."""

    error_code = "password_required"
    user_message = (
        "Cette application demande votre mot de passe à chaque ouverture. "
        "Utilisez le formulaire du catalogue."
    )


class ImpersonationIdentityAuthError(ImpersonationError):
    """Generic auth failure for identity mode (no user enumeration)."""

    error_code = "identity_auth_failed"
    user_message = "Mot de passe incorrect ou compte verrouillé."


class ImpersonationTechnicalError(ImpersonationError):
    """Upstream misconfiguration or unexpected HTTP (not a credential mistake)."""

    error_code = "upstream_technical_error"
    user_message = (
        "Erreur technique lors de la connexion à l'application. "
        "Contactez votre administrateur."
    )


@dataclass(frozen=True)
class RoboticSessionResult:
    cookies: dict[str, str]
    target_url: str
    mode: Literal["subdomain", "legacy"]
    fqdn: str | None
    slug: str
    robotic_username: str
    driver: str
    credential_source: CredentialSource = "shared"
    use_crushftp_cookies: bool = False
    login_base_url: str | None = None
    injected_cookie_scope: str = "host_only"


@dataclass(frozen=True)
class BasicAuthHeaderResult:
    auth_header: str
    slug: str
    robotic_username: str
    credential_source: CredentialSource = "shared"


@dataclass(frozen=True)
class WsseHeaderResult:
    """Fresh X-WSSE UsernameToken value for Nginx auth_request (never cache)."""

    wsse_header: str
    slug: str
    robotic_username: str
    credential_source: CredentialSource = "shared"
    nonce_b64: str | None = None
    created: str | None = None


def cookie_fingerprint(cookies: dict[str, str]) -> dict[str, str]:
    """Truncated/hashed cookie traces for audit — never full values."""
    out: dict[str, str] = {}
    for key, value in cookies.items():
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
        out[key] = f"{value[:2]}…#{digest}" if len(value) >= 2 else f"#{digest}"
    return out


def _cookie_fingerprint(cookies: dict[str, str]) -> dict[str, str]:
    return cookie_fingerprint(cookies)


def _credential_mode_for_source(source: CredentialSource | None) -> str | None:
    if source == "user_identity":
        return "identite_utilisateur"
    return None


def _resolve_target(
    app: App,
    settings: Settings,
    db: Session,
) -> tuple[Literal["subdomain", "legacy"], str, str | None]:
    """Return (mode, target_url, fqdn)."""
    from app.access_modes import public_app_entry_url
    from app.portal_settings_service import get_subdomain_sso_enabled

    mode = normalize_access_mode(app.access_mode)
    fqdn = (app.public_fqdn or "").strip() or None
    if get_subdomain_sso_enabled(db, settings) and mode == "subdomain_proxy" and fqdn:
        return (
            "subdomain",
            public_app_entry_url(app, root_trailing_slash=True) or f"https://{fqdn}/",
            fqdn,
        )
    return "legacy", f"/proxy/{app.slug}/", None


def _crushftp_login_base_url(app: App, settings: Settings, db: Session) -> str:
    """
    Base URL for CrushFTP robotic login/getUsername.

    In subdomain mode the browser presents cookies on the public FQDN. Sessions
    created against upstream_url (often a bare backend IP / Host) are rejected
    by CrushFTP on the FQDN path (new-ui → login.html). Login must therefore
    use the same public URL the browser will hit.
    """
    from app.portal_settings_service import get_subdomain_sso_enabled

    mode = normalize_access_mode(app.access_mode)
    fqdn = (app.public_fqdn or "").strip() or None
    if get_subdomain_sso_enabled(db, settings) and mode == "subdomain_proxy" and fqdn:
        return f"https://{fqdn}/"
    return (app.upstream_url or "").rstrip("/") + "/"


def _generic_form_login_url(app: App) -> str:
    """
    Absolute login URL for generic_form robotic POST.

    Robotic login runs **server-side** from bastion-app. It cannot pass the
    browser SSO ``auth_request`` on ``public_fqdn``. Always prefer the upstream /
    configured internal host; browser cookie Domain is handled by the session
    cookie hop after a successful login.
    """
    from urllib.parse import urlparse, urlunparse

    raw = (app.login_form_url or "").strip()
    if not raw:
        return raw
    mode = normalize_access_mode(app.access_mode)
    fqdn = (app.public_fqdn or "").strip() or None
    upstream = (app.upstream_url or "").strip()
    if mode != "subdomain_proxy" or not fqdn or not upstream:
        return raw

    parsed = urlparse(raw)
    if not parsed.scheme or not parsed.netloc:
        return raw
    host = (parsed.hostname or "").lower()
    if host != fqdn.lower():
        return raw

    up = urlparse(upstream)
    if not up.scheme or not up.netloc:
        return raw
    # Keep login path/query from login_form_url; swap only the host to upstream.
    rewritten = urlunparse(parsed._replace(scheme=up.scheme, netloc=up.netloc))
    logger.info(
        "generic_form login URL host rewritten to upstream (bypass public SSO) "
        "fqdn=%s from=%s to=%s",
        fqdn,
        parsed.netloc,
        up.netloc,
    )
    return rewritten


def _audit_impersonate(
    db: Session,
    *,
    app_slug: str,
    actor: str,
    ip_address: str | None,
    success: bool,
    driver: str,
    error: str | None = None,
    mode: str | None = None,
    robotic_username: str | None = None,
    cookies: dict[str, str] | None = None,
    credential_source: CredentialSource | None = None,
    credential_mode: str | None = None,
    wsse_nonce: str | None = None,
    wsse_created: str | None = None,
) -> None:
    details: dict = {
        "app_slug": app_slug,
        "success": success,
        "driver": driver,
    }
    if error:
        details["error"] = error
    if mode:
        details["mode"] = mode
    if robotic_username:
        details["robotic_username"] = robotic_username
    if cookies:
        details["cookies"] = _cookie_fingerprint(cookies)
    if credential_source:
        details["credential_source"] = credential_source
    if credential_mode:
        details["credential_mode"] = credential_mode
    # Nonce/Created are public by WSSE design; never log password or PasswordDigest.
    if wsse_nonce:
        details["wsse_nonce"] = wsse_nonce
    if wsse_created:
        details["wsse_created"] = wsse_created
    log_action(
        db,
        actor=actor,
        action="robotic.impersonate.generic" if driver != "crushftp" else "robotic.impersonate",
        target=f"app:{app_slug}",
        details=details,
        ip_address=ip_address,
    )


def _load_app_and_credential(
    db: Session,
    app_slug: str,
    settings: Settings,
    *,
    actor: str,
    ip_address: str | None,
    driver: str,
    keycloak_user_id: str | None,
) -> tuple[App, ResolvedCredential, str]:
    """Return (app, ResolvedCredential, password). Raises ImpersonationError on failure."""
    app = db.query(App).filter_by(slug=app_slug).first()
    if app is None or not app.enabled:
        _audit_impersonate(
            db,
            app_slug=app_slug,
            actor=actor,
            ip_address=ip_address,
            success=False,
            driver=driver,
            error="app_not_found",
        )
        raise ImpersonationError(f"App '{app_slug}' not found")

    try:
        resolved, password = resolve_credential(
            db, app_slug, settings, keycloak_user_id=keycloak_user_id
        )
    except EncryptionNotConfiguredError as exc:
        _audit_impersonate(
            db,
            app_slug=app_slug,
            actor=actor,
            ip_address=ip_address,
            success=False,
            driver=driver,
            error="encryption_not_configured",
        )
        raise ImpersonationError(str(exc)) from exc
    except CredentialNotFoundError as exc:
        if normalize_credential_mode(app.credential_mode) == "individual_required":
            log_action(
                db,
                actor=actor,
                action="robotic.impersonate.blocked_no_credential",
                target=f"app:{app_slug}",
                details={
                    "app_slug": app_slug,
                    "success": False,
                    "error": "credential_required",
                    "driver": driver,
                    "keycloak_user_id": keycloak_user_id,
                },
                ip_address=ip_address,
            )
            raise ImpersonationCredentialRequiredError(
                ImpersonationCredentialRequiredError.user_message
            ) from exc
        _audit_impersonate(
            db,
            app_slug=app_slug,
            actor=actor,
            ip_address=ip_address,
            success=False,
            driver=driver,
            error="credential_missing",
        )
        raise ImpersonationError(str(exc)) from exc
    except CredentialDecryptError as exc:
        _audit_impersonate(
            db,
            app_slug=app_slug,
            actor=actor,
            ip_address=ip_address,
            success=False,
            driver=driver,
            error="decrypt_failed",
        )
        raise ImpersonationError(str(exc)) from exc

    return app, resolved, password


async def _impersonate_crushftp(
    db: Session,
    app: App,
    app_slug: str,
    settings: Settings,
    resolved: ResolvedCredential,
    password: str,
    *,
    actor: str,
    ip_address: str | None,
    client_headers: dict[str, str] | None = None,  # unused — uniform handler signature
) -> RoboticSessionResult:
    # CrushFTP limits concurrent sessions per account. After login succeeds, any
    # failure (getUsername, identity mismatch, _resolve_target, …) must call
    # logout() so orphaned CrushAuth sessions do not pile up until idle timeout
    # ("421 — Max simultaneous user limit reached" in QA is usually leftover
    # sessions, not a bastion bug). The success path must NOT logout — cookies
    # are returned to the user's browser for the live session.
    driver = CrushFTPDriver()
    session = None
    login_base = _crushftp_login_base_url(app, settings, db)
    tls_verify = resolve_upstream_tls_verify(app)
    try:
        session = await driver.login(
            login_base,
            resolved.robotic_username,
            password,
            tls_verify=tls_verify,
        )
    except RoboticLoginError as exc:
        _audit_impersonate(
            db,
            app_slug=app_slug,
            actor=actor,
            ip_address=ip_address,
            success=False,
            driver="crushftp",
            error="login_failed",
            credential_source=resolved.source,
            credential_mode=_credential_mode_for_source(resolved.source),
        )
        raise ImpersonationError(str(exc)) from exc
    finally:
        password = ""  # noqa: F841

    try:
        identity = await driver.get_username(session)
        if identity != resolved.robotic_username:
            _audit_impersonate(
                db,
                app_slug=app_slug,
                actor=actor,
                ip_address=ip_address,
                success=False,
                driver="crushftp",
                error="identity_mismatch",
                credential_source=resolved.source,
                credential_mode=_credential_mode_for_source(resolved.source),
            )
            raise ImpersonationError("CrushFTP identity fingerprint mismatch")
        mode, target_url, fqdn = _resolve_target(app, settings, db)
    except ImpersonationError:
        await driver.logout(session)
        raise
    except RoboticLoginError as exc:
        await driver.logout(session)
        _audit_impersonate(
            db,
            app_slug=app_slug,
            actor=actor,
            ip_address=ip_address,
            success=False,
            driver="crushftp",
            error="login_failed",
            credential_source=resolved.source,
            credential_mode=_credential_mode_for_source(resolved.source),
        )
        raise ImpersonationError(str(exc)) from exc
    except Exception:
        await driver.logout(session)
        raise

    _audit_impersonate(
        db,
        app_slug=app_slug,
        actor=actor,
        ip_address=ip_address,
        success=True,
        driver="crushftp",
        mode=mode,
        robotic_username=resolved.robotic_username,
        cookies=session.cookies,
        credential_source=resolved.source,
        credential_mode=_credential_mode_for_source(resolved.source),
    )
    return RoboticSessionResult(
        cookies=session.cookies,
        target_url=target_url,
        mode=mode,
        fqdn=fqdn,
        slug=app.slug,
        robotic_username=resolved.robotic_username,
        driver="crushftp",
        credential_source=resolved.source,
        use_crushftp_cookies=True,
        login_base_url=login_base,
        injected_cookie_scope=_injected_cookie_scope(app),
    )


async def _impersonate_generic_form(
    db: Session,
    app: App,
    app_slug: str,
    settings: Settings,
    resolved: ResolvedCredential,
    password: str,
    *,
    actor: str,
    ip_address: str | None,
    client_headers: dict[str, str] | None = None,
) -> RoboticSessionResult:
    try:
        result = await generic_form_login(
            resolved,
            app,
            password,
            client_headers=client_headers,
            login_url_override=_generic_form_login_url(app),
        )
    except DriverAuthRejectedError as exc:
        _audit_impersonate(
            db,
            app_slug=app_slug,
            actor=actor,
            ip_address=ip_address,
            success=False,
            driver="generic_form",
            error="login_failed",
            robotic_username=resolved.robotic_username,
            credential_source=resolved.source,
            credential_mode=_credential_mode_for_source(resolved.source),
        )
        raise ImpersonationError(str(exc)) from exc
    except DriverUpstreamError as exc:
        _audit_impersonate(
            db,
            app_slug=app_slug,
            actor=actor,
            ip_address=ip_address,
            success=False,
            driver="generic_form",
            error="upstream_technical",
            robotic_username=resolved.robotic_username,
            credential_source=resolved.source,
            credential_mode=_credential_mode_for_source(resolved.source),
        )
        raise ImpersonationTechnicalError(
            ImpersonationTechnicalError.user_message
        ) from exc
    except RoboticLoginError as exc:
        _audit_impersonate(
            db,
            app_slug=app_slug,
            actor=actor,
            ip_address=ip_address,
            success=False,
            driver="generic_form",
            error="login_failed",
            robotic_username=resolved.robotic_username,
            credential_source=resolved.source,
            credential_mode=_credential_mode_for_source(resolved.source),
        )
        raise ImpersonationError(str(exc)) from exc
    finally:
        password = ""  # noqa: F841

    mode, target_url, fqdn = _resolve_target(app, settings, db)
    _audit_impersonate(
        db,
        app_slug=app_slug,
        actor=actor,
        ip_address=ip_address,
        success=True,
        driver="generic_form",
        mode=mode,
        robotic_username=resolved.robotic_username,
        cookies=result.cookies,
        credential_source=resolved.source,
        credential_mode=_credential_mode_for_source(resolved.source),
    )
    verify_base = target_url
    if mode == "subdomain" and fqdn:
        verify_base = f"https://{fqdn}/"
    elif app.upstream_url or app.login_form_url:
        verify_base = (app.upstream_url or app.login_form_url or "").rstrip("/") + "/"
    else:
        verify_base = None
    return RoboticSessionResult(
        cookies=result.cookies,
        target_url=target_url,
        mode=mode,
        fqdn=fqdn,
        slug=app.slug,
        robotic_username=resolved.robotic_username,
        driver="generic_form",
        credential_source=resolved.source,
        use_crushftp_cookies=False,
        login_base_url=verify_base,
        injected_cookie_scope=_injected_cookie_scope(app),
    )


# Cookie-SSO driver dispatch — registry lookup instead of hardcoded if/elif
# (same pattern as app/bastion/drivers/registry.py for provisioning drivers).
_COOKIE_SSO_HANDLERS = {
    "crushftp": _impersonate_crushftp,
    "generic_form": _impersonate_generic_form,
}


async def impersonate(
    db: Session,
    app_slug: str,
    settings: Settings,
    *,
    actor: str = "system",
    ip_address: str | None = None,
    keycloak_user_id: str | None = None,
    ephemeral_username: str | None = None,
    ephemeral_password: str | None = None,
    client_headers: dict[str, str] | None = None,
) -> RoboticSessionResult:
    """
    Vault decrypt + driver login + session cookies for cookie-based robotic SSO.

    Supports crushftp and generic_form drivers only.
    Uses per-user override when keycloak_user_id has an active UserAppCredential.

    For credential_mode=identite_utilisateur, pass ephemeral_username/password
    from the OIDC session + user-typed password (never from vault, never stored).

    client_headers: optional browser User-Agent / Accept-Language forwarded to the
    upstream login so session fingerprints (e.g. grommunio-web) match the user.
    """
    app = db.query(App).filter_by(slug=app_slug).first()
    driver_name = (app.robotic_driver or "").strip().lower() if app else ""
    cred_mode = normalize_credential_mode(app.credential_mode if app else None)

    if app is None or not app.enabled:
        _audit_impersonate(
            db,
            app_slug=app_slug,
            actor=actor,
            ip_address=ip_address,
            success=False,
            driver=driver_name or "unknown",
            error="app_not_found",
            credential_mode=cred_mode if app else None,
        )
        raise ImpersonationError(f"App '{app_slug}' not found")

    if driver_name not in _COOKIE_SSO_HANDLERS:
        _audit_impersonate(
            db,
            app_slug=app_slug,
            actor=actor,
            ip_address=ip_address,
            success=False,
            driver=driver_name or "unknown",
            error="unsupported_driver",
            credential_mode=cred_mode,
        )
        if driver_name == "generic_basic_auth":
            raise ImpersonationError(
                f"App '{app_slug}' uses Basic Auth — access via proxy URL (Nginx auth_request)"
            )
        if driver_name == "generic_wsse":
            raise ImpersonationError(
                f"App '{app_slug}' uses X-WSSE — access via proxy URL (Nginx auth_request)"
            )
        raise ImpersonationError(f"App '{app_slug}' is not configured for robotic cookie SSO")

    mode = normalize_access_mode(app.access_mode)
    if mode not in PROXY_ACCESS_MODES:
        _audit_impersonate(
            db,
            app_slug=app_slug,
            actor=actor,
            ip_address=ip_address,
            success=False,
            driver=driver_name,
            error="invalid_access_mode",
            credential_mode=cred_mode,
        )
        raise ImpersonationError(
            f"App '{app_slug}' robotic SSO requires subdomain_proxy or legacy_path_proxy"
        )

    if cred_mode == "identite_utilisateur":
        if not ephemeral_username or not ephemeral_password:
            _audit_impersonate(
                db,
                app_slug=app_slug,
                actor=actor,
                ip_address=ip_address,
                success=False,
                driver=driver_name,
                error="password_required",
                credential_mode=cred_mode,
            )
            raise ImpersonationPasswordRequiredError(
                ImpersonationPasswordRequiredError.user_message
            )
        resolved = ResolvedCredential(
            robotic_username=ephemeral_username,
            app_slug=app_slug,
            source="user_identity",
        )
        password = ephemeral_password
        app_obj = app
    else:
        app_obj, resolved, password = _load_app_and_credential(
            db,
            app_slug,
            settings,
            actor=actor,
            ip_address=ip_address,
            driver=driver_name,
            keycloak_user_id=keycloak_user_id,
        )

    handler = _COOKIE_SSO_HANDLERS[driver_name]
    try:
        return await handler(
            db,
            app_obj,
            app_slug,
            settings,
            resolved,
            password,
            actor=actor,
            ip_address=ip_address,
            client_headers=client_headers,
        )
    except ImpersonationTechnicalError:
        raise
    except ImpersonationError:
        if cred_mode == "identite_utilisateur":
            raise ImpersonationIdentityAuthError(
                ImpersonationIdentityAuthError.user_message
            ) from None
        raise
    finally:
        password = ""  # noqa: F841
        ephemeral_password = None  # noqa: F841


async def get_basic_auth_header(
    db: Session,
    app_slug: str,
    settings: Settings,
    *,
    actor: str = "system",
    ip_address: str | None = None,
    keycloak_user_id: str | None = None,
) -> BasicAuthHeaderResult:
    """
    Return Authorization header for Nginx auth_request (generic_basic_auth).

    Secret never appears in audit details or response body.
    """
    app = db.query(App).filter_by(slug=app_slug).first()
    driver_name = (app.robotic_driver or "").strip().lower() if app else ""

    if app is None or not app.enabled:
        _audit_impersonate(
            db,
            app_slug=app_slug,
            actor=actor,
            ip_address=ip_address,
            success=False,
            driver=driver_name or "generic_basic_auth",
            error="app_not_found",
        )
        raise ImpersonationError(f"App '{app_slug}' not found")

    if driver_name != "generic_basic_auth":
        _audit_impersonate(
            db,
            app_slug=app_slug,
            actor=actor,
            ip_address=ip_address,
            success=False,
            driver=driver_name or "unknown",
            error="unsupported_driver",
        )
        raise ImpersonationError(f"App '{app_slug}' is not configured for Basic Auth robotic SSO")

    mode = normalize_access_mode(app.access_mode)
    if mode not in PROXY_ACCESS_MODES:
        _audit_impersonate(
            db,
            app_slug=app_slug,
            actor=actor,
            ip_address=ip_address,
            success=False,
            driver="generic_basic_auth",
            error="invalid_access_mode",
        )
        raise ImpersonationError(
            f"App '{app_slug}' Basic Auth requires subdomain_proxy or legacy_path_proxy"
        )

    app_obj, resolved, password = _load_app_and_credential(
        db,
        app_slug,
        settings,
        actor=actor,
        ip_address=ip_address,
        driver="generic_basic_auth",
        keycloak_user_id=keycloak_user_id,
    )
    try:
        auth_header = generic_basic_auth_header(resolved, password)
    finally:
        password = ""  # noqa: F841

    _audit_impersonate(
        db,
        app_slug=app_slug,
        actor=actor,
        ip_address=ip_address,
        success=True,
        driver="generic_basic_auth",
        robotic_username=resolved.robotic_username,
        credential_source=resolved.source,
    )
    return BasicAuthHeaderResult(
        auth_header=auth_header,
        slug=app_obj.slug,
        robotic_username=resolved.robotic_username,
        credential_source=resolved.source,
    )


async def get_wsse_header(
    db: Session,
    app_slug: str,
    settings: Settings,
    *,
    actor: str = "system",
    ip_address: str | None = None,
    keycloak_user_id: str | None = None,
) -> WsseHeaderResult:
    """
    Return a fresh X-WSSE UsernameToken for Nginx auth_request (generic_wsse).

    Never cache the result — nonce/Created must be unique per call.
    Secret and PasswordDigest never appear in audit details or response body.
    """
    app = db.query(App).filter_by(slug=app_slug).first()
    driver_name = (app.robotic_driver or "").strip().lower() if app else ""

    if app is None or not app.enabled:
        _audit_impersonate(
            db,
            app_slug=app_slug,
            actor=actor,
            ip_address=ip_address,
            success=False,
            driver=driver_name or "generic_wsse",
            error="app_not_found",
        )
        raise ImpersonationError(f"App '{app_slug}' not found")

    if driver_name != "generic_wsse":
        _audit_impersonate(
            db,
            app_slug=app_slug,
            actor=actor,
            ip_address=ip_address,
            success=False,
            driver=driver_name or "unknown",
            error="unsupported_driver",
        )
        raise ImpersonationError(f"App '{app_slug}' is not configured for X-WSSE robotic SSO")

    mode = normalize_access_mode(app.access_mode)
    if mode not in PROXY_ACCESS_MODES:
        _audit_impersonate(
            db,
            app_slug=app_slug,
            actor=actor,
            ip_address=ip_address,
            success=False,
            driver="generic_wsse",
            error="invalid_access_mode",
        )
        raise ImpersonationError(
            f"App '{app_slug}' X-WSSE requires subdomain_proxy or legacy_path_proxy"
        )

    app_obj, resolved, password = _load_app_and_credential(
        db,
        app_slug,
        settings,
        actor=actor,
        ip_address=ip_address,
        driver="generic_wsse",
        keycloak_user_id=keycloak_user_id,
    )
    try:
        wsse_header = generic_wsse_header(resolved.robotic_username, password)
    finally:
        password = ""  # noqa: F841

    # Parse public Nonce/Created from the generated header for audit (no digest).
    nonce_b64: str | None = None
    created: str | None = None
    for part in wsse_header.split(", "):
        if part.startswith('Nonce="') and part.endswith('"'):
            nonce_b64 = part[len('Nonce="') : -1]
        elif part.startswith('Created="') and part.endswith('"'):
            created = part[len('Created="') : -1]

    _audit_impersonate(
        db,
        app_slug=app_slug,
        actor=actor,
        ip_address=ip_address,
        success=True,
        driver="generic_wsse",
        robotic_username=resolved.robotic_username,
        credential_source=resolved.source,
        wsse_nonce=nonce_b64,
        wsse_created=created,
    )
    return WsseHeaderResult(
        wsse_header=wsse_header,
        slug=app_obj.slug,
        robotic_username=resolved.robotic_username,
        credential_source=resolved.source,
        nonce_b64=nonce_b64,
        created=created,
    )
