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
    generic_basic_auth_header,
    generic_form_login,
)
from app.models import App
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


class ImpersonationError(Exception):
    """Impersonation failed — messages must never include secrets or full cookies."""


class ImpersonationCredentialRequiredError(ImpersonationError):
    """App is individual_required and the user has no override configured."""

    error_code = "credential_required"
    user_message = (
        "Aucun credential individuel configuré pour cette application. "
        "Contactez un administrateur."
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


@dataclass(frozen=True)
class BasicAuthHeaderResult:
    auth_header: str
    slug: str
    robotic_username: str
    credential_source: CredentialSource = "shared"


def _cookie_fingerprint(cookies: dict[str, str]) -> dict[str, str]:
    """Truncated/hashed cookie traces for audit — never full values."""
    out: dict[str, str] = {}
    for key, value in cookies.items():
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
        out[key] = f"{value[:2]}…#{digest}" if len(value) >= 2 else f"#{digest}"
    return out


def _resolve_target(
    app: App,
    settings: Settings,
    db: Session,
) -> tuple[Literal["subdomain", "legacy"], str, str | None]:
    """Return (mode, target_url, fqdn)."""
    from app.portal_settings_service import get_subdomain_sso_enabled

    mode = normalize_access_mode(app.access_mode)
    fqdn = (app.public_fqdn or "").strip() or None
    if get_subdomain_sso_enabled(db, settings) and mode == "subdomain_proxy" and fqdn:
        return "subdomain", f"https://{fqdn}/", fqdn
    return "legacy", f"/proxy/{app.slug}/", None


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
) -> RoboticSessionResult:
    driver = CrushFTPDriver()
    try:
        session = await driver.login(app.upstream_url, resolved.robotic_username, password)
        identity = await driver.get_username(session)
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
        )
        raise ImpersonationError(str(exc)) from exc
    finally:
        password = ""  # noqa: F841

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
        )
        raise ImpersonationError("CrushFTP identity fingerprint mismatch")

    mode, target_url, fqdn = _resolve_target(app, settings, db)
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
) -> RoboticSessionResult:
    try:
        result = await generic_form_login(resolved, app, password)
    except RoboticLoginError as exc:
        _audit_impersonate(
            db,
            app_slug=app_slug,
            actor=actor,
            ip_address=ip_address,
            success=False,
            driver="generic_form",
            error="login_failed",
            credential_source=resolved.source,
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
    )
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
    )


async def impersonate(
    db: Session,
    app_slug: str,
    settings: Settings,
    *,
    actor: str = "system",
    ip_address: str | None = None,
    keycloak_user_id: str | None = None,
) -> RoboticSessionResult:
    """
    Vault decrypt + driver login + session cookies for cookie-based robotic SSO.

    Supports crushftp and generic_form drivers only.
    Uses per-user override when keycloak_user_id has an active UserAppCredential.
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
            driver=driver_name or "unknown",
            error="app_not_found",
        )
        raise ImpersonationError(f"App '{app_slug}' not found")

    if driver_name not in ("crushftp", "generic_form"):
        _audit_impersonate(
            db,
            app_slug=app_slug,
            actor=actor,
            ip_address=ip_address,
            success=False,
            driver=driver_name or "unknown",
            error="unsupported_driver",
        )
        if driver_name == "generic_basic_auth":
            raise ImpersonationError(
                f"App '{app_slug}' uses Basic Auth — access via proxy URL (Nginx auth_request)"
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
        )
        raise ImpersonationError(
            f"App '{app_slug}' robotic SSO requires subdomain_proxy or legacy_path_proxy"
        )

    app_obj, resolved, password = _load_app_and_credential(
        db,
        app_slug,
        settings,
        actor=actor,
        ip_address=ip_address,
        driver=driver_name,
        keycloak_user_id=keycloak_user_id,
    )

    if driver_name == "crushftp":
        return await _impersonate_crushftp(
            db,
            app_obj,
            app_slug,
            settings,
            resolved,
            password,
            actor=actor,
            ip_address=ip_address,
        )
    return await _impersonate_generic_form(
        db,
        app_obj,
        app_slug,
        settings,
        resolved,
        password,
        actor=actor,
        ip_address=ip_address,
    )


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
