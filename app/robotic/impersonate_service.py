"""Robotic SSO impersonation — vault decrypt + CrushFTP login + session cookies."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Literal

from sqlalchemy.orm import Session

from app.access_modes import normalize_access_mode
from app.audit import log_action
from app.bastion.drivers.base import RoboticLoginError
from app.bastion.drivers.crushftp import CrushFTPDriver
from app.models import App
from app.sso_settings import Settings
from app.vault.app_credential_service import (
    CredentialDecryptError,
    CredentialNotFoundError,
    EncryptionNotConfiguredError,
    get_app_credential,
    get_decrypted_password,
)

logger = logging.getLogger(__name__)


class ImpersonationError(Exception):
    """Impersonation failed — messages must never include secrets or full cookies."""


@dataclass(frozen=True)
class RoboticSessionResult:
    cookies: dict[str, str]
    target_url: str
    mode: Literal["subdomain", "legacy"]
    fqdn: str | None
    slug: str
    robotic_username: str


def _cookie_fingerprint(cookies: dict[str, str]) -> dict[str, str]:
    """Truncated/hashed cookie traces for audit — never full values."""
    out: dict[str, str] = {}
    for key, value in cookies.items():
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
        out[key] = f"{value[:2]}…#{digest}" if len(value) >= 2 else f"#{digest}"
    return out


def _resolve_target(app: App, settings: Settings) -> tuple[Literal["subdomain", "legacy"], str, str | None]:
    """Return (mode, target_url, fqdn)."""
    mode = normalize_access_mode(app.access_mode)
    fqdn = (app.public_fqdn or "").strip() or None
    if settings.subdomain_sso_enabled and mode == "subdomain_proxy" and fqdn:
        return "subdomain", f"https://{fqdn}/", fqdn
    return "legacy", f"/proxy/{app.slug}/", None


async def impersonate(
    db: Session,
    app_slug: str,
    settings: Settings,
    *,
    actor: str = "system",
    ip_address: str | None = None,
) -> RoboticSessionResult:
    """
    1. Load App and verify robotic_driver == crushftp
    2. Decrypt vault credential
    3. CrushFTPDriver.login
    4. Fingerprint via get_username (required before returning cookies)
    5. Resolve target URL (subdomain vs legacy)
    6. Audit robotic.impersonate (no secrets / full cookies)
    """
    app = db.query(App).filter_by(slug=app_slug).first()
    if app is None or not app.enabled:
        log_action(
            db,
            actor=actor,
            action="robotic.impersonate",
            target=f"app:{app_slug}",
            details={"app_slug": app_slug, "success": False, "error": "app_not_found"},
            ip_address=ip_address,
        )
        raise ImpersonationError(f"App '{app_slug}' not found")

    if (app.robotic_driver or "").strip().lower() != "crushftp":
        log_action(
            db,
            actor=actor,
            action="robotic.impersonate",
            target=f"app:{app_slug}",
            details={"app_slug": app_slug, "success": False, "error": "unsupported_driver"},
            ip_address=ip_address,
        )
        raise ImpersonationError(f"App '{app_slug}' is not configured for CrushFTP robotic SSO")

    try:
        password = get_decrypted_password(db, app_slug, settings)
        cred = get_app_credential(db, app_slug)
        assert cred is not None
    except EncryptionNotConfiguredError as exc:
        log_action(
            db,
            actor=actor,
            action="robotic.impersonate",
            target=f"app:{app_slug}",
            details={"app_slug": app_slug, "success": False, "error": "encryption_not_configured"},
            ip_address=ip_address,
        )
        raise ImpersonationError(str(exc)) from exc
    except CredentialNotFoundError as exc:
        log_action(
            db,
            actor=actor,
            action="robotic.impersonate",
            target=f"app:{app_slug}",
            details={"app_slug": app_slug, "success": False, "error": "credential_missing"},
            ip_address=ip_address,
        )
        raise ImpersonationError(str(exc)) from exc
    except CredentialDecryptError as exc:
        log_action(
            db,
            actor=actor,
            action="robotic.impersonate",
            target=f"app:{app_slug}",
            details={"app_slug": app_slug, "success": False, "error": "decrypt_failed"},
            ip_address=ip_address,
        )
        raise ImpersonationError(str(exc)) from exc

    driver = CrushFTPDriver()
    try:
        session = await driver.login(app.upstream_url, cred.robotic_username, password)
        identity = await driver.get_username(session)
    except RoboticLoginError as exc:
        log_action(
            db,
            actor=actor,
            action="robotic.impersonate",
            target=f"app:{app_slug}",
            details={"app_slug": app_slug, "success": False, "error": "login_failed"},
            ip_address=ip_address,
        )
        raise ImpersonationError(str(exc)) from exc
    finally:
        # Ensure plaintext password does not linger in locals longer than needed.
        password = ""  # noqa: F841

    if identity != cred.robotic_username:
        log_action(
            db,
            actor=actor,
            action="robotic.impersonate",
            target=f"app:{app_slug}",
            details={"app_slug": app_slug, "success": False, "error": "identity_mismatch"},
            ip_address=ip_address,
        )
        raise ImpersonationError("CrushFTP identity fingerprint mismatch")

    mode, target_url, fqdn = _resolve_target(app, settings)
    log_action(
        db,
        actor=actor,
        action="robotic.impersonate",
        target=f"app:{app_slug}",
        details={
            "app_slug": app_slug,
            "success": True,
            "mode": mode,
            "robotic_username": cred.robotic_username,
            "cookies": _cookie_fingerprint(session.cookies),
        },
        ip_address=ip_address,
    )
    return RoboticSessionResult(
        cookies=session.cookies,
        target_url=target_url,
        mode=mode,
        fqdn=fqdn,
        slug=app.slug,
        robotic_username=cred.robotic_username,
    )
