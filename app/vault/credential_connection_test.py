"""Credential / robotic driver connection test → ConnectionTestResult."""

from __future__ import annotations

import logging
import time
from collections.abc import Sequence

from sqlalchemy.orm import Session

from app.bastion.drivers.base import RoboticLoginError
from app.bastion.drivers.crushftp import CrushFTPDriver
from app.bastion.drivers.generic import (
    generic_basic_auth_header,
    generic_basic_auth_probe,
    generic_form_login,
    generic_wsse_probe,
)
from app.bastion.drivers.teleport import TeleportDriver, resolve_teleport_login_base_url
from app.bastion.upstream_tls import resolve_upstream_tls_verify
from app.models import App
from app.sso_settings import Settings
from app.testing_framework.connection_test import (
    CheckStatus,
    CheckStep,
    ConnectionTestResult,
    overall_from_checks,
)
from app.vault.app_credential_service import (
    CredentialDecryptError,
    CredentialNotFoundError,
    EncryptionNotConfiguredError,
    VaultError,
)
from app.vault.user_app_credential_service import (
    GroupCredentialExcludedError,
    resolve_credential,
)

logger = logging.getLogger(__name__)

_MSG_NO_CREDENTIAL = "No active credential configured"
_MSG_DECRYPT_FAILED = "Credential decryption failed"


def _vault_message(exc: VaultError) -> str:
    if isinstance(exc, EncryptionNotConfiguredError):
        return str(exc)
    if isinstance(exc, CredentialDecryptError):
        return _MSG_DECRYPT_FAILED
    if isinstance(exc, GroupCredentialExcludedError):
        return GroupCredentialExcludedError.user_message
    if isinstance(exc, CredentialNotFoundError):
        return _MSG_NO_CREDENTIAL
    return "Vault error"


async def test_app_credential_connection(
    db: Session,
    app: App,
    settings: Settings,
    *,
    keycloak_user_id: str | None = None,
    group_names: Sequence[str] | None = None,
    realm_slug: str | None = None,
) -> ConnectionTestResult:
    """Run login + fingerprint steps; never put secrets in CheckStep.detail.

    Resolves the same credential as impersonation (user override, then group
    shared, then app shared) when ``group_names`` is given.
    """
    checks: list[CheckStep] = []
    start = time.monotonic()
    slug = app.slug
    driver = (app.robotic_driver or "").strip().lower()

    try:
        resolved, password = resolve_credential(
            db,
            slug,
            settings,
            keycloak_user_id=keycloak_user_id,
            group_names=group_names,
            realm_slug=realm_slug,
        )
    except VaultError as exc:
        checks.append(
            CheckStep(name="vault", status=CheckStatus.ERROR, message=_vault_message(exc))
        )
        return ConnectionTestResult(
            resource_type="app_credential",
            resource_id=slug,
            overall_status=CheckStatus.ERROR,
            checks=checks,
            latency_ms=int((time.monotonic() - start) * 1000),
        )

    checks.append(
        CheckStep(
            name="vault",
            status=CheckStatus.OK,
            message=f"Credential decrypted ({resolved.source})",
        )
    )
    password_cleared = False

    if driver == "generic_form":
        try:
            result = await generic_form_login(resolved, app, password)
            password = ""
            password_cleared = True
            if result.cookies:
                checks.append(
                    CheckStep(
                        name="login",
                        status=CheckStatus.OK,
                        message=f"Session cookies received ({len(result.cookies)})",
                    )
                )
            else:
                checks.append(
                    CheckStep(
                        name="login",
                        status=CheckStatus.ERROR,
                        message="No session cookies after login",
                    )
                )
        except RoboticLoginError as exc:
            checks.append(
                CheckStep(name="login", status=CheckStatus.ERROR, message=str(exc))
            )
    elif driver == "generic_basic_auth":
        try:
            auth_header = generic_basic_auth_header(resolved, password)
            password = ""
            password_cleared = True
            ok = await generic_basic_auth_probe(app, auth_header)
            if ok:
                checks.append(
                    CheckStep(
                        name="basic_auth",
                        status=CheckStatus.OK,
                        message="Upstream accepted Basic Auth",
                    )
                )
            else:
                checks.append(
                    CheckStep(
                        name="basic_auth",
                        status=CheckStatus.ERROR,
                        message="Upstream rejected Basic Auth (401/403)",
                    )
                )
        except Exception:
            logger.warning("Basic Auth probe failed for app %s", slug, exc_info=True)
            checks.append(
                CheckStep(
                    name="basic_auth",
                    status=CheckStatus.ERROR,
                    message="Basic Auth probe failed",
                )
            )
    elif driver == "generic_wsse":
        try:
            username = resolved.robotic_username
            ok = await generic_wsse_probe(app, username, password)
            password = ""
            password_cleared = True
            if ok:
                checks.append(
                    CheckStep(
                        name="wsse",
                        status=CheckStatus.OK,
                        message="Upstream accepted X-WSSE",
                    )
                )
            else:
                checks.append(
                    CheckStep(
                        name="wsse",
                        status=CheckStatus.ERROR,
                        message="Upstream rejected X-WSSE (401/403)",
                    )
                )
        except Exception:
            logger.warning("X-WSSE probe failed for app %s", slug, exc_info=True)
            checks.append(
                CheckStep(
                    name="wsse",
                    status=CheckStatus.ERROR,
                    message="X-WSSE probe failed",
                )
            )
    elif driver == "teleport":
        from app.bastion.drivers.generic import public_host_binding_headers

        login_base = resolve_teleport_login_base_url(app, settings)
        teleport_driver = TeleportDriver()
        host_headers = public_host_binding_headers(app, login_base)
        try:
            session = await teleport_driver.login(
                login_base,
                resolved.robotic_username,
                password,
                tls_verify=resolve_upstream_tls_verify(app),
                extra_headers=host_headers or None,
            )
            password = ""
            password_cleared = True
            checks.append(
                CheckStep(
                    name="login",
                    status=CheckStatus.OK,
                    message=f"Teleport web session OK ({login_base.rstrip('/')})",
                )
            )
            identity = await teleport_driver.get_username(session)
            if identity != resolved.robotic_username:
                checks.append(
                    CheckStep(
                        name="get_username",
                        status=CheckStatus.ERROR,
                        message="Identity mismatch after login",
                    )
                )
            else:
                checks.append(
                    CheckStep(
                        name="get_username",
                        status=CheckStatus.OK,
                        message="Identity fingerprint OK",
                    )
                )
            await teleport_driver.logout(session)
        except RoboticLoginError as exc:
            checks.append(
                CheckStep(name="login", status=CheckStatus.ERROR, message=str(exc))
            )
    elif driver == "crushftp" or driver == "":
        crush_login_url = (
            (getattr(app, "crushftp_admin_base_url", None) or "").strip()
            or (app.upstream_url or "").strip()
        )
        crush_driver = CrushFTPDriver()
        try:
            session = await crush_driver.login(
                crush_login_url,
                resolved.robotic_username,
                password,
                tls_verify=resolve_upstream_tls_verify(app),
            )
            password = ""
            password_cleared = True
            checks.append(
                CheckStep(
                    name="login",
                    status=CheckStatus.OK,
                    message=f"Robotic login OK ({crush_login_url.rstrip('/')})",
                )
            )
            identity = await crush_driver.get_username(session)
            if identity != resolved.robotic_username:
                checks.append(
                    CheckStep(
                        name="get_username",
                        status=CheckStatus.ERROR,
                        message="Identity mismatch after login",
                    )
                )
            else:
                checks.append(
                    CheckStep(
                        name="get_username",
                        status=CheckStatus.OK,
                        message="Identity fingerprint OK",
                    )
                )
        except RoboticLoginError as exc:
            checks.append(
                CheckStep(name="login", status=CheckStatus.ERROR, message=str(exc))
            )

    if not password_cleared:
        password = ""

    return ConnectionTestResult(
        resource_type="app_credential",
        resource_id=slug,
        overall_status=overall_from_checks(checks),
        checks=checks,
        latency_ms=int((time.monotonic() - start) * 1000),
    )


def credential_test_legacy_response(result: ConnectionTestResult) -> tuple[dict, int]:
    """Map to legacy ``{ok, error?}`` JSON + HTTP status."""
    if result.overall_status == CheckStatus.OK:
        return {"ok": True}, 200
    message = "Connection test failed"
    for step in result.checks:
        if step.status == CheckStatus.ERROR:
            message = step.message
            break
    status = 200
    if message == _MSG_NO_CREDENTIAL:
        status = 404
    elif message == _MSG_DECRYPT_FAILED:
        status = 500
    elif "PORTAL_SECRET" in message or "Fernet" in message or "encryption" in message.lower():
        status = 503
    return {"ok": False, "error": message}, status
