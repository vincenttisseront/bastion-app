"""Credential / robotic driver connection test → ConnectionTestResult."""

from __future__ import annotations

import time

from sqlalchemy.orm import Session

from app.bastion.drivers.base import RoboticLoginError
from app.bastion.drivers.crushftp import CrushFTPDriver
from app.bastion.drivers.generic import (
    generic_basic_auth_header,
    generic_basic_auth_probe,
    generic_form_login,
)
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
    get_app_credential,
    get_decrypted_password,
)


async def test_app_credential_connection(
    db: Session,
    app: App,
    settings: Settings,
) -> ConnectionTestResult:
    """Run login + fingerprint steps; never put secrets in CheckStep.detail."""
    checks: list[CheckStep] = []
    start = time.monotonic()
    slug = app.slug
    driver = (app.robotic_driver or "").strip().lower()

    try:
        password = get_decrypted_password(db, slug, settings)
        cred = get_app_credential(db, slug)
        if cred is None:
            raise CredentialNotFoundError(f"No active credential for app '{slug}'")
    except EncryptionNotConfiguredError as exc:
        checks.append(
            CheckStep(
                name="vault",
                status=CheckStatus.ERROR,
                message=str(exc),
            )
        )
        return ConnectionTestResult(
            resource_type="app_credential",
            resource_id=slug,
            overall_status=CheckStatus.ERROR,
            checks=checks,
            latency_ms=int((time.monotonic() - start) * 1000),
        )
    except CredentialNotFoundError:
        checks.append(
            CheckStep(
                name="vault",
                status=CheckStatus.ERROR,
                message="No active credential configured",
            )
        )
        return ConnectionTestResult(
            resource_type="app_credential",
            resource_id=slug,
            overall_status=CheckStatus.ERROR,
            checks=checks,
            latency_ms=int((time.monotonic() - start) * 1000),
        )
    except CredentialDecryptError:
        checks.append(
            CheckStep(
                name="vault",
                status=CheckStatus.ERROR,
                message="Credential decryption failed",
            )
        )
        return ConnectionTestResult(
            resource_type="app_credential",
            resource_id=slug,
            overall_status=CheckStatus.ERROR,
            checks=checks,
            latency_ms=int((time.monotonic() - start) * 1000),
        )

    checks.append(
        CheckStep(name="vault", status=CheckStatus.OK, message="Credential decrypted")
    )
    password_cleared = False

    if driver == "generic_form":
        try:
            result = await generic_form_login(cred, app, password)
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
            auth_header = generic_basic_auth_header(cred, password)
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
            checks.append(
                CheckStep(
                    name="basic_auth",
                    status=CheckStatus.ERROR,
                    message="Basic Auth probe failed",
                )
            )
    else:
        crush_driver = CrushFTPDriver()
        try:
            session = await crush_driver.login(app.upstream_url, cred.robotic_username, password)
            password = ""
            password_cleared = True
            checks.append(
                CheckStep(name="login", status=CheckStatus.OK, message="Robotic login OK")
            )
            identity = await crush_driver.get_username(session)
            if identity != cred.robotic_username:
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
    # Prefer the first error message
    message = "Connection test failed"
    for step in result.checks:
        if step.status == CheckStatus.ERROR:
            message = step.message
            break
    status = 200
    if message == "No active credential configured":
        status = 404
    elif message == "Credential decryption failed":
        status = 500
    elif "PORTAL_SECRET" in message or "Fernet" in message or "encryption" in message.lower():
        status = 503
    return {"ok": False, "error": message}, status
