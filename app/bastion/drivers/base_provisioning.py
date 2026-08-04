"""Account provisioning driver interface — separate from the robotic SSO ABC.

Deliberately NOT merged into ``RoboticDriver`` (audit §2.2): provisioning and
robotic login are independent capabilities — an app may have one, both, or
neither. Keeping the Protocol separate avoids forcing placeholder methods on
drivers and cannot break the existing impersonation flow.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from app.models import App, BastionAccount
    from app.sso_settings import Settings

PROVISIONING_SUCCESS = "success"
PROVISIONING_FAILED = "failed"
PROVISIONING_NOT_APPLICABLE = "not_applicable"


class AccountProvisioningError(Exception):
    """Driver-level provisioning failure — message must never include secrets."""


@dataclass(frozen=True)
class GeneratedCredential:
    """Application-local credential generated for the provisioned account.

    ``password`` is plaintext and short-lived: pushed to the target app by the
    driver, then stored encrypted via user_app_credential_service — never logged,
    never persisted in provisioning ``detail``.
    """

    username: str
    password: str


@dataclass(frozen=True)
class ProvisioningResult:
    """Structured outcome of one (account, application) provisioning attempt."""

    status: str  # success | failed | not_applicable
    detail: str  # human-readable message — NEVER a plaintext secret
    # True when the driver pushed ``GeneratedCredential`` to the app — the caller
    # then stores it in the internal vault (user_app_credential_service).
    credential_pushed: bool = False
    # CrushFTP (and similar): group membership failures after a successful user
    # create — kept separate so status can stay "success" while detail/audit
    # still surface which group call failed (spec Étape 1.1).
    group_errors: tuple[str, ...] = ()


@runtime_checkable
class AccountProvisioningDriver(Protocol):
    """Per-application account provisioning (V1: create only, cf. spec §5.3)."""

    driver_name: str

    async def create_account(
        self,
        *,
        db: "Session",
        settings: "Settings",
        app: "App",
        account: "BastionAccount",
        credential: GeneratedCredential,
        group_names: list[str] | None = None,
    ) -> ProvisioningResult:
        """Create the application-local account. Must not raise for expected
        failures — return status="failed" with an explicit, secret-free detail.

        ``group_names`` (optional): app-local group names to join after create
        (CrushFTP: same name as RBACGroup.name). Ignored by no-op drivers.
        """
        ...

    async def disable_account(
        self,
        *,
        db: "Session",
        settings: "Settings",
        app: "App",
        account: "BastionAccount",
    ) -> ProvisioningResult:
        """Disable the application-local account (hors périmètre V1 — action
        manuelle uniquement, cf. spec §5.3/§9.3)."""
        ...

    async def delete_account(
        self,
        *,
        db: "Session",
        settings: "Settings",
        app: "App",
        account: "BastionAccount",
    ) -> ProvisioningResult:
        """Delete the application-local account (full user cleanup). Must be
        idempotent — an already-absent account is a success, and expected
        failures return status="failed" with a secret-free detail."""
        ...
