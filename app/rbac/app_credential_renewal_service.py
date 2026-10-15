"""Gradual auto-renewal of application user passwords (CrushFTP, etc.) via API.

Disabled by default (``PortalSettings.app_credential_renewal_enabled``). When
enabled, a leader worker renews a small batch of stale ``UserAppCredential``
rows per tick: push new password to the app first, then store in the vault.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session, joinedload

from app.audit import log_action
from app.bastion.bastion_fields import normalize_provisioning_driver
from app.bastion.drivers.base_provisioning import (
    PROVISIONING_SUCCESS,
    GeneratedCredential,
)
from app.bastion.drivers.registry import get_provisioning_driver
from app.models import (
    App,
    BastionAccount,
    BastionAccountProvisioning,
    PortalSettings,
    UserAppCredential,
    utcnow,
)
from app.portal_settings_service import ensure_portal_settings
from app.sso_settings import Settings
from app.vault.user_app_credential_service import set_user_credential

logger = logging.getLogger(__name__)

_ACTOR = "system:app-credential-renewal"


@dataclass
class AppCredentialRenewalResult:
    examined: int = 0
    renewed: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "examined": self.examined,
            "renewed": self.renewed,
            "skipped": self.skipped,
            "errors": list(self.errors),
        }


def clamp_renewal_fields(
    *,
    enabled: bool,
    max_age_days: int,
    batch_size: int,
    interval_minutes: int,
) -> dict[str, Any]:
    try:
        age = int(max_age_days)
    except (TypeError, ValueError):
        age = 90
    try:
        batch = int(batch_size)
    except (TypeError, ValueError):
        batch = 5
    try:
        interval = int(interval_minutes)
    except (TypeError, ValueError):
        interval = 60
    if age <= 0:
        age = 90
    if batch <= 0:
        batch = 5
    if interval <= 0:
        interval = 60
    return {
        "app_credential_renewal_enabled": bool(enabled),
        "app_credential_max_age_days": max(1, min(3650, age)),
        "app_credential_batch_size": max(1, min(100, batch)),
        "app_credential_renewal_interval_minutes": max(5, min(24 * 60, interval)),
    }


def renewal_public_status(row: PortalSettings) -> dict[str, Any]:
    last = getattr(row, "app_credential_renewal_last_run_at", None)
    last_s = ""
    if last is not None:
        try:
            last_s = last.strftime("%Y-%m-%d %H:%M UTC")
        except (TypeError, ValueError, AttributeError, OSError):
            last_s = str(last)
    return {
        "enabled": bool(getattr(row, "app_credential_renewal_enabled", False)),
        "max_age_days": int(getattr(row, "app_credential_max_age_days", None) or 90),
        "batch_size": int(getattr(row, "app_credential_batch_size", None) or 5),
        "interval_minutes": int(
            getattr(row, "app_credential_renewal_interval_minutes", None) or 60
        ),
        "last_run": last_s,
    }


def update_app_credential_renewal_settings(
    db: Session,
    settings: Settings,
    *,
    actor: str,
    ip_address: str | None = None,
    enabled: bool,
    max_age_days: int,
    batch_size: int,
    interval_minutes: int,
) -> PortalSettings:
    row = ensure_portal_settings(db, settings)
    fields = clamp_renewal_fields(
        enabled=enabled,
        max_age_days=max_age_days,
        batch_size=batch_size,
        interval_minutes=interval_minutes,
    )
    for key, value in fields.items():
        setattr(row, key, value)
    db.commit()
    db.refresh(row)
    log_action(
        db,
        actor=actor,
        action="portal_settings.app_credential_renewal",
        target="portal_settings",
        details=fields,
        ip_address=ip_address,
    )
    return row


def _credential_anchor(cred: UserAppCredential):
    return cred.rotated_at or cred.created_at or utcnow()


def _list_stale_credentials(
    db: Session,
    *,
    max_age_days: int,
    batch_size: int,
) -> list[UserAppCredential]:
    cutoff = utcnow() - timedelta(days=max_age_days)
    # Prefer apps that have a provisioning driver (CrushFTP / generic).
    apps = (
        db.query(App)
        .filter(App.enabled.is_(True), App.provisioning_driver.isnot(None))
        .all()
    )
    driver_slugs = {
        a.slug
        for a in apps
        if normalize_provisioning_driver(a.provisioning_driver)
    }
    if not driver_slugs:
        return []

    candidates = (
        db.query(UserAppCredential)
        .options(joinedload(UserAppCredential.app))
        .filter(
            UserAppCredential.is_active.is_(True),
            UserAppCredential.app_slug.in_(driver_slugs),
        )
        .all()
    )
    stale = [
        cred
        for cred in candidates
        if _credential_anchor(cred) < cutoff
    ]
    stale.sort(
        key=lambda c: (
            _credential_anchor(c),
            c.id or 0,
        )
    )
    return stale[:batch_size]


def _bastion_account_for_cred(
    db: Session, cred: UserAppCredential
) -> BastionAccount | None:
    rows = (
        db.query(BastionAccount)
        .options(
            joinedload(BastionAccount.realm),
            joinedload(BastionAccount.provisionings).joinedload(
                BastionAccountProvisioning.application
            ),
        )
        .filter(BastionAccount.keycloak_user_id == cred.keycloak_user_id)
        .order_by(BastionAccount.id.asc())
        .all()
    )
    for account in rows:
        if account.disabled_at is not None:
            continue
        for prov in account.provisionings or []:
            if (
                prov.status == "success"
                and prov.application
                and prov.application.slug == cred.app_slug
            ):
                return account
    # Fallback: any non-disabled bastion account with matching KC id.
    for account in rows:
        if account.disabled_at is None:
            return account
    return None


async def renew_one_credential(
    db: Session,
    settings: Settings,
    cred: UserAppCredential,
    *,
    actor: str = _ACTOR,
    ip_address: str | None = None,
) -> tuple[bool, str]:
    """Push a new password to the app API, then store it in the vault.

    Returns ``(ok, detail)``. On API failure the vault is left unchanged.
    """
    app = cred.app or db.query(App).filter_by(slug=cred.app_slug).first()
    if app is None or not app.enabled:
        return False, "application introuvable ou désactivée"
    driver_name = normalize_provisioning_driver(app.provisioning_driver)
    driver = get_provisioning_driver(driver_name) if driver_name else None
    if driver is None:
        return False, "pas de driver de provisioning"
    account = _bastion_account_for_cred(db, cred)
    if account is None:
        return False, "compte Bastion introuvable / désactivé"

    group_names: list[str] = []
    if account.organization:
        group_names.append(account.organization)

    new_password = secrets.token_urlsafe(18)
    credential = GeneratedCredential(
        username=cred.robotic_username or account.username,
        password=new_password,
    )
    try:
        result = await driver.create_account(
            db=db,
            settings=settings,
            app=app,
            account=account,
            credential=credential,
            group_names=group_names or None,
        )
    except Exception:
        logger.exception(
            "app credential renew API failed app=%s user=%s",
            cred.app_slug,
            cred.keycloak_user_id,
        )
        return False, "erreur API provisioning"
    finally:
        # Clear local handle; plaintext still needed briefly for vault store.
        pass

    if result.status != PROVISIONING_SUCCESS or not result.credential_pushed:
        detail = result.detail or result.status
        log_action(
            db,
            actor=actor,
            action="app_credential.renewal_failed",
            target=f"app:{cred.app_slug}/user:{cred.keycloak_user_id}",
            details={
                "app_slug": cred.app_slug,
                "bastion_account_id": account.id,
                "detail": detail,
            },
            ip_address=ip_address,
        )
        return False, detail

    set_user_credential(
        db,
        cred.app_slug,
        cred.keycloak_user_id,
        credential.username,
        new_password,
        settings,
        actor=actor,
        ip_address=ip_address,
    )
    credential = None  # noqa: F841
    new_password = ""  # noqa: F841
    log_action(
        db,
        actor=actor,
        action="app_credential.renewed",
        target=f"app:{cred.app_slug}/user:{cred.keycloak_user_id}",
        details={
            "app_slug": cred.app_slug,
            "bastion_account_id": account.id,
            "robotic_username": cred.robotic_username,
        },
        ip_address=ip_address,
    )
    return True, "ok"


async def run_app_credential_renewal(
    db: Session,
    settings: Settings,
    *,
    actor: str = _ACTOR,
    force: bool = False,
) -> AppCredentialRenewalResult:
    """Renew up to ``batch_size`` stale application credentials.

    No-op when disabled unless ``force=True`` (manual admin run).
    """
    row = ensure_portal_settings(db, settings)
    result = AppCredentialRenewalResult()
    if not force and not row.app_credential_renewal_enabled:
        return result

    max_age = int(row.app_credential_max_age_days or 90)
    batch = int(row.app_credential_batch_size or 5)
    stale = _list_stale_credentials(db, max_age_days=max_age, batch_size=batch)
    result.examined = len(stale)

    for cred in stale:
        try:
            ok, detail = await renew_one_credential(
                db, settings, cred, actor=actor
            )
            if ok:
                result.renewed += 1
            else:
                result.skipped += 1
                result.errors.append(f"{cred.app_slug}/{cred.keycloak_user_id}: {detail}")
        except Exception as exc:
            logger.exception(
                "app credential renew crashed cred_id=%s", cred.id
            )
            result.errors.append(
                f"{cred.app_slug}/{cred.keycloak_user_id}: {type(exc).__name__}"
            )

    row.app_credential_renewal_last_run_at = utcnow()
    db.commit()
    log_action(
        db,
        actor=actor,
        action="app_credential_renewal.run",
        target="user_app_credentials",
        details=result.as_dict(),
    )
    return result


async def app_credential_renewal_job(*, settings: Settings) -> None:
    """APScheduler entrypoint — no-op when feature flag is off."""
    from app.database import SessionLocal

    db = SessionLocal()
    try:
        row = ensure_portal_settings(db, settings)
        if not row.app_credential_renewal_enabled:
            return
        result = await run_app_credential_renewal(db, settings)
        logger.info(
            "app credential renewal done examined=%s renewed=%s skipped=%s errors=%s",
            result.examined,
            result.renewed,
            result.skipped,
            len(result.errors),
        )
    except Exception:
        logger.exception("app credential renewal job failed")
    finally:
        db.close()
