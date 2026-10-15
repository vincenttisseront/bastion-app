"""BastionAccount lifecycle — inactivity warnings, password renewal, auto-disable.

Configured in PortalSettings (Admin → Configuration → Comptes). Runs daily on
the health-probe leader. Only accounts created/tracked in ``bastion_accounts``
with a Keycloak user id are processed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session, joinedload

from app.audit import log_action
from app.mail.smtp_service import SmtpError, send_email
from app.models import BastionAccount, PortalSettings, RealmConfig, utcnow
from app.portal_settings_service import ensure_portal_settings
from app.sso_settings import Settings

logger = logging.getLogger(__name__)

DISABLED_REASON_INACTIVITY = "inactivity"
DISABLED_REASON_ADMIN = "admin"


@dataclass
class LifecycleRunResult:
    examined: int = 0
    inactivity_warnings: int = 0
    password_warnings: int = 0
    disabled: int = 0
    password_actions: int = 0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "examined": self.examined,
            "inactivity_warnings": self.inactivity_warnings,
            "password_warnings": self.password_warnings,
            "disabled": self.disabled,
            "password_actions": self.password_actions,
            "errors": list(self.errors),
        }


def parse_warn_days(raw: str | None) -> list[int]:
    """Parse ``\"30,14,7\"`` → sorted descending unique positive ints."""
    out: set[int] = set()
    for part in (raw or "").replace(";", ",").split(","):
        token = part.strip()
        if not token:
            continue
        try:
            value = int(token)
        except ValueError:
            continue
        if value > 0:
            out.add(value)
    return sorted(out, reverse=True)


def clamp_lifecycle_fields(
    *,
    enabled: bool,
    inactivity_days: int,
    warn_days_raw: str,
    password_max_age_days: int,
    password_warn_days: int,
) -> dict[str, Any]:
    inactivity = max(30, min(3650, int(inactivity_days or 180)))
    warn = parse_warn_days(warn_days_raw) or [30, 14, 7]
    warn = [d for d in warn if d < inactivity] or [max(1, inactivity // 6)]
    pwd_max = max(0, min(3650, int(password_max_age_days or 0)))
    pwd_warn = max(1, min(365, int(password_warn_days or 14)))
    if pwd_max and pwd_warn >= pwd_max:
        pwd_warn = max(1, pwd_max // 2)
    return {
        "account_lifecycle_enabled": bool(enabled),
        "account_inactivity_days": inactivity,
        "account_inactivity_warn_days": ",".join(str(d) for d in warn),
        "account_password_max_age_days": pwd_max,
        "account_password_warn_days": pwd_warn,
    }


def lifecycle_public_status(row: PortalSettings) -> dict[str, Any]:
    last = getattr(row, "account_lifecycle_last_run_at", None)
    last_s = ""
    if last is not None:
        try:
            last_s = last.strftime("%Y-%m-%d %H:%M UTC")
        except (TypeError, ValueError, AttributeError, OSError):
            last_s = str(last)
    return {
        "enabled": bool(getattr(row, "account_lifecycle_enabled", False)),
        "inactivity_days": int(getattr(row, "account_inactivity_days", None) or 180),
        "warn_days": getattr(row, "account_inactivity_warn_days", None) or "30,14,7",
        "password_max_age_days": int(
            getattr(row, "account_password_max_age_days", None) or 0
        ),
        "password_warn_days": int(
            getattr(row, "account_password_warn_days", None) or 14
        ),
        "last_run": last_s,
    }


def update_account_lifecycle_settings(
    db: Session,
    settings: Settings,
    *,
    actor: str,
    ip_address: str | None = None,
    enabled: bool,
    inactivity_days: int,
    warn_days_raw: str,
    password_max_age_days: int,
    password_warn_days: int,
) -> PortalSettings:
    row = ensure_portal_settings(db, settings)
    fields = clamp_lifecycle_fields(
        enabled=enabled,
        inactivity_days=inactivity_days,
        warn_days_raw=warn_days_raw,
        password_max_age_days=password_max_age_days,
        password_warn_days=password_warn_days,
    )
    for key, value in fields.items():
        setattr(row, key, value)
    db.commit()
    db.refresh(row)
    log_action(
        db,
        actor=actor,
        action="portal_settings.account_lifecycle",
        target="portal_settings",
        details=fields,
        ip_address=ip_address,
    )
    return row


def touch_bastion_login(
    db: Session,
    *,
    keycloak_user_id: str | None,
    email: str | None = None,
    username: str | None = None,
) -> int:
    """Record a successful login on matching BastionAccount rows. Returns updates."""
    kc = (keycloak_user_id or "").strip()
    mail = (email or "").strip().lower()
    uname = (username or "").strip().lower()
    if not kc and not mail and not uname:
        return 0
    q = db.query(BastionAccount)
    if kc:
        rows = q.filter(BastionAccount.keycloak_user_id == kc).all()
    else:
        clauses = []
        if mail:
            clauses.append(BastionAccount.email == mail)
        if uname:
            clauses.append(BastionAccount.username == uname)
        if not clauses:
            return 0
        from sqlalchemy import or_

        rows = q.filter(or_(*clauses)).all()
    if not rows:
        return 0
    now = utcnow()
    n = 0
    for account in rows:
        account.last_login_at = now
        # A successful login clears inactivity tracking; admin may still need
        # to re-enable a Keycloak-disabled account separately.
        if account.disabled_at and account.disabled_reason == DISABLED_REASON_INACTIVITY:
            account.disabled_at = None
            account.disabled_reason = None
            account.last_inactivity_warn_at = None
            account.last_inactivity_warn_stage = None
        n += 1
    db.commit()
    return n


def _reference_activity(account: BastionAccount):
    return account.last_login_at or account.created_at or utcnow()


def _password_anchor(account: BastionAccount):
    return account.password_changed_at or account.created_at or utcnow()


def _portal_login_url(settings: Settings, row: PortalSettings) -> str:
    domain = (row.portal_domain or settings.portal_domain or "portal.example.com").strip()
    domain = domain.removeprefix("https://").removeprefix("http://").rstrip("/")
    return f"https://{domain}/auth/login"


async def run_account_lifecycle(
    db: Session,
    settings: Settings,
    *,
    actor: str = "system:account-lifecycle",
) -> LifecycleRunResult:
    """Scan BastionAccounts and apply warnings / disables according to settings."""
    row = ensure_portal_settings(db, settings)
    result = LifecycleRunResult()
    if not row.account_lifecycle_enabled:
        return result
    if not row.smtp_enabled:
        result.errors.append("SMTP désactivé — cycle de vie ignoré")
        return result

    inactivity_days = int(row.account_inactivity_days or 180)
    warn_offsets = parse_warn_days(row.account_inactivity_warn_days)
    password_max = int(row.account_password_max_age_days or 0)
    password_warn = int(row.account_password_warn_days or 14)
    login_url = _portal_login_url(settings, row)
    now = utcnow()

    accounts = (
        db.query(BastionAccount)
        .options(joinedload(BastionAccount.realm))
        .filter(BastionAccount.keycloak_user_id.isnot(None))
        .order_by(BastionAccount.id.asc())
        .all()
    )

    for account in accounts:
        result.examined += 1
        realm = account.realm
        if realm is None or not realm.enabled:
            continue
        try:
            await _process_account(
                db,
                settings,
                row,
                account,
                realm,
                result=result,
                inactivity_days=inactivity_days,
                warn_offsets=warn_offsets,
                password_max=password_max,
                password_warn=password_warn,
                login_url=login_url,
                now=now,
                actor=actor,
            )
        except Exception as exc:
            logger.exception(
                "account lifecycle failed account_id=%s", account.id
            )
            result.errors.append(f"{account.username}: {type(exc).__name__}")

    row.account_lifecycle_last_run_at = now
    db.commit()
    log_action(
        db,
        actor=actor,
        action="account_lifecycle.run",
        target="bastion_accounts",
        details=result.as_dict(),
    )
    return result


async def _process_account(
    db: Session,
    settings: Settings,
    portal: PortalSettings,
    account: BastionAccount,
    realm: RealmConfig,
    *,
    result: LifecycleRunResult,
    inactivity_days: int,
    warn_offsets: list[int],
    password_max: int,
    password_warn: int,
    login_url: str,
    now,
    actor: str,
) -> None:
    if account.disabled_at:
        return

    activity = _reference_activity(account)
    idle_days = max(0, (now - activity).days)

    if idle_days >= inactivity_days:
        await _disable_for_inactivity(
            db, settings, account, realm, result=result, actor=actor, idle_days=idle_days
        )
        return

    remaining = inactivity_days - idle_days
    await _maybe_warn_inactivity(
        db,
        settings,
        portal,
        account,
        result=result,
        remaining=remaining,
        idle_days=idle_days,
        warn_offsets=warn_offsets,
        inactivity_days=inactivity_days,
        login_url=login_url,
    )

    if password_max > 0:
        await _maybe_password_renewal(
            db,
            settings,
            portal,
            account,
            realm,
            result=result,
            password_max=password_max,
            password_warn=password_warn,
            login_url=login_url,
            now=now,
        )


async def _maybe_warn_inactivity(
    db: Session,
    settings: Settings,
    portal: PortalSettings,
    account: BastionAccount,
    *,
    result: LifecycleRunResult,
    remaining: int,
    idle_days: int,
    warn_offsets: list[int],
    inactivity_days: int,
    login_url: str,
) -> None:
    applicable = [offset for offset in warn_offsets if remaining <= offset]
    if not applicable:
        return
    # Tightest window (smallest offset) we currently sit in.
    stage = min(applicable)
    prev = account.last_inactivity_warn_stage
    if prev is not None and int(prev) <= stage:
        return

    subject = f"Votre compte Bastion sera désactivé dans {remaining} jour(s)"
    body = (
        f"Bonjour {account.first_name or account.username},\n\n"
        f"Votre compte ({account.email}) n'a pas été utilisé depuis {idle_days} jour(s).\n"
        f"Sans connexion d'ici {remaining} jour(s) "
        f"(délai total {inactivity_days} jours), le compte sera désactivé automatiquement.\n\n"
        f"Reconnectez-vous : {login_url}\n\n"
        f"— Bastion Pro\n"
    )
    try:
        send_email(
            portal,
            settings,
            to_email=account.email,
            subject=subject,
            body_text=body,
        )
    except SmtpError as exc:
        result.errors.append(f"mail inactivity {account.username}: {exc}")
        return
    account.last_inactivity_warn_at = utcnow()
    account.last_inactivity_warn_stage = stage
    db.commit()
    result.inactivity_warnings += 1


async def _disable_for_inactivity(
    db: Session,
    settings: Settings,
    account: BastionAccount,
    realm: RealmConfig,
    *,
    result: LifecycleRunResult,
    actor: str,
    idle_days: int,
) -> None:
    from app.rbac.keycloak_admin import update_keycloak_user

    kc_id = (account.keycloak_user_id or "").strip()
    if not kc_id:
        return
    await update_keycloak_user(
        realm, settings, keycloak_user_id=kc_id, enabled=False
    )
    account.disabled_at = utcnow()
    account.disabled_reason = DISABLED_REASON_INACTIVITY
    db.commit()
    log_action(
        db,
        actor=actor,
        action="bastion_account.disabled_inactivity",
        target=account.username,
        details={
            "account_id": account.id,
            "idle_days": idle_days,
            "keycloak_user_id": kc_id,
            "realm": realm.slug,
        },
    )
    result.disabled += 1
    # Best-effort notification after disable.
    portal = ensure_portal_settings(db, settings)
    try:
        send_email(
            portal,
            settings,
            to_email=account.email,
            subject="Votre compte Bastion a été désactivé",
            body_text=(
                f"Bonjour {account.first_name or account.username},\n\n"
                f"Votre compte ({account.email}) a été désactivé après "
                f"{idle_days} jour(s) sans connexion.\n"
                f"Contactez un administrateur pour le réactiver.\n\n"
                f"— Bastion Pro\n"
            ),
        )
    except SmtpError:
        logger.info("disable mail skipped account_id=%s", account.id)


async def _maybe_password_renewal(
    db: Session,
    settings: Settings,
    portal: PortalSettings,
    account: BastionAccount,
    realm: RealmConfig,
    *,
    result: LifecycleRunResult,
    password_max: int,
    password_warn: int,
    login_url: str,
    now,
) -> None:
    from app.rbac.keycloak_admin import update_keycloak_user

    age_days = max(0, (now - _password_anchor(account)).days)
    if age_days < max(0, password_max - password_warn):
        return

    # Force password change at next login once max age is reached.
    if age_days >= password_max:
        kc_id = (account.keycloak_user_id or "").strip()
        if kc_id:
            await update_keycloak_user(
                realm,
                settings,
                keycloak_user_id=kc_id,
                add_required_actions=["UPDATE_PASSWORD"],
            )
            result.password_actions += 1

    if account.last_password_warn_at and (
        now - account.last_password_warn_at
    ) < timedelta(days=max(1, password_warn // 2)):
        return

    remaining = max(0, password_max - age_days)
    subject = (
        "Renouvelez votre mot de passe Bastion"
        if remaining == 0
        else f"Renouvellement de mot de passe dans {remaining} jour(s)"
    )
    body = (
        f"Bonjour {account.first_name or account.username},\n\n"
        f"La politique de l'organisation limite l'âge du mot de passe à "
        f"{password_max} jour(s).\n"
    )
    if remaining == 0:
        body += (
            "Votre mot de passe doit être renouvelé à la prochaine connexion.\n"
        )
    else:
        body += f"Il vous reste {remaining} jour(s) pour le renouveler.\n"
    body += f"\nConnexion : {login_url}\n\n— Bastion Pro\n"
    try:
        send_email(
            portal,
            settings,
            to_email=account.email,
            subject=subject,
            body_text=body,
        )
    except SmtpError as exc:
        result.errors.append(f"mail password {account.username}: {exc}")
        return
    account.last_password_warn_at = now
    db.commit()
    result.password_warnings += 1


def bastion_directory_stats(db: Session) -> dict[str, int]:
    """Local stats for the « Créés bastion » tab (no Keycloak round-trip)."""
    rows = db.query(BastionAccount).all()
    total = len(rows)
    disabled = sum(1 for r in rows if r.disabled_at is not None)
    pending = sum(
        1
        for r in rows
        if r.disabled_at is None and (r.status or "") == "pending"
    )
    active = total - disabled - pending
    return {
        "total": total,
        "active": max(0, active),
        "suspended": disabled,
        "pending": pending,
        "privileged": 0,
        "privileged_new_7d": 0,
    }


async def account_lifecycle_job(*, settings: Settings) -> None:
    """APScheduler entrypoint (daily)."""
    from app.database import SessionLocal

    db = SessionLocal()
    try:
        row = ensure_portal_settings(db, settings)
        if not row.account_lifecycle_enabled:
            return
        result = await run_account_lifecycle(db, settings)
        logger.info(
            "account lifecycle done examined=%s warn_inact=%s warn_pwd=%s "
            "disabled=%s pwd_actions=%s errors=%s",
            result.examined,
            result.inactivity_warnings,
            result.password_warnings,
            result.disabled,
            result.password_actions,
            len(result.errors),
        )
    except Exception:
        logger.exception("account lifecycle job failed")
    finally:
        db.close()
