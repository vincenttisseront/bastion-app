"""Bastion account creation flow — internal row + Keycloak user + app provisioning.

Pipeline (spec §1) — no silent step, each stage persists its own status:
  1. BastionAccount row (status="pending")
  2. exact duplicate pre-check (find_keycloak_user_exact — never the fuzzy search)
  3. Keycloak user creation (WRITE service account, random password + UPDATE_PASSWORD)
     → failure: status stays "pending" + last_error, no phantom account
  4. optional Keycloak group assignment (per-group audit)
  5. per-app provisioning via driver registry (one BastionAccountProvisioning row
     per app — aggregate never masks a partial failure)

Note transactionnel : log_action() et set_user_credential() commitent en interne
(audit §3/§6) — le pipeline persiste donc chaque étape au fil de l'eau, pas de
transaction englobante.
"""

from __future__ import annotations

import logging
import secrets

from sqlalchemy.orm import Session

from app.audit import log_action
from app.bastion.bastion_fields import normalize_provisioning_driver
from app.bastion.drivers.base_provisioning import (
    PROVISIONING_FAILED,
    PROVISIONING_NOT_APPLICABLE,
    PROVISIONING_SUCCESS,
    GeneratedCredential,
    ProvisioningResult,
)
from app.bastion.drivers.registry import get_provisioning_driver
from app.models import (
    AccessGrant,
    App,
    BastionAccount,
    BastionAccountProvisioning,
    RBACGroup,
    RealmConfig,
    utcnow,
)
from app.rbac.keycloak_admin import (
    USER_CONFLICT_MESSAGE,
    add_user_to_keycloak_group,
    create_keycloak_user,
    find_keycloak_user_exact,
    get_provision_token,
    provisioning_configured,
)
from app.sso_settings import Settings
from app.vault.user_app_credential_service import set_user_credential

logger = logging.getLogger(__name__)

_NO_DRIVER_DETAIL = (
    "Aucun driver de provisioning configuré pour cette application (SSO uniquement)."
)


class AccountCreationError(ValueError):
    """Blocking validation error BEFORE anything is persisted."""


def generate_initial_password() -> str:
    """Random initial password (décision §9.1) — never logged, never stored."""
    return secrets.token_urlsafe(24)


def _account_target(realm: RealmConfig, username: str) -> str:
    return f"realm:{realm.slug}/account:{username}"


def realm_provisioning_ready(realm: RealmConfig) -> bool:
    """Realm selectable in the 'Nouvel utilisateur' form (explicit opt-in + creds)."""
    return bool(realm.enabled and realm.provisioning_enabled) and provisioning_configured(realm)


def update_aggregate_status(account: BastionAccount) -> None:
    """Aggregate is honest by construction: 'provisioned' only when every attempted
    app succeeded (or was explicitly not applicable) — never masks a failure."""
    if not account.keycloak_user_id:
        account.status = "pending"
        return
    rows = list(account.provisionings or [])
    if not rows:
        account.status = "keycloak_created"
        return
    if any(r.status == PROVISIONING_FAILED for r in rows):
        account.status = "partial_failure"
        return
    if all(r.status in (PROVISIONING_SUCCESS, PROVISIONING_NOT_APPLICABLE) for r in rows):
        account.status = "provisioned"
        return
    account.status = "keycloak_created"


def _record_keycloak_failure(
    db: Session,
    account: BastionAccount,
    realm: RealmConfig,
    message: str,
    *,
    actor: str,
    ip_address: str | None,
) -> None:
    account.status = "pending"
    account.last_error = message
    log_action(
        db,
        actor=actor,
        action="account.keycloak_create_failed",
        target=_account_target(realm, account.username),
        details={"realm_slug": realm.slug, "username": account.username, "error": message},
        ip_address=ip_address,
    )


async def create_bastion_account(
    db: Session,
    settings: Settings,
    *,
    realm: RealmConfig,
    username: str,
    email: str,
    first_name: str | None = None,
    last_name: str | None = None,
    group_ids: list[int] | None = None,
    application_ids: list[int] | None = None,
    actor: str,
    ip_address: str | None = None,
) -> tuple[BastionAccount, list[str]]:
    """Run the full creation pipeline. Returns (account, step_errors).

    ``step_errors`` are non-silent per-step messages (already persisted/audited);
    the account row always reflects the exact stage reached.
    """
    username = (username or "").strip()
    email = (email or "").strip()
    first_name = (first_name or "").strip() or None
    last_name = (last_name or "").strip() or None
    group_ids = group_ids or []
    application_ids = application_ids or []

    if not username or not email:
        raise AccountCreationError("Identifiant et email sont requis")
    if "@" not in email:
        raise AccountCreationError("Email invalide")
    if not realm_provisioning_ready(realm):
        raise AccountCreationError(
            "Provisioning non activé pour ce realm — activez-le dans la fiche realm "
            "(compte de service provisioning + opt-in explicite)."
        )
    existing = (
        db.query(BastionAccount)
        .filter_by(realm_id=realm.id, username=username)
        .first()
    )
    if existing:
        raise AccountCreationError(
            "Un compte bastion existe déjà pour cet identifiant dans ce realm "
            f"(fiche #{existing.id})."
        )

    errors: list[str] = []
    account = BastionAccount(
        realm_id=realm.id,
        username=username,
        email=email,
        first_name=first_name,
        last_name=last_name,
        status="pending",
        created_by=actor,
    )
    db.add(account)
    db.flush()
    log_action(
        db,
        actor=actor,
        action="account.created",
        target=_account_target(realm, username),
        details={
            "realm_slug": realm.slug,
            "username": username,
            "email": email,
            "bastion_account_id": account.id,
        },
        ip_address=ip_address,
    )

    # --- Step: exact duplicate pre-check (avoid a doomed write call, spec §4/§7)
    try:
        provision_token = await get_provision_token(realm, settings)
        duplicate = await find_keycloak_user_exact(
            realm, settings, username=username, email=email, token=provision_token
        )
    except ValueError as exc:
        _record_keycloak_failure(
            db, account, realm, str(exc), actor=actor, ip_address=ip_address
        )
        return account, [str(exc)]
    if duplicate:
        _record_keycloak_failure(
            db, account, realm, USER_CONFLICT_MESSAGE, actor=actor, ip_address=ip_address
        )
        return account, [USER_CONFLICT_MESSAGE]

    # --- Step: Keycloak user creation (random password + UPDATE_PASSWORD)
    initial_password = generate_initial_password()
    try:
        keycloak_user_id = await create_keycloak_user(
            realm,
            settings,
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            initial_password=initial_password,
            temporary_password=True,
        )
    except ValueError as exc:
        _record_keycloak_failure(
            db, account, realm, str(exc), actor=actor, ip_address=ip_address
        )
        return account, [str(exc)]
    finally:
        initial_password = ""  # noqa: F841 — never kept around

    account.keycloak_user_id = keycloak_user_id
    account.status = "keycloak_created"
    account.last_error = None
    log_action(
        db,
        actor=actor,
        action="account.keycloak_created",
        target=_account_target(realm, username),
        details={
            "realm_slug": realm.slug,
            "username": username,
            "keycloak_user_id": keycloak_user_id,
            "bastion_account_id": account.id,
            "required_actions": ["UPDATE_PASSWORD"],
        },
        ip_address=ip_address,
    )

    # --- Step: optional Keycloak group assignment (per-group status)
    for group_id in group_ids:
        group = (
            db.query(RBACGroup)
            .filter_by(id=group_id, realm_id=realm.id)
            .first()
        )
        if group is None or not group.keycloak_group_id:
            msg = f"Groupe RBAC #{group_id} introuvable pour ce realm"
            errors.append(msg)
            log_action(
                db,
                actor=actor,
                action="account.group_assign_failed",
                target=_account_target(realm, username),
                details={"group_id": group_id, "error": msg},
                ip_address=ip_address,
            )
            continue
        try:
            await add_user_to_keycloak_group(
                realm,
                settings,
                keycloak_user_id=keycloak_user_id,
                keycloak_group_id=group.keycloak_group_id,
                token=provision_token,
            )
            log_action(
                db,
                actor=actor,
                action="account.group_assigned",
                target=_account_target(realm, username),
                details={"group": group.name, "keycloak_group_id": group.keycloak_group_id},
                ip_address=ip_address,
            )
        except ValueError as exc:
            msg = f"Groupe {group.name} : {exc}"
            errors.append(msg)
            log_action(
                db,
                actor=actor,
                action="account.group_assign_failed",
                target=_account_target(realm, username),
                details={"group": group.name, "error": str(exc)},
                ip_address=ip_address,
            )
    if errors:
        account.last_error = " ; ".join(errors)

    # --- Step: per-app provisioning (one row per app, never aggregated away)
    for application_id in application_ids:
        app = db.query(App).filter_by(id=application_id).first()
        if app is None:
            errors.append(f"Application #{application_id} introuvable")
            continue
        row = await provision_account_app(
            db, settings, account=account, app=app, actor=actor, ip_address=ip_address
        )
        if row.status == PROVISIONING_FAILED:
            errors.append(f"{app.label} : {row.detail}")

    update_aggregate_status(account)
    db.commit()
    return account, errors


async def provision_account_app(
    db: Session,
    settings: Settings,
    *,
    account: BastionAccount,
    app: App,
    actor: str,
    ip_address: str | None = None,
) -> BastionAccountProvisioning:
    """Provision (or retry) one application for one account — upserts the row."""
    realm = account.realm or db.query(RealmConfig).filter_by(id=account.realm_id).first()
    driver_name = normalize_provisioning_driver(app.provisioning_driver)

    row = (
        db.query(BastionAccountProvisioning)
        .filter_by(bastion_account_id=account.id, application_id=app.id)
        .first()
    )
    if row is None:
        row = BastionAccountProvisioning(
            bastion_account_id=account.id,
            application_id=app.id,
            driver_name=driver_name or "none",
            status="pending",
        )
        db.add(row)
        db.flush()
    else:
        row.driver_name = driver_name or "none"

    def _finish(result: ProvisioningResult) -> BastionAccountProvisioning:
        row.status = result.status
        row.detail = result.detail
        row.attempted_at = utcnow()
        log_action(
            db,
            actor=actor,
            action=f"account.provisioning.{result.status}",
            target=_account_target(realm, account.username) if realm else account.username,
            details={
                "app_slug": app.slug,
                "driver": row.driver_name,
                "detail": result.detail,
                "bastion_account_id": account.id,
            },
            ip_address=ip_address,
        )
        update_aggregate_status(account)
        db.commit()
        return row

    if not account.keycloak_user_id:
        return _finish(
            ProvisioningResult(
                status=PROVISIONING_FAILED,
                detail=(
                    "Compte Keycloak non créé — corrigez l'étape Keycloak avant de "
                    "provisionner les applications."
                ),
            )
        )

    if driver_name is None:
        return _finish(
            ProvisioningResult(
                status=PROVISIONING_NOT_APPLICABLE,
                detail=_NO_DRIVER_DETAIL,
            )
        )

    driver = get_provisioning_driver(driver_name)
    credential = GeneratedCredential(
        username=account.username,
        password=secrets.token_urlsafe(18),
    )
    try:
        result = await driver.create_account(
            db=db, settings=settings, app=app, account=account, credential=credential
        )
    except Exception:
        logger.exception(
            "provisioning driver crashed app=%s driver=%s account_id=%s",
            app.slug,
            driver_name,
            account.id,
        )
        result = ProvisioningResult(
            status=PROVISIONING_FAILED,
            detail="Erreur interne du driver de provisioning (voir logs serveur)",
        )

    if result.status == PROVISIONING_SUCCESS and result.credential_pushed:
        # Store the pushed credential in the internal vault (Fernet) — reuses
        # set_user_credential as-is (audit §3), never plaintext in `detail`.
        set_user_credential(
            db,
            app.slug,
            account.keycloak_user_id,
            credential.username,
            credential.password,
            settings,
            actor=actor,
            ip_address=ip_address,
        )
    credential = None  # noqa: F841 — drop plaintext reference

    return _finish(result)


async def provision_for_grant(
    db: Session,
    settings: Settings,
    grant: AccessGrant,
    *,
    actor: str,
    ip_address: str | None = None,
) -> dict | None:
    """Post-grant provisioning hook (spec §5.3) — user grants only in V1.

    Returns None when the grant is out of scope (group subject, non-application
    resource, app without driver); otherwise an explicit summary dict — never a
    silent skip when a provisioning was expected.
    """
    if (grant.subject_type or "") != "user":
        return None
    if (grant.resource_type or "") != "application":
        return None
    if not grant.application_id or not grant.keycloak_user_id:
        return None
    app = db.query(App).filter_by(id=grant.application_id).first()
    if app is None:
        return None
    if normalize_provisioning_driver(app.provisioning_driver) is None:
        return None

    account = (
        db.query(BastionAccount)
        .filter_by(keycloak_user_id=grant.keycloak_user_id)
        .first()
    )
    if account is None:
        detail = (
            "Aucun compte bastion associé à cet utilisateur Keycloak — provisioning "
            "non déclenché (utilisateur créé hors bastion)."
        )
        log_action(
            db,
            actor=actor,
            action="account.provisioning.skipped",
            target=f"app:{app.slug}/user:{grant.keycloak_user_id}",
            details={
                "app_slug": app.slug,
                "keycloak_user_id": grant.keycloak_user_id,
                "detail": detail,
            },
            ip_address=ip_address,
        )
        return {"status": "skipped", "detail": detail, "app_slug": app.slug}

    row = await provision_account_app(
        db, settings, account=account, app=app, actor=actor, ip_address=ip_address
    )
    return {
        "status": row.status,
        "detail": row.detail,
        "app_slug": app.slug,
        "bastion_account_id": account.id,
    }
