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
    BASTION_ACCOUNT_ORIGIN_BASTION,
    BASTION_ACCOUNT_ORIGIN_KEYCLOAK,
    RBACGroup,
    RealmConfig,
    UserAppCredential,
    utcnow,
)
from app.rbac.keycloak_admin import (
    USER_CONFLICT_MESSAGE,
    add_user_to_keycloak_group,
    create_keycloak_group,
    create_keycloak_user,
    delete_keycloak_user,
    find_keycloak_user_exact,
    get_provision_token,
    provisioning_configured,
    remove_user_from_keycloak_group,
    reset_keycloak_password,
    update_keycloak_user,
)
from app.sso_settings import Settings
from app.vault.user_app_credential_service import (
    resolve_credential,
    set_user_credential,
)

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


def _as_int_list(raw) -> list[int]:
    if not raw:
        return []
    if isinstance(raw, list):
        out: list[int] = []
        for item in raw:
            try:
                out.append(int(item))
            except (TypeError, ValueError):
                continue
        return out
    return []


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


def normalize_organization_name(raw: str | None) -> str:
    """Trim + collapse whitespace — display name used as Keycloak/RBAC group name."""
    return " ".join((raw or "").split()).strip()


async def ensure_company_group(
    db: Session,
    settings: Settings,
    *,
    realm: RealmConfig,
    organization: str,
    actor: str,
    ip_address: str | None = None,
    token: str | None = None,
) -> RBACGroup:
    """Find or create the société group (RBAC + Keycloak). Idempotent per realm+name."""
    name = normalize_organization_name(organization)
    if not name:
        raise AccountCreationError("Société / organisation requise")

    existing = (
        db.query(RBACGroup)
        .filter(
            RBACGroup.realm_id == realm.id,
            RBACGroup.name == name,
            RBACGroup.keycloak_group_id.is_not(None),
        )
        .first()
    )
    if existing is not None:
        return existing

    provision_token = token or await get_provision_token(realm, settings)
    try:
        kc_id = await create_keycloak_group(
            realm, settings, name=name, token=provision_token
        )
    except ValueError as exc:
        raise AccountCreationError(f"Groupe société Keycloak : {exc}") from exc

    # Race: another worker may have inserted the same KC group → reuse by kc id
    by_kc = (
        db.query(RBACGroup)
        .filter_by(realm_id=realm.id, keycloak_group_id=kc_id)
        .first()
    )
    if by_kc is not None:
        return by_kc

    group = RBACGroup(
        name=name,
        realm_id=realm.id,
        realm_slug=realm.slug,
        keycloak_group_id=kc_id,
        path=f"/{name}",
        description=f"Groupe société (auto) — {name}",
        group_tag="Société",
    )
    db.add(group)
    db.flush()
    log_action(
        db,
        actor=actor,
        action="account.company_group_ensured",
        target=f"realm:{realm.slug}/group:{name}",
        details={
            "organization": name,
            "rbac_group_id": group.id,
            "keycloak_group_id": kc_id,
        },
        ip_address=ip_address,
    )
    return group


async def sync_company_groups_from_crushftp(
    db: Session,
    settings: Settings,
    *,
    app: App,
    realm: RealmConfig,
    actor: str,
    ip_address: str | None = None,
) -> dict:
    """List CrushFTP folders under vfs base and ensure RBAC/Keycloak company groups.

    Idempotent: existing groups (same realm + name) are skipped/reused.
    """
    from app.bastion.drivers.crushftp import CrushFTPProvisioningDriver

    if normalize_provisioning_driver(getattr(app, "provisioning_driver", None)) != "crushftp":
        raise AccountCreationError(
            "L’application n’utilise pas le driver de provisioning CrushFTP."
        )

    driver = CrushFTPProvisioningDriver()
    folders, err = await driver.list_company_folders(app=app, settings=settings)
    if err:
        raise AccountCreationError(err)

    created: list[str] = []
    existing: list[str] = []
    errors: list[str] = []
    try:
        provision_token = await get_provision_token(realm, settings)
    except ValueError as exc:
        raise AccountCreationError(str(exc)) from exc

    for folder in folders:
        before = (
            db.query(RBACGroup)
            .filter(
                RBACGroup.realm_id == realm.id,
                RBACGroup.name == folder,
                RBACGroup.keycloak_group_id.is_not(None),
            )
            .first()
        )
        try:
            group = await ensure_company_group(
                db,
                settings,
                realm=realm,
                organization=folder,
                actor=actor,
                ip_address=ip_address,
                token=provision_token,
            )
        except AccountCreationError as exc:
            errors.append(f"{folder}: {exc}")
            continue
        if before is not None and before.id == group.id:
            existing.append(folder)
        else:
            created.append(folder)

    db.commit()
    log_action(
        db,
        actor=actor,
        action="app.crushftp.companies_synced",
        target=f"app:{app.slug}",
        details={
            "realm_slug": realm.slug,
            "vfs_base": getattr(app, "crushftp_vfs_base_path", None),
            "folders_found": folders,
            "created": created,
            "existing": existing,
            "errors": errors,
        },
        ip_address=ip_address,
    )
    try:
        db.commit()
    except Exception:
        db.rollback()

    return {
        "ok": not errors,
        "folders_found": folders,
        "created": created,
        "existing": existing,
        "errors": errors,
        "realm_slug": realm.slug,
        "vfs_base": getattr(app, "crushftp_vfs_base_path", None),
    }


def linked_bastion_accounts(
    db: Session,
    *,
    account: BastionAccount,
) -> list[BastionAccount]:
    """Sibling BastionAccounts for the same person (username or email)."""
    from sqlalchemy import or_

    username = (account.username or "").strip()
    email = (account.email or "").strip()
    clauses = [BastionAccount.id == account.id]
    if username:
        clauses.append(BastionAccount.username == username)
    if email:
        clauses.append(BastionAccount.email == email)
    rows = (
        db.query(BastionAccount)
        .filter(or_(*clauses))
        .order_by(BastionAccount.realm_id.asc(), BastionAccount.id.asc())
        .all()
    )
    seen: set[int] = set()
    linked: list[BastionAccount] = []
    for row in rows:
        if row.id in seen:
            continue
        seen.add(row.id)
        linked.append(row)
    return linked


async def ensure_identity_in_realm(
    db: Session,
    settings: Settings,
    *,
    source_account: BastionAccount,
    target_realm: RealmConfig,
    actor: str,
    ip_address: str | None = None,
) -> BastionAccount:
    """Find or create BastionAccount + Keycloak user in ``target_realm`` for source identity."""
    if target_realm.id == source_account.realm_id and source_account.keycloak_user_id:
        return source_account

    existing = (
        db.query(BastionAccount)
        .filter_by(realm_id=target_realm.id, username=source_account.username)
        .first()
    )
    if existing is not None and existing.keycloak_user_id:
        return existing

    if not realm_provisioning_ready(target_realm):
        raise AccountCreationError(
            f"Provisioning non activé pour le realm « {target_realm.slug} » "
            "(requis pour y rattacher des groupes Keycloak)."
        )

    token = await get_provision_token(target_realm, settings)
    found = await find_keycloak_user_exact(
        target_realm,
        settings,
        username=source_account.username,
        email=source_account.email,
        token=token,
    )

    if existing is None:
        existing = BastionAccount(
            realm_id=target_realm.id,
            username=source_account.username,
            email=source_account.email,
            first_name=source_account.first_name,
            last_name=source_account.last_name,
            organization=source_account.organization,
            status="pending",
            origin=BASTION_ACCOUNT_ORIGIN_BASTION,
            created_by=actor or source_account.created_by or "system",
        )
        db.add(existing)
        db.flush()

    if not existing.keycloak_user_id:
        if found:
            existing.keycloak_user_id = str(found.get("id") or "")
            existing.origin = BASTION_ACCOUNT_ORIGIN_KEYCLOAK
            existing.status = "keycloak_created"
            existing.last_error = None
        else:
            initial_password = generate_initial_password()
            try:
                # Permanent password: headless native login cannot complete
                # Keycloak UPDATE_PASSWORD required-action pages.
                uid = await create_keycloak_user(
                    target_realm,
                    settings,
                    username=source_account.username,
                    email=source_account.email,
                    first_name=source_account.first_name,
                    last_name=source_account.last_name,
                    initial_password=initial_password,
                    temporary_password=False,
                )
            except ValueError as exc:
                initial_password = ""  # noqa: F841
                raise AccountCreationError(str(exc)) from exc
            initial_password = ""  # noqa: F841
            existing.keycloak_user_id = uid
            existing.origin = BASTION_ACCOUNT_ORIGIN_BASTION
            existing.status = "keycloak_created"
            existing.last_error = None
            log_action(
                db,
                actor=actor,
                action="account.keycloak_created",
                target=_account_target(target_realm, existing.username),
                details={
                    "realm_slug": target_realm.slug,
                    "username": existing.username,
                    "keycloak_user_id": uid,
                    "bastion_account_id": existing.id,
                    "linked_from_account_id": source_account.id,
                    "required_actions": [],
                    "temporary_password": False,
                },
                ip_address=ip_address,
            )

    db.commit()
    return existing


async def assign_account_to_rbac_group(
    db: Session,
    settings: Settings,
    *,
    source_account: BastionAccount,
    group: RBACGroup,
    actor: str,
    ip_address: str | None = None,
) -> BastionAccount:
    """Add identity to a Keycloak group (any realm) — creates linked account if needed."""
    if not group.keycloak_group_id or group.realm_id is None:
        raise AccountCreationError("Groupe non synchronisé Keycloak")
    target_realm = (
        db.query(RealmConfig).filter_by(id=group.realm_id).first()
    )
    if target_realm is None:
        raise AccountCreationError("Realm du groupe introuvable")

    target_account = await ensure_identity_in_realm(
        db,
        settings,
        source_account=source_account,
        target_realm=target_realm,
        actor=actor,
        ip_address=ip_address,
    )
    assert target_account.keycloak_user_id
    token = await get_provision_token(target_realm, settings)
    try:
        await add_user_to_keycloak_group(
            target_realm,
            settings,
            keycloak_user_id=target_account.keycloak_user_id,
            keycloak_group_id=group.keycloak_group_id,
            token=token,
        )
    except ValueError as exc:
        raise AccountCreationError(str(exc)) from exc

    log_action(
        db,
        actor=actor,
        action="account.group_assigned",
        target=_account_target(target_realm, target_account.username),
        details={
            "group": group.name,
            "keycloak_group_id": group.keycloak_group_id,
            "rbac_group_id": group.id,
            "bastion_account_id": target_account.id,
            "source_account_id": source_account.id,
        },
        ip_address=ip_address,
    )
    db.commit()
    return target_account


async def remove_account_from_rbac_group(
    db: Session,
    settings: Settings,
    *,
    source_account: BastionAccount,
    group: RBACGroup,
    actor: str,
    ip_address: str | None = None,
) -> BastionAccount | None:
    """Remove identity from a Keycloak group in the group's realm."""
    if not group.keycloak_group_id or group.realm_id is None:
        raise AccountCreationError("Groupe non synchronisé Keycloak")
    target_realm = db.query(RealmConfig).filter_by(id=group.realm_id).first()
    if target_realm is None:
        raise AccountCreationError("Realm du groupe introuvable")

    target_account = (
        db.query(BastionAccount)
        .filter_by(realm_id=target_realm.id, username=source_account.username)
        .first()
    )
    if target_account is None or not target_account.keycloak_user_id:
        # Fallback: same email in that realm
        email = (source_account.email or "").strip().lower()
        if email:
            for row in db.query(BastionAccount).filter_by(realm_id=target_realm.id).all():
                if (row.email or "").strip().lower() == email and row.keycloak_user_id:
                    target_account = row
                    break
    if target_account is None or not target_account.keycloak_user_id:
        raise AccountCreationError(
            f"Aucun compte Keycloak lié dans le realm « {target_realm.slug} »"
        )

    token = await get_provision_token(target_realm, settings)
    try:
        await remove_user_from_keycloak_group(
            target_realm,
            settings,
            keycloak_user_id=target_account.keycloak_user_id,
            keycloak_group_id=group.keycloak_group_id,
            token=token,
        )
    except ValueError as exc:
        raise AccountCreationError(str(exc)) from exc

    log_action(
        db,
        actor=actor,
        action="account.group_removed",
        target=_account_target(target_realm, target_account.username),
        details={
            "group": group.name,
            "keycloak_group_id": group.keycloak_group_id,
            "rbac_group_id": group.id,
            "bastion_account_id": target_account.id,
        },
        ip_address=ip_address,
    )
    db.commit()
    return target_account


async def _assign_groups_and_provision_apps(
    db: Session,
    settings: Settings,
    *,
    account: BastionAccount,
    realm: RealmConfig,
    provision_token: str,
    group_ids: list[int],
    application_ids: list[int],
    actor: str,
    ip_address: str | None,
) -> list[str]:
    """After Keycloak user exists — assign groups then provision apps.

    Groups from other realms create/link a sibling BastionAccount then assign
    via that realm's Keycloak Admin API.
    """
    errors: list[str] = []
    keycloak_user_id = account.keycloak_user_id
    assert keycloak_user_id  # caller guarantees
    _ = provision_token  # kept for call-site compatibility

    selected_group_names: list[str] = []
    for group_id in group_ids:
        group = db.query(RBACGroup).filter_by(id=group_id).first()
        if group is None or not group.keycloak_group_id or group.realm_id is None:
            msg = f"Groupe RBAC #{group_id} introuvable ou non synchronisé Keycloak"
            errors.append(msg)
            log_action(
                db,
                actor=actor,
                action="account.group_assign_failed",
                target=_account_target(realm, account.username),
                details={"group_id": group_id, "error": msg},
                ip_address=ip_address,
            )
            continue
        selected_group_names.append(group.name)
        try:
            await assign_account_to_rbac_group(
                db,
                settings,
                source_account=account,
                group=group,
                actor=actor,
                ip_address=ip_address,
            )
        except AccountCreationError as exc:
            msg = f"Groupe {group.name} : {exc}"
            errors.append(msg)
            log_action(
                db,
                actor=actor,
                action="account.group_assign_failed",
                target=_account_target(realm, account.username),
                details={
                    "group": group.name,
                    "group_id": group.id,
                    "realm_id": group.realm_id,
                    "error": str(exc),
                },
                ip_address=ip_address,
            )
    if errors:
        account.last_error = " ; ".join(errors)

    for application_id in application_ids:
        app = db.query(App).filter_by(id=application_id).first()
        if app is None:
            errors.append(f"Application #{application_id} introuvable")
            continue
        crushftp_groups = (
            list(selected_group_names)
            if normalize_provisioning_driver(app.provisioning_driver) == "crushftp"
            else None
        )
        # Always pass société + selected group names to drivers that support groups.
        group_names_for_app = list(selected_group_names) if crushftp_groups is not None else None
        row = await provision_account_app(
            db,
            settings,
            account=account,
            app=app,
            actor=actor,
            ip_address=ip_address,
            group_names=group_names_for_app,
        )
        if row.status == PROVISIONING_FAILED:
            errors.append(f"{app.label} : {row.detail}")
        elif row.detail and "Groupes:" in row.detail and "=échec" in row.detail:
            errors.append(f"{app.label} (groupes) : {row.detail}")

    return errors


async def push_keycloak_user_and_continue(
    db: Session,
    settings: Settings,
    *,
    account: BastionAccount,
    actor: str,
    ip_address: str | None = None,
    is_retry: bool = False,
) -> tuple[list[str], str | None]:
    """Create Keycloak user for a pending BastionAccount, then groups + apps.

    Used by initial create and by explicit « Relancer Keycloak » — never automatic.
    Returns ``(step_errors, temporary_password_or_none)``. The password is only
    set when Keycloak creation succeeded in this call — caller may email it then
    MUST drop the reference (never persisted / logged).
    """
    realm = account.realm or db.query(RealmConfig).filter_by(id=account.realm_id).first()
    if realm is None:
        raise AccountCreationError("Realm introuvable pour ce compte")
    if account.keycloak_user_id:
        raise AccountCreationError(
            "Compte Keycloak déjà créé — utilisez Relancer sur chaque application en échec."
        )
    if not realm_provisioning_ready(realm):
        raise AccountCreationError(
            "Provisioning non activé pour ce realm — activez-le dans la fiche realm "
            "(compte de service provisioning + opt-in explicite)."
        )

    group_ids = _as_int_list(account.pending_group_ids)
    application_ids = _as_int_list(account.pending_application_ids)
    username = account.username
    email = account.email

    try:
        provision_token = await get_provision_token(realm, settings)
        duplicate = await find_keycloak_user_exact(
            realm, settings, username=username, email=email, token=provision_token
        )
    except ValueError as exc:
        _record_keycloak_failure(
            db, account, realm, str(exc), actor=actor, ip_address=ip_address
        )
        db.commit()
        return [str(exc)], None
    if duplicate:
        _record_keycloak_failure(
            db, account, realm, USER_CONFLICT_MESSAGE, actor=actor, ip_address=ip_address
        )
        db.commit()
        return [USER_CONFLICT_MESSAGE], None

    initial_password = generate_initial_password()
    try:
        from app.oidc_native_session import is_oidc_native_session_enabled_for_realm

        # Native headless login cannot complete Keycloak UPDATE_PASSWORD pages.
        use_temporary = not is_oidc_native_session_enabled_for_realm(
            db, realm.slug, settings
        )
        keycloak_user_id = await create_keycloak_user(
            realm,
            settings,
            username=username,
            email=email,
            first_name=account.first_name,
            last_name=account.last_name,
            initial_password=initial_password,
            temporary_password=use_temporary,
        )
    except ValueError as exc:
        initial_password = ""  # noqa: F841
        _record_keycloak_failure(
            db, account, realm, str(exc), actor=actor, ip_address=ip_address
        )
        db.commit()
        return [str(exc)], None

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
            "required_actions": ["UPDATE_PASSWORD"] if use_temporary else [],
            "temporary_password": use_temporary,
            **({"retry": True} if is_retry else {}),
        },
        ip_address=ip_address,
    )

    errors = await _assign_groups_and_provision_apps(
        db,
        settings,
        account=account,
        realm=realm,
        provision_token=provision_token,
        group_ids=group_ids,
        application_ids=application_ids,
        actor=actor,
        ip_address=ip_address,
    )
    update_aggregate_status(account)
    db.commit()
    return errors, initial_password


async def retry_bastion_account_keycloak(
    db: Session,
    settings: Settings,
    *,
    account: BastionAccount,
    actor: str,
    ip_address: str | None = None,
) -> tuple[list[str], str | None]:
    """Explicit admin retry of the Keycloak step (+ pending groups/apps)."""
    realm = account.realm or db.query(RealmConfig).filter_by(id=account.realm_id).first()
    log_action(
        db,
        actor=actor,
        action="account.keycloak_retry",
        target=_account_target(realm, account.username)
        if realm
        else f"account:{account.username}",
        details={
            "bastion_account_id": account.id,
            "username": account.username,
            "previous_error": account.last_error,
        },
        ip_address=ip_address,
    )
    return await push_keycloak_user_and_continue(
        db,
        settings,
        account=account,
        actor=actor,
        ip_address=ip_address,
        is_retry=True,
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
    organization: str | None = None,
    group_ids: list[int] | None = None,
    application_ids: list[int] | None = None,
    actor: str,
    ip_address: str | None = None,
) -> tuple[BastionAccount, list[str], str | None]:
    """Run the full creation pipeline. Returns (account, step_errors, temp_password).

    ``step_errors`` are non-silent per-step messages (already persisted/audited);
    the account row always reflects the exact stage reached.
    ``temp_password`` is set only when Keycloak creation succeeded in this call —
    never logged; caller may email it then must drop the reference.
    """
    username = (username or "").strip()
    email = (email or "").strip()
    first_name = (first_name or "").strip() or None
    last_name = (last_name or "").strip() or None
    organization = normalize_organization_name(organization)
    group_ids = list(group_ids or [])
    application_ids = list(application_ids or [])

    if not username or not email:
        raise AccountCreationError("Identifiant et email sont requis")
    if "@" not in email:
        raise AccountCreationError("Email invalide")
    if not organization:
        raise AccountCreationError("Société / organisation requise")
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

    # Ensure société group before Keycloak user so pending_group_ids is complete.
    company = await ensure_company_group(
        db,
        settings,
        realm=realm,
        organization=organization,
        actor=actor,
        ip_address=ip_address,
    )
    if company.id not in group_ids:
        group_ids = [company.id, *group_ids]

    account = BastionAccount(
        realm_id=realm.id,
        username=username,
        email=email,
        first_name=first_name,
        last_name=last_name,
        organization=organization,
        status="pending",
        origin=BASTION_ACCOUNT_ORIGIN_BASTION,
        pending_group_ids=group_ids or None,
        pending_application_ids=application_ids or None,
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
            "organization": organization,
            "company_group_id": company.id,
            "bastion_account_id": account.id,
            "origin": account.origin,
        },
        ip_address=ip_address,
    )

    errors, temp_password = await push_keycloak_user_and_continue(
        db,
        settings,
        account=account,
        actor=actor,
        ip_address=ip_address,
    )
    return account, errors, temp_password


def send_account_credentials_email(
    settings: Settings,
    *,
    realm: RealmConfig,
    account: BastionAccount,
    temporary_password: str,
    kind: str = "created",
) -> None:
    """Email the temporary Keycloak password via the realm's SMTP. Raises SmtpError."""
    from app.mail.smtp_service import credentials_email_bodies, send_email

    portal = (settings.portal_domain or "portal.ar-systems.fr").strip()
    portal_url = f"https://{portal}" if not portal.startswith("http") else portal
    subject, text, html = credentials_email_bodies(
        portal_url=portal_url,
        username=account.username,
        temporary_password=temporary_password,
        realm_name=realm.name or realm.slug,
        kind=kind,
    )
    send_email(
        realm,
        settings,
        to_email=account.email,
        subject=subject,
        body_text=text,
        body_html=html,
    )


async def reset_bastion_account_password(
    db: Session,
    settings: Settings,
    *,
    account: BastionAccount,
    actor: str,
    ip_address: str | None = None,
    send_email: bool = False,
) -> tuple[str, str | None]:
    """Generate a new Keycloak password. Returns (password, email_error).

    On realms with native headless login, the password is **permanent** (no
    UPDATE_PASSWORD required action) so the revealed/emailed value works on
    ``/auth/login``. Other realms keep a temporary password + UPDATE_PASSWORD.
    ``email_error`` is set when the caller asked to email and SMTP failed —
    the reset itself still succeeded.
    """
    realm = account.realm or db.query(RealmConfig).filter_by(id=account.realm_id).first()
    if realm is None:
        raise AccountCreationError("Realm introuvable pour ce compte")
    if not account.keycloak_user_id:
        raise AccountCreationError(
            "Compte Keycloak non créé — impossible de réinitialiser le mot de passe."
        )
    if not realm_provisioning_ready(realm):
        raise AccountCreationError(
            "Provisioning non activé pour ce realm — requis pour reset Keycloak."
        )

    from app.oidc_native_session import is_oidc_native_session_enabled_for_realm

    temporary = not is_oidc_native_session_enabled_for_realm(db, realm.slug, settings)
    new_password = generate_initial_password()
    logger.info(
        "account_password_reset start realm=%s username=%s account_id=%s "
        "keycloak_user_id=%s temporary=%s send_email=%s actor=%s",
        realm.slug,
        account.username,
        account.id,
        account.keycloak_user_id,
        temporary,
        bool(send_email),
        actor,
    )
    try:
        await reset_keycloak_password(
            realm,
            settings,
            keycloak_user_id=account.keycloak_user_id,
            new_password=new_password,
            temporary=temporary,
        )
    except ValueError as exc:
        logger.warning(
            "account_password_reset keycloak_failed realm=%s username=%s "
            "account_id=%s keycloak_user_id=%s err=%s",
            realm.slug,
            account.username,
            account.id,
            account.keycloak_user_id,
            str(exc)[:200],
        )
        new_password = ""  # noqa: F841
        raise AccountCreationError(str(exc)) from exc

    logger.info(
        "account_password_reset keycloak_ok realm=%s username=%s account_id=%s "
        "keycloak_user_id=%s temporary=%s",
        realm.slug,
        account.username,
        account.id,
        account.keycloak_user_id,
        temporary,
    )
    log_action(
        db,
        actor=actor,
        action="account.password_reset",
        target=_account_target(realm, account.username),
        details={
            "bastion_account_id": account.id,
            "keycloak_user_id": account.keycloak_user_id,
            "temporary": temporary,
            "email_requested": bool(send_email),
        },
        ip_address=ip_address,
    )
    db.commit()

    email_error: str | None = None
    if send_email:
        try:
            send_account_credentials_email(
                settings,
                realm=realm,
                account=account,
                temporary_password=new_password,
                kind="reset",
            )
            log_action(
                db,
                actor=actor,
                action="account.credentials_emailed",
                target=_account_target(realm, account.username),
                details={"kind": "reset", "to": account.email},
                ip_address=ip_address,
            )
            db.commit()
        except Exception as exc:
            email_error = str(exc)
            log_action(
                db,
                actor=actor,
                action="account.credentials_email_failed",
                target=_account_target(realm, account.username),
                details={"kind": "reset", "error": email_error},
                ip_address=ip_address,
            )
            db.commit()

    return new_password, email_error


async def mark_keycloak_email_verified(
    db: Session,
    settings: Settings,
    *,
    realm: RealmConfig,
    keycloak_user_id: str,
    actor: str,
    ip_address: str | None = None,
    username: str | None = None,
    bastion_account_id: int | None = None,
) -> None:
    """Set Keycloak ``emailVerified=true`` and drop ``VERIFY_EMAIL`` required action."""
    uid = (keycloak_user_id or "").strip()
    if not uid:
        raise AccountCreationError("Identifiant utilisateur Keycloak manquant")
    if not realm_provisioning_ready(realm):
        raise AccountCreationError(
            "Provisioning non activé pour ce realm — requis pour modifier Keycloak."
        )
    try:
        await update_keycloak_user(
            realm,
            settings,
            keycloak_user_id=uid,
            email_verified=True,
        )
    except ValueError as exc:
        raise AccountCreationError(str(exc)) from exc

    label = (username or "").strip() or uid
    log_action(
        db,
        actor=actor,
        action="account.email_verified",
        target=_account_target(realm, label),
        details={
            "keycloak_user_id": uid,
            "bastion_account_id": bastion_account_id,
            "email_verified": True,
        },
        ip_address=ip_address,
    )
    db.commit()


async def provision_account_app(
    db: Session,
    settings: Settings,
    *,
    account: BastionAccount,
    app: App,
    actor: str,
    ip_address: str | None = None,
    group_names: list[str] | None = None,
) -> BastionAccountProvisioning:
    """Provision (or retry) one application for one account — upserts the row.

    ``group_names``: optional CrushFTP (same-name) groups to join after user create;
    ignored by other drivers / when empty.
    """
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
                **(
                    {"group_errors": list(result.group_errors)}
                    if result.group_errors
                    else {}
                ),
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
            db=db,
            settings=settings,
            app=app,
            account=account,
            credential=credential,
            group_names=group_names,
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


async def update_bastion_account_identity(
    db: Session,
    settings: Settings,
    *,
    account: BastionAccount,
    email: str | None = None,
    first_name: str | None = None,
    last_name: str | None = None,
    organization: str | None = None,
    actor: str,
    ip_address: str | None = None,
) -> list[str]:
    """Update BastionAccount + Keycloak (+ société group). Returns step warnings."""
    errors: list[str] = []
    realm = account.realm or db.query(RealmConfig).filter_by(id=account.realm_id).first()
    if realm is None:
        raise AccountCreationError("Realm introuvable pour ce compte")

    new_email = (email if email is not None else account.email or "").strip()
    new_first = (first_name if first_name is not None else account.first_name or "").strip() or None
    new_last = (last_name if last_name is not None else account.last_name or "").strip() or None
    org_raw = organization if organization is not None else account.organization
    new_org = normalize_organization_name(org_raw) if org_raw is not None else None

    if not new_email or "@" not in new_email:
        raise AccountCreationError("Email invalide")
    if organization is not None and not new_org:
        raise AccountCreationError("Société / organisation requise")

    org_changed = bool(new_org) and new_org != (account.organization or "")
    company: RBACGroup | None = None
    if org_changed and new_org:
        company = await ensure_company_group(
            db,
            settings,
            realm=realm,
            organization=new_org,
            actor=actor,
            ip_address=ip_address,
        )

    account.email = new_email
    account.first_name = new_first
    account.last_name = new_last
    if new_org is not None:
        account.organization = new_org
    db.flush()

    if account.keycloak_user_id:
        try:
            await update_keycloak_user(
                realm,
                settings,
                keycloak_user_id=account.keycloak_user_id,
                email=new_email,
                first_name=new_first or "",
                last_name=new_last or "",
            )
        except ValueError as exc:
            errors.append(f"Keycloak : {exc}")

        if company is not None and company.keycloak_group_id:
            try:
                token = await get_provision_token(realm, settings)
                await add_user_to_keycloak_group(
                    realm,
                    settings,
                    keycloak_user_id=account.keycloak_user_id,
                    keycloak_group_id=company.keycloak_group_id,
                    token=token,
                )
            except ValueError as exc:
                errors.append(f"Groupe société Keycloak : {exc}")

    # Re-push provisioned apps that have a vault credential (password / VFS replace).
    app_sync = await sync_account_credentials_to_apps(
        db,
        settings,
        account=account,
        actor=actor,
        ip_address=ip_address,
        extra_group_names=[company.name] if company is not None else None,
    )
    errors.extend(app_sync)

    log_action(
        db,
        actor=actor,
        action="account.identity_updated",
        target=_account_target(realm, account.username),
        details={
            "bastion_account_id": account.id,
            "email": new_email,
            "organization": account.organization,
            "org_changed": org_changed,
            "errors": errors,
        },
        ip_address=ip_address,
    )
    db.commit()
    return errors


async def sync_vault_credential_to_app(
    db: Session,
    settings: Settings,
    *,
    account: BastionAccount,
    app: App,
    actor: str,
    ip_address: str | None = None,
    group_names: list[str] | None = None,
) -> ProvisioningResult:
    """Push the vault-stored individual credential to the app (CrushFTP replace, etc.)."""
    if not account.keycloak_user_id:
        return ProvisioningResult(
            status=PROVISIONING_FAILED,
            detail="Keycloak user id manquant — sync vault impossible",
        )
    driver_name = normalize_provisioning_driver(app.provisioning_driver)
    driver = get_provisioning_driver(driver_name)
    if driver is None:
        return ProvisioningResult(
            status=PROVISIONING_NOT_APPLICABLE,
            detail=_NO_DRIVER_DETAIL,
        )
    try:
        resolved, password = resolve_credential(
            db, app.slug, settings, keycloak_user_id=account.keycloak_user_id
        )
    except Exception as exc:
        return ProvisioningResult(
            status=PROVISIONING_FAILED,
            detail=f"Vault : {exc}",
        )
    credential = GeneratedCredential(
        username=resolved.robotic_username or account.username,
        password=password,
    )
    try:
        result = await driver.create_account(
            db=db,
            settings=settings,
            app=app,
            account=account,
            credential=credential,
            group_names=group_names,
        )
    except Exception:
        logger.exception(
            "sync vault→app crashed app=%s account_id=%s", app.slug, account.id
        )
        result = ProvisioningResult(
            status=PROVISIONING_FAILED,
            detail="Erreur interne sync vault → application",
        )
    finally:
        credential = None  # noqa: F841
        password = ""  # noqa: F841

    log_action(
        db,
        actor=actor,
        action="account.credential_synced_to_app",
        target=f"app:{app.slug}/account:{account.username}",
        details={
            "app_slug": app.slug,
            "bastion_account_id": account.id,
            "status": result.status,
            "detail": result.detail,
        },
        ip_address=ip_address,
    )
    return result


async def sync_account_credentials_to_apps(
    db: Session,
    settings: Settings,
    *,
    account: BastionAccount,
    actor: str,
    ip_address: str | None = None,
    extra_group_names: list[str] | None = None,
) -> list[str]:
    """For each successful provisioning with vault override — push to the app."""
    errors: list[str] = []
    names = [n for n in (extra_group_names or []) if n]
    if account.organization and account.organization not in names:
        names = [account.organization, *names]
    for row in account.provisionings or []:
        if row.status != "success" or not row.application:
            continue
        app = row.application
        if not normalize_provisioning_driver(app.provisioning_driver):
            continue
        result = await sync_vault_credential_to_app(
            db,
            settings,
            account=account,
            app=app,
            actor=actor,
            ip_address=ip_address,
            group_names=names or None,
        )
        if result.status == PROVISIONING_FAILED:
            errors.append(f"{app.label or app.slug} : {result.detail}")
    return errors


async def delete_bastion_account(
    db: Session,
    settings: Settings,
    *,
    account: BastionAccount,
    actor: str,
    ip_address: str | None = None,
    force: bool = False,
) -> tuple[bool, list[str]]:
    """Full user cleanup — apps provisionnées → Keycloak → vault/grants → fiche.

    Order matters: application-local accounts first (CrushFTP…), then the
    Keycloak user, then local rows (vault credentials, RBAC user grants, and
    finally the BastionAccount itself, cascade provisionings).

    Returns ``(deleted, errors)``. Without ``force`` the bastion row is KEPT
    whenever a remote deletion failed — the fiche stays visible with
    ``last_error`` so the admin can fix and retry; never a silent partial
    delete. With ``force`` the local rows are removed anyway (orphans upstream
    are the admin's explicit choice, audited as such).
    """
    realm = account.realm or db.query(RealmConfig).filter_by(id=account.realm_id).first()
    target = (
        _account_target(realm, account.username)
        if realm
        else f"account:{account.username}"
    )
    errors: list[str] = []
    app_results: list[dict] = []

    # 1) Application-local accounts. Attempt for every row that reached a
    # driver (success OR failed — a failed create may still have left an
    # account upstream; drivers are idempotent and report "déjà absent").
    for row in list(account.provisionings or []):
        app = row.application or db.query(App).filter_by(id=row.application_id).first()
        if app is None:
            continue
        driver = get_provisioning_driver(
            normalize_provisioning_driver(app.provisioning_driver)
        )
        if driver is None or not hasattr(driver, "delete_account"):
            continue
        if row.status == PROVISIONING_NOT_APPLICABLE:
            continue
        try:
            result = await driver.delete_account(
                db=db, settings=settings, app=app, account=account
            )
        except Exception:
            logger.exception(
                "delete_account driver crashed app=%s account_id=%s",
                app.slug,
                account.id,
            )
            result = ProvisioningResult(
                status=PROVISIONING_FAILED,
                detail="Erreur interne du driver (voir logs serveur)",
            )
        app_results.append(
            {"app_slug": app.slug, "status": result.status, "detail": result.detail}
        )
        if result.status == PROVISIONING_FAILED:
            errors.append(f"{app.label or app.slug} : {result.detail}")
        log_action(
            db,
            actor=actor,
            action=(
                "account.app_deleted"
                if result.status != PROVISIONING_FAILED
                else "account.app_delete_failed"
            ),
            target=target,
            details={
                "app_slug": app.slug,
                "bastion_account_id": account.id,
                "status": result.status,
                "detail": result.detail,
            },
            ip_address=ip_address,
        )

    # 2) Keycloak user.
    keycloak_deleted: bool | None = None
    if account.keycloak_user_id:
        if realm is None:
            errors.append("Keycloak : realm introuvable pour ce compte")
        else:
            try:
                keycloak_deleted = await delete_keycloak_user(
                    realm, settings, keycloak_user_id=account.keycloak_user_id
                )
                log_action(
                    db,
                    actor=actor,
                    action="account.keycloak_deleted",
                    target=target,
                    details={
                        "bastion_account_id": account.id,
                        "keycloak_user_id": account.keycloak_user_id,
                        "already_absent": keycloak_deleted is False,
                    },
                    ip_address=ip_address,
                )
            except ValueError as exc:
                errors.append(f"Keycloak : {exc}")
                log_action(
                    db,
                    actor=actor,
                    action="account.keycloak_delete_failed",
                    target=target,
                    details={
                        "bastion_account_id": account.id,
                        "keycloak_user_id": account.keycloak_user_id,
                        "error": str(exc),
                    },
                    ip_address=ip_address,
                )

    if errors and not force:
        account.last_error = "Suppression incomplète : " + " ; ".join(errors)
        log_action(
            db,
            actor=actor,
            action="account.delete_incomplete",
            target=target,
            details={
                "bastion_account_id": account.id,
                "errors": errors,
                "app_results": app_results,
            },
            ip_address=ip_address,
        )
        db.commit()
        return False, errors

    # 3) Local rows — vault credentials + user grants + fiche bastion.
    vault_deleted = 0
    grants_deleted = 0
    if account.keycloak_user_id:
        vault_deleted = (
            db.query(UserAppCredential)
            .filter_by(keycloak_user_id=account.keycloak_user_id)
            .delete(synchronize_session=False)
        )
        grants_deleted = (
            db.query(AccessGrant)
            .filter_by(subject_type="user", keycloak_user_id=account.keycloak_user_id)
            .delete(synchronize_session=False)
        )

    log_action(
        db,
        actor=actor,
        action="account.deleted",
        target=target,
        details={
            "bastion_account_id": account.id,
            "username": account.username,
            "email": account.email,
            "keycloak_user_id": account.keycloak_user_id,
            "keycloak_deleted": keycloak_deleted,
            "vault_credentials_deleted": vault_deleted,
            "grants_deleted": grants_deleted,
            "app_results": app_results,
            "forced": bool(force and errors),
            "errors": errors,
        },
        ip_address=ip_address,
    )
    db.delete(account)  # cascade: BastionAccountProvisioning rows
    db.commit()
    return True, errors
