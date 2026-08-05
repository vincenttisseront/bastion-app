"""RBAC group lifecycle helpers (empty-group deletion, etc.)."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.audit import log_action
from app.models import (
    AccessGrant,
    BastionAccount,
    FileChannelAssignment,
    GroupAppCredential,
    RBACGroup,
    RealmConfig,
)
from app.rbac.keycloak_admin import delete_keycloak_group, fetch_group_members
from app.sso_settings import Settings


class GroupNotEmptyError(ValueError):
    """Raised when a group still has members or subgroups and cannot be deleted."""


def group_has_local_children(db: Session, group: RBACGroup) -> bool:
    """True when another synced group is nested under this group's path."""
    path = (group.path or "").rstrip("/")
    if not path or not group.realm_id:
        return False
    prefix = f"{path}/"
    return (
        db.query(RBACGroup.id)
        .filter(
            RBACGroup.realm_id == group.realm_id,
            RBACGroup.id != group.id,
            RBACGroup.path.is_not(None),
            RBACGroup.path.like(f"{prefix}%"),
        )
        .first()
        is not None
    )


async def assert_group_is_empty(
    db: Session,
    group: RBACGroup,
    realm: RealmConfig,
    settings: Settings,
    *,
    live_members: list | None = None,
) -> None:
    """Raise GroupNotEmptyError unless the group has zero members and no subgroups."""
    if group_has_local_children(db, group):
        raise GroupNotEmptyError(
            "Ce groupe a des sous-groupes — retirez-les d'abord dans Keycloak."
        )

    members = live_members
    if members is None and group.keycloak_group_id:
        try:
            members = await fetch_group_members(realm, group.keycloak_group_id, settings)
        except Exception as exc:
            # Fall back to cached count only when Keycloak is unreachable.
            cached = group.member_count
            if cached is not None and int(cached) > 0:
                raise GroupNotEmptyError(
                    f"Ce groupe a encore {int(cached)} membre(s) (compteur local)."
                ) from exc
            if cached is None:
                raise GroupNotEmptyError(
                    "Impossible de vérifier les membres Keycloak — "
                    "réessayez ou synchronisez les groupes."
                ) from exc
            members = []

    count = len(members) if members is not None else int(group.member_count or 0)
    if count > 0:
        raise GroupNotEmptyError(
            f"Ce groupe a encore {count} membre(s) — retirez-les avant de supprimer."
        )
    if group.member_count is not None and int(group.member_count) > 0:
        raise GroupNotEmptyError(
            f"Ce groupe a encore {int(group.member_count)} membre(s) (compteur local)."
        )


def _scrub_pending_group_ids(db: Session, group_id: int) -> int:
    """Remove ``group_id`` from BastionAccount.pending_group_ids JSON lists."""
    touched = 0
    accounts = (
        db.query(BastionAccount)
        .filter(BastionAccount.pending_group_ids.is_not(None))
        .all()
    )
    for account in accounts:
        raw = account.pending_group_ids
        if not isinstance(raw, list):
            continue
        cleaned = [gid for gid in raw if gid != group_id and str(gid) != str(group_id)]
        if cleaned != raw:
            account.pending_group_ids = cleaned or None
            touched += 1
    return touched


async def delete_empty_rbac_group(
    db: Session,
    settings: Settings,
    *,
    group: RBACGroup,
    realm: RealmConfig,
    actor: str,
    ip_address: str | None = None,
    live_members: list | None = None,
    force_local: bool = False,
) -> dict:
    """Delete an empty group in Keycloak (if linked) then purge local Bastion rows.

    Only groups with zero members and no local subgroups may be deleted.
    Associated AccessGrant / shared credentials / file channel rows are removed.
    """
    await assert_group_is_empty(
        db, group, realm, settings, live_members=live_members
    )

    details: dict = {
        "group_id": group.id,
        "name": group.name,
        "path": group.path,
        "realm_id": realm.id,
        "keycloak_group_id": group.keycloak_group_id,
        "force_local": bool(force_local),
    }

    keycloak_deleted = False
    if group.keycloak_group_id:
        try:
            keycloak_deleted = await delete_keycloak_group(
                realm,
                settings,
                keycloak_group_id=group.keycloak_group_id,
            )
        except ValueError:
            if not force_local:
                raise
            details["keycloak_error"] = "force_local after Keycloak failure"
        details["keycloak_deleted"] = keycloak_deleted

    grants = (
        db.query(AccessGrant).filter(AccessGrant.rbac_group_id == group.id).all()
    )
    details["grants_deleted"] = len(grants)
    for grant in grants:
        db.delete(grant)

    creds = (
        db.query(GroupAppCredential)
        .filter(GroupAppCredential.rbac_group_id == group.id)
        .all()
    )
    details["credentials_deleted"] = len(creds)
    for cred in creds:
        db.delete(cred)

    assignments = (
        db.query(FileChannelAssignment)
        .filter(FileChannelAssignment.rbac_group_id == group.id)
        .all()
    )
    details["file_assignments_deleted"] = len(assignments)
    for row in assignments:
        db.delete(row)

    details["pending_scrubbed"] = _scrub_pending_group_ids(db, group.id)

    db.delete(group)
    db.flush()

    log_action(
        db,
        actor=actor,
        action="rbac.group.deleted",
        target=f"group:{details['group_id']}:{details.get('name')}",
        details=details,
        ip_address=ip_address,
    )
    return details
