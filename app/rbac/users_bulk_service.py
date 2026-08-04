"""Bulk user operations for /admin/rbac/users (bastion accounts)."""

from __future__ import annotations

import csv
import io
from typing import Any, Literal

from sqlalchemy.orm import Session

from app.audit import log_action
from app.models import BastionAccount, RBACGroup, RealmConfig
from app.rbac.account_service import (
    AccountCreationError,
    assign_account_to_rbac_group,
    remove_account_from_rbac_group,
)
from app.rbac.users_list_service import query_bastion_accounts
from app.sso_settings import Settings

MAX_BULK_ACCOUNTS = 200

BulkGroupAction = Literal["add", "remove"]


def resolve_bastion_account_ids(
    db: Session,
    *,
    account_ids: list[int] | None,
    select_all_matching: bool,
    q: str | None,
    realm_id: int | None,
    group_name: str | None,
    status_filter: str | None,
) -> list[int]:
    """Resolve target account ids (explicit selection or full filtered set, capped)."""
    if select_all_matching:
        rows, _meta = query_bastion_accounts(
            db,
            q=q,
            realm_id=realm_id,
            group_name=group_name,
            status_filter=status_filter,
            page=1,
            page_size=MAX_BULK_ACCOUNTS,
        )
        return [int(a.id) for a in rows]

    cleaned: list[int] = []
    seen: set[int] = set()
    for raw in account_ids or []:
        try:
            aid = int(raw)
        except (TypeError, ValueError):
            continue
        if aid <= 0 or aid in seen:
            continue
        seen.add(aid)
        cleaned.append(aid)
        if len(cleaned) >= MAX_BULK_ACCOUNTS:
            break
    return cleaned


async def bulk_assign_or_remove_groups(
    db: Session,
    settings: Settings,
    *,
    account_ids: list[int],
    group_id: int,
    action: BulkGroupAction,
    actor: str,
    ip_address: str | None = None,
) -> dict[str, Any]:
    """Add/remove many bastion accounts to/from one RBAC group. Audits once."""
    if not account_ids:
        raise AccountCreationError("Aucun compte sélectionné")
    if len(account_ids) > MAX_BULK_ACCOUNTS:
        raise AccountCreationError(
            f"Trop de comptes (max {MAX_BULK_ACCOUNTS} par opération)"
        )

    group = db.query(RBACGroup).filter_by(id=group_id).first()
    if group is None:
        raise AccountCreationError("Groupe introuvable")

    accounts = (
        db.query(BastionAccount)
        .filter(BastionAccount.id.in_(account_ids))
        .all()
    )
    by_id = {a.id: a for a in accounts}
    ok: list[str] = []
    errors: list[dict[str, str]] = []

    for aid in account_ids:
        account = by_id.get(aid)
        if account is None:
            errors.append({"account_id": str(aid), "error": "Compte introuvable"})
            continue
        try:
            if action == "add":
                await assign_account_to_rbac_group(
                    db,
                    settings,
                    source_account=account,
                    group=group,
                    actor=actor,
                    ip_address=ip_address,
                )
            else:
                await remove_account_from_rbac_group(
                    db,
                    settings,
                    source_account=account,
                    group=group,
                    actor=actor,
                    ip_address=ip_address,
                )
            ok.append(account.username)
        except AccountCreationError as exc:
            errors.append(
                {
                    "account_id": str(aid),
                    "username": account.username,
                    "error": str(exc),
                }
            )

    log_action(
        db,
        actor=actor,
        action=(
            "users.bulk_group_add"
            if action == "add"
            else "users.bulk_group_remove"
        ),
        target=f"group:{group.name}",
        details={
            "group_id": group.id,
            "group": group.name,
            "action": action,
            "requested": len(account_ids),
            "ok_count": len(ok),
            "error_count": len(errors),
            "usernames_ok": ok[:50],
            "errors": errors[:20],
        },
        ip_address=ip_address,
    )
    db.commit()
    return {
        "ok_count": len(ok),
        "error_count": len(errors),
        "usernames_ok": ok,
        "errors": errors,
        "group": group.name,
        "action": action,
    }


def bastion_accounts_csv(
    db: Session,
    *,
    q: str | None = None,
    realm_id: int | None = None,
    group_name: str | None = None,
    status_filter: str | None = None,
    account_ids: list[int] | None = None,
) -> str:
    """CSV export for filtered bastion accounts (or explicit ids)."""
    if account_ids:
        rows = (
            db.query(BastionAccount)
            .filter(BastionAccount.id.in_(account_ids[:MAX_BULK_ACCOUNTS]))
            .order_by(BastionAccount.username)
            .all()
        )
    else:
        rows, _meta = query_bastion_accounts(
            db,
            q=q,
            realm_id=realm_id,
            group_name=group_name,
            status_filter=status_filter,
            page=1,
            page_size=MAX_BULK_ACCOUNTS,
        )

    realm_slugs = {
        r.id: r.slug
        for r in db.query(RealmConfig).filter(
            RealmConfig.id.in_({a.realm_id for a in rows if a.realm_id})
        ).all()
    }

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "id",
            "username",
            "email",
            "organization",
            "realm",
            "status",
            "keycloak_user_id",
        ]
    )
    for a in rows:
        writer.writerow(
            [
                a.id,
                a.username,
                a.email or "",
                a.organization or "",
                realm_slugs.get(a.realm_id, a.realm_id or ""),
                a.status or "",
                a.keycloak_user_id or "",
            ]
        )
    return buf.getvalue()
