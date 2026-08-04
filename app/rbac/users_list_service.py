"""Pagination / filtering helpers for /admin/rbac/users (search-first)."""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, or_
from sqlalchemy.orm import Session, joinedload

from app.models import BastionAccount, BastionAccountProvisioning


DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 100


def clamp_page_size(raw: int | None) -> int:
    try:
        value = int(raw if raw is not None else DEFAULT_PAGE_SIZE)
    except (TypeError, ValueError):
        value = DEFAULT_PAGE_SIZE
    return max(1, min(MAX_PAGE_SIZE, value))


def clamp_page(page: int | None, *, total_pages: int) -> int:
    try:
        value = int(page if page is not None else 1)
    except (TypeError, ValueError):
        value = 1
    return max(1, min(max(1, total_pages), value))


def pagination_meta(*, total: int, page: int, page_size: int) -> dict[str, Any]:
    total_pages = max(1, (max(0, total) + page_size - 1) // page_size) if total else 1
    page = clamp_page(page, total_pages=total_pages)
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "offset": (page - 1) * page_size,
    }


def query_bastion_accounts(
    db: Session,
    *,
    q: str | None = None,
    realm_id: int | None = None,
    group_name: str | None = None,
    status_filter: str | None = None,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> tuple[list[BastionAccount], dict[str, Any]]:
    """Filter + paginate bastion-created accounts (origin bastion)."""
    page_size = clamp_page_size(page_size)
    query = db.query(BastionAccount).options(
        joinedload(BastionAccount.realm),
        joinedload(BastionAccount.provisionings).joinedload(
            BastionAccountProvisioning.application
        ),
    )
    if realm_id is not None:
        query = query.filter(BastionAccount.realm_id == realm_id)
    needle = (q or "").strip()
    if needle:
        like = f"%{needle}%"
        query = query.filter(
            or_(
                BastionAccount.username.ilike(like),
                BastionAccount.email.ilike(like),
                BastionAccount.organization.ilike(like),
                BastionAccount.first_name.ilike(like),
                BastionAccount.last_name.ilike(like),
            )
        )
    group = (group_name or "").strip()
    if group:
        query = query.filter(BastionAccount.organization.ilike(f"%{group}%"))
    status = (status_filter or "tous").strip().lower()
    if status == "actifs":
        query = query.filter(
            BastionAccount.status.in_(("keycloak_created", "provisioned"))
        )
    elif status == "privilegies":
        # Bastion list has no portal_admin flag — empty set keeps UX honest.
        query = query.filter(BastionAccount.id < 0)

    total = query.with_entities(func.count(BastionAccount.id)).scalar() or 0
    meta = pagination_meta(total=int(total), page=page, page_size=page_size)
    rows = (
        query.order_by(BastionAccount.created_at.desc())
        .offset(meta["offset"])
        .limit(page_size)
        .all()
    )
    return rows, meta


def paginate_list(
    items: list[Any],
    *,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> tuple[list[Any], dict[str, Any]]:
    page_size = clamp_page_size(page_size)
    meta = pagination_meta(total=len(items), page=page, page_size=page_size)
    start = meta["offset"]
    return items[start : start + page_size], meta


def filter_import_users(
    users: list[dict[str, Any]],
    *,
    q: str | None = None,
) -> list[dict[str, Any]]:
    needle = (q or "").strip().casefold()
    if not needle:
        return users
    out: list[dict[str, Any]] = []
    for u in users:
        hay = " ".join(
            str(u.get(k) or "")
            for k in ("display", "keycloak_user_id", "email", "username")
        ).casefold()
        if needle in hay:
            out.append(u)
    return out
