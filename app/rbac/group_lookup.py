"""Resolve OIDC ``groups`` claim names to RBACGroup rows of one realm."""

from __future__ import annotations

from typing import Sequence

from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session

from app.models import RBACGroup, RealmConfig
from app.realm_lookup import find_realm


def _session_realm(db: Session, realm_slug: str | None) -> RealmConfig | None:
    if realm_slug and realm_slug.strip():
        return find_realm(db, realm_slug)
    return db.query(RealmConfig).filter_by(is_default=True).first()


def resolve_rbac_groups(
    db: Session,
    *,
    realm_slug: str | None,
    group_names: Sequence[str] | None,
) -> list[RBACGroup]:
    """Groups of the session realm whose name matches the claim (case-insensitive).

    Group names are only unique per realm: a token from realm A must never pick
    up grants of a same-named group in realm B. Groups without ``realm_id``
    (manual, pre multi-realm) match through ``realm_slug``, or the default realm
    when they carry no realm at all. Without ``realm_slug`` the default realm is
    assumed.
    """
    names = {n.strip().lower() for n in (group_names or []) if n and n.strip()}
    if not names:
        return []
    realm = _session_realm(db, realm_slug)
    slug = (realm.slug if realm else (realm_slug or "")).strip().lower()
    unscoped = and_(RBACGroup.realm_id.is_(None), RBACGroup.realm_slug.is_(None))
    legacy = and_(
        RBACGroup.realm_id.is_(None),
        func.lower(RBACGroup.realm_slug) == slug,
    )
    if realm is None:
        scope = or_(unscoped, legacy) if slug else unscoped
    else:
        scope = or_(RBACGroup.realm_id == realm.id, legacy)
        if realm.is_default:
            scope = or_(scope, unscoped)
    return (
        db.query(RBACGroup)
        .filter(scope, func.lower(RBACGroup.name).in_(names))
        .all()
    )
