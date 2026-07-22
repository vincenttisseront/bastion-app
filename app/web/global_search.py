"""Global search API — role-filtered results for the topbar modal."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.audit import list_audit_entries
from app.database import get_db
from app.models import App, RBACGroup, RealmConfig
from app.rbac.effective_access_service import get_effective_apps_for_user
from app.rbac.grants_service import serialize_user_search_result
from app.rbac.keycloak_admin import search_keycloak_users_fuzzy
from app.search_fuzzy import score_query_against_fields
from app.sso_settings import Settings, get_settings
from app.web.user_context import UserContext, is_portal_admin, require_user

logger = logging.getLogger(__name__)

router = APIRouter(tags=["search"])

MIN_QUERY_LEN = 2
RESULT_LIMIT = 8
MIN_SCORE = 0.52
AUDIT_LOOKBACK_DAYS = 30

CATEGORY_LABELS = {
    "applications": "Applications",
    "users": "Utilisateurs",
    "groups": "Groupes",
    "sessions": "Sessions",
    "realms": "Realms",
    "audit": "Audit",
}


def _hit(label: str, url: str, *, sublabel: str | None = None) -> dict[str, str]:
    item = {"label": label, "url": url}
    if sublabel:
        item["sublabel"] = sublabel
    return item


def _search_applications(db: Session, user: UserContext, q: str) -> list[dict[str, str]]:
    entries = get_effective_apps_for_user(
        db,
        keycloak_user_id=user.keycloak_user_id,
        group_names=user.groups,
    )
    scored: list[tuple[float, dict[str, str]]] = []
    for entry in entries:
        app: App = entry.app
        if not app.enabled:
            continue
        score = score_query_against_fields(
            q,
            [app.label or "", app.description or "", app.slug or ""],
        )
        if score < MIN_SCORE:
            continue
        scored.append(
            (
                score,
                _hit(
                    app.label or app.slug,
                    f"/apps#app-{app.slug}",
                    sublabel=(app.description or "").strip() or None,
                ),
            )
        )
    scored.sort(key=lambda pair: (-pair[0], pair[1]["label"].casefold()))
    return [item for _, item in scored[:RESULT_LIMIT]]


def _search_groups(db: Session, q: str) -> list[dict[str, str]]:
    groups = db.query(RBACGroup).order_by(RBACGroup.name).all()
    realms = {
        r.id: r for r in db.query(RealmConfig).all()
    }
    scored: list[tuple[float, dict[str, str]]] = []
    for g in groups:
        realm_slug = ""
        if g.realm_id and g.realm_id in realms:
            realm_slug = realms[g.realm_id].slug or ""
        elif g.realm_slug:
            realm_slug = g.realm_slug
        score = score_query_against_fields(
            q,
            [g.name or "", g.path or "", realm_slug],
        )
        if score < MIN_SCORE:
            continue
        scored.append(
            (
                score,
                _hit(
                    g.name,
                    f"/admin/rbac/groups/{g.id}",
                    sublabel=g.path or realm_slug or None,
                ),
            )
        )
    scored.sort(key=lambda pair: (-pair[0], pair[1]["label"].casefold()))
    return [item for _, item in scored[:RESULT_LIMIT]]


def _search_realms(db: Session, q: str) -> list[dict[str, str]]:
    realms = db.query(RealmConfig).order_by(RealmConfig.slug).all()
    scored: list[tuple[float, dict[str, str]]] = []
    for r in realms:
        score = score_query_against_fields(q, [r.name or "", r.slug or ""])
        if score < MIN_SCORE:
            continue
        scored.append(
            (
                score,
                _hit(r.name or r.slug, f"/admin/realms/{r.id}/edit", sublabel=r.slug),
            )
        )
    scored.sort(key=lambda pair: (-pair[0], pair[1]["label"].casefold()))
    return [item for _, item in scored[:RESULT_LIMIT]]


def _search_sessions(db: Session, q: str) -> list[dict[str, str]]:
    from app.models import ActiveSession
    from app.web.sessions_service import expire_stale_sessions

    expire_stale_sessions(db)
    rows = (
        db.query(ActiveSession)
        .order_by(ActiveSession.last_seen_at.desc())
        .limit(200)
        .all()
    )
    scored: list[tuple[float, dict[str, str]]] = []
    for row in rows:
        score = score_query_against_fields(
            q,
            [
                row.username or "",
                row.user_email or "",
                row.target or "",
                row.source_ip or "",
                row.realm or "",
            ],
        )
        if score < MIN_SCORE:
            continue
        label = row.username or row.user_email or "Session"
        sub = row.target or row.kind
        scored.append((score, _hit(str(label), "/sessions", sublabel=sub)))
    scored.sort(key=lambda pair: (-pair[0], pair[1]["label"].casefold()))
    return [item for _, item in scored[:RESULT_LIMIT]]


def _search_audit(db: Session, q: str) -> list[dict[str, str]]:
    now = datetime.now(timezone.utc)
    date_from = now - timedelta(days=AUDIT_LOOKBACK_DAYS)
    entries, _total = list_audit_entries(
        db, date_from=date_from, limit=200, offset=0
    )
    scored: list[tuple[float, dict[str, str]]] = []
    for e in entries:
        score = score_query_against_fields(
            q,
            [
                e.get("action") or "",
                e.get("target") or "",
                e.get("user") or "",
                e.get("ip_address") or "",
            ],
        )
        if score < MIN_SCORE:
            continue
        label = e.get("action") or "audit"
        sub_parts = [p for p in (e.get("user"), e.get("target")) if p]
        scored.append(
            (
                score,
                _hit(str(label), "/audit", sublabel=" — ".join(sub_parts) or None),
            )
        )
    scored.sort(key=lambda pair: (-pair[0], pair[1]["label"].casefold()))
    return [item for _, item in scored[:RESULT_LIMIT]]


async def _search_users(
    db: Session, settings: Settings, q: str
) -> list[dict[str, str]]:
    realms = (
        db.query(RealmConfig)
        .filter_by(groups_sync_enabled=True)
        .order_by(RealmConfig.slug)
        .all()
    )
    by_id: dict[str, tuple[float, dict, RealmConfig]] = {}
    for realm in realms:
        try:
            found = await search_keycloak_users_fuzzy(
                realm, q, settings, limit=RESULT_LIMIT
            )
        except ValueError:
            logger.debug("global search users skipped realm=%s", realm.slug, exc_info=True)
            continue
        except Exception:
            logger.exception("global search users failed realm=%s", realm.slug)
            continue
        for u in found:
            uid = u.get("id")
            if not isinstance(uid, str) or not uid:
                continue
            score = score_query_against_fields(
                q,
                [
                    u.get("username") or "",
                    u.get("email") or "",
                    u.get("firstName") or "",
                    u.get("lastName") or "",
                ],
            )
            prev = by_id.get(uid)
            if prev is None or score > prev[0]:
                by_id[uid] = (score, u, realm)

    ranked = sorted(by_id.values(), key=lambda t: (-t[0], t[1].get("username") or ""))
    out: list[dict[str, str]] = []
    for score, user, realm in ranked[:RESULT_LIMIT]:
        if score < MIN_SCORE:
            continue
        ser = serialize_user_search_result(user)
        out.append(
            _hit(
                ser.get("display") or ser.get("username") or "user",
                f"/admin/rbac/users?realm_id={realm.id}&keycloak_user_id={user.get('id')}",
                sublabel=ser.get("email") or realm.slug,
            )
        )
    return out


@router.get("/api/search")
async def global_search(
    request: Request,
    q: str = Query(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user),
):
    """
    Unified search for the topbar modal.

    Always returns ``applications`` (effective access = same as /apps).
    Admin-only keys (users, groups, sessions, realms, audit) are omitted entirely
    for non-admins — never empty stubs that could leak category existence.
    """
    query = (q or "").strip()
    if len(query) < MIN_QUERY_LEN:
        return JSONResponse({"ok": True, "results": {}})

    admin = is_portal_admin(user, db, settings)
    results: dict[str, Any] = {
        "applications": _search_applications(db, user, query),
    }

    if admin:
        results["groups"] = _search_groups(db, query)
        results["realms"] = _search_realms(db, query)
        results["sessions"] = _search_sessions(db, query)
        results["audit"] = _search_audit(db, query)
        results["users"] = await _search_users(db, settings, query)

    # Drop empty admin categories to keep the payload tight for the UI iterator.
    if admin:
        results = {k: v for k, v in results.items() if v or k == "applications"}

    return JSONResponse(
        {
            "ok": True,
            "results": results,
            "category_labels": {
                k: CATEGORY_LABELS[k] for k in results if k in CATEGORY_LABELS
            },
        }
    )
