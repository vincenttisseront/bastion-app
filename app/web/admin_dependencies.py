"""Admin Dependencies inventory — Python + npm packages."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.admin.dependencies_service import (
    ManifestMissingError,
    count_summary,
    last_checked_summary,
    list_snapshots,
    refresh_latest_versions,
    snapshots_to_export,
)
from app.database import get_db
from app.sso_settings import Settings, get_settings
from app.web.constants import APP_VERSION
from app.web.flash import base_template_context, flash_redirect
from app.web.templates import render
from app.web.user_context import require_admin

router = APIRouter(tags=["admin-dependencies"], dependencies=[Depends(require_admin)])

_STATUS_LABELS = {
    "up_to_date": "À jour",
    "outdated_patch": "patch",
    "outdated_minor": "minor",
    "outdated_major": "major",
    "unknown": "n/a",
}

_STATUS_BADGE = {
    "up_to_date": "ok",
    "outdated_patch": "warn",
    "outdated_minor": "warn",
    "outdated_major": "err",
    "unknown": "muted",
}

_TYPE_LABELS = {
    "runtime": "prod",
    "dev": "dev",
}


def _row_view(row) -> dict:
    outdated = (row.status or "").startswith("outdated_")
    is_direct = bool(getattr(row, "is_direct", True))
    return {
        "ecosystem": row.ecosystem,
        "name": row.name,
        "dep_type": row.dep_type,
        "type_label": _TYPE_LABELS.get(row.dep_type, row.dep_type),
        "is_direct": is_direct,
        "direct_label": "direct" if is_direct else "transitif",
        "declared_version": row.declared_version or "",
        "current_version": row.current_version,
        "latest_version": row.latest_version or "",
        "status": row.status,
        "status_label": _STATUS_LABELS.get(row.status, row.status),
        "badge": _STATUS_BADGE.get(row.status, "muted"),
        "notes": row.notes or "",
        "check_error": row.check_error or "",
        "last_checked_at": (
            row.last_checked_at.strftime("%Y-%m-%d %H:%M UTC") if row.last_checked_at else ""
        ),
        "is_major": row.status == "outdated_major",
        "is_outdated": outdated,
    }


@router.get("/admin/dependencies")
def admin_dependencies_page(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    rows = list_snapshots(db)
    python_rows = [_row_view(r) for r in rows if r.ecosystem == "python"]
    npm_rows = [_row_view(r) for r in rows if r.ecosystem == "npm"]
    last_at = last_checked_summary(rows)
    summary = count_summary(rows)
    ctx = base_template_context(request, settings, APP_VERSION)
    return render(
        "admin/dependencies.html",
        **ctx,
        python_packages=python_rows,
        npm_packages=npm_rows,
        python_count=len(python_rows),
        npm_count=len(npm_rows),
        summary=summary,
        last_checked_at=last_at.strftime("%Y-%m-%d %H:%M UTC") if last_at else None,
        has_snapshots=bool(rows),
    )


@router.post("/admin/dependencies/refresh")
def admin_dependencies_refresh(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    token = settings.vault_portal_internal_token or "dev"
    response = RedirectResponse(url="/admin/dependencies", status_code=302)
    try:
        result = refresh_latest_versions(db)
    except ManifestMissingError as exc:
        flash_redirect(response, str(exc), "error", token)
        return response
    if result.get("throttled"):
        flash_redirect(response, result["message"], "error", token)
    elif result.get("errors"):
        flash_redirect(
            response,
            f"{result['message']} — certains paquets sont restés en statut inconnu.",
            "error",
            token,
        )
    else:
        flash_redirect(response, result["message"], "success", token)
    return response


@router.get("/admin/dependencies/export.json")
def admin_dependencies_export(
    status: str | None = Query(None),
    db: Session = Depends(get_db),
    _user=Depends(require_admin),
):
    outdated_only = status in ("outdated", "outdated_only")
    rows = list_snapshots(db, outdated_only=outdated_only)
    payload = snapshots_to_export(rows)
    date_stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    suffix = "-outdated" if outdated_only else ""
    filename = f"bastion-dependencies{suffix}-{date_stamp}.json"
    return JSONResponse(
        content=payload,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )
