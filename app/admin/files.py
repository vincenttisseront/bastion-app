"""Admin — versioned file catalogue (CRUD, versions, beta channel, grants)."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.audit import log_action
from app.database import get_db
from app.files.service import (
    archive_file_version,
    assign_beta_channel,
    create_file_resource,
    delete_channel_assignment,
    promote_file_version,
    resolve_storage_path,
    store_file_version,
)
from app.models import FileChannelAssignment, FileResource, FileVersion, RBACGroup, RealmConfig
from app.rbac.grants_service import ACCESS_LEVELS, build_file_access_view
from app.request_client_ip import client_ip_from_request
from app.search_fuzzy import score_query_against_fields
from app.sso_settings import Settings, get_settings
from app.web.flash import flash_redirect
from app.web.templates import render
from app.web.user_context import require_admin

logger = logging.getLogger(__name__)

router = APIRouter(tags=["admin-files"], dependencies=[Depends(require_admin)])

_RESOLVE_MIN_SCORE = 0.52
_RESOLVE_STRONG_SCORE = 0.78
_RESOLVE_LIMIT = 8


def _ctx(request: Request, settings: Settings, **extra):
    from app.web.constants import APP_VERSION
    from app.web.flash import base_template_context

    return base_template_context(request, settings, APP_VERSION, **extra)


def _client_ip(request: Request) -> str:
    return client_ip_from_request(request)


def _wants_json(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return (
        "application/json" in accept
        or request.headers.get("x-requested-with") == "XMLHttpRequest"
    )


def _file_catalogue_rows(db: Session) -> list[dict]:
    files = db.query(FileResource).order_by(FileResource.label).all()
    rows = []
    for fr in files:
        versions = (
            db.query(FileVersion)
            .filter_by(file_id=fr.id, status="active")
            .order_by(FileVersion.uploaded_at.desc())
            .all()
        )
        stable = next((v for v in versions if v.channel == "stable"), None)
        beta = next((v for v in versions if v.channel == "beta"), None)
        rows.append(
            {
                "id": fr.id,
                "slug": fr.slug,
                "label": fr.label,
                "description": fr.description,
                "is_active": fr.is_active,
                "stable_label": stable.version_label if stable else None,
                "beta_label": beta.version_label if beta else None,
                "version_count": len(versions),
            }
        )
    return rows


def _unlink_blob(storage_path: str | None, settings: Settings) -> None:
    if not storage_path:
        return
    try:
        resolve_storage_path(storage_path, settings).unlink(missing_ok=True)
    except (OSError, ValueError):
        logger.exception("failed to clean orphan blob path=%s", storage_path)


def _file_or_404(db: Session, file_id: int) -> FileResource:
    fr = db.query(FileResource).filter_by(id=file_id).first()
    if not fr:
        raise HTTPException(status_code=404, detail="Fichier introuvable")
    return fr


def _version_or_404(db: Session, file_id: int, version_id: int) -> FileVersion:
    version = db.query(FileVersion).filter_by(id=version_id, file_id=file_id).first()
    if not version:
        raise HTTPException(status_code=404, detail="Version introuvable")
    return version


@router.get("/admin/files")
def admin_files_list(
    request: Request,
    folder_id: int | None = None,
):
    """CrushFTP browser lives at /files — keep admin URL as redirect."""
    qs = f"?folder_id={folder_id}" if folder_id is not None else ""
    return RedirectResponse(url=f"/files{qs}", status_code=302)


@router.get("/admin/files/resolve-name")
def admin_files_resolve_name(
    q: str = Query("", min_length=0),
    db: Session = Depends(get_db),
    _user=Depends(require_admin),
):
    """Deprecated — kept for compatibility; prefer folder browser deposit."""
    query = (q or "").strip()
    if not query:
        return JSONResponse({"ok": True, "results": [], "best": None})

    scored: list[tuple[float, dict]] = []
    for fr in db.query(FileResource).order_by(FileResource.label).all():
        score = score_query_against_fields(query, [fr.label or "", fr.slug or ""])
        if score < _RESOLVE_MIN_SCORE:
            continue
        scored.append(
            (
                score,
                {
                    "id": fr.id,
                    "slug": fr.slug,
                    "label": fr.label,
                    "description": fr.description,
                    "score": round(score, 3),
                },
            )
        )
    scored.sort(key=lambda pair: (-pair[0], (pair[1]["label"] or "").casefold()))
    results = [item for _, item in scored[:_RESOLVE_LIMIT]]
    best = results[0] if results and results[0]["score"] >= _RESOLVE_STRONG_SCORE else None
    return JSONResponse({"ok": True, "results": results, "best": best})


@router.post("/admin/files/deposit")
async def admin_files_deposit(
    request: Request,
    mode: str = Form(...),
    version_label: str = Form(...),
    channel: str = Form("stable"),
    changelog: str = Form(""),
    upload: UploadFile = File(...),
    file_id: int | None = Form(None),
    label: str = Form(""),
    slug: str = Form(""),
    description: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    """Legacy composite deposit — prefer POST /files/upload."""
    mode_norm = (mode or "").strip().lower()
    if mode_norm not in ("new", "existing"):
        detail = 'mode must be "new" or "existing"'
        if _wants_json(request):
            return JSONResponse({"ok": False, "detail": detail}, status_code=400)
        raise HTTPException(status_code=400, detail=detail)

    data = await upload.read()
    created_resource = False
    written_path: str | None = None
    fr: FileResource | None = None
    version: FileVersion | None = None

    try:
        if mode_norm == "new":
            fr = create_file_resource(
                db,
                slug=slug or None,
                label=label,
                description=description or None,
                created_by=user.email,
            )
            created_resource = True
        else:
            if not file_id:
                raise ValueError("file_id is required when mode=existing")
            fr = db.query(FileResource).filter_by(id=file_id).first()
            if not fr:
                raise ValueError("Fichier introuvable")

        version = store_file_version(
            db,
            file=fr,
            channel=channel,
            version_label=version_label,
            filename=upload.filename or "upload.bin",
            content_type=upload.content_type,
            data=data,
            uploaded_by=user.email,
            changelog=changelog or None,
            settings=settings,
            encrypt=True,
        )
        written_path = version.storage_path
        db.commit()
    except ValueError as exc:
        db.rollback()
        _unlink_blob(written_path, settings)
        if _wants_json(request):
            return JSONResponse({"ok": False, "detail": str(exc)}, status_code=400)
        response = RedirectResponse(url="/files", status_code=302)
        flash_redirect(
            response, str(exc), "error", settings.vault_portal_internal_token or "dev"
        )
        return response
    except Exception:
        db.rollback()
        _unlink_blob(written_path, settings)
        logger.exception("deposit failed")
        if _wants_json(request):
            return JSONResponse({"ok": False, "detail": "Échec du dépôt"}, status_code=500)
        raise

    assert fr is not None and version is not None
    if created_resource:
        log_action(
            db,
            actor=user.email,
            action="file.created",
            target=f"file:{fr.id}",
            details={"slug": fr.slug, "label": fr.label, "via": "deposit"},
            ip_address=_client_ip(request),
        )
    log_action(
        db,
        actor=user.email,
        action="file.version.published",
        target=f"file:{fr.id}:version:{version.id}",
        details={
            "channel": version.channel,
            "version_label": version.version_label,
            "checksum_sha256": version.checksum_sha256,
            "size_bytes": version.size_bytes,
            "original_filename": version.original_filename,
            "encrypted": version.encrypted,
            "via": "deposit",
            "mode": mode_norm,
        },
        ip_address=_client_ip(request),
    )

    payload = {
        "ok": True,
        "file": {"id": fr.id, "slug": fr.slug, "label": fr.label},
        "version": {
            "id": version.id,
            "version_label": version.version_label,
            "channel": version.channel,
        },
        "message": f"Version {version.version_label} publiée sur {fr.label}",
        "files": _file_catalogue_rows(db),
    }
    if _wants_json(request):
        return JSONResponse(payload)

    response = RedirectResponse(url=f"/admin/files/{fr.id}", status_code=302)
    flash_redirect(
        response,
        payload["message"],
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@router.post("/admin/files")
async def admin_files_create(
    request: Request,
    slug: str = Form(...),
    label: str = Form(...),
    description: str = Form(""),
    category: str = Form(""),
    is_active: str | None = Form(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    try:
        fr = create_file_resource(
            db,
            slug=slug,
            label=label,
            description=description or None,
            category=category or None,
            is_active=is_active is not None and is_active != "0",
            created_by=user.email,
        )
        db.commit()
    except ValueError as exc:
        response = RedirectResponse(url="/admin/files", status_code=302)
        flash_redirect(
            response, str(exc), "error", settings.vault_portal_internal_token or "dev"
        )
        return response

    log_action(
        db,
        actor=user.email,
        action="file.created",
        target=f"file:{fr.id}",
        details={"slug": fr.slug, "label": fr.label},
        ip_address=_client_ip(request),
    )
    response = RedirectResponse(url=f"/admin/files/{fr.id}", status_code=302)
    flash_redirect(
        response, "Fichier créé.", "success", settings.vault_portal_internal_token or "dev"
    )
    return response


@router.get("/admin/files/{file_id}")
async def admin_files_detail(
    file_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    fr = _file_or_404(db, file_id)
    versions = (
        db.query(FileVersion)
        .filter_by(file_id=fr.id)
        .order_by(FileVersion.uploaded_at.desc())
        .all()
    )
    access = await build_file_access_view(db, fr.id, settings)
    beta_rows = (
        db.query(FileChannelAssignment)
        .filter_by(file_id=fr.id)
        .order_by(FileChannelAssignment.assigned_at.desc())
        .all()
    )
    beta_testers = []
    for row in beta_rows:
        group_name = None
        if row.rbac_group_id:
            group = db.query(RBACGroup).filter_by(id=row.rbac_group_id).first()
            group_name = group.name if group else None
        beta_testers.append(
            {
                "id": row.id,
                "subject_type": row.subject_type,
                "rbac_group_id": row.rbac_group_id,
                "group_name": group_name,
                "keycloak_user_id": row.keycloak_user_id,
                "user_display_cache": row.user_display_cache,
                "assigned_by": row.assigned_by,
                "assigned_at": row.assigned_at.isoformat() if row.assigned_at else None,
            }
        )
    groups = db.query(RBACGroup).order_by(RBACGroup.name).all()
    realms = (
        db.query(RealmConfig).filter_by(enabled=True).order_by(RealmConfig.slug).all()
    )
    return render(
        "admin/files/detail.html",
        **_ctx(
            request,
            settings,
            file=fr,
            versions=versions,
            grant_rows=access["grants"],
            grant_count=access["grant_count"],
            unique_people_count=access["unique_people_count"],
            people_sources=access["people_sources"],
            beta_testers=beta_testers,
            groups=groups,
            realms=realms,
            access_levels=sorted(ACCESS_LEVELS),
        ),
    )


@router.post("/admin/files/{file_id}/edit")
async def admin_files_edit(
    file_id: int,
    request: Request,
    label: str = Form(...),
    description: str = Form(""),
    category: str = Form(""),
    is_active: str | None = Form(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    fr = _file_or_404(db, file_id)
    fr.label = (label or "").strip() or fr.label
    fr.description = (description or "").strip() or None
    fr.category = (category or "").strip() or None
    fr.is_active = is_active is not None and is_active != "0"
    db.commit()
    log_action(
        db,
        actor=user.email,
        action="file.updated",
        target=f"file:{fr.id}",
        details={"slug": fr.slug, "label": fr.label, "is_active": fr.is_active},
        ip_address=_client_ip(request),
    )
    response = RedirectResponse(url=f"/admin/files/{fr.id}", status_code=302)
    flash_redirect(
        response,
        "Fichier mis à jour.",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@router.post("/admin/files/{file_id}/delete")
async def admin_files_delete(
    file_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    fr = _file_or_404(db, file_id)
    slug = fr.slug
    db.delete(fr)
    db.commit()
    log_action(
        db,
        actor=user.email,
        action="file.deleted",
        target=f"file:{file_id}",
        details={"slug": slug},
        ip_address=_client_ip(request),
    )
    response = RedirectResponse(url="/admin/files", status_code=302)
    flash_redirect(
        response,
        "Fichier supprimé.",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@router.post("/admin/files/{file_id}/versions")
async def admin_files_upload_version(
    file_id: int,
    request: Request,
    channel: str = Form(...),
    version_label: str = Form(...),
    changelog: str = Form(""),
    upload: UploadFile = File(...),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    fr = _file_or_404(db, file_id)
    data = await upload.read()
    try:
        version = store_file_version(
            db,
            file=fr,
            channel=channel,
            version_label=version_label,
            filename=upload.filename or "upload.bin",
            content_type=upload.content_type,
            data=data,
            uploaded_by=user.email,
            changelog=changelog or None,
            settings=settings,
            encrypt=True,
        )
        db.commit()
    except ValueError as exc:
        response = RedirectResponse(url=f"/admin/files/{fr.id}", status_code=302)
        flash_redirect(
            response, str(exc), "error", settings.vault_portal_internal_token or "dev"
        )
        return response

    log_action(
        db,
        actor=user.email,
        action="file.version.published",
        target=f"file:{fr.id}:version:{version.id}",
        details={
            "channel": version.channel,
            "version_label": version.version_label,
            "checksum_sha256": version.checksum_sha256,
            "size_bytes": version.size_bytes,
            "original_filename": version.original_filename,
            "encrypted": version.encrypted,
        },
        ip_address=_client_ip(request),
    )
    response = RedirectResponse(url=f"/admin/files/{fr.id}", status_code=302)
    flash_redirect(
        response,
        f"Version {version.version_label} ({version.channel}) publiée.",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@router.post("/admin/files/{file_id}/versions/{version_id}/promote")
@router.patch("/admin/files/{file_id}/versions/{version_id}")
async def admin_files_promote_or_patch_version(
    file_id: int,
    version_id: int,
    request: Request,
    channel: str | None = Form(None),
    status: str | None = Form(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    version = _version_or_404(db, file_id, version_id)

    # HTML form "Promouvoir" posts without body fields → promote.
    if request.method == "POST" and channel is None and status is None:
        try:
            promote_file_version(db, version)
            db.commit()
        except ValueError as exc:
            response = RedirectResponse(url=f"/admin/files/{file_id}", status_code=302)
            flash_redirect(
                response, str(exc), "error", settings.vault_portal_internal_token or "dev"
            )
            return response
        log_action(
            db,
            actor=user.email,
            action="file.version.promoted",
            target=f"file:{file_id}:version:{version.id}",
            details={
                "version_label": version.version_label,
                "checksum_sha256": version.checksum_sha256,
                "channel": version.channel,
            },
            ip_address=_client_ip(request),
        )
        response = RedirectResponse(url=f"/admin/files/{file_id}", status_code=302)
        flash_redirect(
            response,
            f"Version {version.version_label} promue en stable.",
            "success",
            settings.vault_portal_internal_token or "dev",
        )
        return response

    if channel == "stable" and version.channel == "beta":
        promote_file_version(db, version)
        action = "file.version.promoted"
    elif status == "archived":
        archive_file_version(db, version)
        action = "file.version.archived"
    else:
        raise HTTPException(status_code=400, detail="Rien à mettre à jour")

    db.commit()
    log_action(
        db,
        actor=user.email,
        action=action,
        target=f"file:{file_id}:version:{version.id}",
        details={
            "version_label": version.version_label,
            "channel": version.channel,
            "status": version.status,
            "checksum_sha256": version.checksum_sha256,
        },
        ip_address=_client_ip(request),
    )
    response = RedirectResponse(url=f"/admin/files/{file_id}", status_code=302)
    flash_redirect(
        response, "Version mise à jour.", "success", settings.vault_portal_internal_token or "dev"
    )
    return response


@router.post("/admin/files/{file_id}/versions/{version_id}/archive")
async def admin_files_archive_version(
    file_id: int,
    version_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    version = _version_or_404(db, file_id, version_id)
    archive_file_version(db, version)
    db.commit()
    log_action(
        db,
        actor=user.email,
        action="file.version.archived",
        target=f"file:{file_id}:version:{version.id}",
        details={
            "version_label": version.version_label,
            "channel": version.channel,
            "checksum_sha256": version.checksum_sha256,
        },
        ip_address=_client_ip(request),
    )
    response = RedirectResponse(url=f"/admin/files/{file_id}", status_code=302)
    flash_redirect(
        response, "Version archivée.", "success", settings.vault_portal_internal_token or "dev"
    )
    return response


@router.post("/admin/files/{file_id}/channel-assignments")
async def admin_files_assign_beta(
    file_id: int,
    request: Request,
    subject_type: str = Form(...),
    rbac_group_id: int | None = Form(None),
    keycloak_user_id: str | None = Form(None),
    user_display_cache: str | None = Form(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    _file_or_404(db, file_id)
    redirect_url = f"/admin/files/{file_id}"
    try:
        row = assign_beta_channel(
            db,
            file_id=file_id,
            subject_type=subject_type,
            rbac_group_id=rbac_group_id,
            keycloak_user_id=keycloak_user_id or None,
            user_display_cache=user_display_cache or None,
            assigned_by=user.email,
        )
        db.commit()
    except ValueError as exc:
        response = RedirectResponse(url=redirect_url, status_code=302)
        flash_redirect(
            response, str(exc), "error", settings.vault_portal_internal_token or "dev"
        )
        return response

    log_action(
        db,
        actor=user.email,
        action="file.channel_assignment.created",
        target=f"file:{file_id}:channel:{row.id}",
        details={
            "file_id": file_id,
            "subject_type": row.subject_type,
            "rbac_group_id": row.rbac_group_id,
            "keycloak_user_id": row.keycloak_user_id,
            "channel": row.channel,
        },
        ip_address=_client_ip(request),
    )
    response = RedirectResponse(url=redirect_url, status_code=302)
    flash_redirect(
        response,
        "Affectation canal bêta ajoutée.",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response


@router.post("/admin/files/{file_id}/channel-assignments/{assignment_id}/delete")
@router.delete("/admin/files/{file_id}/channel-assignments/{assignment_id}")
async def admin_files_unassign_beta(
    file_id: int,
    assignment_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
):
    _file_or_404(db, file_id)
    row = db.query(FileChannelAssignment).filter_by(id=assignment_id).first()
    if not row or row.file_id != file_id:
        raise HTTPException(status_code=404, detail="Affectation introuvable")
    details = {
        "file_id": file_id,
        "subject_type": row.subject_type,
        "rbac_group_id": row.rbac_group_id,
        "keycloak_user_id": row.keycloak_user_id,
    }
    delete_channel_assignment(db, assignment_id)
    db.commit()
    log_action(
        db,
        actor=user.email,
        action="file.channel_assignment.removed",
        target=f"file:{file_id}:channel:{assignment_id}",
        details=details,
        ip_address=_client_ip(request),
    )
    response = RedirectResponse(url=f"/admin/files/{file_id}", status_code=302)
    flash_redirect(
        response,
        "Affectation canal bêta retirée (accès conservé, canal stable).",
        "success",
        settings.vault_portal_internal_token or "dev",
    )
    return response
