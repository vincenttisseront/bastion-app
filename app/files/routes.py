"""CrushFTP-style file browser API — shared by portal and admin."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from sqlalchemy.orm import Session

from app.audit import log_action
from app.database import get_db
from app.files.service import (
    archive_file_resource,
    archive_file_version,
    create_folder,
    deposit_file,
    get_effective_access_on_file,
    get_effective_access_on_folder,
    iter_version_plaintext,
    list_file_versions,
    list_folder_contents,
    rename_file_resource,
    rename_version_label,
    set_version_channel,
)
from app.models import FileResource, FileVersion
from app.request_client_ip import client_ip_from_request
from app.sso_settings import Settings, get_settings
from app.web.flash import base_template_context
from app.web.templates import render
from app.web.user_context import UserContext, require_user_enriched

logger = logging.getLogger(__name__)

router = APIRouter(tags=["files-browser"])


def _client_ip(request: Request) -> str:
    return client_ip_from_request(request)


def _portal_admin(user: UserContext, db: Session, settings: Settings) -> bool:
    if user.is_admin:
        return True
    from app.web.portal import _resolve_portal_admin

    return bool(_resolve_portal_admin(user, db, settings))


def _actor(user: UserContext) -> str:
    return user.email or user.username or user.keycloak_user_id or "unknown"


def _page_ctx(request: Request, settings: Settings, user: UserContext, **extra):
    from app.web.constants import APP_VERSION

    return base_template_context(
        request,
        settings,
        APP_VERSION,
        current_user=user,
        **extra,
    )


@router.get("/files")
async def files_browser_page(
    request: Request,
    folder_id: int | None = Query(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user_enriched),
):
    if user.is_breakglass:
        return RedirectResponse(url="/dashboard", status_code=302)

    from app.web.portal import _portal_page_ctx, _resolve_portal_admin, touch_portal_session

    touch_portal_session(db, user, _client_ip(request), request=request)
    portal_admin = _resolve_portal_admin(user, db, settings)
    listing = list_folder_contents(
        db,
        folder_id=folder_id,
        keycloak_user_id=user.keycloak_user_id,
        group_names=user.groups,
        is_portal_admin=bool(portal_admin or user.is_admin),
    )
    return render(
        "files/browser.html",
        **_portal_page_ctx(
            request,
            settings,
            user=user,
            portal_admin=portal_admin,
            listing=listing,
            folder_id=folder_id,
            greeting_name=user.first_name,
        ),
    )


@router.get("/api/files")
async def api_list_folder(
    folder_id: int | None = Query(None),
    q: str | None = Query(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user_enriched),
):
    is_admin = _portal_admin(user, db, settings)
    return JSONResponse(
        {
            "ok": True,
            **list_folder_contents(
                db,
                folder_id=folder_id,
                keycloak_user_id=user.keycloak_user_id,
                group_names=user.groups,
                is_portal_admin=is_admin,
                q=q,
            ),
        }
    )


# Spec routes under /files/* (also accept /api aliases where useful)


@router.get("/files/list")
async def files_list_alias(
    folder_id: int | None = Query(None),
    q: str | None = Query(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user_enriched),
):
    return await api_list_folder(folder_id, q, db, settings, user)


@router.post("/files/folders")
async def files_create_folder(
    request: Request,
    name: str = Form(...),
    parent_folder_id: int | None = Form(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user_enriched),
):
    is_admin = _portal_admin(user, db, settings)
    access = get_effective_access_on_folder(
        db,
        folder_id=parent_folder_id,
        keycloak_user_id=user.keycloak_user_id,
        group_names=user.groups,
        is_portal_admin=is_admin,
    )
    if not access.can_manage and not (parent_folder_id is None and is_admin):
        raise HTTPException(status_code=403, detail="Droit manage requis")
    try:
        folder = create_folder(
            db,
            name=name,
            parent_folder_id=parent_folder_id,
            created_by=_actor(user),
        )
        db.commit()
    except ValueError as exc:
        db.rollback()
        return JSONResponse({"ok": False, "detail": str(exc)}, status_code=400)

    log_action(
        db,
        actor=_actor(user),
        action="file.folder.created",
        target=f"folder:{folder.id}",
        details={"name": folder.name, "parent_folder_id": parent_folder_id},
        ip_address=_client_ip(request),
    )
    return JSONResponse(
        {
            "ok": True,
            "folder": {"id": folder.id, "name": folder.name, "parent_folder_id": parent_folder_id},
        }
    )


@router.post("/files/upload")
async def files_upload(
    request: Request,
    folder_id: int | None = Form(None),
    upload: UploadFile = File(...),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user_enriched),
):
    is_admin = _portal_admin(user, db, settings)
    data = await upload.read()
    try:
        fr, version, created_new = deposit_file(
            db,
            folder_id=folder_id,
            filename=upload.filename or "upload.bin",
            content_type=upload.content_type,
            data=data,
            uploaded_by=_actor(user),
            keycloak_user_id=user.keycloak_user_id,
            group_names=user.groups,
            is_portal_admin=is_admin,
            settings=settings,
        )
        db.commit()
    except PermissionError as exc:
        db.rollback()
        return JSONResponse({"ok": False, "detail": str(exc)}, status_code=403)
    except ValueError as exc:
        db.rollback()
        return JSONResponse({"ok": False, "detail": str(exc)}, status_code=400)
    except Exception:
        db.rollback()
        logger.exception("upload failed")
        return JSONResponse({"ok": False, "detail": "Échec du dépôt"}, status_code=500)

    if created_new:
        log_action(
            db,
            actor=_actor(user),
            action="file.created",
            target=f"file:{fr.id}",
            details={"label": fr.label, "folder_id": folder_id, "via": "deposit"},
            ip_address=_client_ip(request),
        )
    log_action(
        db,
        actor=_actor(user),
        action="file.version.published",
        target=f"file:{fr.id}:version:{version.id}",
        details={
            "version_label": version.version_label,
            "channel": version.channel,
            "checksum_sha256": version.checksum_sha256,
            "size_bytes": version.size_bytes,
            "via": "deposit",
        },
        ip_address=_client_ip(request),
    )
    listing = list_folder_contents(
        db,
        folder_id=folder_id,
        keycloak_user_id=user.keycloak_user_id,
        group_names=user.groups,
        is_portal_admin=is_admin,
    )
    return JSONResponse(
        {
            "ok": True,
            "file": {"id": fr.id, "label": fr.label, "slug": fr.slug},
            "version": {
                "id": version.id,
                "version_label": version.version_label,
                "channel": version.channel,
            },
            "created_new_file": created_new,
            "listing": listing,
        }
    )


@router.get("/files/versions/{file_id}")
async def files_versions(
    file_id: int,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user_enriched),
):
    is_admin = _portal_admin(user, db, settings)
    fr = db.query(FileResource).filter_by(id=file_id).first()
    if not fr or not fr.is_active:
        raise HTTPException(status_code=404, detail="Fichier introuvable")
    access = get_effective_access_on_file(
        db,
        file=fr,
        keycloak_user_id=user.keycloak_user_id,
        group_names=user.groups,
        is_portal_admin=is_admin,
    )
    if not access.can_view:
        raise HTTPException(status_code=403, detail="Accès refusé")
    versions = list_file_versions(db, file_id)
    return JSONResponse(
        {
            "ok": True,
            "file": {"id": fr.id, "label": fr.label},
            "can_manage": access.can_manage,
            "versions": [
                {
                    "id": v.id,
                    "version_label": v.version_label,
                    "channel": v.channel,
                    "status": v.status,
                    "size_bytes": v.size_bytes,
                    "uploaded_at": v.uploaded_at.isoformat() if v.uploaded_at else None,
                    "uploaded_by": v.uploaded_by,
                    "checksum_sha256": v.checksum_sha256,
                    "original_filename": v.original_filename,
                }
                for v in versions
            ],
        }
    )


@router.patch("/files/versions/{version_id}/channel")
async def files_version_channel(
    version_id: int,
    request: Request,
    channel: str = Form(...),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user_enriched),
):
    is_admin = _portal_admin(user, db, settings)
    version = db.query(FileVersion).filter_by(id=version_id).first()
    if not version:
        raise HTTPException(status_code=404, detail="Version introuvable")
    access = get_effective_access_on_file(
        db,
        file=version.file_id,
        keycloak_user_id=user.keycloak_user_id,
        group_names=user.groups,
        is_portal_admin=is_admin,
    )
    if not access.can_manage:
        raise HTTPException(status_code=403, detail="Droit manage requis")
    try:
        set_version_channel(db, version, channel)
        db.commit()
    except ValueError as exc:
        db.rollback()
        return JSONResponse({"ok": False, "detail": str(exc)}, status_code=400)

    log_action(
        db,
        actor=_actor(user),
        action="file.version.channel_changed",
        target=f"file:{version.file_id}:version:{version.id}",
        details={
            "version_label": version.version_label,
            "channel": version.channel,
        },
        ip_address=_client_ip(request),
    )
    return JSONResponse(
        {"ok": True, "version": {"id": version.id, "channel": version.channel}}
    )


@router.patch("/files/versions/{version_id}")
async def files_version_patch(
    version_id: int,
    request: Request,
    version_label: str | None = Form(None),
    status: str | None = Form(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user_enriched),
):
    is_admin = _portal_admin(user, db, settings)
    version = db.query(FileVersion).filter_by(id=version_id).first()
    if not version:
        raise HTTPException(status_code=404, detail="Version introuvable")
    access = get_effective_access_on_file(
        db,
        file=version.file_id,
        keycloak_user_id=user.keycloak_user_id,
        group_names=user.groups,
        is_portal_admin=is_admin,
    )
    if not access.can_manage:
        raise HTTPException(status_code=403, detail="Droit manage requis")
    try:
        if version_label is not None:
            rename_version_label(db, version, version_label)
        if status == "archived":
            archive_file_version(db, version)
        db.commit()
    except ValueError as exc:
        db.rollback()
        return JSONResponse({"ok": False, "detail": str(exc)}, status_code=400)

    log_action(
        db,
        actor=_actor(user),
        action="file.version.updated",
        target=f"file:{version.file_id}:version:{version.id}",
        details={
            "version_label": version.version_label,
            "status": version.status,
        },
        ip_address=_client_ip(request),
    )
    return JSONResponse(
        {
            "ok": True,
            "version": {
                "id": version.id,
                "version_label": version.version_label,
                "status": version.status,
            },
        }
    )


@router.get("/files/download/{version_id}")
async def files_download_version(
    version_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user_enriched),
):
    is_admin = _portal_admin(user, db, settings)
    version = db.query(FileVersion).filter_by(id=version_id).first()
    if not version or version.status != "active":
        return JSONResponse({"ok": False, "detail": "Version introuvable"}, status_code=404)
    access = get_effective_access_on_file(
        db,
        file=version.file_id,
        keycloak_user_id=user.keycloak_user_id,
        group_names=user.groups,
        is_portal_admin=is_admin,
    )
    if not access.can_launch:
        return JSONResponse(
            {"ok": False, "detail": "Téléchargement non autorisé"}, status_code=403
        )
    try:
        stream = iter_version_plaintext(version, settings)
    except FileNotFoundError:
        return JSONResponse({"ok": False, "detail": "Contenu indisponible"}, status_code=404)

    fr = db.query(FileResource).filter_by(id=version.file_id).first()
    log_action(
        db,
        actor=_actor(user),
        action="file.downloaded",
        target=f"file:{version.file_id}:version:{version.id}",
        details={
            "file_id": version.file_id,
            "version_id": version.id,
            "version_label": version.version_label,
            "checksum_sha256": version.checksum_sha256,
            "keycloak_user_id": user.keycloak_user_id,
        },
        ip_address=_client_ip(request),
    )
    filename = version.original_filename or (fr.label if fr else "download.bin")
    return StreamingResponse(
        stream,
        media_type=version.content_type or "application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-SHA256": version.checksum_sha256,
        },
    )


@router.get("/files/{slug}/download")
async def files_download_by_slug(
    slug: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user_enriched),
):
    """Back-compat: resolve effective version for slug then stream."""
    from app.files.service import (
        get_effective_file_channel,
        get_effective_file_version,
        user_can_download_file,
    )

    is_admin = _portal_admin(user, db, settings)
    fr = db.query(FileResource).filter_by(slug=slug, is_active=True).first()
    if not fr:
        return JSONResponse({"ok": False, "detail": "Fichier introuvable"}, status_code=404)
    if not user_can_download_file(
        db,
        file_id=fr.id,
        keycloak_user_id=user.keycloak_user_id,
        group_names=user.groups,
        is_portal_admin=is_admin,
    ):
        return JSONResponse(
            {"ok": False, "detail": "Téléchargement non autorisé"}, status_code=403
        )
    channel, _ = get_effective_file_channel(
        db,
        file_id=fr.id,
        keycloak_user_id=user.keycloak_user_id,
        group_names=user.groups,
    )
    version = get_effective_file_version(db, fr, channel)
    if version is None:
        return JSONResponse(
            {"ok": False, "detail": "Aucune version disponible"}, status_code=404
        )
    return await files_download_version(version.id, request, db, settings, user)


@router.patch("/files/{file_id}/rename")
async def files_rename(
    file_id: int,
    request: Request,
    label: str = Form(...),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user_enriched),
):
    is_admin = _portal_admin(user, db, settings)
    fr = db.query(FileResource).filter_by(id=file_id).first()
    if not fr:
        raise HTTPException(status_code=404, detail="Fichier introuvable")
    access = get_effective_access_on_file(
        db,
        file=fr,
        keycloak_user_id=user.keycloak_user_id,
        group_names=user.groups,
        is_portal_admin=is_admin,
    )
    if not access.can_manage:
        raise HTTPException(status_code=403, detail="Droit manage requis")
    try:
        rename_file_resource(db, fr, label)
        db.commit()
    except ValueError as exc:
        db.rollback()
        return JSONResponse({"ok": False, "detail": str(exc)}, status_code=400)
    log_action(
        db,
        actor=_actor(user),
        action="file.renamed",
        target=f"file:{fr.id}",
        details={"label": fr.label},
        ip_address=_client_ip(request),
    )
    return JSONResponse({"ok": True, "file": {"id": fr.id, "label": fr.label}})


@router.delete("/files/{file_id}")
async def files_archive(
    file_id: int,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_user_enriched),
):
    is_admin = _portal_admin(user, db, settings)
    fr = db.query(FileResource).filter_by(id=file_id).first()
    if not fr:
        raise HTTPException(status_code=404, detail="Fichier introuvable")
    access = get_effective_access_on_file(
        db,
        file=fr,
        keycloak_user_id=user.keycloak_user_id,
        group_names=user.groups,
        is_portal_admin=is_admin,
    )
    if not access.can_manage:
        raise HTTPException(status_code=403, detail="Droit manage requis")
    archive_file_resource(db, fr)
    db.commit()
    log_action(
        db,
        actor=_actor(user),
        action="file.archived",
        target=f"file:{fr.id}",
        details={"label": fr.label},
        ip_address=_client_ip(request),
    )
    return JSONResponse({"ok": True})
