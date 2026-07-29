"""Admin Infrastructure — export desired state from DB to files."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.admin.infrastructure import (
    MANIFEST_FILENAME,
    apply_infrastructure,
    build_infrastructure_manifest,
)
from app.database import get_db
from app.sso_settings import Settings, get_settings
from app.web.constants import APP_VERSION
from app.web.flash import base_template_context, flash_redirect
from app.web.templates import render
from app.web.user_context import require_admin

router = APIRouter(tags=["admin-infrastructure"], dependencies=[Depends(require_admin)])

_KIND_LABELS = {
    "oauth2_proxy_core_config": "oauth2-proxy (core)",
    "oauth2_proxy_config": "oauth2-proxy (realm)",
    "nginx_realms_conf": "nginx — realms",
    "nginx_apps_conf": "nginx — apps catalogue",
    "nginx_subdomain_apps_conf": "nginx — subdomain apps",
    "subdomain_apps_inventory": "inventaire subdomain",
    "nginx_public_proxy_apps_conf": "nginx — public proxy",
    "public_proxy_apps_inventory": "inventaire public proxy",
}


def _load_saved_manifest(settings: Settings) -> dict | None:
    path = Path(settings.exports_dir) / MANIFEST_FILENAME
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _file_rows(files: list[dict]) -> list[dict]:
    rows = []
    for entry in files:
        kind = entry.get("kind") or ""
        rows.append(
            {
                "path": entry.get("path") or "",
                "kind": kind,
                "kind_label": _KIND_LABELS.get(kind, kind or "—"),
                "realm_slug": entry.get("realm_slug") or "",
            }
        )
    return rows


@router.get("/admin/infrastructure")
def admin_infrastructure_page(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    saved = _load_saved_manifest(settings)
    preview = saved or build_infrastructure_manifest(db, settings)
    ctx = base_template_context(request, settings, APP_VERSION)
    return render(
        "admin/infrastructure.html",
        **ctx,
        manifest=preview,
        exports_dir=settings.exports_dir,
        file_rows=_file_rows(preview.get("files") or []),
        realm_count=len(preview.get("realms") or []),
        app_count=len(preview.get("applications") or []),
        has_saved_manifest=saved is not None,
        manifest_path=str(Path(settings.exports_dir) / MANIFEST_FILENAME),
    )


@router.post("/admin/infrastructure/apply")
def admin_infrastructure_apply(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user=Depends(require_admin),
):
    token = settings.vault_portal_internal_token or "dev"
    response = RedirectResponse(url="/admin/infrastructure", status_code=302)
    manifest = apply_infrastructure(db, settings)
    file_count = len(manifest.get("files") or [])

    if manifest.get("partial"):
        error = manifest.get("error") or "export partiel"
        flash_redirect(
            response,
            f"Export partiel ({file_count} fichier(s)) : {error}",
            "error",
            token,
        )
    else:
        flash_redirect(
            response,
            (
                f"Infrastructure exportée ({file_count} fichier(s)). "
                "Sur l'hôte Docker, exécutez scripts/apply-infra-docker.sh "
                "pour recharger nginx et oauth2-proxy."
            ),
            "success",
            token,
        )
    return response
