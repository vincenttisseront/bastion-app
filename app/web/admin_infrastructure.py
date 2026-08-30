"""Admin Infrastructure — export desired state from DB to files."""

from __future__ import annotations

import json
import time
from pathlib import Path
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.admin.infra_host_apply import (
    HOST_APPLY_WAIT_POLL_SEC,
    HOST_APPLY_WAIT_TIMEOUT_SEC,
    host_apply_is_terminal,
    read_host_apply_status,
    request_host_apply,
)
from app.admin.infrastructure import (
    MANIFEST_FILENAME,
    apply_infrastructure,
    build_infrastructure_manifest,
)
from app.audit import log_action
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


def safe_admin_next_path(raw: str | None, *, default: str = "/admin/infrastructure") -> str:
    """Allow only same-origin relative admin paths (open-redirect safe)."""
    path = (raw or "").strip() or default
    if not path.startswith("/") or path.startswith("//"):
        return default
    if not path.startswith("/admin"):
        return default
    if any(ch in path for ch in ("\n", "\r", "\\")):
        return default
    return path


def host_apply_wait_redirect(
    *,
    next_path: str,
    context_label: str = "",
    audit_target: str = "",
    audit_source: str = "infrastructure.apply",
) -> RedirectResponse:
    """Send the admin to the apply-wait page instead of returning while pending."""
    params = {
        "next": safe_admin_next_path(next_path),
        "started": str(int(time.time())),
        "context": (context_label or "")[:200],
        "audit_target": (audit_target or "")[:120],
        "audit_source": (audit_source or "infrastructure.apply")[:80],
    }
    return RedirectResponse(
        url=f"/admin/infrastructure/apply-wait?{urlencode(params)}",
        status_code=302,
    )


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
    host = read_host_apply_status(settings)
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
        host_apply=host,
    )


@router.post("/admin/infrastructure/apply")
def admin_infrastructure_apply(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
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
        return response

    host = request_host_apply(settings, exported_files=file_count)
    if not host.get("ok"):
        flash_redirect(
            response,
            (
                f"Export OK ({file_count} fichier(s)), mais signal hôte en échec : "
                f"{host.get('message')}. "
                "Lancez manuellement scripts/apply-infra-docker.sh sur l’hôte Docker."
            ),
            "error",
            token,
        )
        return response

    log_action(
        db,
        actor=user.email,
        action="infrastructure.apply.requested",
        target="infrastructure",
        details={
            "source": "admin.infrastructure",
            "exported_files": file_count,
            "request_path": host.get("path"),
        },
    )
    return host_apply_wait_redirect(
        next_path="/admin/infrastructure",
        context_label=f"Export OK ({file_count} fichier(s)).",
        audit_target="infrastructure",
        audit_source="admin.infrastructure",
    )


@router.get("/admin/infrastructure/apply-wait")
def admin_infrastructure_apply_wait(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user=Depends(require_admin),
    next: str = Query("/admin/infrastructure"),
    started: int = Query(0),
    context: str = Query(""),
    audit_target: str = Query(""),
    audit_source: str = Query("infrastructure.apply"),
):
    """Poll host apply status and only then return the admin to ``next``."""
    token = settings.vault_portal_internal_token or "dev"
    next_path = safe_admin_next_path(next)
    context_label = (context or "").strip()[:200]
    target = (audit_target or "infrastructure").strip()[:120] or "infrastructure"
    source = (audit_source or "infrastructure.apply").strip()[:80]
    started_at = int(started) if started > 0 else int(time.time())
    elapsed = max(0, int(time.time()) - started_at)
    timeout = int(HOST_APPLY_WAIT_TIMEOUT_SEC)
    poll = int(HOST_APPLY_WAIT_POLL_SEC)

    state = read_host_apply_status(settings)
    status = (state.get("status") or "").strip().lower()

    if host_apply_is_terminal(status):
        log_action(
            db,
            actor=user.email,
            action=f"infrastructure.apply.{status}",
            target=target,
            details={
                "source": source,
                "status_path": state.get("status_path"),
                "log_path": state.get("log_path"),
                "request_pending": state.get("request_pending"),
                "elapsed_sec": elapsed,
            },
        )
        response = RedirectResponse(url=next_path, status_code=302)
        if status == "ok":
            prefix = f"{context_label} " if context_label else ""
            flash_redirect(
                response,
                f"{prefix}Export et apply hôte confirmés.".strip(),
                "success",
                token,
            )
        else:
            prefix = f"{context_label} " if context_label else ""
            flash_redirect(
                response,
                (
                    f"{prefix}L'apply hôte a échoué. "
                    "Voir Admin → Infrastructure pour le log détaillé."
                ).strip(),
                "error",
                token,
            )
        return response

    if elapsed >= timeout:
        log_action(
            db,
            actor=user.email,
            action="infrastructure.apply.pending_timeout",
            target=target,
            details={
                "source": source,
                "elapsed_sec": elapsed,
                "timeout_sec": timeout,
                "request_pending": state.get("request_pending"),
                "status_path": state.get("status_path"),
            },
        )
        response = RedirectResponse(url="/admin/infrastructure", status_code=302)
        prefix = f"{context_label} " if context_label else ""
        flash_redirect(
            response,
            (
                f"{prefix}Apply hôte toujours en attente après {timeout}s. "
                "Vérifiez le watcher systemd ou lancez "
                "scripts/apply-infra-docker.sh sur l'hôte."
            ).strip(),
            "error",
            token,
        )
        return response

    refresh_params = {
        "next": next_path,
        "started": str(started_at),
        "context": context_label,
        "audit_target": target,
        "audit_source": source,
    }
    refresh_url = f"/admin/infrastructure/apply-wait?{urlencode(refresh_params)}"
    ctx = base_template_context(request, settings, APP_VERSION)
    return render(
        "admin/infrastructure_apply_wait.html",
        **ctx,
        host_apply=state,
        context_label=context_label,
        elapsed_sec=elapsed,
        timeout_sec=timeout,
        poll_sec=poll,
        refresh_url=refresh_url,
        refresh_url_json=json.dumps(refresh_url),
    )
