"""Infrastructure desired-state manifest for apply-infrastructure.sh.

Exports oauth2-proxy configs and nginx snippets for secondary realms only.
The default portal realm (ar-systems) is served by oauth2-proxy-core :4180 via Ansible.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.admin.export import (
    core_static_realm_slugs,
    export_app_catalogue_files,
    generate_nginx_realms_conf,
    prune_deleted_realm_exports,
    write_oauth2_proxy_export,
)
from app.database import SessionLocal, get_db
from app.models import App, RealmConfig
from app.security import require_internal_token
from app.sso_settings import Settings, get_settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/internal/infrastructure", tags=["infrastructure"])

MANIFEST_FILENAME = "infrastructure-manifest.json"


def _exports_path(settings: Settings) -> Path:
    path = Path(settings.exports_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def iter_exportable_realms(db: Session, settings: Settings) -> list[RealmConfig]:
    """Enabled realms that should get a dedicated oauth2-proxy instance."""
    exclude = core_static_realm_slugs(settings)
    query = db.query(RealmConfig).filter_by(enabled=True).order_by(RealmConfig.slug)
    return [realm for realm in query.all() if realm.slug not in exclude]


def _realm_manifest_entry(realm: RealmConfig) -> dict[str, Any]:
    return {
        "slug": realm.slug,
        "name": realm.name,
        "oauth2_proxy_port": realm.oauth2_proxy_port,
        "redirect_uri": realm.redirect_uri,
        "enabled": realm.enabled,
        "is_default": realm.is_default,
        "last_test_status": realm.last_test_status,
    }


def _application_manifest_entry(app: App) -> dict[str, Any]:
    return {
        "slug": app.slug,
        "label": app.label,
        "access_mode": app.access_mode,
        "public_fqdn": app.public_fqdn,
        "enabled": app.enabled,
    }


def _file_manifest_entry(path: Path, *, kind: str, realm_slug: str | None = None) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "path": str(path),
        "kind": kind,
    }
    if realm_slug:
        entry["realm_slug"] = realm_slug
    return entry


def build_infrastructure_manifest(
    db: Session,
    settings: Settings,
    *,
    files: list[dict[str, Any]] | None = None,
    partial: bool = False,
    error: str | None = None,
) -> dict[str, Any]:
    """Build manifest consumed by apply-infrastructure.sh / admin diagnostics."""
    realms = iter_exportable_realms(db, settings)
    applications = db.query(App).order_by(App.slug).all()
    return {
        "portal_domain": settings.portal_domain,
        "core_static_realm": settings.sso_portal_default_realm_slug
        if settings.oauth2_core_static_enabled
        else None,
        "realms": [_realm_manifest_entry(realm) for realm in realms],
        "applications": [_application_manifest_entry(app) for app in applications],
        "files": files or [],
        "partial": partial,
        "error": error,
    }


def apply_infrastructure(db: Session, settings: Settings) -> dict[str, Any]:
    """Write export files and return the infrastructure manifest."""
    exports_path = _exports_path(settings)
    written_files: list[dict[str, Any]] = []
    partial = False
    error: str | None = None

    try:
        exclude = core_static_realm_slugs(settings)
        for realm in iter_exportable_realms(db, settings):
            if realm.last_test_status != "ok":
                logger.warning(
                    "Skipping oauth2 export for realm %s (last_test_status=%s)",
                    realm.slug,
                    realm.last_test_status,
                )
                continue
            proxy_path = write_oauth2_proxy_export(realm, settings)
            written_files.append(
                _file_manifest_entry(proxy_path, kind="oauth2_proxy_config", realm_slug=realm.slug)
            )

        nginx_realms_path = exports_path / "nginx-portal-realms.conf"
        nginx_realms_path.write_text(
            generate_nginx_realms_conf(db, settings, exclude_slugs=exclude),
            encoding="utf-8",
        )
        written_files.append(_file_manifest_entry(nginx_realms_path, kind="nginx_realms_conf"))

        app_paths = export_app_catalogue_files(db, settings)
        written_files.append(
            _file_manifest_entry(Path(app_paths["nginx_apps_conf"]), kind="nginx_apps_conf")
        )

        prune_deleted_realm_exports(db, settings)
        db.commit()
    except Exception as exc:
        logger.exception("Infrastructure export failed")
        partial = True
        error = str(exc)
        db.rollback()

    manifest = build_infrastructure_manifest(
        db,
        settings,
        files=written_files,
        partial=partial,
        error=error,
    )
    manifest_path = exports_path / MANIFEST_FILENAME
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    manifest["manifest_path"] = str(manifest_path)
    return manifest


@router.get("/manifest")
def get_infrastructure_manifest(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _token: str = Depends(require_internal_token),
):
    return build_infrastructure_manifest(db, settings)


@router.post("/apply")
def post_infrastructure_apply(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _token: str = Depends(require_internal_token),
):
    manifest = apply_infrastructure(db, settings)
    status = "partial" if manifest.get("partial") else "ok"
    return {"status": status, **manifest}


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for apply-infrastructure.sh."""
    argv = argv if argv is not None else sys.argv[1:]
    if argv and argv[0] not in {"apply", "manifest"}:
        print(f"Usage: python -m app.admin.infrastructure [apply|manifest]", file=sys.stderr)
        return 2

    command = argv[0] if argv else "apply"
    settings = get_settings()
    db = SessionLocal()
    try:
        if command == "manifest":
            manifest = build_infrastructure_manifest(db, settings)
        else:
            manifest = apply_infrastructure(db, settings)
        print(json.dumps(manifest, indent=2, ensure_ascii=False))
        return 1 if manifest.get("partial") else 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
