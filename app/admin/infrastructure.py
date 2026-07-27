"""Infrastructure desired-state manifest for apply-infrastructure.sh.

Exports oauth2-proxy configs from DB RealmConfig (source of truth).
- Default/core realm (ar-systems): oauth2 cfg only → synced to oauth2-proxy-core by apply-infra-docker.
- Secondary realms: oauth2 cfg + nginx snippet + dedicated containers.
Nginx location for the core realm stays static (snippets/nginx-portal-core-realm-oauth2).
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
    prune_deleted_realm_exports,
    write_nginx_realms_conf,
    write_oauth2_proxy_export,
)
from app.database import SessionLocal, get_db
from app.models import App, RealmConfig
from app.security import require_internal_token
from app.sso_settings import Settings, get_settings

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/internal/infrastructure",
    tags=["infrastructure"],
    dependencies=[Depends(require_internal_token)],
)

MANIFEST_FILENAME = "infrastructure-manifest.json"


def _exports_path(settings: Settings) -> Path:
    path = Path(settings.exports_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def iter_exportable_realms(db: Session, settings: Settings) -> list[RealmConfig]:
    """Enabled secondary realms (dedicated oauth2-proxy instance each)."""
    exclude = core_static_realm_slugs(settings)
    query = db.query(RealmConfig).filter_by(enabled=True).order_by(RealmConfig.slug)
    return [realm for realm in query.all() if realm.slug not in exclude]


def get_core_realm_for_oauth2_export(db: Session, settings: Settings) -> RealmConfig | None:
    """Default portal realm whose oauth2-proxy-core cfg is generated from DB."""
    slug = settings.sso_portal_default_realm_slug
    realm = db.query(RealmConfig).filter_by(slug=slug, enabled=True).first()
    if realm:
        return realm
    return (
        db.query(RealmConfig)
        .filter_by(is_default=True, enabled=True)
        .order_by(RealmConfig.id)
        .first()
    )



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
    from app.access_modes import normalize_access_mode

    mode = normalize_access_mode(app.access_mode)
    entry: dict[str, Any] = {
        "slug": app.slug,
        "label": app.label,
        "access_mode": app.access_mode,
        "public_fqdn": app.public_fqdn,
        "enabled": app.enabled,
    }
    if mode == "subdomain_proxy" and (app.public_fqdn or "").strip():
        entry["session_cookie_hop"] = True
        entry["hop_path"] = "/.bastion/session-cookies"
    return entry


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
    """Write export files from DB and return the infrastructure manifest."""
    exports_path = _exports_path(settings)
    written_files: list[dict[str, Any]] = []
    partial = False
    error: str | None = None

    try:
        # Core/default realm: oauth2 cfg from DB → oauth2-proxy-core (via apply-infra-docker).
        # Exported even if last_test_status != ok so secrets entered in Admin can be applied.
        core_realm = get_core_realm_for_oauth2_export(db, settings)
        if core_realm:
            proxy_path = write_oauth2_proxy_export(core_realm, settings)
            written_files.append(
                _file_manifest_entry(
                    proxy_path,
                    kind="oauth2_proxy_core_config",
                    realm_slug=core_realm.slug,
                )
            )
            if core_realm.last_test_status != "ok":
                logger.warning(
                    "Core realm %s exported with last_test_status=%s — run OIDC test when ready",
                    core_realm.slug,
                    core_realm.last_test_status,
                )
        else:
            logger.warning(
                "No enabled default realm (%s) — oauth2-proxy-core cfg not refreshed from DB",
                settings.sso_portal_default_realm_slug,
            )

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

        nginx_realms_path = write_nginx_realms_conf(db, settings)
        written_files.append(_file_manifest_entry(nginx_realms_path, kind="nginx_realms_conf"))

        app_paths = export_app_catalogue_files(db, settings)
        written_files.append(
            _file_manifest_entry(Path(app_paths["nginx_apps_conf"]), kind="nginx_apps_conf")
        )
        if app_paths.get("nginx_subdomain_apps_conf"):
            written_files.append(
                _file_manifest_entry(
                    Path(app_paths["nginx_subdomain_apps_conf"]),
                    kind="nginx_subdomain_apps_conf",
                )
            )
        if app_paths.get("subdomain_apps_inventory"):
            written_files.append(
                _file_manifest_entry(
                    Path(app_paths["subdomain_apps_inventory"]),
                    kind="subdomain_apps_inventory",
                )
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
):
    return build_infrastructure_manifest(db, settings)


@router.post("/apply")
def post_infrastructure_apply(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
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
