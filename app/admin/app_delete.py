"""Hard-delete an application and its dependent catalogue rows."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.models import (
    AccessGrant,
    ActiveSyncDevice,
    App,
    AppCredential,
    BastionAccountProvisioning,
    GroupAppCredential,
    PendingHost,
    UserAppCredential,
    UserAppFavorite,
)
from app.sso_settings import Settings


def purge_application(
    db: Session,
    app: App,
    *,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Remove the app and related grants/credentials/devices. Caller commits."""
    slug = app.slug
    app_id = app.id
    summary: dict[str, Any] = {"slug": slug, "application_id": app_id}

    summary["access_grants"] = (
        db.query(AccessGrant)
        .filter(AccessGrant.application_id == app_id)
        .delete(synchronize_session=False)
    )
    summary["app_credentials"] = (
        db.query(AppCredential)
        .filter(AppCredential.app_slug == slug)
        .delete(synchronize_session=False)
    )
    summary["user_app_credentials"] = (
        db.query(UserAppCredential)
        .filter(UserAppCredential.app_slug == slug)
        .delete(synchronize_session=False)
    )
    group_creds = (
        db.query(GroupAppCredential).filter(GroupAppCredential.app_slug == slug).all()
    )
    for row in group_creds:
        db.delete(row)
    summary["group_app_credentials"] = len(group_creds)
    summary["bastion_provisionings"] = (
        db.query(BastionAccountProvisioning)
        .filter(BastionAccountProvisioning.application_id == app_id)
        .delete(synchronize_session=False)
    )
    summary["activesync_devices"] = (
        db.query(ActiveSyncDevice)
        .filter(ActiveSyncDevice.application_id == app_id)
        .delete(synchronize_session=False)
    )
    summary["user_app_favorites"] = (
        db.query(UserAppFavorite)
        .filter(UserAppFavorite.application_id == app_id)
        .delete(synchronize_session=False)
    )

    pending_rows = (
        db.query(PendingHost).filter(PendingHost.approved_app_slug == slug).all()
    )
    for row in pending_rows:
        row.approved_app_slug = None
    summary["pending_hosts_cleared"] = len(pending_rows)

    if settings is not None:
        from app.web.app_logos import delete_logo_file

        delete_logo_file(app, settings)

    db.delete(app)
    db.flush()
    return summary
