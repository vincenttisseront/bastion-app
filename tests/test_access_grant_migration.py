"""AppGroup → AccessGrant backfill: idempotence, conflicts, catalogue parity."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import AccessGrant, App, RBACGroup
from app.rbac.effective_access_service import get_effective_apps_for_user
from app.rbac.grants_service import AccessGrantCreate, create_grant
from app.rbac.migrate_appgroup import (
    MIGRATION_GRANTED_BY,
    backfill_appgroup_links,
)


def _app(db: Session, slug: str) -> App:
    app = App(
        slug=slug,
        label=slug.title(),
        upstream_url=f"https://{slug}.example/",
        enabled=True,
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    return app


def _group(db: Session, name: str) -> RBACGroup:
    group = RBACGroup(name=name)
    db.add(group)
    db.commit()
    db.refresh(group)
    return group


def test_access_grant_migration_creates_launch_grants(db_session: Session):
    wiki = _app(db_session, "wiki")
    grafana = _app(db_session, "grafana")
    users = _group(db_session, "app-users")
    ops = _group(db_session, "ops")

    report = backfill_appgroup_links(
        db_session,
        [(wiki.id, users.id), (grafana.id, ops.id)],
    )
    db_session.commit()

    assert report.appgroup_rows == 2
    assert report.grants_created == 2
    assert report.duplicates_skipped == 0
    assert report.conflicts_upgraded == 0

    grants = db_session.query(AccessGrant).filter_by(granted_by=MIGRATION_GRANTED_BY).all()
    assert len(grants) == 2
    assert all(g.access_level == "launch" for g in grants)
    assert all(g.subject_type == "group" for g in grants)
    assert all(g.resource_type == "application" for g in grants)


def test_access_grant_migration_idempotent(db_session: Session):
    wiki = _app(db_session, "wiki")
    users = _group(db_session, "app-users")
    links = [(wiki.id, users.id)]

    first = backfill_appgroup_links(db_session, links)
    db_session.commit()
    second = backfill_appgroup_links(db_session, links)
    db_session.commit()

    assert first.grants_created == 1
    assert second.grants_created == 0
    assert second.duplicates_skipped == 1
    assert db_session.query(AccessGrant).count() == 1


def test_access_grant_migration_conflict_keeps_highest(db_session: Session):
    wiki = _app(db_session, "wiki")
    users = _group(db_session, "app-users")

    # Existing manage grant — must not be downgraded to launch.
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="group",
            rbac_group_id=users.id,
            resource_type="application",
            application_id=wiki.id,
            access_level="manage",
        ),
        granted_by="admin",
    )
    db_session.commit()

    report = backfill_appgroup_links(db_session, [(wiki.id, users.id)])
    db_session.commit()

    assert report.grants_created == 0
    assert report.duplicates_skipped == 1
    assert report.conflicts_upgraded == 0
    assert len(report.conflicts) == 1
    assert report.conflicts[0].action == "kept_higher"
    assert report.conflicts[0].resolved_level == "manage"

    grant = db_session.query(AccessGrant).one()
    assert grant.access_level == "manage"
    assert grant.granted_by == "admin"


def test_access_grant_migration_conflict_upgrades_view(db_session: Session):
    wiki = _app(db_session, "wiki")
    users = _group(db_session, "app-users")

    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="group",
            rbac_group_id=users.id,
            resource_type="application",
            application_id=wiki.id,
            access_level="view",
        ),
        granted_by="admin",
    )
    db_session.commit()

    report = backfill_appgroup_links(db_session, [(wiki.id, users.id)])
    db_session.commit()

    assert report.grants_created == 0
    assert report.conflicts_upgraded == 1
    assert report.conflicts[0].action == "upgraded"
    assert report.conflicts[0].existing_level == "view"
    assert report.conflicts[0].resolved_level == "launch"

    grant = db_session.query(AccessGrant).one()
    assert grant.access_level == "launch"


def test_access_grant_migration_catalogue_parity(db_session: Session):
    """After backfill, visible apps for a group member match the AppGroup pairs."""
    wiki = _app(db_session, "wiki")
    mail = _app(db_session, "mail")
    other = _app(db_session, "other")
    users = _group(db_session, "app-users")
    guests = _group(db_session, "guests")

    # Simulate legacy AppGroup rows: users→wiki,mail ; guests→other
    legacy_links = [
        (wiki.id, users.id),
        (mail.id, users.id),
        (other.id, guests.id),
    ]
    # Old catalogue filter for a user in app-users would show {wiki, mail}.
    expected_before = {wiki.slug, mail.slug}

    report = backfill_appgroup_links(db_session, legacy_links)
    db_session.commit()
    assert report.grants_created == 3

    after = get_effective_apps_for_user(db_session, group_names=["app-users"])
    assert {e.app.slug for e in after} == expected_before
    assert all(e.can_launch for e in after)
