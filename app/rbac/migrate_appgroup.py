"""One-shot backfill: legacy AppGroup rows → AccessGrant (group → application).

Used by Alembic ``026_migrate_appgroup_to_accessgrant`` and by unit tests.
Idempotent: never creates a duplicate grant for the same (group, application) pair.
Conflict rule: keep the highest access_level (rank view < launch < manage).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.rbac.effective_access_service import ACCESS_LEVEL_RANK

MIGRATION_GRANTED_BY = "migration_appgroup_2026-07-23"
DEFAULT_ACCESS_LEVEL = "launch"


@dataclass
class MigrationConflict:
    app_id: int
    rbac_group_id: int
    existing_level: str
    resolved_level: str
    action: str  # "upgraded" | "kept_higher"


@dataclass
class MigrationReport:
    appgroup_rows: int = 0
    grants_created: int = 0
    duplicates_skipped: int = 0
    conflicts_upgraded: int = 0
    conflicts: list[MigrationConflict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "appgroup_rows": self.appgroup_rows,
            "grants_created": self.grants_created,
            "duplicates_skipped": self.duplicates_skipped,
            "conflicts_upgraded": self.conflicts_upgraded,
            "conflicts": [
                {
                    "app_id": c.app_id,
                    "rbac_group_id": c.rbac_group_id,
                    "existing_level": c.existing_level,
                    "resolved_level": c.resolved_level,
                    "action": c.action,
                }
                for c in self.conflicts
            ],
        }


def _rank(level: str | None) -> int:
    return ACCESS_LEVEL_RANK.get((level or "").strip().lower(), 0)


def backfill_appgroup_links(
    db: Session,
    links: Iterable[tuple[int, int]],
    *,
    granted_by: str = MIGRATION_GRANTED_BY,
    default_level: str = DEFAULT_ACCESS_LEVEL,
) -> MigrationReport:
    """
    For each ``(app_id, group_id)`` pair, ensure a group→application AccessGrant.

    - Missing grant → create with ``default_level`` (``launch``).
    - Existing grant with lower level → upgrade to ``default_level`` (conflict).
    - Existing grant with equal/higher level → skip (duplicate / keep higher).
    """
    from app.models import AccessGrant

    report = MigrationReport()
    target_rank = _rank(default_level)

    for app_id, group_id in links:
        report.appgroup_rows += 1
        existing = (
            db.query(AccessGrant)
            .filter_by(
                subject_type="group",
                rbac_group_id=group_id,
                resource_type="application",
                application_id=app_id,
            )
            .first()
        )
        if existing is None:
            db.add(
                AccessGrant(
                    subject_type="group",
                    rbac_group_id=group_id,
                    keycloak_user_id=None,
                    resource_type="application",
                    application_id=app_id,
                    system_role=None,
                    access_level=default_level,
                    granted_by=granted_by,
                )
            )
            report.grants_created += 1
            continue

        current = (existing.access_level or "view").strip().lower()
        if _rank(current) >= target_rank:
            report.duplicates_skipped += 1
            if current != default_level:
                report.conflicts.append(
                    MigrationConflict(
                        app_id=app_id,
                        rbac_group_id=group_id,
                        existing_level=current,
                        resolved_level=current,
                        action="kept_higher",
                    )
                )
            continue

        # Existing lower than default (e.g. view) → upgrade to launch.
        report.conflicts.append(
            MigrationConflict(
                app_id=app_id,
                rbac_group_id=group_id,
                existing_level=current,
                resolved_level=default_level,
                action="upgraded",
            )
        )
        existing.access_level = default_level
        report.conflicts_upgraded += 1

    db.flush()
    return report


def list_appgroup_pairs_from_db(db: Session) -> list[tuple[int, int]]:
    """Read ``app_groups`` via SQL (works even after the ORM model is removed)."""
    bind = db.get_bind()
    insp = __import__("sqlalchemy", fromlist=["inspect"]).inspect(bind)
    if "app_groups" not in insp.get_table_names():
        return []
    rows = db.execute(text("SELECT app_id, group_id FROM app_groups")).fetchall()
    return [(int(r[0]), int(r[1])) for r in rows]


def migrate_appgroups_to_access_grants(db: Session) -> MigrationReport:
    """Full DB backfill from the ``app_groups`` table (no-op if table absent)."""
    return backfill_appgroup_links(db, list_appgroup_pairs_from_db(db))


def drop_app_groups_table(connection) -> bool:
    """Drop ``app_groups`` if present. Returns True when a drop was executed."""
    from sqlalchemy import inspect

    insp = inspect(connection)
    if "app_groups" not in insp.get_table_names():
        return False
    # SQLite / generic: drop with CASCADE not always available — plain DROP.
    connection.execute(text("DROP TABLE IF EXISTS app_groups"))
    return True
