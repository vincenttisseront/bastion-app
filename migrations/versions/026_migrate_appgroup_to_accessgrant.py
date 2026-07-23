"""Backfill AppGroup → AccessGrant, then drop legacy app_groups table."""

from __future__ import annotations

import logging
from typing import Sequence, Union

from alembic import op
from sqlalchemy.orm import Session

revision: str = "026_migrate_appgroup_to_accessgrant"
down_revision: Union[str, None] = "025_breakglass_rotation_chain"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.runtime.migration")


def upgrade() -> None:
    from app.rbac.migrate_appgroup import migrate_appgroups_to_access_grants

    bind = op.get_bind()
    session = Session(bind=bind)
    try:
        report = migrate_appgroups_to_access_grants(session)
        session.commit()
        logger.info(
            "AppGroup→AccessGrant migration: rows=%s created=%s skipped=%s upgraded=%s conflicts=%s",
            report.appgroup_rows,
            report.grants_created,
            report.duplicates_skipped,
            report.conflicts_upgraded,
            len(report.conflicts),
        )
        for conflict in report.conflicts:
            logger.info(
                "  conflict app_id=%s group_id=%s %s→%s (%s)",
                conflict.app_id,
                conflict.rbac_group_id,
                conflict.existing_level,
                conflict.resolved_level,
                conflict.action,
            )
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

    from sqlalchemy import inspect

    if "app_groups" in inspect(bind).get_table_names():
        op.drop_table("app_groups")


def downgrade() -> None:
    """Recreate empty app_groups shell only — AccessGrant rows are not rolled back."""
    import sqlalchemy as sa
    from sqlalchemy import inspect

    bind = op.get_bind()
    if "app_groups" in inspect(bind).get_table_names():
        return
    op.create_table(
        "app_groups",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("app_id", sa.Integer(), sa.ForeignKey("apps.id"), nullable=False),
        sa.Column(
            "group_id", sa.Integer(), sa.ForeignKey("rbac_groups.id"), nullable=False
        ),
    )
