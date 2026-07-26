"""Saved log views and per-user column prefs for /admin/logs."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "035_saved_log_views"
down_revision: Union[str, None] = "034_container_logs_settings"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())

    if "saved_log_views" not in tables:
        op.create_table(
            "saved_log_views",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("user_email", sa.String(), nullable=False),
            sa.Column("name", sa.String(), nullable=False),
            sa.Column("filters_json", sa.JSON(), nullable=False),
            sa.Column("columns_json", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("user_email", "name", name="uq_saved_log_view_user_name"),
        )
        op.create_index(
            "ix_saved_log_views_user_email", "saved_log_views", ["user_email"]
        )

    if "admin_logs_user_prefs" not in tables:
        op.create_table(
            "admin_logs_user_prefs",
            sa.Column("user_email", sa.String(), primary_key=True),
            sa.Column("columns_json", sa.JSON(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )


def downgrade() -> None:
    op.drop_table("admin_logs_user_prefs")
    op.drop_index("ix_saved_log_views_user_email", table_name="saved_log_views")
    op.drop_table("saved_log_views")
