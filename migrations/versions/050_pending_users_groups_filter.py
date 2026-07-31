"""Create pending_users + realm groups_sync_include filter."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "050_pending_users_groups_filter"
down_revision: Union[str, None] = "049_crushftp_vfs_base_path"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())

    if "realm_configs" in tables:
        cols = {c["name"] for c in inspect(bind).get_columns("realm_configs")}
        if "groups_sync_include" not in cols:
            op.add_column(
                "realm_configs",
                sa.Column("groups_sync_include", sa.Text(), nullable=True),
            )

    if "pending_users" not in tables:
        op.create_table(
            "pending_users",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("user_email", sa.String(), nullable=False),
            sa.Column("username", sa.String(), nullable=True),
            sa.Column("realm_slug", sa.String(), nullable=False),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("hit_count", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("last_client_ip", sa.String(), nullable=True),
            sa.Column("status", sa.String(), nullable=False, server_default="pending"),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column("reviewed_by", sa.String(), nullable=True),
            sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_pending_users_user_email", "pending_users", ["user_email"], unique=True)
        op.create_index("ix_pending_users_status", "pending_users", ["status"])


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "pending_users" in tables:
        op.drop_index("ix_pending_users_status", table_name="pending_users")
        op.drop_index("ix_pending_users_user_email", table_name="pending_users")
        op.drop_table("pending_users")
    if "realm_configs" in tables:
        cols = {c["name"] for c in inspect(bind).get_columns("realm_configs")}
        if "groups_sync_include" in cols:
            op.drop_column("realm_configs", "groups_sync_include")
