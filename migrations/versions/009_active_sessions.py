"""Active sessions registry for Sessions UI."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "009_active_sessions"
down_revision: Union[str, None] = "008_app_credentials_vault"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _table_names(conn) -> set[str]:
    return set(inspect(conn).get_table_names())


def upgrade() -> None:
    bind = op.get_bind()
    if "active_sessions" in _table_names(bind):
        return
    op.create_table(
        "active_sessions",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("user_email", sa.String(), nullable=False),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("realm", sa.String(), nullable=False),
        sa.Column("protocol", sa.String(), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("source_ip", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="active"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_active_sessions_kind", "active_sessions", ["kind"])
    op.create_index("ix_active_sessions_user_email", "active_sessions", ["user_email"])


def downgrade() -> None:
    bind = op.get_bind()
    if "active_sessions" not in _table_names(bind):
        return
    op.drop_index("ix_active_sessions_user_email", table_name="active_sessions")
    op.drop_index("ix_active_sessions_kind", table_name="active_sessions")
    op.drop_table("active_sessions")
