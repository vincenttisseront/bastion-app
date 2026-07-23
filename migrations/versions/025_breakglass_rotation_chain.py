"""Add break-glass rotation chain columns (anti-replay)."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "025_breakglass_rotation_chain"
down_revision: Union[str, None] = "024_session_identity_binding"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _add_column_if_missing(bind, table: str, column: str, coltype, **kwargs) -> None:
    cols = {c["name"] for c in inspect(bind).get_columns(table)}
    if column not in cols:
        op.add_column(table, sa.Column(column, coltype, **kwargs))


def upgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()
    if "breakglass_sessions" not in tables:
        return
    _add_column_if_missing(bind, "breakglass_sessions", "chain_id", sa.String())
    _add_column_if_missing(bind, "breakglass_sessions", "superseded_by", sa.String())
    _add_column_if_missing(
        bind, "breakglass_sessions", "superseded_at", sa.DateTime(timezone=True)
    )
    _add_column_if_missing(
        bind,
        "breakglass_sessions",
        "chain_revoked",
        sa.Boolean(),
        nullable=False,
        server_default=sa.false(),
    )
    cols = {c["name"] for c in inspect(bind).get_columns("breakglass_sessions")}
    indexes = {i["name"] for i in inspect(bind).get_indexes("breakglass_sessions")}
    if "chain_id" in cols and "ix_breakglass_sessions_chain_id" not in indexes:
        op.create_index(
            "ix_breakglass_sessions_chain_id",
            "breakglass_sessions",
            ["chain_id"],
        )
    if "superseded_by" in cols and "ix_breakglass_sessions_superseded_by" not in indexes:
        op.create_index(
            "ix_breakglass_sessions_superseded_by",
            "breakglass_sessions",
            ["superseded_by"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()
    if "breakglass_sessions" not in tables:
        return
    indexes = {i["name"] for i in inspect(bind).get_indexes("breakglass_sessions")}
    if "ix_breakglass_sessions_superseded_by" in indexes:
        op.drop_index(
            "ix_breakglass_sessions_superseded_by", table_name="breakglass_sessions"
        )
    if "ix_breakglass_sessions_chain_id" in indexes:
        op.drop_index(
            "ix_breakglass_sessions_chain_id", table_name="breakglass_sessions"
        )
    cols = {c["name"] for c in inspect(bind).get_columns("breakglass_sessions")}
    for col in ("chain_revoked", "superseded_at", "superseded_by", "chain_id"):
        if col in cols:
            op.drop_column("breakglass_sessions", col)
