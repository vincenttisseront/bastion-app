"""Break-glass identity-binding columns + sso_session_anchors table."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "024_session_identity_binding"
down_revision: Union[str, None] = "023_breakglass_jwt_secret"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _add_column_if_missing(bind, table: str, column: str, coltype) -> None:
    cols = {c["name"] for c in inspect(bind).get_columns(table)}
    if column not in cols:
        op.add_column(table, sa.Column(column, coltype, nullable=True))


def upgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()

    if "breakglass_sessions" in tables:
        _add_column_if_missing(
            bind, "breakglass_sessions", "first_ip_subnet", sa.String()
        )
        _add_column_if_missing(
            bind, "breakglass_sessions", "first_fingerprint_hash", sa.String()
        )
        _add_column_if_missing(
            bind, "breakglass_sessions", "last_ip_subnet", sa.String()
        )
        _add_column_if_missing(
            bind, "breakglass_sessions", "last_fingerprint_hash", sa.String()
        )
        _add_column_if_missing(
            bind, "breakglass_sessions", "mismatch_count", sa.Integer()
        )

    if "sso_session_anchors" not in tables:
        op.create_table(
            "sso_session_anchors",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("cookie_hash", sa.String(), nullable=False),
            sa.Column("username", sa.String(), nullable=True),
            sa.Column("first_ip_subnet", sa.String(), nullable=True),
            sa.Column("first_fingerprint_hash", sa.String(), nullable=True),
            sa.Column("last_ip_subnet", sa.String(), nullable=True),
            sa.Column("last_fingerprint_hash", sa.String(), nullable=True),
            sa.Column("mismatch_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index(
            "ix_sso_session_anchors_cookie_hash",
            "sso_session_anchors",
            ["cookie_hash"],
            unique=True,
        )
        op.create_index(
            "ix_sso_session_anchors_username",
            "sso_session_anchors",
            ["username"],
        )
        op.create_index(
            "ix_sso_session_anchors_last_seen",
            "sso_session_anchors",
            ["last_seen"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()
    if "sso_session_anchors" in tables:
        op.drop_table("sso_session_anchors")
    if "breakglass_sessions" in tables:
        cols = {c["name"] for c in inspect(bind).get_columns("breakglass_sessions")}
        for col in (
            "mismatch_count",
            "last_fingerprint_hash",
            "last_ip_subnet",
            "first_fingerprint_hash",
            "first_ip_subnet",
        ):
            if col in cols:
                op.drop_column("breakglass_sessions", col)
