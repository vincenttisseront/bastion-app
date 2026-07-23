"""Add breakglass_sessions table (jti denylist for individual revocation)."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "022_breakglass_sessions"
down_revision: Union[str, None] = "021_dependency_is_direct"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()
    if "breakglass_sessions" in tables:
        return
    op.create_table(
        "breakglass_sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("jti", sa.String(), nullable=False),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(), nullable=True),
        sa.Column("revoked_reason", sa.String(), nullable=True),
    )
    op.create_index("ix_breakglass_sessions_jti", "breakglass_sessions", ["jti"], unique=True)
    op.create_index("ix_breakglass_sessions_username", "breakglass_sessions", ["username"])


def downgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()
    if "breakglass_sessions" not in tables:
        return
    op.drop_index("ix_breakglass_sessions_username", table_name="breakglass_sessions")
    op.drop_index("ix_breakglass_sessions_jti", table_name="breakglass_sessions")
    op.drop_table("breakglass_sessions")
