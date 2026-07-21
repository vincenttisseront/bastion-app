"""Active sessions — live verification status for driven app sessions."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "016_active_session_verify"
down_revision: Union[str, None] = "015_active_session_details"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    cols = {c["name"] for c in inspect(bind).get_columns("active_sessions")}
    if "last_verified_at" not in cols:
        op.add_column(
            "active_sessions",
            sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
        )
    if "last_verified_status" not in cols:
        op.add_column(
            "active_sessions",
            sa.Column("last_verified_status", sa.String(), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()
    cols = {c["name"] for c in inspect(bind).get_columns("active_sessions")}
    if "last_verified_status" in cols:
        op.drop_column("active_sessions", "last_verified_status")
    if "last_verified_at" in cols:
        op.drop_column("active_sessions", "last_verified_at")
