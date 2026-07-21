"""Active sessions — diagnostics JSON (cookies, credential source)."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "015_active_session_details"
down_revision: Union[str, None] = "014_portal_settings"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    cols = {c["name"] for c in inspect(bind).get_columns("active_sessions")}
    if "details" not in cols:
        op.add_column("active_sessions", sa.Column("details", sa.JSON(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    cols = {c["name"] for c in inspect(bind).get_columns("active_sessions")}
    if "details" in cols:
        op.drop_column("active_sessions", "details")
