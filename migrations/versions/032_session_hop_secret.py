"""Add session-cookie hop HMAC secret on portal_settings (DB source of truth)."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "032_session_hop_secret"
down_revision: Union[str, None] = "031_injected_cookie_scope"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _add_column_if_missing(bind, table: str, column: str, coltype) -> None:
    cols = {c["name"] for c in inspect(bind).get_columns(table)}
    if column not in cols:
        op.add_column(table, sa.Column(column, coltype, nullable=True))


def upgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()
    if "portal_settings" not in tables:
        return
    _add_column_if_missing(
        bind, "portal_settings", "session_hop_secret_encrypted", sa.Text()
    )


def downgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()
    if "portal_settings" not in tables:
        return
    cols = {c["name"] for c in inspect(bind).get_columns("portal_settings")}
    if "session_hop_secret_encrypted" in cols:
        op.drop_column("portal_settings", "session_hop_secret_encrypted")
