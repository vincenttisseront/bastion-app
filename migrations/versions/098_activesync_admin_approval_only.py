"""ActiveSync: per-app « admin approval only » for new devices.

Revision ID: 098_activesync_admin_approval_only
Revises: 097_identity_password_session_cache
Create Date: 2026-11-06
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "098_activesync_admin_approval_only"
down_revision: Union[str, None] = "097_identity_password_session_cache"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_COLUMN = "activesync_admin_approval_only"


def _app_columns() -> set[str] | None:
    inspector = inspect(op.get_bind())
    if "apps" not in inspector.get_table_names():
        return None
    return {c["name"] for c in inspector.get_columns("apps")}


def upgrade() -> None:
    cols = _app_columns()
    if cols is None or _COLUMN in cols:
        return
    with op.batch_alter_table("apps") as batch:
        batch.add_column(
            sa.Column(
                _COLUMN,
                sa.Boolean(create_constraint=False),
                nullable=False,
                server_default=sa.false(),
            )
        )


def downgrade() -> None:
    cols = _app_columns()
    if cols is None or _COLUMN not in cols:
        return
    with op.batch_alter_table("apps") as batch:
        batch.drop_column(_COLUMN)
