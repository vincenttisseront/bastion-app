"""App catalogue description and logo_path."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "010_app_description_logo"
down_revision: Union[str, None] = "009_active_sessions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_COLUMNS: list[tuple[str, sa.Column]] = [
    ("description", sa.Column("description", sa.String(length=140), nullable=True)),
    ("logo_path", sa.Column("logo_path", sa.String(), nullable=True)),
]


def upgrade() -> None:
    bind = op.get_bind()
    if "apps" not in inspect(bind).get_table_names():
        return
    existing = {col["name"] for col in inspect(bind).get_columns("apps")}
    for name, column in _COLUMNS:
        if name not in existing:
            op.add_column("apps", column)


def downgrade() -> None:
    bind = op.get_bind()
    if "apps" not in inspect(bind).get_table_names():
        return
    existing = {col["name"] for col in inspect(bind).get_columns("apps")}
    for name, _ in reversed(_COLUMNS):
        if name in existing:
            op.drop_column("apps", name)
