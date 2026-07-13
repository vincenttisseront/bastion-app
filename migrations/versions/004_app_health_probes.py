"""App health probe columns."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "004_app_health_probes"
down_revision: Union[str, None] = "003_app_access_modes"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_COLUMNS: list[tuple[str, sa.Column]] = [
    ("last_probe_status", sa.Column("last_probe_status", sa.String(), nullable=True)),
    ("last_probe_http_code", sa.Column("last_probe_http_code", sa.Integer(), nullable=True)),
    ("last_probe_latency_ms", sa.Column("last_probe_latency_ms", sa.Integer(), nullable=True)),
    ("last_probe_at", sa.Column("last_probe_at", sa.DateTime(timezone=True), nullable=True)),
    ("last_probe_error", sa.Column("last_probe_error", sa.String(), nullable=True)),
    ("probe_enabled", sa.Column("probe_enabled", sa.Boolean(), nullable=True, server_default=sa.true())),
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
