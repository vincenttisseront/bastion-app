"""Container logs settings singleton (admin UI, not env)."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "034_container_logs_settings"
down_revision: Union[str, None] = "033_security_banning"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _seed_from_env() -> dict:
    from app.web.container_logs_settings import seed_values_from_environ

    return seed_values_from_environ(dict(os.environ))


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())

    if "container_logs_settings" not in tables:
        op.create_table(
            "container_logs_settings",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column(
                "enabled", sa.Boolean(), nullable=False, server_default=sa.false()
            ),
            sa.Column(
                "proxy_url", sa.String(), nullable=False, server_default=""
            ),
            sa.Column("allowed_containers", sa.JSON(), nullable=False),
            sa.Column(
                "tail_lines", sa.Integer(), nullable=False, server_default="200"
            ),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_by", sa.String(), nullable=True),
        )

    seed = _seed_from_env()
    now = datetime.now(timezone.utc)
    # Idempotent seed for id=1 only when missing.
    existing = bind.execute(
        sa.text("SELECT id FROM container_logs_settings WHERE id = 1")
    ).fetchone()
    if existing is None:
        bind.execute(
            sa.text(
                "INSERT INTO container_logs_settings "
                "(id, enabled, proxy_url, allowed_containers, tail_lines, updated_at) "
                "VALUES (1, :enabled, :proxy_url, :allowed, :tail, :updated_at)"
            ),
            {
                "enabled": 1 if seed["enabled"] else 0,
                "proxy_url": seed["proxy_url"] or "",
                "allowed": json.dumps(seed["allowed_containers"]),
                "tail": int(seed["tail_lines"]),
                "updated_at": now,
            },
        )


def downgrade() -> None:
    op.drop_table("container_logs_settings")
