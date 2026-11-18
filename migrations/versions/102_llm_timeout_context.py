"""LLM assistant: admin-tunable timeout and context window, server info from /api/ps.

Revision ID: 102_llm_timeout_context
Revises: 101_llm_companion
Create Date: 2026-11-18
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "102_llm_timeout_context"
down_revision: Union[str, None] = "101_llm_companion"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "portal_settings"


def _columns_spec() -> list[sa.Column]:
    return [
        sa.Column("llm_server_info", sa.JSON(), nullable=True),
        sa.Column("llm_timeout_s", sa.Integer(), nullable=True),
        sa.Column("llm_num_ctx", sa.Integer(), nullable=True),
    ]


def _existing() -> set[str] | None:
    inspector = inspect(op.get_bind())
    if _TABLE not in inspector.get_table_names():
        return None
    return {c["name"] for c in inspector.get_columns(_TABLE)}


def upgrade() -> None:
    cols = _existing()
    if cols is None:
        return
    missing = [c for c in _columns_spec() if c.name not in cols]
    if not missing:
        return
    with op.batch_alter_table(_TABLE) as batch:
        for column in missing:
            batch.add_column(column)


def downgrade() -> None:
    cols = _existing()
    if cols is None:
        return
    present = [c.name for c in _columns_spec() if c.name in cols]
    if not present:
        return
    with op.batch_alter_table(_TABLE) as batch:
        for name in present:
            batch.drop_column(name)
