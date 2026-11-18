"""LLM assistant: end-user companion toggle and autonomous response toggle.

Revision ID: 101_llm_companion
Revises: 100_llm_external_ollama
Create Date: 2026-11-18
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "101_llm_companion"
down_revision: Union[str, None] = "100_llm_external_ollama"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "portal_settings"
_COLUMNS = ("llm_companion_enabled", "llm_auto_response_enabled")


def _existing() -> set[str] | None:
    inspector = inspect(op.get_bind())
    if _TABLE not in inspector.get_table_names():
        return None
    return {c["name"] for c in inspector.get_columns(_TABLE)}


def upgrade() -> None:
    cols = _existing()
    if cols is None:
        return
    missing = [name for name in _COLUMNS if name not in cols]
    if not missing:
        return
    with op.batch_alter_table(_TABLE) as batch:
        for name in missing:
            batch.add_column(
                sa.Column(
                    name,
                    sa.Boolean(create_constraint=False),
                    nullable=False,
                    server_default=sa.false(),
                )
            )


def downgrade() -> None:
    cols = _existing()
    if cols is None:
        return
    present = [name for name in _COLUMNS if name in cols]
    if not present:
        return
    with op.batch_alter_table(_TABLE) as batch:
        for name in present:
            batch.drop_column(name)
