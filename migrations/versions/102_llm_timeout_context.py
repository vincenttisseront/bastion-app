"""LLM assistant: admin-tunable timeout and context window, server info from /api/ps.

Revision ID: 102_llm_timeout_context
Revises: 101_llm_companion
Create Date: 2026-11-18
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "102_llm_timeout_context"
down_revision: Union[str, None] = "101_llm_companion"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# All nullable: NULL means "use the env default" (LLM_TIMEOUT_S / LLM_NUM_CTX).
_NEW_COLUMNS: dict[str, type[sa.types.TypeEngine]] = {
    "llm_server_info": sa.JSON,
    "llm_timeout_s": sa.Integer,
    "llm_num_ctx": sa.Integer,
}


def _portal_settings_columns() -> set[str] | None:
    """Column names of portal_settings, or None when the table is absent."""
    insp = sa.inspect(op.get_bind())
    if not insp.has_table("portal_settings"):
        return None
    return {col["name"] for col in insp.get_columns("portal_settings")}


def upgrade() -> None:
    existing = _portal_settings_columns()
    if existing is None:
        return
    to_add = [name for name in _NEW_COLUMNS if name not in existing]
    if to_add:
        with op.batch_alter_table("portal_settings") as batch:
            for name in to_add:
                batch.add_column(sa.Column(name, _NEW_COLUMNS[name](), nullable=True))


def downgrade() -> None:
    existing = _portal_settings_columns() or set()
    to_drop = [name for name in _NEW_COLUMNS if name in existing]
    if to_drop:
        with op.batch_alter_table("portal_settings") as batch:
            for name in to_drop:
                batch.drop_column(name)
