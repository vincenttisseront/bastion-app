"""LLM assistant: external Ollama connection (URL, token, TLS), model list, WAF auto analysis.

Revision ID: 100_llm_external_ollama
Revises: 099_llm_assistant
Create Date: 2026-11-18
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "100_llm_external_ollama"
down_revision: Union[str, None] = "099_llm_assistant"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "portal_settings"


def _columns_spec() -> list[sa.Column]:
    return [
        sa.Column("llm_base_url", sa.String(), nullable=True),
        sa.Column("llm_api_token_encrypted", sa.Text(), nullable=True),
        sa.Column(
            "llm_tls_verify",
            sa.Boolean(create_constraint=False),
            nullable=False,
            server_default=sa.true(),
        ),
        sa.Column("llm_model", sa.String(), nullable=True),
        sa.Column("llm_models_json", sa.JSON(), nullable=True),
        sa.Column("llm_last_probe_at", sa.DateTime(), nullable=True),
        sa.Column("llm_last_probe_ok", sa.Boolean(create_constraint=False), nullable=True),
        sa.Column("llm_last_probe_error", sa.Text(), nullable=True),
        sa.Column(
            "llm_waf_auto_enabled",
            sa.Boolean(create_constraint=False),
            nullable=False,
            server_default=sa.true(),
        ),
        sa.Column("llm_waf_last_event_at", sa.DateTime(), nullable=True),
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
