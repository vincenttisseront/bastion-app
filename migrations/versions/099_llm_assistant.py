"""Optional local LLM assistant (Ollama): admin toggle + separate insights table.

Revision ID: 099_llm_assistant
Revises: 098_activesync_admin_approval_only
Create Date: 2026-11-17
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "099_llm_assistant"
down_revision: Union[str, None] = "098_activesync_admin_approval_only"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SETTINGS = "portal_settings"
_COLUMN = "llm_enabled"
_INSIGHTS = "llm_insights"


def _tables() -> set[str]:
    return set(inspect(op.get_bind()).get_table_names())


def _settings_columns() -> set[str]:
    return {c["name"] for c in inspect(op.get_bind()).get_columns(_SETTINGS)}


def upgrade() -> None:
    tables = _tables()
    if _SETTINGS in tables and _COLUMN not in _settings_columns():
        with op.batch_alter_table(_SETTINGS) as batch:
            batch.add_column(
                sa.Column(
                    _COLUMN,
                    sa.Boolean(create_constraint=False),
                    nullable=False,
                    server_default=sa.false(),
                )
            )
    if _INSIGHTS not in tables:
        op.create_table(
            _INSIGHTS,
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("kind", sa.String(64), nullable=False),
            sa.Column("subject_type", sa.String(64), nullable=False),
            sa.Column("subject_id", sa.String(255), nullable=False),
            sa.Column("status", sa.String(16), nullable=False, server_default="info"),
            sa.Column("payload", sa.JSON(), nullable=False),
            sa.Column("model", sa.String(128), nullable=True),
            sa.Column("prompt_sha256", sa.String(64), nullable=True),
            sa.Column("generated_by", sa.String(64), nullable=False, server_default="llm"),
            sa.Column("requested_by", sa.String(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("decided_by", sa.String(), nullable=True),
            sa.Column("decided_at", sa.DateTime(), nullable=True),
            sa.Column("decision_note", sa.Text(), nullable=True),
        )
        op.create_index("ix_llm_insights_kind", _INSIGHTS, ["kind"])
        op.create_index("ix_llm_insights_status", _INSIGHTS, ["status"])
        op.create_index("ix_llm_insights_created_at", _INSIGHTS, ["created_at"])
        op.create_index(
            "ix_llm_insights_subject", _INSIGHTS, ["kind", "subject_type", "subject_id"]
        )


def downgrade() -> None:
    tables = _tables()
    if _INSIGHTS in tables:
        op.drop_table(_INSIGHTS)
    if _SETTINGS in tables and _COLUMN in _settings_columns():
        with op.batch_alter_table(_SETTINGS) as batch:
            batch.drop_column(_COLUMN)
