"""identite_utilisateur: optional per-session password cache.

Adds ``apps.identity_password_session_cache`` (opt-in per app) and the
``identity_password_cache`` table (ciphertext only — the key half stays in the
user's browser cookie).

Revision ID: 097_identity_password_session_cache
Revises: 096_user_passkeys
Create Date: 2026-11-06
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "097_identity_password_session_cache"
down_revision: Union[str, None] = "096_user_passkeys"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "identity_password_cache"
_COLUMN = "identity_password_session_cache"


def _add_app_column(inspector) -> None:
    if "apps" not in inspector.get_table_names():
        return
    cols = {c["name"] for c in inspector.get_columns("apps")}
    if _COLUMN in cols:
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


def _create_cache_table(inspector) -> None:
    if _TABLE in inspector.get_table_names():
        return
    op.create_table(
        _TABLE,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("handle", sa.String(), nullable=False),
        sa.Column(
            "application_id",
            sa.Integer(),
            sa.ForeignKey("apps.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("user_key", sa.String(), nullable=False),
        sa.Column("user_email", sa.String(), nullable=True),
        sa.Column("login_username", sa.String(), nullable=False),
        sa.Column("ciphertext", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint(
            "handle", "application_id", name="uq_identity_password_cache_handle_app"
        ),
    )
    for column in ("handle", "application_id", "user_key", "user_email", "expires_at"):
        op.create_index(f"ix_{_TABLE}_{column}", _TABLE, [column])


def upgrade() -> None:
    inspector = inspect(op.get_bind())
    _add_app_column(inspector)
    _create_cache_table(inspector)


def downgrade() -> None:
    inspector = inspect(op.get_bind())
    if _TABLE in inspector.get_table_names():
        op.drop_table(_TABLE)
    if "apps" in inspector.get_table_names():
        cols = {c["name"] for c in inspector.get_columns("apps")}
        if _COLUMN in cols:
            with op.batch_alter_table("apps") as batch:
                batch.drop_column(_COLUMN)
