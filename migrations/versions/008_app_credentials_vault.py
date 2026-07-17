"""App credentials vault — robotic service accounts (Fernet)."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "008_app_credentials_vault"
down_revision: Union[str, None] = "007_access_grants"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _table_names(conn) -> set[str]:
    return set(inspect(conn).get_table_names())


def upgrade() -> None:
    bind = op.get_bind()
    if "app_credentials" in _table_names(bind):
        return
    op.create_table(
        "app_credentials",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("app_slug", sa.String(), nullable=False),
        sa.Column("robotic_username", sa.String(), nullable=False),
        sa.Column("encrypted_password", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.ForeignKeyConstraint(["app_slug"], ["apps.slug"]),
        sa.UniqueConstraint("app_slug", name="uq_app_credentials_app_slug"),
    )
    op.create_index("ix_app_credentials_app_slug", "app_credentials", ["app_slug"])


def downgrade() -> None:
    bind = op.get_bind()
    if "app_credentials" not in _table_names(bind):
        return
    op.drop_index("ix_app_credentials_app_slug", table_name="app_credentials")
    op.drop_table("app_credentials")
