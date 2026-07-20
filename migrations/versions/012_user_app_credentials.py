"""Per-user application vault credentials (optional override of shared AppCredential)."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "012_user_app_credentials"
down_revision: Union[str, None] = "011_generic_driver_fields"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "user_app_credentials" in tables:
        return
    op.create_table(
        "user_app_credentials",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("app_slug", sa.String(), sa.ForeignKey("apps.slug"), nullable=False),
        sa.Column("keycloak_user_id", sa.String(), nullable=False),
        sa.Column("robotic_username", sa.String(), nullable=False),
        sa.Column("encrypted_password", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("app_slug", "keycloak_user_id", name="uq_user_app_credential"),
    )
    op.create_index(
        "ix_user_app_credentials_app_slug",
        "user_app_credentials",
        ["app_slug"],
    )
    op.create_index(
        "ix_user_app_credentials_keycloak_user_id",
        "user_app_credentials",
        ["keycloak_user_id"],
    )


def downgrade() -> None:
    bind = op.get_bind()
    if "user_app_credentials" not in set(inspect(bind).get_table_names()):
        return
    op.drop_index("ix_user_app_credentials_keycloak_user_id", table_name="user_app_credentials")
    op.drop_index("ix_user_app_credentials_app_slug", table_name="user_app_credentials")
    op.drop_table("user_app_credentials")
