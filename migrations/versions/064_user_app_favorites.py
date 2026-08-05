"""Per-user pinned apps for portal Accès rapides."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "064_user_app_favorites"
down_revision: Union[str, None] = "063_hot_store_wizard"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "user_app_favorites" in tables:
        return
    if "apps" not in tables:
        return
    op.create_table(
        "user_app_favorites",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("keycloak_user_id", sa.String(), nullable=False),
        sa.Column("application_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["application_id"], ["apps.id"], ondelete="CASCADE"
        ),
        sa.UniqueConstraint(
            "keycloak_user_id",
            "application_id",
            name="uq_user_app_favorite",
        ),
    )
    op.create_index(
        "ix_user_app_favorites_keycloak_user_id",
        "user_app_favorites",
        ["keycloak_user_id"],
    )
    op.create_index(
        "ix_user_app_favorites_application_id",
        "user_app_favorites",
        ["application_id"],
    )


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "user_app_favorites" not in tables:
        return
    op.drop_index(
        "ix_user_app_favorites_application_id", table_name="user_app_favorites"
    )
    op.drop_index(
        "ix_user_app_favorites_keycloak_user_id", table_name="user_app_favorites"
    )
    op.drop_table("user_app_favorites")
