"""Access grants — group or user subjects, application or system role resources."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "007_access_grants"
down_revision: Union[str, None] = "006_rbac_group_sync"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "access_grants",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("subject_type", sa.String(), nullable=False),
        sa.Column("rbac_group_id", sa.Integer(), nullable=True),
        sa.Column("keycloak_user_id", sa.String(), nullable=True),
        sa.Column("user_display_cache", sa.String(), nullable=True),
        sa.Column("resource_type", sa.String(), nullable=False),
        sa.Column("application_id", sa.Integer(), nullable=True),
        sa.Column("system_role", sa.String(), nullable=True),
        sa.Column("access_level", sa.String(), nullable=False, server_default="view"),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("granted_by", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["rbac_group_id"], ["rbac_groups.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["application_id"], ["apps.id"], ondelete="CASCADE"),
        sa.CheckConstraint(
            "(subject_type = 'group' AND rbac_group_id IS NOT NULL AND keycloak_user_id IS NULL) OR "
            "(subject_type = 'user' AND keycloak_user_id IS NOT NULL AND rbac_group_id IS NULL)",
            name="ck_access_grant_subject_exclusive",
        ),
        sa.CheckConstraint(
            "(resource_type = 'application' AND application_id IS NOT NULL AND system_role IS NULL) OR "
            "(resource_type = 'system_role' AND system_role IS NOT NULL AND application_id IS NULL)",
            name="ck_access_grant_resource_exclusive",
        ),
    )
    op.create_index("ix_access_grants_rbac_group_id", "access_grants", ["rbac_group_id"])
    op.create_index("ix_access_grants_keycloak_user_id", "access_grants", ["keycloak_user_id"])
    op.create_index("ix_access_grants_application_id", "access_grants", ["application_id"])


def downgrade() -> None:
    op.drop_index("ix_access_grants_application_id", table_name="access_grants")
    op.drop_index("ix_access_grants_keycloak_user_id", table_name="access_grants")
    op.drop_index("ix_access_grants_rbac_group_id", table_name="access_grants")
    op.drop_table("access_grants")
