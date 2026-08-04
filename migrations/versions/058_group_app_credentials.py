"""Group-scoped vault credentials + per-user exclusions."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "058_group_app_credentials"
down_revision: Union[str, None] = "057_realm_smtp_access_requests"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "group_app_credentials" not in tables:
        op.create_table(
            "group_app_credentials",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column(
                "rbac_group_id",
                sa.Integer(),
                sa.ForeignKey("rbac_groups.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "app_slug",
                sa.String(),
                sa.ForeignKey("apps.slug"),
                nullable=False,
            ),
            sa.Column("robotic_username", sa.String(), nullable=False),
            sa.Column("encrypted_password", sa.Text(), nullable=False),
            sa.Column(
                "priority",
                sa.Integer(),
                nullable=False,
                server_default="100",
            ),
            sa.Column(
                "is_active",
                sa.Boolean(),
                nullable=False,
                server_default=sa.true(),
            ),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint(
                "rbac_group_id",
                "app_slug",
                name="uq_group_app_credential",
            ),
        )
        op.create_index(
            "ix_group_app_credentials_rbac_group_id",
            "group_app_credentials",
            ["rbac_group_id"],
        )
        op.create_index(
            "ix_group_app_credentials_app_slug",
            "group_app_credentials",
            ["app_slug"],
        )

    tables = set(inspect(bind).get_table_names())
    if "group_app_credential_exclusions" not in tables:
        op.create_table(
            "group_app_credential_exclusions",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column(
                "group_app_credential_id",
                sa.Integer(),
                sa.ForeignKey("group_app_credentials.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("keycloak_user_id", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint(
                "group_app_credential_id",
                "keycloak_user_id",
                name="uq_group_app_credential_exclusion",
            ),
        )
        op.create_index(
            "ix_group_app_credential_exclusions_cred_id",
            "group_app_credential_exclusions",
            ["group_app_credential_id"],
        )
        op.create_index(
            "ix_group_app_credential_exclusions_kc_user",
            "group_app_credential_exclusions",
            ["keycloak_user_id"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "group_app_credential_exclusions" in tables:
        op.drop_index(
            "ix_group_app_credential_exclusions_kc_user",
            table_name="group_app_credential_exclusions",
        )
        op.drop_index(
            "ix_group_app_credential_exclusions_cred_id",
            table_name="group_app_credential_exclusions",
        )
        op.drop_table("group_app_credential_exclusions")
    if "group_app_credentials" in tables:
        op.drop_index(
            "ix_group_app_credentials_app_slug",
            table_name="group_app_credentials",
        )
        op.drop_index(
            "ix_group_app_credentials_rbac_group_id",
            table_name="group_app_credentials",
        )
        op.drop_table("group_app_credentials")
