"""RBAC groups sync from Keycloak admin API."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "006_rbac_group_sync"
down_revision: Union[str, None] = "005_realm_legacy_drop"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())

    with op.batch_alter_table("realm_configs") as batch_op:
        batch_op.add_column(sa.Column("keycloak_admin_client_id", sa.String(), nullable=True))
        batch_op.add_column(
            sa.Column("keycloak_admin_client_secret_encrypted", sa.String(), nullable=True)
        )
        batch_op.add_column(sa.Column("groups_sync_enabled", sa.Boolean(), nullable=False, server_default=sa.text("0")))
        batch_op.add_column(sa.Column("last_groups_sync_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("last_groups_sync_status", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("last_groups_sync_error", sa.String(), nullable=True))

    if "rbac_groups" not in tables:
        op.create_table(
            "rbac_groups",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(), nullable=False),
            sa.Column("realm_slug", sa.String(), nullable=True),
            sa.Column("realm_id", sa.Integer(), nullable=True),
            sa.Column("keycloak_group_id", sa.String(), nullable=True),
            sa.Column("path", sa.String(), nullable=True),
            sa.Column("member_count", sa.Integer(), nullable=True),
            sa.Column("synced_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint("realm_id", "keycloak_group_id", name="uq_realm_kc_group"),
            sa.ForeignKeyConstraint(
                ["realm_id"],
                ["realm_configs.id"],
                name="fk_rbac_groups_realm_id",
                ondelete="SET NULL",
            ),
        )
        op.create_index("ix_rbac_groups_realm_id", "rbac_groups", ["realm_id"])
        op.create_index(
            "ix_rbac_groups_keycloak_group_id", "rbac_groups", ["keycloak_group_id"]
        )
        op.create_index("ix_rbac_groups_name", "rbac_groups", ["name"])
    else:
        with op.batch_alter_table("rbac_groups") as batch_op:
            # Keep existing 'name' and legacy 'realm_slug'. Add sync metadata.
            batch_op.add_column(sa.Column("realm_id", sa.Integer(), nullable=True))
            batch_op.add_column(sa.Column("keycloak_group_id", sa.String(), nullable=True))
            batch_op.add_column(sa.Column("path", sa.String(), nullable=True))
            batch_op.add_column(sa.Column("member_count", sa.Integer(), nullable=True))
            batch_op.add_column(sa.Column("synced_at", sa.DateTime(timezone=True), nullable=True))
            batch_op.create_index("ix_rbac_groups_realm_id", ["realm_id"])
            batch_op.create_index("ix_rbac_groups_keycloak_group_id", ["keycloak_group_id"])
            batch_op.create_index("ix_rbac_groups_name", ["name"])
            batch_op.create_unique_constraint("uq_realm_kc_group", ["realm_id", "keycloak_group_id"])

        op.create_foreign_key(
            "fk_rbac_groups_realm_id",
            "rbac_groups",
            "realm_configs",
            ["realm_id"],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    # Downgrade is best-effort; keep data.
    with op.batch_alter_table("rbac_groups") as batch_op:
        batch_op.drop_constraint("uq_realm_kc_group", type_="unique")
        batch_op.drop_index("ix_rbac_groups_keycloak_group_id")
        batch_op.drop_index("ix_rbac_groups_realm_id")
        batch_op.drop_column("synced_at")
        batch_op.drop_column("member_count")
        batch_op.drop_column("path")
        batch_op.drop_column("keycloak_group_id")
        batch_op.drop_column("realm_id")

    with op.batch_alter_table("realm_configs") as batch_op:
        batch_op.drop_column("last_groups_sync_error")
        batch_op.drop_column("last_groups_sync_status")
        batch_op.drop_column("last_groups_sync_at")
        batch_op.drop_column("groups_sync_enabled")
        batch_op.drop_column("keycloak_admin_client_secret_encrypted")
        batch_op.drop_column("keycloak_admin_client_id")

