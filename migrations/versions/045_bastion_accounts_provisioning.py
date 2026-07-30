"""Bastion accounts (Keycloak user creation) + per-app provisioning.

- bastion_accounts / bastion_account_provisioning tables
- realm_configs: keycloak_provision_client_id / _secret_encrypted + provisioning_enabled
  (explicit opt-in, NOT auto-derived like groups_sync_enabled)
- apps: provisioning_driver (nullable — None = SSO only)
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "045_bastion_accounts_provisioning"
down_revision: Union[str, None] = "044_security_rate_events"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    tables = set(inspector.get_table_names())

    if "bastion_accounts" not in tables:
        op.create_table(
            "bastion_accounts",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column(
                "realm_id",
                sa.Integer(),
                sa.ForeignKey("realm_configs.id"),
                nullable=False,
                index=True,
            ),
            sa.Column("username", sa.String(), nullable=False),
            sa.Column("email", sa.String(), nullable=False),
            sa.Column("first_name", sa.String(), nullable=True),
            sa.Column("last_name", sa.String(), nullable=True),
            sa.Column("keycloak_user_id", sa.String(), nullable=True, index=True),
            sa.Column("status", sa.String(), nullable=False, server_default="pending"),
            sa.Column("created_by", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_error", sa.String(), nullable=True),
            sa.UniqueConstraint(
                "realm_id", "username", name="uq_bastion_account_realm_username"
            ),
        )

    if "bastion_account_provisioning" not in tables:
        op.create_table(
            "bastion_account_provisioning",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column(
                "bastion_account_id",
                sa.Integer(),
                sa.ForeignKey("bastion_accounts.id"),
                nullable=False,
                index=True,
            ),
            sa.Column(
                "application_id",
                sa.Integer(),
                sa.ForeignKey("apps.id"),
                nullable=False,
                index=True,
            ),
            sa.Column("driver_name", sa.String(), nullable=False),
            sa.Column("status", sa.String(), nullable=False, server_default="pending"),
            sa.Column("detail", sa.String(), nullable=True),
            sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint(
                "bastion_account_id",
                "application_id",
                name="uq_bastion_account_provisioning_app",
            ),
        )

    if "realm_configs" in tables:
        realm_cols = {c["name"] for c in inspector.get_columns("realm_configs")}
        if "keycloak_provision_client_id" not in realm_cols:
            op.add_column(
                "realm_configs",
                sa.Column("keycloak_provision_client_id", sa.String(), nullable=True),
            )
        if "keycloak_provision_client_secret_encrypted" not in realm_cols:
            op.add_column(
                "realm_configs",
                sa.Column(
                    "keycloak_provision_client_secret_encrypted",
                    sa.String(),
                    nullable=True,
                ),
            )
        if "provisioning_enabled" not in realm_cols:
            op.add_column(
                "realm_configs",
                sa.Column(
                    "provisioning_enabled",
                    sa.Boolean(),
                    nullable=False,
                    server_default=sa.false(),
                ),
            )

    if "apps" in tables:
        app_cols = {c["name"] for c in inspector.get_columns("apps")}
        if "provisioning_driver" not in app_cols:
            op.add_column(
                "apps",
                sa.Column("provisioning_driver", sa.String(), nullable=True),
            )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    tables = set(inspector.get_table_names())

    if "bastion_account_provisioning" in tables:
        op.drop_table("bastion_account_provisioning")
    if "bastion_accounts" in tables:
        op.drop_table("bastion_accounts")

    if "realm_configs" in tables:
        realm_cols = {c["name"] for c in inspector.get_columns("realm_configs")}
        for col in (
            "provisioning_enabled",
            "keycloak_provision_client_secret_encrypted",
            "keycloak_provision_client_id",
        ):
            if col in realm_cols:
                op.drop_column("realm_configs", col)

    if "apps" in tables:
        app_cols = {c["name"] for c in inspector.get_columns("apps")}
        if "provisioning_driver" in app_cols:
            op.drop_column("apps", "provisioning_driver")
