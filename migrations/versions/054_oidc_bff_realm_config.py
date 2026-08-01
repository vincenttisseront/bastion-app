"""Add per-realm OIDC BFF client columns + global OIDC session JWT secret (PortalSettings)."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "054_oidc_bff_realm_config"
down_revision: Union[str, None] = "053_oidc_native_session_realm"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()

    if "realm_configs" in tables:
        cols = {c["name"] for c in inspect(bind).get_columns("realm_configs")}
        with op.batch_alter_table("realm_configs") as batch:
            if "oidc_keycloak_base_url" not in cols:
                batch.add_column(sa.Column("oidc_keycloak_base_url", sa.String(), nullable=True))
            if "oidc_bff_client_id" not in cols:
                batch.add_column(sa.Column("oidc_bff_client_id", sa.String(), nullable=True))
            if "oidc_bff_client_secret_encrypted" not in cols:
                batch.add_column(
                    sa.Column("oidc_bff_client_secret_encrypted", sa.Text(), nullable=True)
                )
            if "oidc_bff_redirect_uri" not in cols:
                batch.add_column(sa.Column("oidc_bff_redirect_uri", sa.String(), nullable=True))

    if "portal_settings" in tables:
        pcols = {c["name"] for c in inspect(bind).get_columns("portal_settings")}
        if "oidc_session_jwt_secret_encrypted" not in pcols:
            with op.batch_alter_table("portal_settings") as batch:
                batch.add_column(
                    sa.Column("oidc_session_jwt_secret_encrypted", sa.Text(), nullable=True)
                )


def downgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()

    if "realm_configs" in tables:
        cols = {c["name"] for c in inspect(bind).get_columns("realm_configs")}
        with op.batch_alter_table("realm_configs") as batch:
            for name in (
                "oidc_bff_redirect_uri",
                "oidc_bff_client_secret_encrypted",
                "oidc_bff_client_id",
                "oidc_keycloak_base_url",
            ):
                if name in cols:
                    batch.drop_column(name)

    if "portal_settings" in tables:
        pcols = {c["name"] for c in inspect(bind).get_columns("portal_settings")}
        if "oidc_session_jwt_secret_encrypted" in pcols:
            with op.batch_alter_table("portal_settings") as batch:
                batch.drop_column("oidc_session_jwt_secret_encrypted")
