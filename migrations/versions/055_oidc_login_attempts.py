"""Add oidc_login_attempts table (short-lived password→OTP headless state)."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "055_oidc_login_attempts"
down_revision: Union[str, None] = "054_oidc_bff_realm_config"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()
    if "oidc_login_attempts" in tables:
        return
    op.create_table(
        "oidc_login_attempts",
        sa.Column("attempt_id", sa.String(), primary_key=True),
        sa.Column("realm", sa.String(), nullable=False),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("keycloak_cookies_encrypted", sa.Text(), nullable=False),
        sa.Column("otp_form_encrypted", sa.Text(), nullable=False),
        sa.Column("code_verifier", sa.String(), nullable=False),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("keycloak_base_url", sa.String(), nullable=False),
        sa.Column("keycloak_realm", sa.String(), nullable=False),
        sa.Column("client_id", sa.String(), nullable=False),
        sa.Column("redirect_uri", sa.String(), nullable=False),
        sa.Column("otp_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_oidc_login_attempts_realm", "oidc_login_attempts", ["realm"])
    op.create_index(
        "ix_oidc_login_attempts_expires_at", "oidc_login_attempts", ["expires_at"]
    )


def downgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()
    if "oidc_login_attempts" not in tables:
        return
    indexes = {i["name"] for i in inspect(bind).get_indexes("oidc_login_attempts")}
    if "ix_oidc_login_attempts_expires_at" in indexes:
        op.drop_index("ix_oidc_login_attempts_expires_at", table_name="oidc_login_attempts")
    if "ix_oidc_login_attempts_realm" in indexes:
        op.drop_index("ix_oidc_login_attempts_realm", table_name="oidc_login_attempts")
    op.drop_table("oidc_login_attempts")
