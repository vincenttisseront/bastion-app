"""Create admin_mfa_credential for TOTP (Phase A) + WebAuthn columns (Phase B)."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "093_auth_mfa_credentials"
down_revision: Union[str, None] = "092_mtls_client_apps"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if "admin_mfa_credential" in inspect(bind).get_table_names():
        return
    op.create_table(
        "admin_mfa_credential",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_email", sa.String(), nullable=False),
        sa.Column("totp_secret", sa.Text(), nullable=True),
        sa.Column(
            "totp_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("webauthn_credential_id", sa.String(), nullable=True),
        sa.Column("webauthn_public_key", sa.Text(), nullable=True),
        sa.Column("webauthn_sign_count", sa.Integer(), nullable=True),
        sa.Column("webauthn_transports", sa.JSON(), nullable=True),
        sa.Column(
            "webauthn_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "user_email", name="uq_admin_mfa_credential_user_email"
        ),
        sa.UniqueConstraint(
            "webauthn_credential_id",
            name="uq_admin_mfa_credential_webauthn_id",
        ),
    )
    op.create_index(
        "ix_admin_mfa_credential_user_email",
        "admin_mfa_credential",
        ["user_email"],
    )


def downgrade() -> None:
    bind = op.get_bind()
    if "admin_mfa_credential" not in inspect(bind).get_table_names():
        return
    op.drop_index(
        "ix_admin_mfa_credential_user_email",
        table_name="admin_mfa_credential",
    )
    op.drop_table("admin_mfa_credential")
