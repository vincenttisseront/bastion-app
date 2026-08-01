"""Add oidc_sessions table (native bastion OIDC session registry)."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "052_oidc_sessions"
down_revision: Union[str, None] = "051_branding_settings"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()
    if "oidc_sessions" in tables:
        return
    op.create_table(
        "oidc_sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("jti", sa.String(), nullable=False),
        sa.Column("sub", sa.String(), nullable=False),
        sa.Column("username", sa.String(), nullable=True),
        sa.Column("realm", sa.String(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(), nullable=True),
        sa.Column("revoked_reason", sa.String(), nullable=True),
        sa.Column("ip_subnet", sa.String(), nullable=True),
        sa.Column("fingerprint_hash", sa.String(), nullable=True),
    )
    op.create_index("ix_oidc_sessions_jti", "oidc_sessions", ["jti"], unique=True)
    op.create_index("ix_oidc_sessions_sub", "oidc_sessions", ["sub"])


def downgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()
    if "oidc_sessions" not in tables:
        return
    indexes = {i["name"] for i in inspect(bind).get_indexes("oidc_sessions")}
    if "ix_oidc_sessions_sub" in indexes:
        op.drop_index("ix_oidc_sessions_sub", table_name="oidc_sessions")
    if "ix_oidc_sessions_jti" in indexes:
        op.drop_index("ix_oidc_sessions_jti", table_name="oidc_sessions")
    op.drop_table("oidc_sessions")
