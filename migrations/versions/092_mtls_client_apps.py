"""Create mtls_client_apps for inter-app mTLS client identities."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "092_mtls_client_apps"
down_revision: Union[str, None] = "091_acme_certificate_domain"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if "mtls_client_apps" in inspect(bind).get_table_names():
        return
    op.create_table(
        "mtls_client_apps",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("app_name", sa.String(), nullable=False),
        sa.Column("cn", sa.String(), nullable=False),
        sa.Column(
            "status", sa.String(), nullable=False, server_default="active"
        ),
        sa.Column("serial_number", sa.String(), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("app_name", name="uq_mtls_client_apps_app_name"),
        sa.UniqueConstraint("cn", name="uq_mtls_client_apps_cn"),
        sa.CheckConstraint(
            "status IN ('active', 'revoked')",
            name="ck_mtls_client_apps_status",
        ),
    )
    op.create_index(
        "ix_mtls_client_apps_app_name", "mtls_client_apps", ["app_name"]
    )


def downgrade() -> None:
    bind = op.get_bind()
    if "mtls_client_apps" not in inspect(bind).get_table_names():
        return
    op.drop_index("ix_mtls_client_apps_app_name", table_name="mtls_client_apps")
    op.drop_table("mtls_client_apps")
