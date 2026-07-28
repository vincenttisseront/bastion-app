"""Create acme_settings singleton for Admin → ACME UI."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "039_acme_settings"
down_revision: Union[str, None] = "038_pending_hosts"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if "acme_settings" in inspect(bind).get_table_names():
        return
    op.create_table(
        "acme_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("dns_api", sa.String(), nullable=False, server_default="dns_cf"),
        sa.Column("acme_ca", sa.String(), nullable=False, server_default="letsencrypt"),
        sa.Column("cf_token_encrypted", sa.Text(), nullable=True),
        sa.Column("cf_account_id", sa.String(), nullable=False, server_default=""),
        sa.Column("cf_zone_id", sa.String(), nullable=False, server_default=""),
        sa.Column("last_reconcile_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_reconcile_status", sa.String(), nullable=True),
        sa.Column("last_reconcile_message", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(), nullable=True),
    )


def downgrade() -> None:
    bind = op.get_bind()
    if "acme_settings" in inspect(bind).get_table_names():
        op.drop_table("acme_settings")
