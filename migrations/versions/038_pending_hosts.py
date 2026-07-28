"""Create pending_hosts for bastion-nginx unknown-Host discovery."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "038_pending_hosts"
down_revision: Union[str, None] = "037_public_proxy_access_mode"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if "pending_hosts" in inspect(bind).get_table_names():
        return
    op.create_table(
        "pending_hosts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("hostname", sa.String(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("hit_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("last_client_ip", sa.String(), nullable=True),
        sa.Column("last_user_agent", sa.String(), nullable=True),
        sa.Column("last_uri", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="pending"),
        sa.Column("approved_app_slug", sa.String(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_pending_hosts_hostname", "pending_hosts", ["hostname"], unique=True)
    op.create_index("ix_pending_hosts_status", "pending_hosts", ["status"])


def downgrade() -> None:
    bind = op.get_bind()
    if "pending_hosts" not in inspect(bind).get_table_names():
        return
    op.drop_index("ix_pending_hosts_status", table_name="pending_hosts")
    op.drop_index("ix_pending_hosts_hostname", table_name="pending_hosts")
    op.drop_table("pending_hosts")
