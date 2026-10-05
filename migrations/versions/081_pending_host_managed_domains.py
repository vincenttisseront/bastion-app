"""Alembic: extra managed domain suffixes for pending-host discovery filter."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "081_pending_host_managed_domains"
down_revision: Union[str, None] = "080_siem_syslog_ca"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "portal_settings" not in tables:
        return
    existing = {c["name"] for c in inspect(bind).get_columns("portal_settings")}
    if "managed_domain_suffixes" in existing:
        return
    op.add_column(
        "portal_settings",
        sa.Column("managed_domain_suffixes", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "portal_settings" not in tables:
        return
    existing = {c["name"] for c in inspect(bind).get_columns("portal_settings")}
    if "managed_domain_suffixes" not in existing:
        return
    op.drop_column("portal_settings", "managed_domain_suffixes")
