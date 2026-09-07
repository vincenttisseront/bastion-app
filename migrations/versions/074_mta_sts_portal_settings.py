"""MTA-STS policy columns on portal_settings (publish via nginx edge)."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "074_mta_sts_portal_settings"
down_revision: Union[str, None] = "073_portal_setup_wizard"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "portal_settings",
        sa.Column("mta_sts_enabled", sa.Boolean(), nullable=False, server_default="0"),
    )
    op.add_column(
        "portal_settings",
        sa.Column("mta_sts_mail_domain", sa.String(), nullable=True),
    )
    op.add_column(
        "portal_settings",
        sa.Column("mta_sts_mode", sa.String(), nullable=False, server_default="testing"),
    )
    op.add_column(
        "portal_settings",
        sa.Column("mta_sts_mx_hosts", sa.Text(), nullable=True),
    )
    op.add_column(
        "portal_settings",
        sa.Column("mta_sts_max_age", sa.Integer(), nullable=False, server_default="604800"),
    )
    op.add_column(
        "portal_settings",
        sa.Column(
            "mta_sts_published_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("portal_settings", "mta_sts_published_at")
    op.drop_column("portal_settings", "mta_sts_max_age")
    op.drop_column("portal_settings", "mta_sts_mx_hosts")
    op.drop_column("portal_settings", "mta_sts_mode")
    op.drop_column("portal_settings", "mta_sts_mail_domain")
    op.drop_column("portal_settings", "mta_sts_enabled")
