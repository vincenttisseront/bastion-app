"""Add MTA-STS public domain split + configurable public DNS resolvers."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "075_mta_sts_public_dns"
down_revision: str | None = "074_mta_sts_portal_settings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "portal_settings",
        sa.Column(
            "mta_sts_same_public_domain",
            sa.Boolean(),
            nullable=False,
            server_default="1",
        ),
    )
    op.add_column(
        "portal_settings",
        sa.Column("mta_sts_public_mail_domain", sa.String(), nullable=True),
    )
    op.add_column(
        "portal_settings",
        sa.Column(
            "mta_sts_public_dns_resolvers",
            sa.Text(),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("portal_settings", "mta_sts_public_dns_resolvers")
    op.drop_column("portal_settings", "mta_sts_public_mail_domain")
    op.drop_column("portal_settings", "mta_sts_same_public_domain")
