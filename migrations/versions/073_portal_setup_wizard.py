"""Portal site identity + setup wizard columns on portal_settings."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "073_portal_setup_wizard"
down_revision: Union[str, None] = "072_waf_exclusion_scope"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "portal_settings",
        sa.Column("portal_domain", sa.String(), nullable=True),
    )
    op.add_column(
        "portal_settings",
        sa.Column("default_realm_slug", sa.String(), nullable=True),
    )
    op.add_column(
        "portal_settings",
        sa.Column(
            "setup_wizard_completed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("portal_settings", "setup_wizard_completed_at")
    op.drop_column("portal_settings", "default_realm_slug")
    op.drop_column("portal_settings", "portal_domain")
