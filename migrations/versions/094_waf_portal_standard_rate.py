"""Add portal_standard rate/burst columns on waf_profiles (v3.1 rate-limit)."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "094_waf_portal_standard_rate"
down_revision: Union[str, None] = "093_auth_mfa_credentials"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()
    if "waf_profiles" not in tables:
        return
    cols = {c["name"] for c in inspect(bind).get_columns("waf_profiles")}
    if "portal_standard_rate" not in cols:
        op.add_column(
            "waf_profiles",
            sa.Column(
                "portal_standard_rate",
                sa.Integer(),
                nullable=False,
                server_default="20",
            ),
        )
    if "portal_standard_burst" not in cols:
        op.add_column(
            "waf_profiles",
            sa.Column(
                "portal_standard_burst",
                sa.Integer(),
                nullable=False,
                server_default="10",
            ),
        )


def downgrade() -> None:
    bind = op.get_bind()
    if "waf_profiles" not in inspect(bind).get_table_names():
        return
    cols = {c["name"] for c in inspect(bind).get_columns("waf_profiles")}
    if "portal_standard_burst" in cols:
        op.drop_column("waf_profiles", "portal_standard_burst")
    if "portal_standard_rate" in cols:
        op.drop_column("waf_profiles", "portal_standard_rate")
