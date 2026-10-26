"""WafProfile: OWASP CRS paranoia level (1–4)."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "089_waf_paranoia_level"
down_revision: Union[str, None] = "088_waf_pack_mode"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "waf_profiles" not in tables:
        return
    existing = {c["name"] for c in inspect(bind).get_columns("waf_profiles")}
    if "paranoia_level" not in existing:
        op.add_column(
            "waf_profiles",
            sa.Column(
                "paranoia_level",
                sa.Integer(),
                nullable=False,
                server_default="1",
            ),
        )


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "waf_profiles" not in tables:
        return
    existing = {c["name"] for c in inspect(bind).get_columns("waf_profiles")}
    if "paranoia_level" in existing:
        op.drop_column("waf_profiles", "paranoia_level")
