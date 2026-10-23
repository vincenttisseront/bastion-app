"""WafProfile: extended virtual-patch pack modes (WP / API JSON / RCE)."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "090_waf_extended_packs"
down_revision: Union[str, None] = "089_waf_paranoia_level"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_COLUMNS = (
    "patch_wordpress_cms_mode",
    "patch_api_json_strict_mode",
    "patch_rce_extended_mode",
)


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "waf_profiles" not in tables:
        return
    existing = {c["name"] for c in inspect(bind).get_columns("waf_profiles")}
    for col in _COLUMNS:
        if col in existing:
            continue
        op.add_column(
            "waf_profiles",
            sa.Column(
                col,
                sa.String(),
                nullable=False,
                server_default="off",
            ),
        )


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "waf_profiles" not in tables:
        return
    existing = {c["name"] for c in inspect(bind).get_columns("waf_profiles")}
    for col in reversed(_COLUMNS):
        if col in existing:
            op.drop_column("waf_profiles", col)
