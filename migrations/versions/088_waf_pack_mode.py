"""WafProfile: virtual-patch pack mode (off|detection|on)."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect, text

revision: str = "088_waf_pack_mode"
down_revision: Union[str, None] = "087_waf_patch_php2shell"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "waf_profiles" not in tables:
        return
    existing = {c["name"] for c in inspect(bind).get_columns("waf_profiles")}
    if "patch_php2shell_mode" not in existing:
        op.add_column(
            "waf_profiles",
            sa.Column(
                "patch_php2shell_mode",
                sa.String(),
                nullable=False,
                server_default="on",
            ),
        )
    if "patch_php2shell_enabled" in existing:
        bind.execute(
            text(
                "UPDATE waf_profiles SET patch_php2shell_mode = "
                "CASE WHEN patch_php2shell_enabled = 0 THEN 'off' ELSE 'on' END"
            )
        )


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "waf_profiles" not in tables:
        return
    existing = {c["name"] for c in inspect(bind).get_columns("waf_profiles")}
    if "patch_php2shell_mode" in existing:
        if "patch_php2shell_enabled" in existing:
            bind.execute(
                text(
                    "UPDATE waf_profiles SET patch_php2shell_enabled = "
                    "CASE WHEN patch_php2shell_mode = 'off' THEN 0 ELSE 1 END"
                )
            )
        op.drop_column("waf_profiles", "patch_php2shell_mode")
