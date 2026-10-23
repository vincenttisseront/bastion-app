"""WafProfile: toggle PHP2Shell virtual-patch pack."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "087_waf_patch_php2shell"
down_revision: Union[str, None] = "086_siem_ca_pem_encrypted"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "waf_profiles" not in tables:
        return
    existing = {c["name"] for c in inspect(bind).get_columns("waf_profiles")}
    if "patch_php2shell_enabled" not in existing:
        op.add_column(
            "waf_profiles",
            sa.Column(
                "patch_php2shell_enabled",
                sa.Boolean(),
                nullable=False,
                server_default=sa.true(),
            ),
        )


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "waf_profiles" not in tables:
        return
    existing = {c["name"] for c in inspect(bind).get_columns("waf_profiles")}
    if "patch_php2shell_enabled" in existing:
        op.drop_column("waf_profiles", "patch_php2shell_enabled")
