"""WAF profile: ip-api.com geolocation toggle.

Revision ID: 071_waf_ip_geoloc_enabled
Revises: 070_activesync_devices
Create Date: 2026-08-28
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "071_waf_ip_geoloc_enabled"
down_revision: Union[str, None] = "070_activesync_devices"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "waf_profiles" not in inspector.get_table_names():
        return
    cols = {c["name"] for c in inspector.get_columns("waf_profiles")}
    if "ip_geoloc_enabled" not in cols:
        with op.batch_alter_table("waf_profiles") as batch:
            batch.add_column(
                sa.Column(
                    "ip_geoloc_enabled",
                    sa.Boolean(),
                    nullable=False,
                    server_default=sa.true(),
                )
            )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "waf_profiles" not in inspector.get_table_names():
        return
    cols = {c["name"] for c in inspector.get_columns("waf_profiles")}
    if "ip_geoloc_enabled" in cols:
        with op.batch_alter_table("waf_profiles") as batch:
            batch.drop_column("ip_geoloc_enabled")
