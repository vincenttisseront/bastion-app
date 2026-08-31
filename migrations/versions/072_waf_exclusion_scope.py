"""WAF exclusions: scope_kind, target_name, uri_match.

Revision ID: 072_waf_exclusion_scope
Revises: 071_waf_ip_geoloc_enabled
Create Date: 2026-08-31
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "072_waf_exclusion_scope"
down_revision: Union[str, None] = "071_waf_ip_geoloc_enabled"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "waf_exclusions" not in inspector.get_table_names():
        return
    cols = {c["name"] for c in inspector.get_columns("waf_exclusions")}
    with op.batch_alter_table("waf_exclusions") as batch:
        if "scope_kind" not in cols:
            batch.add_column(
                sa.Column(
                    "scope_kind",
                    sa.String(),
                    nullable=False,
                    server_default="rule",
                )
            )
        if "target_name" not in cols:
            batch.add_column(sa.Column("target_name", sa.String(), nullable=True))
        if "uri_match" not in cols:
            batch.add_column(
                sa.Column(
                    "uri_match",
                    sa.String(),
                    nullable=False,
                    server_default="exact",
                )
            )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "waf_exclusions" not in inspector.get_table_names():
        return
    cols = {c["name"] for c in inspector.get_columns("waf_exclusions")}
    with op.batch_alter_table("waf_exclusions") as batch:
        if "uri_match" in cols:
            batch.drop_column("uri_match")
        if "target_name" in cols:
            batch.drop_column("target_name")
        if "scope_kind" in cols:
            batch.drop_column("scope_kind")
