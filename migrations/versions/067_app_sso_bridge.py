"""Add apps.sso_bridge — trusted_headers vs app_oidc under auth_mode=sso.

Revision ID: 067_app_sso_bridge
Revises: 066_waf_profiles
Create Date: 2026-08-07
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "067_app_sso_bridge"
down_revision: Union[str, None] = "066_waf_profiles"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if "apps" not in inspect(bind).get_table_names():
        return
    cols = {c["name"] for c in inspect(bind).get_columns("apps")}
    if "sso_bridge" in cols:
        return
    op.add_column(
        "apps",
        sa.Column(
            "sso_bridge",
            sa.String(),
            nullable=False,
            server_default="trusted_headers",
        ),
    )


def downgrade() -> None:
    bind = op.get_bind()
    if "apps" not in inspect(bind).get_table_names():
        return
    cols = {c["name"] for c in inspect(bind).get_columns("apps")}
    if "sso_bridge" not in cols:
        return
    op.drop_column("apps", "sso_bridge")
