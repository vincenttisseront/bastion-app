"""WAF profiles and targeted CRS exclusions (Phase B).

Revision ID: 066_waf_profiles
Revises: 065_global_smtp_portal_settings
Create Date: 2026-08-06
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "066_waf_profiles"
down_revision: Union[str, None] = "065_global_smtp_portal_settings"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())

    if "waf_profiles" not in tables:
        op.create_table(
            "waf_profiles",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(), nullable=False),
            sa.Column("mode", sa.String(), nullable=False, server_default="on"),
            sa.Column(
                "anomaly_threshold", sa.Integer(), nullable=False, server_default="5"
            ),
            sa.Column(
                "ip_deny_min_occurrences",
                sa.Integer(),
                nullable=False,
                server_default="3",
            ),
            sa.Column(
                "portal_login_rate", sa.Integer(), nullable=False, server_default="3"
            ),
            sa.Column(
                "portal_login_burst", sa.Integer(), nullable=False, server_default="5"
            ),
            sa.Column(
                "portal_api_rate", sa.Integer(), nullable=False, server_default="30"
            ),
            sa.Column(
                "portal_api_burst", sa.Integer(), nullable=False, server_default="60"
            ),
            sa.Column(
                "is_active", sa.Boolean(), nullable=False, server_default=sa.false()
            ),
            sa.Column("created_by", sa.String(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("name", name="uq_waf_profiles_name"),
        )
        op.create_index("ix_waf_profiles_is_active", "waf_profiles", ["is_active"])
        op.execute(
            sa.text(
                "INSERT INTO waf_profiles ("
                "name, mode, anomaly_threshold, ip_deny_min_occurrences, "
                "portal_login_rate, portal_login_burst, portal_api_rate, portal_api_burst, "
                "is_active, created_by, created_at, updated_at"
                ") VALUES ("
                "'Production', 'on', 5, 3, 3, 5, 30, 60, 1, 'migration', "
                "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP"
                ")"
            )
        )
        op.execute(
            sa.text(
                "INSERT INTO waf_profiles ("
                "name, mode, anomaly_threshold, ip_deny_min_occurrences, "
                "portal_login_rate, portal_login_burst, portal_api_rate, portal_api_burst, "
                "is_active, created_by, created_at, updated_at"
                ") VALUES ("
                "'Préproduction', 'on', 7, 3, 3, 5, 30, 60, 0, 'migration', "
                "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP"
                ")"
            )
        )
        op.execute(
            sa.text(
                "INSERT INTO waf_profiles ("
                "name, mode, anomaly_threshold, ip_deny_min_occurrences, "
                "portal_login_rate, portal_login_burst, portal_api_rate, portal_api_burst, "
                "is_active, created_by, created_at, updated_at"
                ") VALUES ("
                "'Développement', 'detection_only', 10, 3, 10, 20, 100, 50, 0, 'migration', "
                "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP"
                ")"
            )
        )

    if "waf_exclusions" not in tables:
        op.create_table(
            "waf_exclusions",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("uri_pattern", sa.String(), nullable=True),
            sa.Column("host", sa.String(), nullable=True),
            sa.Column("crs_rule_id", sa.Integer(), nullable=True),
            sa.Column("reason", sa.String(), nullable=False),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_by", sa.String(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_waf_exclusions_active", "waf_exclusions", ["active"])


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "waf_exclusions" in tables:
        op.drop_index("ix_waf_exclusions_active", table_name="waf_exclusions")
        op.drop_table("waf_exclusions")
    if "waf_profiles" in tables:
        op.drop_index("ix_waf_profiles_is_active", table_name="waf_profiles")
        op.drop_table("waf_profiles")
