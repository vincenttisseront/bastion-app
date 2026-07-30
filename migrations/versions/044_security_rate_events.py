"""Shared security rate-limit events (multi-worker counters) + new ban rule types."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "044_security_rate_events"
down_revision: Union[str, None] = "043_upstream_tls_verify"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())

    if "security_rate_events" not in tables:
        op.create_table(
            "security_rate_events",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("kind", sa.String(), nullable=False),
            sa.Column("key", sa.String(), nullable=False),
            sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index(
            "ix_security_rate_events_kind_key_at",
            "security_rate_events",
            ["kind", "key", "occurred_at"],
        )
        op.create_index(
            "ix_security_rate_events_occurred_at",
            "security_rate_events",
            ["occurred_at"],
        )

    if "security_ban_rules" in tables:
        # Seed new rule types if missing (idempotent).
        op.execute(
            sa.text(
                """
                INSERT INTO security_ban_rules
                  (rule_type, enabled, threshold, window_seconds, ban_minutes,
                   ban_permanent, config_json, updated_at)
                SELECT 'hammering_login', 1, 30, 60, 60, 0, NULL, CURRENT_TIMESTAMP
                WHERE NOT EXISTS (
                  SELECT 1 FROM security_ban_rules WHERE rule_type = 'hammering_login'
                )
                """
            )
        )
        op.execute(
            sa.text(
                """
                INSERT INTO security_ban_rules
                  (rule_type, enabled, threshold, window_seconds, ban_minutes,
                   ban_permanent, config_json, updated_at)
                SELECT 'successful_login', 1, 20, 300, 30, 0, NULL, CURRENT_TIMESTAMP
                WHERE NOT EXISTS (
                  SELECT 1 FROM security_ban_rules WHERE rule_type = 'successful_login'
                )
                """
            )
        )


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "security_rate_events" in tables:
        op.drop_table("security_rate_events")
    if "security_ban_rules" in tables:
        op.execute(
            sa.text(
                "DELETE FROM security_ban_rules "
                "WHERE rule_type IN ('hammering_login', 'successful_login')"
            )
        )
