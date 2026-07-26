"""Security anti-abuse policy, bans, allowlist, and rules."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "033_security_banning"
down_revision: Union[str, None] = "032_session_hop_secret"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())

    if "security_policy" not in tables:
        op.create_table(
            "security_policy",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column(
                "breakglass_allow_cidrs",
                sa.Text(),
                nullable=False,
                server_default="",
            ),
            sa.Column(
                "breakglass_deny_cidrs",
                sa.Text(),
                nullable=False,
                server_default="",
            ),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_by", sa.String(), nullable=True),
        )
        op.execute(
            sa.text(
                "INSERT INTO security_policy "
                "(id, enabled, breakglass_allow_cidrs, breakglass_deny_cidrs, updated_at) "
                "VALUES (1, 1, '', '', CURRENT_TIMESTAMP)"
            )
        )

    if "security_ban_rules" not in tables:
        op.create_table(
            "security_ban_rules",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("rule_type", sa.String(), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("threshold", sa.Integer(), nullable=False, server_default="0"),
            sa.Column(
                "window_seconds", sa.Integer(), nullable=False, server_default="0"
            ),
            sa.Column("ban_minutes", sa.Integer(), nullable=False, server_default="60"),
            sa.Column(
                "ban_permanent", sa.Boolean(), nullable=False, server_default=sa.false()
            ),
            sa.Column("config_json", sa.JSON(), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("rule_type", name="uq_security_ban_rule_type"),
        )
        op.create_index(
            "ix_security_ban_rules_rule_type", "security_ban_rules", ["rule_type"]
        )

    if "security_bans" not in tables:
        op.create_table(
            "security_bans",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("target_type", sa.String(), nullable=False),
            sa.Column("target", sa.String(), nullable=False),
            sa.Column("reason", sa.String(), nullable=False, server_default=""),
            sa.Column("rule_type", sa.String(), nullable=True),
            sa.Column("banned_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "permanent", sa.Boolean(), nullable=False, server_default=sa.false()
            ),
            sa.Column("lifted_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("lifted_by", sa.String(), nullable=True),
            sa.Column("created_by", sa.String(), nullable=True),
        )
        op.create_index(
            "ix_security_bans_target_type", "security_bans", ["target_type"]
        )
        op.create_index("ix_security_bans_target", "security_bans", ["target"])

    if "security_allowlist" not in tables:
        op.create_table(
            "security_allowlist",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("entry_type", sa.String(), nullable=False),
            sa.Column("value", sa.String(), nullable=False),
            sa.Column("comment", sa.String(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_by", sa.String(), nullable=True),
            sa.UniqueConstraint(
                "entry_type", "value", name="uq_security_allowlist_type_value"
            ),
        )
        op.create_index(
            "ix_security_allowlist_entry_type", "security_allowlist", ["entry_type"]
        )


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    for name in (
        "security_allowlist",
        "security_bans",
        "security_ban_rules",
        "security_policy",
    ):
        if name in tables:
            op.drop_table(name)
