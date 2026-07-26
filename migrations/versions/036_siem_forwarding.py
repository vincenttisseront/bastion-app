"""SIEM forwarding settings + persistent outbox."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "036_siem_forwarding"
down_revision: Union[str, None] = "035_saved_log_views"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())

    if "siem_forwarding_settings" not in tables:
        op.create_table(
            "siem_forwarding_settings",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column(
                "enabled", sa.Boolean(), nullable=False, server_default=sa.false()
            ),
            sa.Column(
                "protocol",
                sa.String(),
                nullable=False,
                server_default="webhook_https",
            ),
            sa.Column("syslog_host", sa.String(), nullable=False, server_default=""),
            sa.Column(
                "syslog_port", sa.Integer(), nullable=False, server_default="6514"
            ),
            sa.Column(
                "syslog_tls_verify",
                sa.Boolean(),
                nullable=False,
                server_default=sa.true(),
            ),
            sa.Column("webhook_url", sa.String(), nullable=False, server_default=""),
            sa.Column(
                "webhook_auth_type",
                sa.String(),
                nullable=False,
                server_default="none",
            ),
            sa.Column("webhook_auth_secret_encrypted", sa.Text(), nullable=True),
            sa.Column(
                "filter_mode",
                sa.String(),
                nullable=False,
                server_default="denylist",
            ),
            sa.Column("filter_actions", sa.JSON(), nullable=False),
            sa.Column(
                "retry_max_queue_size",
                sa.Integer(),
                nullable=False,
                server_default="5000",
            ),
            sa.Column(
                "retry_max_age_minutes",
                sa.Integer(),
                nullable=False,
                server_default="1440",
            ),
            sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_by", sa.String(), nullable=True),
        )

    now = datetime.now(timezone.utc)
    existing = bind.execute(
        sa.text("SELECT id FROM siem_forwarding_settings WHERE id = 1")
    ).fetchone()
    if existing is None:
        bind.execute(
            sa.text(
                "INSERT INTO siem_forwarding_settings "
                "(id, enabled, protocol, syslog_host, syslog_port, syslog_tls_verify, "
                "webhook_url, webhook_auth_type, filter_mode, filter_actions, "
                "retry_max_queue_size, retry_max_age_minutes, updated_at) "
                "VALUES (1, 0, 'webhook_https', '', 6514, 1, '', 'none', "
                "'denylist', :actions, 5000, 1440, :updated_at)"
            ),
            {"actions": json.dumps([]), "updated_at": now},
        )

    if "siem_outbox" not in tables:
        op.create_table(
            "siem_outbox",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("audit_log_id", sa.Integer(), nullable=False),
            sa.Column("action", sa.String(), nullable=False),
            sa.Column("payload_json", sa.JSON(), nullable=False),
            sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_error", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_siem_outbox_audit_log_id", "siem_outbox", ["audit_log_id"])
        op.create_index("ix_siem_outbox_action", "siem_outbox", ["action"])
        op.create_index(
            "ix_siem_outbox_next_attempt_at", "siem_outbox", ["next_attempt_at"]
        )
        op.create_index("ix_siem_outbox_created_at", "siem_outbox", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_siem_outbox_created_at", table_name="siem_outbox")
    op.drop_index("ix_siem_outbox_next_attempt_at", table_name="siem_outbox")
    op.drop_index("ix_siem_outbox_action", table_name="siem_outbox")
    op.drop_index("ix_siem_outbox_audit_log_id", table_name="siem_outbox")
    op.drop_table("siem_outbox")
    op.drop_table("siem_forwarding_settings")
