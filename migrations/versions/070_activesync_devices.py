"""ActiveSync device inventory + per-app device gate.

Revision ID: 070_activesync_devices
Revises: 069_daily_recap_smtp
Create Date: 2026-08-14
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "070_activesync_devices"
down_revision: Union[str, None] = "069_daily_recap_smtp"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    tables = set(inspector.get_table_names())

    if "apps" in tables:
        cols = {c["name"] for c in inspector.get_columns("apps")}
        with op.batch_alter_table("apps") as batch:
            if "activesync_device_control" not in cols:
                batch.add_column(
                    sa.Column(
                        "activesync_device_control",
                        sa.Boolean(),
                        nullable=False,
                        server_default=sa.false(),
                    )
                )
            if "activesync_device_control_enabled_at" not in cols:
                batch.add_column(
                    sa.Column(
                        "activesync_device_control_enabled_at",
                        sa.DateTime(timezone=True),
                        nullable=True,
                    )
                )

    if "activesync_devices" in tables:
        return

    op.create_table(
        "activesync_devices",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "application_id",
            sa.Integer(),
            sa.ForeignKey("apps.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("user_key", sa.String(), nullable=False),
        sa.Column("keycloak_user_id", sa.String(), nullable=True),
        sa.Column(
            "realm_id",
            sa.Integer(),
            sa.ForeignKey("realm_configs.id"),
            nullable=True,
        ),
        sa.Column("device_id", sa.String(), nullable=False),
        sa.Column("device_type", sa.String(), nullable=True),
        sa.Column("friendly_name", sa.String(), nullable=True),
        sa.Column("user_agent", sa.String(), nullable=True),
        sa.Column("client_kind", sa.String(), nullable=True),
        sa.Column(
            "status", sa.String(), nullable=False, server_default="pending"
        ),
        sa.Column("source", sa.String(), nullable=False, server_default="observed"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("last_ip", sa.String(), nullable=True),
        sa.Column("sample_source_ips", sa.JSON(), nullable=True),
        sa.Column("decided_by", sa.String(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_note", sa.Text(), nullable=True),
        sa.Column(
            "blocked_by_admin",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "application_id",
            "user_key",
            "device_id",
            name="uq_activesync_device_app_user_device",
        ),
    )
    op.create_index(
        "ix_activesync_devices_application_id", "activesync_devices", ["application_id"]
    )
    op.create_index("ix_activesync_devices_user_key", "activesync_devices", ["user_key"])
    op.create_index(
        "ix_activesync_devices_keycloak_user_id",
        "activesync_devices",
        ["keycloak_user_id"],
    )
    op.create_index("ix_activesync_devices_realm_id", "activesync_devices", ["realm_id"])
    op.create_index(
        "ix_activesync_devices_device_id", "activesync_devices", ["device_id"]
    )
    op.create_index("ix_activesync_devices_status", "activesync_devices", ["status"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    tables = set(inspector.get_table_names())

    if "activesync_devices" in tables:
        op.drop_table("activesync_devices")

    if "apps" in tables:
        cols = {c["name"] for c in inspector.get_columns("apps")}
        with op.batch_alter_table("apps") as batch:
            if "activesync_device_control_enabled_at" in cols:
                batch.drop_column("activesync_device_control_enabled_at")
            if "activesync_device_control" in cols:
                batch.drop_column("activesync_device_control")
