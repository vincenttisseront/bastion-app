"""Add audit event_code/severity columns and saved_log_views.is_system.

Revision ID: 068_audit_event_codes
Revises: 067_app_sso_bridge
Create Date: 2026-08-12
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "068_audit_event_codes"
down_revision: Union[str, None] = "067_app_sso_bridge"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "audit_logs" in tables:
        cols = {c["name"] for c in inspect(bind).get_columns("audit_logs")}
        if "event_code" not in cols:
            op.add_column("audit_logs", sa.Column("event_code", sa.String(), nullable=True))
        if "severity" not in cols:
            op.add_column("audit_logs", sa.Column("severity", sa.String(), nullable=True))
        existing = {ix["name"] for ix in inspect(bind).get_indexes("audit_logs")}
        if "ix_audit_logs_event_code" not in existing:
            op.create_index("ix_audit_logs_event_code", "audit_logs", ["event_code"])
        if "ix_audit_logs_severity" not in existing:
            op.create_index("ix_audit_logs_severity", "audit_logs", ["severity"])
    if "saved_log_views" in tables:
        cols = {c["name"] for c in inspect(bind).get_columns("saved_log_views")}
        if "is_system" not in cols:
            op.add_column(
                "saved_log_views",
                sa.Column("is_system", sa.Boolean(), nullable=False, server_default="0"),
            )


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "audit_logs" in tables:
        existing = {ix["name"] for ix in inspect(bind).get_indexes("audit_logs")}
        if "ix_audit_logs_severity" in existing:
            op.drop_index("ix_audit_logs_severity", table_name="audit_logs")
        if "ix_audit_logs_event_code" in existing:
            op.drop_index("ix_audit_logs_event_code", table_name="audit_logs")
        cols = {c["name"] for c in inspect(bind).get_columns("audit_logs")}
        if "severity" in cols:
            op.drop_column("audit_logs", "severity")
        if "event_code" in cols:
            op.drop_column("audit_logs", "event_code")
    if "saved_log_views" in tables:
        cols = {c["name"] for c in inspect(bind).get_columns("saved_log_views")}
        if "is_system" in cols:
            op.drop_column("saved_log_views", "is_system")
