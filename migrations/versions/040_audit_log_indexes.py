"""Add indexes for notification center / admin logs audit queries."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "040_audit_log_indexes"
down_revision: Union[str, None] = "039_acme_settings"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "audit_logs" not in tables:
        return
    existing = {ix["name"] for ix in inspect(bind).get_indexes("audit_logs")}
    if "ix_audit_logs_created_at" not in existing:
        op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])
    if "ix_audit_logs_action" not in existing:
        op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    if "ix_audit_logs_action_created_at" not in existing:
        op.create_index(
            "ix_audit_logs_action_created_at",
            "audit_logs",
            ["action", "created_at"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    if "audit_logs" not in inspect(bind).get_table_names():
        return
    existing = {ix["name"] for ix in inspect(bind).get_indexes("audit_logs")}
    for name in (
        "ix_audit_logs_action_created_at",
        "ix_audit_logs_action",
        "ix_audit_logs_created_at",
    ):
        if name in existing:
            op.drop_index(name, table_name="audit_logs")
