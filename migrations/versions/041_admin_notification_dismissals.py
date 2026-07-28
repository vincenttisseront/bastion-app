"""Admin notification dismissals (per-user)."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "041_admin_notification_dismissals"
down_revision: Union[str, None] = "040_audit_log_indexes"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if "admin_notification_dismissals" in inspect(bind).get_table_names():
        return
    op.create_table(
        "admin_notification_dismissals",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_email", sa.String(), nullable=False),
        sa.Column("item_id", sa.String(), nullable=False),
        sa.Column("fingerprint", sa.String(), nullable=False, server_default=""),
        sa.Column("dismissed_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "user_email",
            "item_id",
            name="uq_admin_notif_dismissal_user_item",
        ),
    )
    op.create_index(
        "ix_admin_notification_dismissals_user_email",
        "admin_notification_dismissals",
        ["user_email"],
    )
    op.create_index(
        "ix_admin_notification_dismissals_item_id",
        "admin_notification_dismissals",
        ["item_id"],
    )


def downgrade() -> None:
    bind = op.get_bind()
    if "admin_notification_dismissals" in inspect(bind).get_table_names():
        op.drop_table("admin_notification_dismissals")
