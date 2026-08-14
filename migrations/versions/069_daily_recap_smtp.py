"""Daily ops recap email settings on portal_settings.

Revision ID: 069_daily_recap_smtp
Revises: 068_audit_event_codes
Create Date: 2026-08-14
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "069_daily_recap_smtp"
down_revision: Union[str, None] = "068_audit_event_codes"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "portal_settings" not in tables:
        return
    cols = {c["name"] for c in inspect(bind).get_columns("portal_settings")}
    with op.batch_alter_table("portal_settings") as batch:
        if "daily_recap_enabled" not in cols:
            batch.add_column(
                sa.Column(
                    "daily_recap_enabled",
                    sa.Boolean(),
                    nullable=False,
                    server_default=sa.false(),
                )
            )
        if "daily_recap_email" not in cols:
            batch.add_column(sa.Column("daily_recap_email", sa.String(), nullable=True))
        if "daily_recap_hour" not in cols:
            batch.add_column(
                sa.Column(
                    "daily_recap_hour",
                    sa.Integer(),
                    nullable=False,
                    server_default="7",
                )
            )
        if "daily_recap_last_sent_at" not in cols:
            batch.add_column(
                sa.Column("daily_recap_last_sent_at", sa.DateTime(timezone=True), nullable=True)
            )


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "portal_settings" not in tables:
        return
    cols = {c["name"] for c in inspect(bind).get_columns("portal_settings")}
    with op.batch_alter_table("portal_settings") as batch:
        if "daily_recap_last_sent_at" in cols:
            batch.drop_column("daily_recap_last_sent_at")
        if "daily_recap_hour" in cols:
            batch.drop_column("daily_recap_hour")
        if "daily_recap_email" in cols:
            batch.drop_column("daily_recap_email")
        if "daily_recap_enabled" in cols:
            batch.drop_column("daily_recap_enabled")
