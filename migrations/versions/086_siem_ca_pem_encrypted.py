"""Persist SIEM syslog TLS CA PEM in DB (Fernet) so it survives volume/file loss."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "086_siem_ca_pem_encrypted"
down_revision: Union[str, None] = "085_app_credential_renewal"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "siem_forwarding_settings" not in tables:
        return
    existing = {c["name"] for c in inspect(bind).get_columns("siem_forwarding_settings")}
    if "syslog_ca_pem_encrypted" not in existing:
        op.add_column(
            "siem_forwarding_settings",
            sa.Column("syslog_ca_pem_encrypted", sa.Text(), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "siem_forwarding_settings" not in tables:
        return
    existing = {c["name"] for c in inspect(bind).get_columns("siem_forwarding_settings")}
    if "syslog_ca_pem_encrypted" in existing:
        op.drop_column("siem_forwarding_settings", "syslog_ca_pem_encrypted")
