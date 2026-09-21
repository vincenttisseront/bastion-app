"""Alembic: SIEM syslog TLS CA metadata (relative path under PORTAL_DATA_DIR)."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "080_siem_syslog_ca"
down_revision: Union[str, None] = "079_jenkins_m2m_wsagents"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_COLS = (
    ("syslog_ca_relative_path", sa.String(), True),
    ("syslog_ca_logical_name", sa.String(), True),
    ("syslog_ca_subject", sa.String(), True),
    ("syslog_ca_issuer", sa.String(), True),
    ("syslog_ca_fingerprint_sha256", sa.String(), True),
    ("syslog_ca_not_before", sa.DateTime(timezone=True), True),
    ("syslog_ca_not_after", sa.DateTime(timezone=True), True),
    ("syslog_ca_uploaded_at", sa.DateTime(timezone=True), True),
    ("syslog_ca_uploaded_by", sa.String(), True),
)


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "siem_forwarding_settings" not in tables:
        return
    existing = {c["name"] for c in inspect(bind).get_columns("siem_forwarding_settings")}
    for name, col_type, nullable in _COLS:
        if name in existing:
            continue
        op.add_column(
            "siem_forwarding_settings",
            sa.Column(name, col_type, nullable=nullable),
        )


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "siem_forwarding_settings" not in tables:
        return
    existing = {c["name"] for c in inspect(bind).get_columns("siem_forwarding_settings")}
    for name, _col_type, _nullable in reversed(_COLS):
        if name in existing:
            op.drop_column("siem_forwarding_settings", name)
