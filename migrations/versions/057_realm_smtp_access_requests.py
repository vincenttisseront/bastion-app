"""Per-realm SMTP + access_request flags; access_requests table."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "057_realm_smtp_access_requests"
down_revision: Union[str, None] = "056_branding_three_colors"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_REALM_COLS: tuple[tuple[str, object], ...] = (
    ("smtp_enabled", sa.Boolean(create_constraint=False)),
    ("smtp_host", sa.String()),
    ("smtp_port", sa.Integer()),
    ("smtp_use_tls", sa.Boolean(create_constraint=False)),
    ("smtp_username", sa.String()),
    ("smtp_password_encrypted", sa.Text()),
    ("smtp_from_email", sa.String()),
    ("smtp_from_name", sa.String()),
    ("access_request_enabled", sa.Boolean(create_constraint=False)),
    ("send_credentials_email", sa.Boolean(create_constraint=False)),
)


def _add_column_if_missing(bind, table: str, column: str, coltype, **kwargs) -> None:
    cols = {c["name"] for c in inspect(bind).get_columns(table)}
    if column not in cols:
        op.add_column(table, sa.Column(column, coltype, **kwargs))


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "realm_configs" in tables:
        for name, coltype in _REALM_COLS:
            kwargs: dict = {"nullable": True}
            if name in (
                "smtp_enabled",
                "smtp_use_tls",
                "access_request_enabled",
                "send_credentials_email",
            ):
                kwargs = {
                    "nullable": False,
                    "server_default": sa.text(
                        "1" if name == "smtp_use_tls" else "0"
                    ),
                }
            _add_column_if_missing(bind, "realm_configs", name, coltype, **kwargs)

    if "access_requests" not in tables:
        op.create_table(
            "access_requests",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column(
                "realm_id",
                sa.Integer(),
                sa.ForeignKey("realm_configs.id"),
                nullable=False,
            ),
            sa.Column("username", sa.String(), nullable=False),
            sa.Column("email", sa.String(), nullable=False),
            sa.Column("first_name", sa.String(), nullable=True),
            sa.Column("last_name", sa.String(), nullable=True),
            sa.Column("organization", sa.String(), nullable=True),
            sa.Column("message", sa.Text(), nullable=True),
            sa.Column("client_ip", sa.String(), nullable=True),
            sa.Column(
                "status", sa.String(), nullable=False, server_default="pending"
            ),
            sa.Column(
                "bastion_account_id",
                sa.Integer(),
                sa.ForeignKey("bastion_accounts.id"),
                nullable=True,
            ),
            sa.Column("reviewed_by", sa.String(), nullable=True),
            sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("review_notes", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index("ix_access_requests_realm_id", "access_requests", ["realm_id"])
        op.create_index("ix_access_requests_email", "access_requests", ["email"])
        op.create_index("ix_access_requests_status", "access_requests", ["status"])


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "access_requests" in tables:
        op.drop_index("ix_access_requests_status", table_name="access_requests")
        op.drop_index("ix_access_requests_email", table_name="access_requests")
        op.drop_index("ix_access_requests_realm_id", table_name="access_requests")
        op.drop_table("access_requests")
    if "realm_configs" in tables:
        cols = {c["name"] for c in inspect(bind).get_columns("realm_configs")}
        for name, _ in _REALM_COLS:
            if name in cols:
                op.drop_column("realm_configs", name)
