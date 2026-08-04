"""Portal settings columns for optional PostgreSQL hot store."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "060_hot_store_settings"
down_revision: Union[str, None] = "059_realm_mfa_login_display"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _add_column_if_missing(bind, table: str, column: str, coltype, **kwargs) -> None:
    cols = {c["name"] for c in inspect(bind).get_columns(table)}
    if column not in cols:
        op.add_column(table, sa.Column(column, coltype, **kwargs))


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "portal_settings" not in tables:
        return
    _add_column_if_missing(
        bind,
        "portal_settings",
        "hot_store_enabled",
        sa.Boolean(create_constraint=False),
        nullable=False,
        server_default=sa.false(),
    )
    _add_column_if_missing(
        bind, "portal_settings", "hot_store_host", sa.String(), nullable=True
    )
    _add_column_if_missing(
        bind, "portal_settings", "hot_store_port", sa.Integer(), nullable=True
    )
    _add_column_if_missing(
        bind, "portal_settings", "hot_store_database", sa.String(), nullable=True
    )
    _add_column_if_missing(
        bind, "portal_settings", "hot_store_user", sa.String(), nullable=True
    )
    _add_column_if_missing(
        bind,
        "portal_settings",
        "hot_store_password_encrypted",
        sa.Text(),
        nullable=True,
    )
    _add_column_if_missing(
        bind, "portal_settings", "hot_store_sslmode", sa.String(), nullable=True
    )
    _add_column_if_missing(
        bind,
        "portal_settings",
        "hot_store_last_migrate_at",
        sa.DateTime(timezone=True),
        nullable=True,
    )
    _add_column_if_missing(
        bind,
        "portal_settings",
        "hot_store_last_migrate_summary",
        sa.Text(),
        nullable=True,
    )


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "portal_settings" not in tables:
        return
    cols = {c["name"] for c in inspect(bind).get_columns("portal_settings")}
    drop = [
        "hot_store_last_migrate_summary",
        "hot_store_last_migrate_at",
        "hot_store_sslmode",
        "hot_store_password_encrypted",
        "hot_store_user",
        "hot_store_database",
        "hot_store_port",
        "hot_store_host",
        "hot_store_enabled",
    ]
    with op.batch_alter_table("portal_settings") as batch:
        for name in drop:
            if name in cols:
                batch.drop_column(name)
