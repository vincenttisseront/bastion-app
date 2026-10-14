"""Drop legacy per-realm SMTP columns; make tri-state booleans NOT NULL.

The per-realm SMTP settings were copied to portal_settings by 065 and have not
been read since. Their encrypted password is skipped by Fernet key rotation, so
it would otherwise linger under a retired key.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "083_core_schema_cleanup"
down_revision: Union[str, None] = "082_user_public_app_links"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_LEGACY_REALM_SMTP_COLUMNS: tuple[str, ...] = (
    "smtp_enabled",
    "smtp_host",
    "smtp_port",
    "smtp_use_tls",
    "smtp_username",
    "smtp_password_encrypted",
    "smtp_from_email",
    "smtp_from_name",
)

# table → (column, existing type, backfill SQL literal)
_NOT_NULL_COLUMNS: dict[str, tuple[tuple[str, sa.types.TypeEngine, str], ...]] = {
    "apps": (
        ("enabled", sa.Boolean(create_constraint=False), "1"),
        ("probe_enabled", sa.Boolean(create_constraint=False), "1"),
        ("auth_mode", sa.String(), "'sso'"),
    ),
    "realm_configs": (
        ("is_default", sa.Boolean(create_constraint=False), "0"),
        ("enabled", sa.Boolean(create_constraint=False), "0"),
        ("groups_sync_enabled", sa.Boolean(create_constraint=False), "0"),
    ),
    "breakglass_accounts": (
        ("is_active", sa.Boolean(create_constraint=False), "1"),
    ),
}


def _columns(bind, table: str) -> set[str]:
    return {c["name"] for c in inspect(bind).get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())

    if "realm_configs" in tables:
        present = _columns(bind, "realm_configs")
        legacy = [c for c in _LEGACY_REALM_SMTP_COLUMNS if c in present]
        if legacy:
            with op.batch_alter_table("realm_configs") as batch:
                for column in legacy:
                    batch.drop_column(column)

    for table, specs in _NOT_NULL_COLUMNS.items():
        if table not in tables:
            continue
        present = _columns(bind, table)
        specs = tuple(s for s in specs if s[0] in present)
        if not specs:
            continue
        for column, _type, backfill in specs:
            op.execute(f"UPDATE {table} SET {column} = {backfill} WHERE {column} IS NULL")
        with op.batch_alter_table(table) as batch:
            for column, coltype, _backfill in specs:
                batch.alter_column(column, existing_type=coltype, nullable=False)


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())

    for table, specs in _NOT_NULL_COLUMNS.items():
        if table not in tables:
            continue
        present = _columns(bind, table)
        with op.batch_alter_table(table) as batch:
            for column, coltype, _backfill in specs:
                if column in present:
                    batch.alter_column(column, existing_type=coltype, nullable=True)

    if "realm_configs" in tables:
        present = _columns(bind, "realm_configs")
        with op.batch_alter_table("realm_configs") as batch:
            if "smtp_enabled" not in present:
                batch.add_column(
                    sa.Column("smtp_enabled", sa.Boolean(), nullable=False, server_default=sa.text("0"))
                )
            if "smtp_use_tls" not in present:
                batch.add_column(
                    sa.Column("smtp_use_tls", sa.Boolean(), nullable=False, server_default=sa.text("1"))
                )
            for column, coltype in (
                ("smtp_host", sa.String()),
                ("smtp_port", sa.Integer()),
                ("smtp_username", sa.String()),
                ("smtp_password_encrypted", sa.Text()),
                ("smtp_from_email", sa.String()),
                ("smtp_from_name", sa.String()),
            ):
                if column not in present:
                    batch.add_column(sa.Column(column, coltype, nullable=True))
