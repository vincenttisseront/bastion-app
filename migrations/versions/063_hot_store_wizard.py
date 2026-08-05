"""Wizard state columns for hot-store guided setup."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "063_hot_store_wizard"
down_revision: Union[str, None] = "062_access_request_realm_nullable"
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
        "hot_store_schema_prepared_at",
        sa.DateTime(timezone=True),
        nullable=True,
    )
    _add_column_if_missing(
        bind,
        "portal_settings",
        "hot_store_schema_prepared_by",
        sa.String(),
        nullable=True,
    )
    _add_column_if_missing(
        bind,
        "portal_settings",
        "hot_store_last_test_at",
        sa.DateTime(timezone=True),
        nullable=True,
    )
    _add_column_if_missing(
        bind,
        "portal_settings",
        "hot_store_last_test_ok",
        sa.Boolean(create_constraint=False),
        nullable=True,
    )
    _add_column_if_missing(
        bind,
        "portal_settings",
        "hot_store_last_test_ms",
        sa.Float(),
        nullable=True,
    )
    _add_column_if_missing(
        bind,
        "portal_settings",
        "hot_store_last_test_error",
        sa.Text(),
        nullable=True,
    )
    _add_column_if_missing(
        bind,
        "portal_settings",
        "hot_store_migrate_skipped_at",
        sa.DateTime(timezone=True),
        nullable=True,
    )
    _add_column_if_missing(
        bind,
        "portal_settings",
        "hot_store_migrate_skipped_by",
        sa.String(),
        nullable=True,
    )
    # Legacy installs that already migrated: treat as schema prepared.
    cols = {c["name"] for c in inspect(bind).get_columns("portal_settings")}
    if (
        "hot_store_schema_prepared_at" in cols
        and "hot_store_last_migrate_at" in cols
    ):
        op.execute(
            sa.text(
                """
                UPDATE portal_settings
                SET hot_store_schema_prepared_at = hot_store_last_migrate_at
                WHERE hot_store_last_migrate_at IS NOT NULL
                  AND hot_store_schema_prepared_at IS NULL
                """
            )
        )


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "portal_settings" not in tables:
        return
    cols = {c["name"] for c in inspect(bind).get_columns("portal_settings")}
    drop = [
        "hot_store_migrate_skipped_by",
        "hot_store_migrate_skipped_at",
        "hot_store_last_test_error",
        "hot_store_last_test_ms",
        "hot_store_last_test_ok",
        "hot_store_last_test_at",
        "hot_store_schema_prepared_by",
        "hot_store_schema_prepared_at",
    ]
    with op.batch_alter_table("portal_settings") as batch:
        for name in drop:
            if name in cols:
                batch.drop_column(name)
