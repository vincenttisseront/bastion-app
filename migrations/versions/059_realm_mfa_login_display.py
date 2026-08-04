"""Per-realm MFA gate + login chooser label / visibility."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "059_realm_mfa_login_display"
down_revision: Union[str, None] = "058_group_app_credentials"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _add_column_if_missing(bind, table: str, column: str, coltype, **kwargs) -> None:
    cols = {c["name"] for c in inspect(bind).get_columns(table)}
    if column not in cols:
        op.add_column(table, sa.Column(column, coltype, **kwargs))


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "realm_configs" not in tables:
        return
    _add_column_if_missing(
        bind,
        "realm_configs",
        "oidc_mfa_enabled",
        sa.Boolean(create_constraint=False),
        nullable=False,
        server_default=sa.true(),
    )
    _add_column_if_missing(
        bind,
        "realm_configs",
        "show_on_login",
        sa.Boolean(create_constraint=False),
        nullable=False,
        server_default=sa.true(),
    )
    _add_column_if_missing(
        bind,
        "realm_configs",
        "login_label",
        sa.String(),
        nullable=True,
    )


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "realm_configs" not in tables:
        return
    cols = {c["name"] for c in inspect(bind).get_columns("realm_configs")}
    with op.batch_alter_table("realm_configs") as batch:
        if "login_label" in cols:
            batch.drop_column("login_label")
        if "show_on_login" in cols:
            batch.drop_column("show_on_login")
        if "oidc_mfa_enabled" in cols:
            batch.drop_column("oidc_mfa_enabled")
