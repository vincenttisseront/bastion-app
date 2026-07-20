"""Generic vault driver configuration fields on apps."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "011_generic_driver_fields"
down_revision: Union[str, None] = "010_app_description_logo"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_COLUMNS: list[tuple[str, sa.Column]] = [
    ("login_form_url", sa.Column("login_form_url", sa.String(), nullable=True)),
    (
        "login_username_field",
        sa.Column("login_username_field", sa.String(), nullable=False, server_default="username"),
    ),
    (
        "login_password_field",
        sa.Column("login_password_field", sa.String(), nullable=False, server_default="password"),
    ),
    ("login_extra_fields", sa.Column("login_extra_fields", sa.Text(), nullable=True)),
    (
        "login_http_method",
        sa.Column("login_http_method", sa.String(), nullable=False, server_default="POST"),
    ),
]


def upgrade() -> None:
    bind = op.get_bind()
    if "apps" not in inspect(bind).get_table_names():
        return
    existing = {col["name"] for col in inspect(bind).get_columns("apps")}
    for name, column in _COLUMNS:
        if name not in existing:
            op.add_column("apps", column)
    # Normalize legacy auth_mode values to "sso" (retrocompatible alias for oidc).
    op.execute(
        """
        UPDATE apps
        SET auth_mode = 'sso'
        WHERE auth_mode IS NULL OR auth_mode IN ('oidc', '')
        """
    )


def downgrade() -> None:
    bind = op.get_bind()
    if "apps" not in inspect(bind).get_table_names():
        return
    existing = {col["name"] for col in inspect(bind).get_columns("apps")}
    for name, _ in reversed(_COLUMNS):
        if name in existing:
            op.drop_column("apps", name)
