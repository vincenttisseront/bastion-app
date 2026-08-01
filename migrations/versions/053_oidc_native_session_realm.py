"""Add oidc_native_session_enabled on realm_configs (per-realm pilot flag)."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "053_oidc_native_session_realm"
down_revision: Union[str, None] = "052_oidc_sessions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()
    if "realm_configs" not in tables:
        return
    cols = {c["name"] for c in inspect(bind).get_columns("realm_configs")}
    if "oidc_native_session_enabled" in cols:
        return
    with op.batch_alter_table("realm_configs") as batch:
        batch.add_column(
            sa.Column(
                "oidc_native_session_enabled",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )


def downgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()
    if "realm_configs" not in tables:
        return
    cols = {c["name"] for c in inspect(bind).get_columns("realm_configs")}
    if "oidc_native_session_enabled" not in cols:
        return
    with op.batch_alter_table("realm_configs") as batch:
        batch.drop_column("oidc_native_session_enabled")
