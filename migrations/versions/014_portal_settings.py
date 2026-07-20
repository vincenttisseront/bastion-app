"""Portal settings singleton — seed subdomain_sso_enabled from env."""

from __future__ import annotations

import os
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "014_portal_settings"
down_revision: Union[str, None] = "013_credential_mode"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


def upgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()
    if "portal_settings" not in tables:
        op.create_table(
            "portal_settings",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column(
                "subdomain_sso_enabled",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            ),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_by", sa.String(), nullable=True),
        )

    # Seed singleton from current env so runtime behaviour is unchanged after migrate.
    seeded = _env_bool("SUBDOMAIN_SSO_ENABLED", False)
    op.execute(
        sa.text(
            "INSERT INTO portal_settings (id, subdomain_sso_enabled, updated_at, updated_by) "
            "SELECT 1, :enabled, CURRENT_TIMESTAMP, NULL "
            "WHERE NOT EXISTS (SELECT 1 FROM portal_settings WHERE id = 1)"
        ).bindparams(enabled=seeded)
    )


def downgrade() -> None:
    bind = op.get_bind()
    if "portal_settings" in inspect(bind).get_table_names():
        op.drop_table("portal_settings")
