"""App access_mode enum + public_fqdn for subdomain proxy."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "003_app_access_modes"
down_revision: Union[str, None] = "002_realm_oidc_admin"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_MODE_MAP = {
    "sso": "sso_gate",
    "direct": "sso_gate",
    "robotic": "sso_gate",
    "subdomain": "subdomain_proxy",
}


def _column_names(conn, table: str) -> set[str]:
    return {col["name"] for col in inspect(conn).get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()
    if "apps" not in inspect(bind).get_table_names():
        return

    if "public_fqdn" not in _column_names(bind, "apps"):
        op.add_column("apps", sa.Column("public_fqdn", sa.String(), nullable=True))

    for old, new in _MODE_MAP.items():
        op.execute(
            sa.text("UPDATE apps SET access_mode = :new WHERE access_mode = :old").bindparams(
                old=old, new=new
            )
        )

    op.execute(
        sa.text(
            "UPDATE apps SET access_mode = 'sso_gate' "
            "WHERE access_mode IS NULL OR access_mode NOT IN "
            "('sso_gate', 'subdomain_proxy', 'legacy_path_proxy')"
        )
    )


def downgrade() -> None:
    bind = op.get_bind()
    if "apps" not in inspect(bind).get_table_names():
        return

    op.execute(
        sa.text(
            "UPDATE apps SET access_mode = 'sso' WHERE access_mode = 'sso_gate'"
        )
    )
    op.execute(
        sa.text(
            "UPDATE apps SET access_mode = 'subdomain' "
            "WHERE access_mode = 'subdomain_proxy'"
        )
    )
    op.execute(
        sa.text(
            "UPDATE apps SET access_mode = 'sso' "
            "WHERE access_mode = 'legacy_path_proxy'"
        )
    )

    if "public_fqdn" in _column_names(bind, "apps"):
        op.drop_column("apps", "public_fqdn")
