"""CrushFTP Admin API credentials (Basic Auth) — distinct from AppCredential vault."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "046_crushftp_admin_api"
down_revision: Union[str, None] = "045_bastion_accounts_provisioning"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if "apps" not in inspect(bind).get_table_names():
        return
    cols = {c["name"] for c in inspect(bind).get_columns("apps")}
    additions = [
        ("crushftp_admin_base_url", sa.Column("crushftp_admin_base_url", sa.String(), nullable=True)),
        (
            "crushftp_admin_server_group",
            sa.Column("crushftp_admin_server_group", sa.String(), nullable=True),
        ),
        ("crushftp_admin_username", sa.Column("crushftp_admin_username", sa.String(), nullable=True)),
        (
            "crushftp_admin_password_encrypted",
            sa.Column("crushftp_admin_password_encrypted", sa.Text(), nullable=True),
        ),
    ]
    for name, column in additions:
        if name not in cols:
            op.add_column("apps", column)


def downgrade() -> None:
    bind = op.get_bind()
    if "apps" not in inspect(bind).get_table_names():
        return
    cols = {c["name"] for c in inspect(bind).get_columns("apps")}
    for name in (
        "crushftp_admin_password_encrypted",
        "crushftp_admin_username",
        "crushftp_admin_server_group",
        "crushftp_admin_base_url",
    ):
        if name in cols:
            op.drop_column("apps", name)
