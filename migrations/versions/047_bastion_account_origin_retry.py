"""BastionAccount origin + pending targets for Keycloak retry."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "047_bastion_account_origin_retry"
down_revision: Union[str, None] = "046_crushftp_admin_api"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if "bastion_accounts" not in inspect(bind).get_table_names():
        return
    cols = {c["name"] for c in inspect(bind).get_columns("bastion_accounts")}
    if "origin" not in cols:
        op.add_column(
            "bastion_accounts",
            sa.Column("origin", sa.String(), nullable=False, server_default="bastion"),
        )
    if "pending_group_ids" not in cols:
        op.add_column(
            "bastion_accounts",
            sa.Column("pending_group_ids", sa.JSON(), nullable=True),
        )
    if "pending_application_ids" not in cols:
        op.add_column(
            "bastion_accounts",
            sa.Column("pending_application_ids", sa.JSON(), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()
    if "bastion_accounts" not in inspect(bind).get_table_names():
        return
    cols = {c["name"] for c in inspect(bind).get_columns("bastion_accounts")}
    for name in ("pending_application_ids", "pending_group_ids", "origin"):
        if name in cols:
            op.drop_column("bastion_accounts", name)
