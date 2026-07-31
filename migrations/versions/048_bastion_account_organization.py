"""BastionAccount.organization (company group for société)."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "048_bastion_account_organization"
down_revision: Union[str, None] = "047_bastion_account_origin_retry"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if "bastion_accounts" not in inspect(bind).get_table_names():
        return
    cols = {c["name"] for c in inspect(bind).get_columns("bastion_accounts")}
    if "organization" not in cols:
        op.add_column(
            "bastion_accounts",
            sa.Column("organization", sa.String(), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()
    if "bastion_accounts" not in inspect(bind).get_table_names():
        return
    cols = {c["name"] for c in inspect(bind).get_columns("bastion_accounts")}
    if "organization" in cols:
        op.drop_column("bastion_accounts", "organization")
