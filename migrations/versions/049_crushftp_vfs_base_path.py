"""App.crushftp_vfs_base_path — company folders under CrushFTP data root."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "049_crushftp_vfs_base_path"
down_revision: Union[str, None] = "048_bastion_account_organization"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if "apps" not in inspect(bind).get_table_names():
        return
    cols = {c["name"] for c in inspect(bind).get_columns("apps")}
    if "crushftp_vfs_base_path" not in cols:
        op.add_column(
            "apps",
            sa.Column("crushftp_vfs_base_path", sa.String(), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()
    if "apps" not in inspect(bind).get_table_names():
        return
    cols = {c["name"] for c in inspect(bind).get_columns("apps")}
    if "crushftp_vfs_base_path" in cols:
        op.drop_column("apps", "crushftp_vfs_base_path")
