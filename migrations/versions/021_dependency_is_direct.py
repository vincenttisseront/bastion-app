"""Add is_direct flag to dependency_snapshots (npm direct vs transitive)."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "021_dependency_is_direct"
down_revision: Union[str, None] = "020_dependency_declared_version"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()
    if "dependency_snapshots" not in tables:
        return
    cols = {c["name"] for c in inspect(bind).get_columns("dependency_snapshots")}
    if "is_direct" not in cols:
        with op.batch_alter_table("dependency_snapshots") as batch:
            batch.add_column(
                sa.Column(
                    "is_direct",
                    sa.Boolean(),
                    nullable=False,
                    server_default=sa.true(),
                )
            )


def downgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()
    if "dependency_snapshots" not in tables:
        return
    cols = {c["name"] for c in inspect(bind).get_columns("dependency_snapshots")}
    if "is_direct" in cols:
        with op.batch_alter_table("dependency_snapshots") as batch:
            batch.drop_column("is_direct")
