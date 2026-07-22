"""Add declared_version to dependency_snapshots."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "020_dependency_declared_version"
down_revision: Union[str, None] = "019_dependency_snapshots"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()
    if "dependency_snapshots" not in tables:
        return
    cols = {c["name"] for c in inspect(bind).get_columns("dependency_snapshots")}
    if "declared_version" not in cols:
        with op.batch_alter_table("dependency_snapshots") as batch:
            batch.add_column(sa.Column("declared_version", sa.String(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()
    if "dependency_snapshots" not in tables:
        return
    cols = {c["name"] for c in inspect(bind).get_columns("dependency_snapshots")}
    if "declared_version" in cols:
        with op.batch_alter_table("dependency_snapshots") as batch:
            batch.drop_column("declared_version")
