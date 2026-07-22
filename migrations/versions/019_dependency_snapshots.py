"""Dependency inventory snapshots for admin Dependencies page."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "019_dependency_snapshots"
down_revision: Union[str, None] = "018_encryption_key_versions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()

    if "dependency_snapshots" not in tables:
        op.create_table(
            "dependency_snapshots",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("ecosystem", sa.String(), nullable=False),
            sa.Column("name", sa.String(), nullable=False),
            sa.Column("current_version", sa.String(), nullable=False),
            sa.Column("latest_version", sa.String(), nullable=True),
            sa.Column("dep_type", sa.String(), nullable=False),
            sa.Column("status", sa.String(), nullable=False),
            sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("check_error", sa.String(), nullable=True),
            sa.Column("notes", sa.String(), nullable=True),
            sa.UniqueConstraint("ecosystem", "name", name="uq_dependency_ecosystem_name"),
        )
        op.create_index(
            "ix_dependency_snapshots_ecosystem",
            "dependency_snapshots",
            ["ecosystem"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()
    if "dependency_snapshots" in tables:
        op.drop_index("ix_dependency_snapshots_ecosystem", table_name="dependency_snapshots")
        op.drop_table("dependency_snapshots")
