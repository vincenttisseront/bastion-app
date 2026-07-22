"""Encryption key version metadata + vault_key_rotation_days on portal_settings."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "018_encryption_key_versions"
down_revision: Union[str, None] = "017_identity_format"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()

    if "encryption_key_versions" not in tables:
        op.create_table(
            "encryption_key_versions",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("version", sa.Integer(), nullable=False),
            sa.Column("status", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("source", sa.String(), nullable=True),
            sa.UniqueConstraint("version", name="uq_encryption_key_version"),
        )
        op.create_index(
            "ix_encryption_key_versions_version",
            "encryption_key_versions",
            ["version"],
        )

    if "portal_settings" in tables:
        cols = {c["name"] for c in inspect(bind).get_columns("portal_settings")}
        if "vault_key_rotation_days" not in cols:
            with op.batch_alter_table("portal_settings") as batch:
                batch.add_column(
                    sa.Column(
                        "vault_key_rotation_days",
                        sa.Integer(),
                        nullable=False,
                        server_default="180",
                    )
                )


def downgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()
    if "portal_settings" in tables:
        cols = {c["name"] for c in inspect(bind).get_columns("portal_settings")}
        if "vault_key_rotation_days" in cols:
            with op.batch_alter_table("portal_settings") as batch:
                batch.drop_column("vault_key_rotation_days")
    if "encryption_key_versions" in tables:
        op.drop_index("ix_encryption_key_versions_version", table_name="encryption_key_versions")
        op.drop_table("encryption_key_versions")
