"""Global SMTP on portal_settings (Général → Configuration).

Revision ID: 065_global_smtp_portal_settings
Revises: 064_user_app_favorites
Create Date: 2026-08-05

Moves outbound mail config off per-realm into the portal singleton.
Copies credentials from the first realm that already had SMTP enabled.
Realm smtp_* columns are left in place (unused) for a later cleanup.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "065_global_smtp_portal_settings"
down_revision: Union[str, None] = "064_user_app_favorites"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("portal_settings") as batch:
        batch.add_column(
            sa.Column("smtp_enabled", sa.Boolean(), nullable=False, server_default=sa.false())
        )
        batch.add_column(sa.Column("smtp_host", sa.String(), nullable=True))
        batch.add_column(sa.Column("smtp_port", sa.Integer(), nullable=True))
        batch.add_column(
            sa.Column("smtp_use_tls", sa.Boolean(), nullable=False, server_default=sa.true())
        )
        batch.add_column(sa.Column("smtp_username", sa.String(), nullable=True))
        batch.add_column(sa.Column("smtp_password_encrypted", sa.Text(), nullable=True))
        batch.add_column(sa.Column("smtp_from_email", sa.String(), nullable=True))
        batch.add_column(sa.Column("smtp_from_name", sa.String(), nullable=True))

    # Best-effort migrate from the first realm that had SMTP configured.
    conn = op.get_bind()
    row = conn.execute(
        sa.text(
            """
            SELECT smtp_enabled, smtp_host, smtp_port, smtp_use_tls, smtp_username,
                   smtp_password_encrypted, smtp_from_email, smtp_from_name
            FROM realm_configs
            WHERE smtp_enabled = 1
              AND smtp_host IS NOT NULL
              AND TRIM(smtp_host) != ''
              AND smtp_from_email IS NOT NULL
              AND TRIM(smtp_from_email) != ''
            ORDER BY id
            LIMIT 1
            """
        )
    ).mappings().first()
    if row:
        conn.execute(
            sa.text(
                """
                UPDATE portal_settings
                SET smtp_enabled = :smtp_enabled,
                    smtp_host = :smtp_host,
                    smtp_port = :smtp_port,
                    smtp_use_tls = :smtp_use_tls,
                    smtp_username = :smtp_username,
                    smtp_password_encrypted = :smtp_password_encrypted,
                    smtp_from_email = :smtp_from_email,
                    smtp_from_name = :smtp_from_name
                WHERE id = 1
                """
            ),
            {
                "smtp_enabled": 1 if row["smtp_enabled"] else 0,
                "smtp_host": row["smtp_host"],
                "smtp_port": row["smtp_port"],
                "smtp_use_tls": 1 if row["smtp_use_tls"] else 0,
                "smtp_username": row["smtp_username"],
                "smtp_password_encrypted": row["smtp_password_encrypted"],
                "smtp_from_email": row["smtp_from_email"],
                "smtp_from_name": row["smtp_from_name"],
            },
        )


def downgrade() -> None:
    with op.batch_alter_table("portal_settings") as batch:
        batch.drop_column("smtp_from_name")
        batch.drop_column("smtp_from_email")
        batch.drop_column("smtp_password_encrypted")
        batch.drop_column("smtp_username")
        batch.drop_column("smtp_use_tls")
        batch.drop_column("smtp_port")
        batch.drop_column("smtp_host")
        batch.drop_column("smtp_enabled")
