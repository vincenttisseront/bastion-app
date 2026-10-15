"""Account lifecycle: inactivity / password renewal settings + BastionAccount tracking."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "084_account_lifecycle"
down_revision: Union[str, None] = "083_core_schema_cleanup"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("portal_settings") as batch:
        batch.add_column(
            sa.Column(
                "account_lifecycle_enabled",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )
        batch.add_column(
            sa.Column(
                "account_inactivity_days",
                sa.Integer(),
                nullable=False,
                server_default="180",
            )
        )
        batch.add_column(
            sa.Column(
                "account_inactivity_warn_days",
                sa.String(),
                nullable=False,
                server_default="30,14,7",
            )
        )
        batch.add_column(
            sa.Column(
                "account_password_max_age_days",
                sa.Integer(),
                nullable=False,
                server_default="90",
            )
        )
        batch.add_column(
            sa.Column(
                "account_password_warn_days",
                sa.Integer(),
                nullable=False,
                server_default="14",
            )
        )
        batch.add_column(
            sa.Column("account_lifecycle_last_run_at", sa.DateTime(), nullable=True)
        )

    with op.batch_alter_table("bastion_accounts") as batch:
        batch.add_column(sa.Column("last_login_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("password_changed_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("disabled_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("disabled_reason", sa.String(), nullable=True))
        batch.add_column(
            sa.Column("last_inactivity_warn_at", sa.DateTime(), nullable=True)
        )
        batch.add_column(
            sa.Column("last_inactivity_warn_stage", sa.Integer(), nullable=True)
        )
        batch.add_column(
            sa.Column("last_password_warn_at", sa.DateTime(), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("bastion_accounts") as batch:
        batch.drop_column("last_password_warn_at")
        batch.drop_column("last_inactivity_warn_stage")
        batch.drop_column("last_inactivity_warn_at")
        batch.drop_column("disabled_reason")
        batch.drop_column("disabled_at")
        batch.drop_column("password_changed_at")
        batch.drop_column("last_login_at")

    with op.batch_alter_table("portal_settings") as batch:
        batch.drop_column("account_lifecycle_last_run_at")
        batch.drop_column("account_password_warn_days")
        batch.drop_column("account_password_max_age_days")
        batch.drop_column("account_inactivity_warn_days")
        batch.drop_column("account_inactivity_days")
        batch.drop_column("account_lifecycle_enabled")
