"""Optional gradual auto-renewal of application (CrushFTP) user passwords."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "085_app_credential_renewal"
down_revision: Union[str, None] = "084_account_lifecycle"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("portal_settings") as batch:
        batch.add_column(
            sa.Column(
                "app_credential_renewal_enabled",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )
        batch.add_column(
            sa.Column(
                "app_credential_max_age_days",
                sa.Integer(),
                nullable=False,
                server_default="90",
            )
        )
        batch.add_column(
            sa.Column(
                "app_credential_batch_size",
                sa.Integer(),
                nullable=False,
                server_default="5",
            )
        )
        batch.add_column(
            sa.Column(
                "app_credential_renewal_interval_minutes",
                sa.Integer(),
                nullable=False,
                server_default="60",
            )
        )
        batch.add_column(
            sa.Column(
                "app_credential_renewal_last_run_at", sa.DateTime(), nullable=True
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("portal_settings") as batch:
        batch.drop_column("app_credential_renewal_last_run_at")
        batch.drop_column("app_credential_renewal_interval_minutes")
        batch.drop_column("app_credential_batch_size")
        batch.drop_column("app_credential_max_age_days")
        batch.drop_column("app_credential_renewal_enabled")
