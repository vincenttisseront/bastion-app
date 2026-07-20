"""Application credential_mode — shared vs individual_required."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "013_credential_mode"
down_revision: Union[str, None] = "012_user_app_credentials"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if "apps" not in inspect(bind).get_table_names():
        return
    existing = {col["name"] for col in inspect(bind).get_columns("apps")}
    if "credential_mode" not in existing:
        op.add_column(
            "apps",
            sa.Column(
                "credential_mode",
                sa.String(),
                nullable=False,
                server_default="shared",
            ),
        )


def downgrade() -> None:
    bind = op.get_bind()
    if "apps" not in inspect(bind).get_table_names():
        return
    existing = {col["name"] for col in inspect(bind).get_columns("apps")}
    if "credential_mode" in existing:
        op.drop_column("apps", "credential_mode")
