"""Add apps.allow_activesync for mobile messaging (EAS) access."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "042_allow_activesync"
down_revision: Union[str, None] = "041_admin_notification_dismissals"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if "apps" not in inspect(bind).get_table_names():
        return
    cols = {c["name"] for c in inspect(bind).get_columns("apps")}
    if "allow_activesync" in cols:
        return
    op.add_column(
        "apps",
        sa.Column(
            "allow_activesync",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    bind = op.get_bind()
    if "apps" not in inspect(bind).get_table_names():
        return
    cols = {c["name"] for c in inspect(bind).get_columns("apps")}
    if "allow_activesync" not in cols:
        return
    op.drop_column("apps", "allow_activesync")
