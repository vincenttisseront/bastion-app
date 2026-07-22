"""App identity_format for identite_utilisateur (email UPN vs short username)."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "017_identity_format"
down_revision: Union[str, None] = "016_active_session_verify"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if "apps" not in inspect(bind).get_table_names():
        return
    existing = {col["name"] for col in inspect(bind).get_columns("apps")}
    if "identity_format" not in existing:
        op.add_column(
            "apps",
            sa.Column(
                "identity_format",
                sa.String(),
                nullable=False,
                server_default="email",
            ),
        )


def downgrade() -> None:
    bind = op.get_bind()
    if "apps" not in inspect(bind).get_table_names():
        return
    existing = {col["name"] for col in inspect(bind).get_columns("apps")}
    if "identity_format" in existing:
        op.drop_column("apps", "identity_format")
