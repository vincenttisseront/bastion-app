"""App.injected_cookie_scope — host_only (default) vs wide_domain opt-in."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "031_injected_cookie_scope"
down_revision: Union[str, None] = "030_file_folders_crushftp"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if "apps" not in inspect(bind).get_table_names():
        return
    existing = {col["name"] for col in inspect(bind).get_columns("apps")}
    if "injected_cookie_scope" not in existing:
        op.add_column(
            "apps",
            sa.Column(
                "injected_cookie_scope",
                sa.String(),
                nullable=False,
                server_default="host_only",
            ),
        )


def downgrade() -> None:
    bind = op.get_bind()
    if "apps" not in inspect(bind).get_table_names():
        return
    existing = {col["name"] for col in inspect(bind).get_columns("apps")}
    if "injected_cookie_scope" in existing:
        op.drop_column("apps", "injected_cookie_scope")
