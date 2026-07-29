"""Add apps.upstream_tls_verify for bastion→upstream TLS certificate checks."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "043_upstream_tls_verify"
down_revision: Union[str, None] = "042_allow_activesync"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if "apps" not in inspect(bind).get_table_names():
        return
    cols = {c["name"] for c in inspect(bind).get_columns("apps")}
    if "upstream_tls_verify" in cols:
        return
    op.add_column(
        "apps",
        sa.Column(
            "upstream_tls_verify",
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
    if "upstream_tls_verify" not in cols:
        return
    op.drop_column("apps", "upstream_tls_verify")
