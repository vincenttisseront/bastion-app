"""Add secondary_color + highlight_color for three-color company branding."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "056_branding_three_colors"
down_revision: Union[str, None] = "055_oidc_login_attempts"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()
    if "branding_settings" not in tables:
        return
    cols = {c["name"] for c in inspect(bind).get_columns("branding_settings")}
    with op.batch_alter_table("branding_settings") as batch:
        if "secondary_color" not in cols:
            batch.add_column(
                sa.Column(
                    "secondary_color",
                    sa.String(),
                    nullable=False,
                    server_default="#059669",
                )
            )
        if "highlight_color" not in cols:
            batch.add_column(
                sa.Column(
                    "highlight_color",
                    sa.String(),
                    nullable=False,
                    server_default="#34d399",
                )
            )


def downgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()
    if "branding_settings" not in tables:
        return
    cols = {c["name"] for c in inspect(bind).get_columns("branding_settings")}
    with op.batch_alter_table("branding_settings") as batch:
        if "highlight_color" in cols:
            batch.drop_column("highlight_color")
        if "secondary_color" in cols:
            batch.drop_column("secondary_color")
