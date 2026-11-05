"""Dedicated portal signing secret (S7) — CSRF / flash / MFA cookie HMAC base.

Previously the nginx→app internal token doubled as the signing key.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "095_portal_signing_secret"
down_revision: Union[str, None] = "094_waf_portal_standard_rate"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_COL = "portal_signing_secret_encrypted"


def upgrade() -> None:
    bind = op.get_bind()
    if "portal_settings" not in inspect(bind).get_table_names():
        return
    cols = {c["name"] for c in inspect(bind).get_columns("portal_settings")}
    if _COL not in cols:
        with op.batch_alter_table("portal_settings") as batch:
            batch.add_column(sa.Column(_COL, sa.Text(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    if "portal_settings" not in inspect(bind).get_table_names():
        return
    cols = {c["name"] for c in inspect(bind).get_columns("portal_settings")}
    if _COL in cols:
        with op.batch_alter_table("portal_settings") as batch:
            batch.drop_column(_COL)
