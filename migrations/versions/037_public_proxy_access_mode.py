"""Allow access_mode=public_proxy (string whitelist; no SQL ENUM)."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "037_public_proxy_access_mode"
down_revision: Union[str, None] = "036_siem_forwarding"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_ALLOWED = (
    "sso_gate",
    "subdomain_proxy",
    "legacy_path_proxy",
    "public_proxy",
)


def upgrade() -> None:
    bind = op.get_bind()
    if "apps" not in inspect(bind).get_table_names():
        return
    # No data remap — only extend the clamp whitelist used by prior migrations.
    # Rows already set to public_proxy (if any) remain; others stay untouched.
    _ = _ALLOWED


def downgrade() -> None:
    bind = op.get_bind()
    if "apps" not in inspect(bind).get_table_names():
        return
    op.execute(
        sa.text(
            "UPDATE apps SET access_mode = 'sso_gate' "
            "WHERE access_mode = 'public_proxy'"
        )
    )
