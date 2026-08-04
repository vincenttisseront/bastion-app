"""Enable access-request opt-in on the clients realm (login CTA)."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "061_clients_access_request_opt_in"
down_revision: Union[str, None] = "060_hot_store_settings"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Show « Demander un accès » for the clients realm when it exists.

    Does not create accounts by itself — admin approval + provisioning still required.
    Idempotent: only flips False → True for slug ``clients``.
    """
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "realm_configs" not in tables:
        return
    cols = {c["name"] for c in inspect(bind).get_columns("realm_configs")}
    if "access_request_enabled" not in cols:
        return
    op.execute(
        sa.text(
            "UPDATE realm_configs SET access_request_enabled = 1 "
            "WHERE enabled = 1 AND lower(slug) = 'clients' "
            "AND (access_request_enabled = 0 OR access_request_enabled IS NULL)"
        )
    )


def downgrade() -> None:
    # Do not flip back — admin may have intentionally kept the opt-in.
    pass
