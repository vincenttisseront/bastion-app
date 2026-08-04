"""Make access_requests.realm_id nullable — admin assigns realm on approve."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "062_access_request_realm_nullable"
down_revision: Union[str, None] = "061_clients_access_request_opt_in"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)
    if "access_requests" not in insp.get_table_names():
        return
    cols = {c["name"]: c for c in insp.get_columns("access_requests")}
    col = cols.get("realm_id")
    if col is None or col.get("nullable"):
        return
    with op.batch_alter_table("access_requests") as batch:
        batch.alter_column(
            "realm_id",
            existing_type=sa.Integer(),
            nullable=True,
        )


def downgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)
    if "access_requests" not in insp.get_table_names():
        return
    # Fail closed: refuse downgrade if nulls exist.
    nulls = bind.execute(
        sa.text("SELECT COUNT(*) FROM access_requests WHERE realm_id IS NULL")
    ).scalar()
    if nulls:
        raise RuntimeError(
            "Cannot make realm_id NOT NULL: pending rows without realm exist"
        )
    with op.batch_alter_table("access_requests") as batch:
        batch.alter_column(
            "realm_id",
            existing_type=sa.Integer(),
            nullable=False,
        )
