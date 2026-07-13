"""Drop legacy v1 realm_configs columns that block OIDC admin inserts."""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
from sqlalchemy import inspect

revision: str = "005_realm_legacy_drop"
down_revision: Union[str, None] = "004_app_health_probes"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# v1 portal.db columns — NOT NULL without ORM mapping causes INSERT failures on new realms.
_LEGACY_COLUMNS = ("keycloak_realm", "keycloak_base_url", "oauth2_proxy_url")


def upgrade() -> None:
    bind = op.get_bind()
    if "realm_configs" not in inspect(bind).get_table_names():
        return

    existing = {col["name"] for col in inspect(bind).get_columns("realm_configs")}
    to_drop = [name for name in _LEGACY_COLUMNS if name in existing]
    if not to_drop:
        return

    with op.batch_alter_table("realm_configs") as batch_op:
        for name in to_drop:
            batch_op.drop_column(name)


def downgrade() -> None:
    pass
