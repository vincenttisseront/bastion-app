"""Realm OIDC admin fields — idempotent brownfield migration."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "002_realm_oidc_admin"
down_revision: Union[str, None] = "001_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _column_names(conn, table: str) -> set[str]:
    return {col["name"] for col in inspect(conn).get_columns(table)}


def _add_column_if_missing(conn, table: str, name: str, col_type: str) -> None:
    if name in _column_names(conn, table):
        return
    op.execute(f"ALTER TABLE {table} ADD COLUMN {name} {col_type}")


def upgrade() -> None:
    bind = op.get_bind()
    if "realm_configs" not in inspect(bind).get_table_names():
        return

    cols = _column_names(bind, "realm_configs")

    if "name" not in cols:
        _add_column_if_missing(bind, "realm_configs", "name", "TEXT")
    if "issuer_url" not in cols:
        _add_column_if_missing(bind, "realm_configs", "issuer_url", "TEXT")
    if "client_secret_encrypted" not in cols:
        _add_column_if_missing(bind, "realm_configs", "client_secret_encrypted", "TEXT")
    if "redirect_uri" not in cols:
        _add_column_if_missing(bind, "realm_configs", "redirect_uri", "TEXT")
    if "scopes" not in cols:
        _add_column_if_missing(bind, "realm_configs", "scopes", "TEXT")
    if "oauth2_cookie_secret_encrypted" not in cols:
        _add_column_if_missing(bind, "realm_configs", "oauth2_cookie_secret_encrypted", "TEXT")
    if "last_test_status" not in cols:
        _add_column_if_missing(bind, "realm_configs", "last_test_status", "TEXT")
    if "last_test_detail" not in cols:
        _add_column_if_missing(bind, "realm_configs", "last_test_detail", "TEXT")
    if "last_tested_at" not in cols:
        _add_column_if_missing(bind, "realm_configs", "last_tested_at", "TEXT")
    if "updated_at" not in cols:
        _add_column_if_missing(bind, "realm_configs", "updated_at", "TEXT")

    cols = _column_names(bind, "realm_configs")

    if "keycloak_realm" in cols:
        op.execute(
            """
            UPDATE realm_configs
            SET name = COALESCE(NULLIF(name, ''), keycloak_realm)
            WHERE name IS NULL OR name = ''
            """
        )
    if "keycloak_base_url" in cols:
        op.execute(
            """
            UPDATE realm_configs
            SET issuer_url = COALESCE(NULLIF(issuer_url, ''), keycloak_base_url)
            WHERE issuer_url IS NULL OR issuer_url = ''
            """
        )
    if "oauth2_proxy_url" in cols:
        op.execute(
            """
            UPDATE realm_configs
            SET redirect_uri = COALESCE(
                NULLIF(redirect_uri, ''),
                'https://portal.example/oauth2/' || slug || '/callback'
            )
            WHERE redirect_uri IS NULL OR redirect_uri = ''
            """
        )

    # Drop legacy NOT NULL columns after data copy (also handled by 005 for brownfield DBs
    # that already ran 002 before this block existed).
    cols = _column_names(bind, "realm_configs")
    legacy = [c for c in ("keycloak_realm", "keycloak_base_url", "oauth2_proxy_url") if c in cols]
    if legacy:
        with op.batch_alter_table("realm_configs") as batch_op:
            for name in legacy:
                batch_op.drop_column(name)

    op.execute(
        """
        UPDATE realm_configs
        SET scopes = COALESCE(NULLIF(scopes, ''), 'openid profile email')
        WHERE scopes IS NULL OR scopes = ''
        """
    )
    op.execute(
        """
        UPDATE realm_configs
        SET client_secret_encrypted = COALESCE(client_secret_encrypted, '')
        WHERE client_secret_encrypted IS NULL
        """
    )
    op.execute(
        """
        UPDATE realm_configs
        SET redirect_uri = COALESCE(
            NULLIF(redirect_uri, ''),
            'https://portal.example/oauth2/' || slug || '/callback'
        )
        WHERE redirect_uri IS NULL OR redirect_uri = ''
        """
    )


def downgrade() -> None:
    pass
