"""Baseline schema — idempotent for brownfield SQLite (prod portal.db)."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "001_baseline"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _table_names(conn) -> set[str]:
    return set(inspect(conn).get_table_names())


def _column_names(conn, table: str) -> set[str]:
    return {col["name"] for col in inspect(conn).get_columns(table)}


def _add_column_if_missing(conn, table: str, name: str, col_type: str) -> None:
    if name in _column_names(conn, table):
        return
    op.execute(f"ALTER TABLE {table} ADD COLUMN {name} {col_type}")


def upgrade() -> None:
    bind = op.get_bind()
    tables = _table_names(bind)

    if "audit_logs" not in tables:
        op.create_table(
            "audit_logs",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("actor", sa.String(), nullable=False),
            sa.Column("action", sa.String(), nullable=False),
            sa.Column("target", sa.String(), nullable=True),
            sa.Column("details", sa.JSON(), nullable=True),
            sa.Column("ip_address", sa.String(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        )
    else:
        for name, col_type in (
            ("actor", "TEXT"),
            ("action", "TEXT"),
            ("target", "TEXT"),
            ("details", "TEXT"),
            ("ip_address", "TEXT"),
            ("created_at", "TEXT"),
        ):
            _add_column_if_missing(bind, "audit_logs", name, col_type)

        if "actor_username" in _column_names(bind, "audit_logs"):
            op.execute(
                """
                UPDATE audit_logs
                SET actor = COALESCE(NULLIF(actor, ''), actor_username)
                WHERE (actor IS NULL OR actor = '') AND actor_username IS NOT NULL
                """
            )
        if "actor_email" in _column_names(bind, "audit_logs"):
            op.execute(
                """
                UPDATE audit_logs
                SET actor = COALESCE(NULLIF(actor, ''), actor_email)
                WHERE (actor IS NULL OR actor = '') AND actor_email IS NOT NULL
                """
            )
        if "client_ip" in _column_names(bind, "audit_logs"):
            op.execute(
                """
                UPDATE audit_logs
                SET ip_address = client_ip
                WHERE (ip_address IS NULL OR ip_address = '') AND client_ip IS NOT NULL
                """
            )

    if "breakglass_accounts" not in tables:
        op.create_table(
            "breakglass_accounts",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("username", sa.String(), nullable=False, unique=True),
            sa.Column("hashed_password", sa.Text(), nullable=False),
            sa.Column("is_active", sa.Boolean(), nullable=True),
            sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        )

    if "apps" not in tables:
        op.create_table(
            "apps",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("slug", sa.String(), nullable=False, unique=True),
            sa.Column("label", sa.String(), nullable=False),
            sa.Column("upstream_url", sa.String(), nullable=False),
            sa.Column("realm_slug", sa.String(), nullable=True),
            sa.Column("access_mode", sa.String(), nullable=True),
            sa.Column("auth_mode", sa.String(), nullable=True),
            sa.Column("robotic_driver", sa.String(), nullable=True),
            sa.Column("healthcheck_url", sa.String(), nullable=True),
            sa.Column("enabled", sa.Boolean(), nullable=True),
            sa.Column("tile_icon", sa.String(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        )

    if "realm_configs" not in tables:
        op.create_table(
            "realm_configs",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("slug", sa.String(), nullable=False, unique=True),
            sa.Column("keycloak_realm", sa.String(), nullable=False),
            sa.Column("keycloak_base_url", sa.String(), nullable=False),
            sa.Column("client_id", sa.String(), nullable=False),
            sa.Column("oauth2_proxy_port", sa.Integer(), nullable=False),
            sa.Column("oauth2_proxy_url", sa.String(), nullable=False),
            sa.Column("is_default", sa.Boolean(), nullable=True),
            sa.Column("enabled", sa.Boolean(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        )


def downgrade() -> None:
    # Brownfield-safe baseline — no destructive downgrade.
    pass
