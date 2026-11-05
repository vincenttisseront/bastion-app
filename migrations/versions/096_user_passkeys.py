"""Passwordless passkey sign-in: user passkeys, WebAuthn handles, single-use challenges.

Also adds ``realm_configs.passkey_login_enabled`` (per-realm pilot toggle).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "096_user_passkeys"
down_revision: Union[str, None] = "095_portal_signing_secret"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_REALM_FK = "realm_configs.id"


def _create_handles() -> None:
    op.create_table(
        "user_webauthn_handles",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("realm_id", sa.Integer(), sa.ForeignKey(_REALM_FK), nullable=False),
        sa.Column("keycloak_sub", sa.String(), nullable=False),
        sa.Column("user_handle", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "realm_id", "keycloak_sub", name="uq_user_webauthn_handle_identity"
        ),
        sa.UniqueConstraint("user_handle", name="uq_user_webauthn_handles_user_handle"),
    )
    op.create_index(
        "ix_user_webauthn_handles_realm_id", "user_webauthn_handles", ["realm_id"]
    )


def _create_passkeys() -> None:
    op.create_table(
        "user_passkeys",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("realm_id", sa.Integer(), sa.ForeignKey(_REALM_FK), nullable=False),
        sa.Column("keycloak_sub", sa.String(), nullable=False),
        sa.Column("username", sa.String(), nullable=True),
        sa.Column("credential_id", sa.String(), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("sign_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("transports", sa.JSON(), nullable=True),
        sa.Column("aaguid", sa.String(), nullable=True),
        sa.Column(
            "backup_eligible",
            sa.Boolean(create_constraint=False),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "backup_state",
            sa.Boolean(create_constraint=False),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("name", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_ip", sa.String(), nullable=True),
        sa.Column(
            "revoked",
            sa.Boolean(create_constraint=False),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(), nullable=True),
        sa.Column("revoked_reason", sa.String(), nullable=True),
        sa.UniqueConstraint("credential_id", name="uq_user_passkeys_credential_id"),
    )
    op.create_index("ix_user_passkeys_realm_id", "user_passkeys", ["realm_id"])
    op.create_index("ix_user_passkeys_keycloak_sub", "user_passkeys", ["keycloak_sub"])
    op.create_index(
        "ix_user_passkeys_identity", "user_passkeys", ["realm_id", "keycloak_sub"]
    )


def _create_challenges() -> None:
    op.create_table(
        "webauthn_challenges",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("purpose", sa.String(), nullable=False),
        sa.Column("subject", sa.String(), nullable=False, server_default=""),
        sa.Column("challenge", sa.String(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_webauthn_challenges_expires_at", "webauthn_challenges", ["expires_at"]
    )


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "realm_configs" in tables:
        cols = {c["name"] for c in inspect(bind).get_columns("realm_configs")}
        if "passkey_login_enabled" not in cols:
            op.add_column(
                "realm_configs",
                sa.Column(
                    "passkey_login_enabled",
                    sa.Boolean(create_constraint=False),
                    nullable=False,
                    server_default=sa.false(),
                ),
            )
    if "user_webauthn_handles" not in tables:
        _create_handles()
    if "user_passkeys" not in tables:
        _create_passkeys()
    if "webauthn_challenges" not in tables:
        _create_challenges()


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "webauthn_challenges" in tables:
        op.drop_index("ix_webauthn_challenges_expires_at", table_name="webauthn_challenges")
        op.drop_table("webauthn_challenges")
    if "user_passkeys" in tables:
        op.drop_index("ix_user_passkeys_identity", table_name="user_passkeys")
        op.drop_index("ix_user_passkeys_keycloak_sub", table_name="user_passkeys")
        op.drop_index("ix_user_passkeys_realm_id", table_name="user_passkeys")
        op.drop_table("user_passkeys")
    if "user_webauthn_handles" in tables:
        op.drop_index(
            "ix_user_webauthn_handles_realm_id", table_name="user_webauthn_handles"
        )
        op.drop_table("user_webauthn_handles")
    if "realm_configs" in tables:
        cols = {c["name"] for c in inspect(bind).get_columns("realm_configs")}
        if "passkey_login_enabled" in cols:
            with op.batch_alter_table("realm_configs") as batch:
                batch.drop_column("passkey_login_enabled")
