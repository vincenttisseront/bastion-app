"""Branding settings singleton — public portal anonymization."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "051_branding_settings"
down_revision: Union[str, None] = "050_pending_users_groups_filter"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()
    if "branding_settings" not in tables:
        op.create_table(
            "branding_settings",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column(
                "company_name",
                sa.String(),
                nullable=False,
                server_default="Portail sécurisé",
            ),
            sa.Column("logo_path", sa.String(), nullable=True),
            sa.Column("favicon_path", sa.String(), nullable=True),
            sa.Column(
                "page_title",
                sa.String(),
                nullable=False,
                server_default="Connexion",
            ),
            sa.Column(
                "accent_color",
                sa.String(),
                nullable=False,
                server_default="#10b981",
            ),
            sa.Column(
                "default_theme",
                sa.String(),
                nullable=False,
                server_default="dark",
            ),
            sa.Column("welcome_text", sa.Text(), nullable=True),
            sa.Column("footer_text", sa.Text(), nullable=True),
            sa.Column("support_contact", sa.String(), nullable=True),
            sa.Column(
                "show_product_branding",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            ),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_by", sa.String(), nullable=True),
        )

    op.execute(
        sa.text(
            "INSERT INTO branding_settings ("
            "id, company_name, page_title, accent_color, default_theme, "
            "show_product_branding, updated_at, updated_by"
            ") SELECT 1, 'Portail sécurisé', 'Connexion', '#10b981', 'dark', "
            "0, CURRENT_TIMESTAMP, NULL "
            "WHERE NOT EXISTS (SELECT 1 FROM branding_settings WHERE id = 1)"
        )
    )


def downgrade() -> None:
    bind = op.get_bind()
    if "branding_settings" in inspect(bind).get_table_names():
        op.drop_table("branding_settings")
