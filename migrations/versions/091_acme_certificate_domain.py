"""Create acme_certificate_domains for hybrid DNS-01 / HTTP-01 state."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "091_acme_certificate_domain"
down_revision: Union[str, None] = "090_waf_extended_packs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if "acme_certificate_domains" in inspect(bind).get_table_names():
        return
    op.create_table(
        "acme_certificate_domains",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column(
            "provider_type",
            sa.String(),
            nullable=False,
            server_default="dns_cloudflare",
        ),
        sa.Column(
            "status",
            sa.String(),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("domain", name="uq_acme_certificate_domains_domain"),
        sa.CheckConstraint(
            "provider_type IN ('dns_cloudflare', 'http_native')",
            name="ck_acme_cert_domain_provider",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'valid', 'expired', 'failed')",
            name="ck_acme_cert_domain_status",
        ),
    )
    op.create_index(
        "ix_acme_certificate_domains_domain",
        "acme_certificate_domains",
        ["domain"],
    )


def downgrade() -> None:
    bind = op.get_bind()
    if "acme_certificate_domains" not in inspect(bind).get_table_names():
        return
    op.drop_index(
        "ix_acme_certificate_domains_domain",
        table_name="acme_certificate_domains",
    )
    op.drop_table("acme_certificate_domains")
