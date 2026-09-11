"""Add declarative M2M fields on apps; seed from legacy CI/Teleport heuristics."""

from __future__ import annotations

import json
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect, text

revision: str = "076_app_m2m_policy"
down_revision: Union[str, None] = "075_mta_sts_public_dns"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Keep in sync with app.bastion.m2m_policy.TELEPORT_SEED_BYPASS_PATHS (one-shot seed).
_TELEPORT_SEED = (
    "/webapi/find",
    "/webapi/ping",
    "/webapi/connectionupgrade",
    "/webapi/host/",
    "/v1/webapi/",
    "/v2/webapi/",
)


def upgrade() -> None:
    bind = op.get_bind()
    if "apps" not in inspect(bind).get_table_names():
        return
    cols = {c["name"] for c in inspect(bind).get_columns("apps")}

    if "m2m_accept_basic" not in cols:
        op.add_column(
            "apps",
            sa.Column(
                "m2m_accept_basic",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            ),
        )
    if "m2m_accept_bearer" not in cols:
        op.add_column(
            "apps",
            sa.Column(
                "m2m_accept_bearer",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            ),
        )
    if "m2m_bypass_paths" not in cols:
        op.add_column(
            "apps",
            sa.Column("m2m_bypass_paths", sa.Text(), nullable=True),
        )
    if "m2m_bypass_long_timeout" not in cols:
        op.add_column(
            "apps",
            sa.Column(
                "m2m_bypass_long_timeout",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            ),
        )

    # One-shot seed from former hard-coded heuristics (then runtime uses columns only).
    rows = bind.execute(
        text(
            "SELECT id, slug, public_fqdn, label, robotic_driver, provisioning_driver, "
            "m2m_bypass_paths FROM apps"
        )
    ).fetchall()
    for row in rows:
        (
            app_id,
            slug,
            public_fqdn,
            label,
            robotic_driver,
            provisioning_driver,
            existing_paths,
        ) = row
        hay = " ".join(
            [
                (slug or "").strip().lower(),
                (public_fqdn or "").strip().lower(),
                (label or "").strip().lower(),
            ]
        )
        paths: list[str] = []
        if existing_paths:
            try:
                parsed = json.loads(existing_paths)
                if isinstance(parsed, list):
                    paths = [str(x) for x in parsed if str(x).strip()]
            except (json.JSONDecodeError, TypeError):
                paths = []

        long_timeout = False
        if "jenkins" in hay and "/sonarqube-webhook" not in paths:
            paths.append("/sonarqube-webhook")
        if "sonar" in hay and "/api/" not in paths:
            paths.append("/api/")
        driver = (robotic_driver or "").strip().lower()
        provision = (provisioning_driver or "").strip().lower()
        if driver == "teleport" or provision == "teleport":
            for p in _TELEPORT_SEED:
                if p not in paths:
                    paths.append(p)
            long_timeout = True

        if not paths and not long_timeout:
            continue
        bind.execute(
            text(
                "UPDATE apps SET m2m_bypass_paths = :paths, "
                "m2m_bypass_long_timeout = :long_to WHERE id = :id"
            ),
            {
                "paths": json.dumps(paths, ensure_ascii=False) if paths else None,
                "long_to": 1 if long_timeout else 0,
                "id": app_id,
            },
        )


def downgrade() -> None:
    bind = op.get_bind()
    if "apps" not in inspect(bind).get_table_names():
        return
    cols = {c["name"] for c in inspect(bind).get_columns("apps")}
    for col in (
        "m2m_bypass_long_timeout",
        "m2m_bypass_paths",
        "m2m_accept_bearer",
        "m2m_accept_basic",
    ):
        if col in cols:
            op.drop_column("apps", col)
