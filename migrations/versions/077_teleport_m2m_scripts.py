"""Backfill /scripts/ M2M bypass on Teleport apps (install-node.sh without SSO)."""

from __future__ import annotations

import json
from typing import Sequence, Union

from alembic import op
from sqlalchemy import inspect, text

revision: str = "077_teleport_m2m_scripts"
down_revision: Union[str, None] = "076_app_m2m_policy"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SCRIPTS_PREFIX = "/scripts/"


def upgrade() -> None:
    bind = op.get_bind()
    if "apps" not in inspect(bind).get_table_names():
        return
    cols = {c["name"] for c in inspect(bind).get_columns("apps")}
    if "m2m_bypass_paths" not in cols:
        return

    rows = bind.execute(
        text(
            "SELECT id, robotic_driver, provisioning_driver, m2m_bypass_paths, "
            "m2m_bypass_long_timeout FROM apps"
        )
    ).fetchall()
    for app_id, robotic_driver, provisioning_driver, existing_paths, long_to in rows:
        driver = (robotic_driver or "").strip().lower()
        provision = (provisioning_driver or "").strip().lower()
        if driver != "teleport" and provision != "teleport":
            continue
        paths: list[str] = []
        if existing_paths:
            try:
                parsed = json.loads(existing_paths)
                if isinstance(parsed, list):
                    paths = [str(x) for x in parsed if str(x).strip()]
            except (json.JSONDecodeError, TypeError):
                paths = []
        if _SCRIPTS_PREFIX in paths:
            # Still ensure long timeouts for agent/WS traffic.
            if not long_to:
                bind.execute(
                    text(
                        "UPDATE apps SET m2m_bypass_long_timeout = 1 WHERE id = :id"
                    ),
                    {"id": app_id},
                )
            continue
        paths.append(_SCRIPTS_PREFIX)
        bind.execute(
            text(
                "UPDATE apps SET m2m_bypass_paths = :paths, "
                "m2m_bypass_long_timeout = 1 WHERE id = :id"
            ),
            {
                "paths": json.dumps(paths, ensure_ascii=False),
                "id": app_id,
            },
        )


def downgrade() -> None:
    # Do not strip /scripts/ — may have been added manually for a reason.
    pass
