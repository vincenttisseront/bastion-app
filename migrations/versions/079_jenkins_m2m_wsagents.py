"""Backfill /wsagents/ M2M bypass on Jenkins apps (inbound WebSocket agents)."""

from __future__ import annotations

import json
from typing import Sequence, Union

from alembic import op
from sqlalchemy import inspect, text

revision: str = "079_jenkins_m2m_wsagents"
down_revision: Union[str, None] = "078_jenkins_m2m_agents"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_WSAGENTS = "/wsagents/"


def upgrade() -> None:
    bind = op.get_bind()
    if "apps" not in inspect(bind).get_table_names():
        return
    cols = {c["name"] for c in inspect(bind).get_columns("apps")}
    if "m2m_bypass_paths" not in cols:
        return

    rows = bind.execute(
        text(
            "SELECT id, slug, public_fqdn, label, m2m_bypass_paths, "
            "m2m_bypass_long_timeout FROM apps"
        )
    ).fetchall()
    for app_id, slug, public_fqdn, label, existing_paths, long_to in rows:
        hay = " ".join(
            [
                (slug or "").strip().lower(),
                (public_fqdn or "").strip().lower(),
                (label or "").strip().lower(),
            ]
        )
        if "jenkins" not in hay:
            continue
        paths: list[str] = []
        if existing_paths:
            try:
                parsed = json.loads(existing_paths)
                if isinstance(parsed, list):
                    paths = [str(x) for x in parsed if str(x).strip()]
            except (json.JSONDecodeError, TypeError):
                paths = []
        changed = False
        if _WSAGENTS not in paths:
            paths.append(_WSAGENTS)
            changed = True
        need_long = not bool(long_to)
        if not changed and not need_long:
            continue
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
    pass
