"""Template context for the optional AI hooks on existing admin pages.

``llm_on`` hides every AI button when the assistant is off; ``llm_insights``
maps subject id → latest insight for list pages. Never raises: on any error
the page renders exactly as before.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def llm_ui_context(
    db: Session,
    settings: Any,
    *,
    kind: str | None = None,
    subject_type: str | None = None,
    subject_ids: list[Any] | None = None,
) -> dict[str, Any]:
    try:
        from app.llm.service import llm_enabled

        on = llm_enabled(settings, db)
        insights: dict[str, Any] = {}
        if kind and subject_type and subject_ids:
            from app.llm.insights import latest_insights_map

            insights = latest_insights_map(db, kind, subject_type, list(subject_ids))
        return {"llm_on": on, "llm_insights": insights}
    except Exception:
        logger.debug("llm ui context failed", exc_info=True)
        return {"llm_on": False, "llm_insights": {}}
