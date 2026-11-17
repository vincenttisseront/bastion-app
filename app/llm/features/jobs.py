"""Run LLM work off the request path, in a worker thread with its own loop.

Same pattern as the health probe scheduler (incident 2026-11-06): sync
SQLite/SQLCipher work must never run on the main event loop for long, and an
LLM call can take tens of seconds.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

JobFn = Callable[..., Awaitable[Any]]


def run_llm_job(fn: JobFn, /, **kwargs: Any) -> None:
    """Sync entry point (BackgroundTasks / APScheduler thread pool). Never raises."""
    from app import database

    db: Session = database.SessionLocal()
    try:
        asyncio.run(fn(db=db, **kwargs))
    except Exception:
        logger.warning("llm job %s failed", getattr(fn, "__name__", fn), exc_info=True)
    finally:
        db.close()


async def run_llm_job_async(fn: JobFn, /, **kwargs: Any) -> None:
    """Async entry point for APScheduler coroutine jobs: hop to a thread first."""
    await asyncio.to_thread(run_llm_job, fn, **kwargs)
