"""Background SIEM outbox worker (APScheduler)."""

from __future__ import annotations

import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.database import SessionLocal
from app.siem.outbox import process_outbox_once
from app.sso_settings import Settings

logger = logging.getLogger(__name__)

_siem_scheduler = AsyncIOScheduler()


def _drain_job() -> None:
    db = SessionLocal()
    try:
        stats = process_outbox_once(db)
        if stats.get("sent") or stats.get("failed") or stats.get("purged"):
            logger.debug("siem outbox drain %s", stats)
    except Exception:
        logger.exception("siem outbox drain failed")
    finally:
        db.close()


def start_siem_scheduler(settings: Settings | None = None) -> None:
    del settings  # reserved for future interval tuning
    if _siem_scheduler.running:
        return
    _siem_scheduler.add_job(
        _drain_job,
        "interval",
        seconds=5,
        id="siem_outbox_drain",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    try:
        _siem_scheduler.start()
        logger.info("SIEM outbox scheduler started (every 5s)")
    except RuntimeError:
        logger.warning("SIEM outbox scheduler not started (event loop closed)")


def stop_siem_scheduler() -> None:
    if _siem_scheduler.running:
        try:
            _siem_scheduler.shutdown(wait=False)
            logger.info("SIEM outbox scheduler stopped")
        except RuntimeError:
            logger.warning("SIEM outbox scheduler shutdown skipped (event loop closed)")
