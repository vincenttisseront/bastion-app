"""Periodic background health probe scheduler."""

from __future__ import annotations

import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.database import SessionLocal
from app.health_probe import probe_all_enabled_apps
from app.sso_settings import Settings

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()


async def _scheduled_probe_cycle() -> None:
    db = SessionLocal()
    try:
        await probe_all_enabled_apps(db)
    finally:
        db.close()


def start_health_scheduler(settings: Settings) -> None:
    if not settings.health_probe_leader:
        logger.info("Health probe scheduler disabled (HEALTH_PROBE_LEADER=false)")
        return
    if scheduler.running:
        return

    interval = settings.health_probe_interval_minutes
    scheduler.add_job(
        _scheduled_probe_cycle,
        "interval",
        minutes=interval,
        id="health_probe",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    logger.info("Health probe scheduler started (every %d min)", interval)


def stop_health_scheduler() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("Health probe scheduler stopped")
