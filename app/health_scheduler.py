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
    try:
        scheduler.start()
        logger.info("Health probe scheduler started (every %d min)", interval)
    except RuntimeError:
        # On some environments (notably Windows + TestClient), the asyncio loop used by
        # APScheduler may already be closed during lifespan startup. This is non-fatal
        # for the web app: probes are best-effort.
        logger.warning("Health probe scheduler not started (event loop closed)")
        return

    # Daily watch: flag rotation recommended — never auto-rotates (§8.4).
    from app.vault.encryption_key_store import check_rotation_recommended_job

    scheduler.add_job(
        check_rotation_recommended_job,
        "interval",
        hours=24,
        id="vault_key_rotation_watch",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
        kwargs={"settings": settings},
    )
    logger.info("Vault key rotation watch scheduled (every 24h)")


def stop_health_scheduler() -> None:
    if scheduler.running:
        try:
            scheduler.shutdown(wait=False)
            logger.info("Health probe scheduler stopped")
        except RuntimeError:
            # TestClient / Windows ProactorEventLoop can be closed before shutdown hooks run.
            logger.warning("Health probe scheduler shutdown skipped (event loop closed)")
