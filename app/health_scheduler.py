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

    from app.mail.recap_service import daily_recap_job, recap_timezone

    scheduler.add_job(
        daily_recap_job,
        "cron",
        minute=5,
        timezone=recap_timezone(),
        id="daily_ops_recap",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
        kwargs={"settings": settings},
    )
    logger.info("Daily ops recap scheduled (hourly check at :05)")

    from app.bastion.modsec_audit_aggregator import run_aggregation

    def _modsec_audit_aggregate_job() -> None:
        try:
            run_aggregation(settings)
        except Exception:
            logger.exception("modsec audit aggregation failed")

    scheduler.add_job(
        _modsec_audit_aggregate_job,
        "interval",
        minutes=5,
        id="modsec_audit_aggregate",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    logger.info("ModSec audit aggregator scheduled (every 5 min)")

    def _nginx_ratelimit_sensor_job() -> None:
        from app.database import SessionLocal
        from app.security.banning.nginx_ratelimit_sensor import run_sensor_tick

        db = SessionLocal()
        try:
            run_sensor_tick(db, settings)
        except Exception:
            logger.exception("nginx rate-limit sensor failed")
        finally:
            db.close()

    scheduler.add_job(
        _nginx_ratelimit_sensor_job,
        "interval",
        seconds=30,
        id="nginx_ratelimit_sensor",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    logger.info("Nginx rate-limit sensor scheduled (every 30s)")

    from app.rbac.account_lifecycle_service import account_lifecycle_job

    scheduler.add_job(
        account_lifecycle_job,
        "cron",
        hour=6,
        minute=20,
        timezone=recap_timezone(),
        id="account_lifecycle",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
        kwargs={"settings": settings},
    )
    logger.info("Account lifecycle job scheduled (daily 06:20 Europe/Paris)")

    from app.rbac.app_credential_renewal_service import app_credential_renewal_job

    # Interval is fixed at registration; PortalSettings batch/age apply per tick.
    # Feature stays off until Admin enables app_credential_renewal_enabled.
    scheduler.add_job(
        app_credential_renewal_job,
        "interval",
        minutes=60,
        id="app_credential_renewal",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
        kwargs={"settings": settings},
    )
    logger.info(
        "App credential renewal worker scheduled (every 60 min, disabled by default)"
    )

    from app.reporting.security_report import monthly_compliance_report_job

    scheduler.add_job(
        monthly_compliance_report_job,
        "cron",
        day=1,
        hour=6,
        minute=30,
        timezone=recap_timezone(),
        id="monthly_compliance_report",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
        kwargs={"settings": settings},
    )
    logger.info(
        "Monthly compliance PDF scheduled (1st of month 06:30 Europe/Paris)"
    )


def stop_health_scheduler() -> None:
    if scheduler.running:
        try:
            scheduler.shutdown(wait=False)
            logger.info("Health probe scheduler stopped")
        except RuntimeError:
            # TestClient / Windows ProactorEventLoop can be closed before shutdown hooks run.
            logger.warning("Health probe scheduler shutdown skipped (event loop closed)")
