"""HTTP upstream health probes for catalogue applications."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.models import App, utcnow
from app.testing_framework.connection_test import (
    CheckStatus,
    CheckStep,
    ConnectionTestResult,
    overall_from_checks,
)

logger = logging.getLogger(__name__)


def probe_target_url(app: App) -> str | None:
    url = (app.healthcheck_url or app.upstream_url or "").strip()
    return url or None


def classify_http_status(status_code: int) -> str:
    if 200 <= status_code < 400:
        return "ok"
    if 400 <= status_code < 500:
        return "warn"
    return "error"


def _status_from_http(code: int) -> CheckStatus:
    return CheckStatus(classify_http_status(code))


def _legacy_probe_dict(result: ConnectionTestResult) -> dict[str, Any]:
    """Map ConnectionTestResult to the dict expected by apply_probe_result / API."""
    http_code = None
    error = None
    for step in result.checks:
        if step.name != "http_probe":
            continue
        if step.detail:
            http_code = step.detail.get("http_code")
        if step.status == CheckStatus.ERROR:
            error = step.message
        elif step.status == CheckStatus.WARN:
            error = None
    if result.overall_status == CheckStatus.ERROR and error is None:
        for step in result.checks:
            if step.status == CheckStatus.ERROR:
                error = step.message
                break
    return {
        "status": result.overall_status.value,
        "http_code": http_code,
        "latency_ms": result.latency_ms,
        "error": error,
    }


async def probe_application_result(app: App) -> ConnectionTestResult:
    """Probe HTTP and return a ConnectionTestResult."""
    resource_id = getattr(app, "id", None)
    if resource_id is None:
        resource_id = getattr(app, "slug", None) or "unknown"

    url = probe_target_url(app)
    if not url:
        checks = [
            CheckStep(
                name="http_probe",
                status=CheckStatus.ERROR,
                message="Aucune URL upstream configurée",
            )
        ]
        return ConnectionTestResult(
            resource_type="app_health",
            resource_id=resource_id,
            overall_status=CheckStatus.ERROR,
            checks=checks,
            latency_ms=None,
        )

    start = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True, verify=True) as client:
            resp = await client.get(url)
        latency_ms = int((time.monotonic() - start) * 1000)
        status = _status_from_http(resp.status_code)
        if status == CheckStatus.OK:
            message = f"Upstream joignable (HTTP {resp.status_code})"
        elif status == CheckStatus.WARN:
            message = f"Réponse client HTTP {resp.status_code}"
        else:
            message = f"Réponse serveur HTTP {resp.status_code}"
        checks = [
            CheckStep(
                name="http_probe",
                status=status,
                message=message,
                detail={"http_code": resp.status_code},
            )
        ]
        return ConnectionTestResult(
            resource_type="app_health",
            resource_id=resource_id,
            overall_status=overall_from_checks(checks),
            checks=checks,
            latency_ms=latency_ms,
        )
    except httpx.TimeoutException:
        checks = [
            CheckStep(
                name="http_probe",
                status=CheckStatus.ERROR,
                message="Timeout (> 5s)",
            )
        ]
        return ConnectionTestResult(
            resource_type="app_health",
            resource_id=resource_id,
            overall_status=CheckStatus.ERROR,
            checks=checks,
            latency_ms=None,
        )
    except httpx.RequestError as exc:
        checks = [
            CheckStep(
                name="http_probe",
                status=CheckStatus.ERROR,
                message=f"Injoignable : {exc}",
            )
        ]
        return ConnectionTestResult(
            resource_type="app_health",
            resource_id=resource_id,
            overall_status=CheckStatus.ERROR,
            checks=checks,
            latency_ms=None,
        )


async def probe_application(app: App) -> dict[str, Any]:
    """Probe HTTP on the app's target URL. Returns a dict ready to persist."""
    return _legacy_probe_dict(await probe_application_result(app))


def apply_probe_result(app: App, result: dict[str, Any], probed_at: datetime | None = None) -> None:
    app.last_probe_status = result["status"]
    app.last_probe_http_code = result["http_code"]
    app.last_probe_latency_ms = result["latency_ms"]
    app.last_probe_error = result["error"]
    app.last_probe_at = probed_at or utcnow()


def probe_row_from_app(app: App) -> dict[str, Any]:
    from app.access_modes import normalize_access_mode

    status = app.last_probe_status or "unknown"
    probed_at = app.last_probe_at
    probed_at_iso = None
    if probed_at:
        if probed_at.tzinfo is None:
            probed_at = probed_at.replace(tzinfo=timezone.utc)
        probed_at_iso = probed_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    return {
        "app_id": app.id,
        "slug": app.slug,
        "label": app.label,
        "upstream_url": probe_target_url(app) or "—",
        "access_mode": normalize_access_mode(app.access_mode),
        "public_fqdn": app.public_fqdn,
        "status": status,
        "http_code": app.last_probe_http_code,
        "latency_ms": app.last_probe_latency_ms,
        "probed_at": probed_at_iso,
        "error": app.last_probe_error,
    }


def compute_status_counts(probes: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"ok": 0, "warn": 0, "error": 0, "unknown": 0}
    for probe in probes:
        key = probe.get("status") or "unknown"
        if key not in counts:
            key = "unknown"
        counts[key] += 1
    return counts


def compute_health_score(status_counts: dict[str, int], total: int) -> int:
    if total == 0:
        return 100
    return int((status_counts["ok"] / total) * 100)


def probe_result_payload(app: App) -> dict[str, Any]:
    row = probe_row_from_app(app)
    status = app.last_probe_status
    return {
        "app_id": row["app_id"],
        "status": status,
        "http_code": row["http_code"],
        "latency_ms": row["latency_ms"],
        "probed_at": row["probed_at"],
        "error": row["error"],
    }


async def probe_and_persist_app(db: Session, app: App) -> dict[str, Any]:
    result = await probe_application(app)
    apply_probe_result(app, result)
    db.commit()
    db.refresh(app)
    return probe_result_payload(app)


async def probe_all_enabled_apps(db: Session) -> dict[str, Any]:
    """Probe all enabled apps with probe_enabled=True. Never raises."""
    summary = {"ok": 0, "warn": 0, "error": 0, "unknown": 0, "skipped": 0}
    results: list[dict[str, Any]] = []

    try:
        apps = (
            db.query(App)
            .filter_by(probe_enabled=True, enabled=True)
            .order_by(App.slug)
            .all()
        )
        for app in apps:
            try:
                url = probe_target_url(app)
                if not url:
                    no_url = {
                        "status": "error",
                        "http_code": None,
                        "latency_ms": None,
                        "error": "Aucune URL upstream configurée",
                    }
                    apply_probe_result(app, no_url)
                    summary["error"] += 1
                    results.append(probe_result_payload(app))
                    continue

                result = await probe_application(app)
                apply_probe_result(app, result)
                key = result["status"]
                if key in summary:
                    summary[key] += 1
                results.append(probe_result_payload(app))
            except Exception:
                logger.exception("Health probe failed for app %s", app.slug)
                summary["error"] += 1

        db.commit()
        for app in apps:
            db.refresh(app)

        no_url_count = sum(
            1 for app in apps if not probe_target_url(app) and app.last_probe_error
        )
        logger.info(
            "Health probe cycle: %d ok, %d warn, %d error (%d no url)",
            summary["ok"],
            summary["warn"],
            summary["error"],
            no_url_count,
        )
    except Exception:
        logger.exception("Health probe cycle failed")
        db.rollback()

    probes = [probe_row_from_app(app) for app in apps] if "apps" in locals() else []
    status_counts = compute_status_counts(probes)
    total = len(probes)

    return {
        "results": results,
        "status_counts": status_counts,
        "health_score": compute_health_score(status_counts, total),
    }
