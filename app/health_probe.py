"""HTTP upstream health probes for catalogue applications."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from app.bastion.upstream_proxy import upstream_origin
from app.bastion.upstream_tls import resolve_upstream_tls_verify
from app.models import App, utcnow
from app.testing_framework.connection_test import (
    CheckStatus,
    CheckStep,
    ConnectionTestResult,
    overall_from_checks,
)

logger = logging.getLogger(__name__)

_PROBE_TIMEOUT_S = 10.0


def probe_target_url(app: App) -> str | None:
    """
    URL used for the HTTP probe.

    Prefer an explicit ``healthcheck_url``. Otherwise hit the upstream origin
    (same backend nginx uses) plus the app entry path from ``login_form_url``
    or a legacy path on ``upstream_url`` (e.g. ``/web/`` for grommunio).
    Never probes the public SSO edge.
    """
    from app.access_modes import upstream_entry_path

    explicit = (getattr(app, "healthcheck_url", None) or "").strip()
    if explicit:
        return explicit
    raw = (getattr(app, "upstream_url", None) or "").strip()
    if not raw:
        return None
    try:
        origin = upstream_origin(raw)
    except ValueError:
        return raw
    path = upstream_entry_path(app)
    return f"{origin.rstrip('/')}{path}"


def classify_http_status(status_code: int) -> str:
    """
    Map HTTP codes to probe status.

    3xx and 401/403 count as ``ok``: the TCP/TLS hop succeeded and the target
    answered (SSO redirect at the edge, Basic/form login, etc.). We do **not**
    follow redirects into the IdP — that would measure Keycloak, not the app.
    """
    if 200 <= status_code < 400:
        return "ok"
    if status_code in (401, 403):
        return "ok"
    if 400 <= status_code < 500:
        return "warn"
    return "error"


def _status_from_http(code: int) -> CheckStatus:
    return CheckStatus(classify_http_status(code))


def _probe_request_headers(app: App, url: str) -> dict[str, str]:
    """Send public FQDN as Host when probing an IP/LAN upstream (vhost apps)."""
    fqdn = (getattr(app, "public_fqdn", None) or "").strip()
    if not fqdn:
        return {}
    host = (urlparse(url).hostname or "").lower()
    if not host or host == fqdn.lower():
        return {}
    return {"Host": fqdn}


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

    # Align with nginx / robotic login (default: do not verify LAN/self-signed).
    tls_verify = resolve_upstream_tls_verify(app)
    headers = _probe_request_headers(app, url)
    start = time.monotonic()
    try:
        # Never follow redirects: a 302 to portal/Keycloak means the edge (or
        # upstream) answered; following would health-check the IdP instead.
        async with httpx.AsyncClient(
            timeout=_PROBE_TIMEOUT_S,
            follow_redirects=False,
            verify=tls_verify,
        ) as client:
            resp = await client.get(url, headers=headers)
        latency_ms = int((time.monotonic() - start) * 1000)
        status = _status_from_http(resp.status_code)
        if status == CheckStatus.OK:
            if resp.status_code in (401, 403):
                message = (
                    f"Upstream joignable (HTTP {resp.status_code} — auth attendue)"
                )
            elif 300 <= resp.status_code < 400:
                message = (
                    f"Upstream joignable (HTTP {resp.status_code} — redirect)"
                )
            else:
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
                detail={
                    "http_code": resp.status_code,
                    "tls_verify": tls_verify,
                    "url": url,
                },
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
                message=f"Timeout (> {_PROBE_TIMEOUT_S:g}s) sur {url}",
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
                message=f"Injoignable ({url}) : {exc}",
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
    from app.database import release_db_connection

    app_id = app.id
    # Probe only needs column values already loaded on ``app``.
    release_db_connection(db)
    result = await probe_application(app)
    app = db.get(App, app_id) or app
    apply_probe_result(app, result)
    db.commit()
    db.refresh(app)
    return probe_result_payload(app)


async def probe_all_enabled_apps(db: Session) -> dict[str, Any]:
    """Probe all enabled apps with probe_enabled=True. Never raises."""
    from app.database import release_db_connection

    summary = {"ok": 0, "warn": 0, "error": 0, "unknown": 0, "skipped": 0}
    results: list[dict[str, Any]] = []
    apps: list[App] = []

    try:
        # Collect IDs first so we can release the pool connection during HTTP waits.
        app_ids = [
            row[0]
            for row in (
                db.query(App.id)
                .filter_by(probe_enabled=True, enabled=True)
                .order_by(App.slug)
                .all()
            )
        ]
        release_db_connection(db)

        for app_id in app_ids:
            app = db.get(App, app_id)
            if app is None:
                continue
            slug = app.slug
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
                    db.commit()
                    summary["error"] += 1
                    results.append(probe_result_payload(app))
                    apps.append(app)
                    release_db_connection(db)
                    logger.warning("Health probe %s → error (no url)", slug)
                    continue

                # Hold no pool connection for the (up to 10s) HTTP probe.
                release_db_connection(db)
                result = await probe_application(app)
                app = db.get(App, app_id)
                if app is None:
                    summary["error"] += 1
                    continue
                apply_probe_result(app, result)
                db.commit()
                key = result["status"]
                if key in summary:
                    summary[key] += 1
                results.append(probe_result_payload(app))
                apps.append(app)
                release_db_connection(db)
                if key == "ok":
                    logger.info(
                        "Health probe %s → ok http=%s url=%s",
                        slug,
                        result.get("http_code"),
                        url,
                    )
                else:
                    logger.warning(
                        "Health probe %s → %s http=%s url=%s error=%s",
                        slug,
                        key,
                        result.get("http_code"),
                        url,
                        result.get("error"),
                    )
            except Exception:
                logger.exception("Health probe failed for app %s", slug)
                try:
                    db.rollback()
                except Exception:
                    pass
                release_db_connection(db)
                summary["error"] += 1

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
        try:
            db.rollback()
        except Exception:
            pass

    probes = [probe_row_from_app(app) for app in apps]
    status_counts = compute_status_counts(probes)
    total = len(probes)

    return {
        "results": results,
        "status_counts": status_counts,
        "health_score": compute_health_score(status_counts, total),
    }
