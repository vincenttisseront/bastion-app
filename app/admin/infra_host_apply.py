"""Host-side infrastructure apply signal (no docker.sock in bastion-app).

Same pattern as ACME ``.reconcile_request`` / bare-metal ``apply-infra.request``:
bastion-app writes a sentinel under ``portal_data_dir``; a host systemd path unit
(or ops) runs ``apply-infra-docker.sh`` / ``apply-infrastructure.sh`` and writes
``apply-infra.status`` + ``apply-infra.log``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import time
from typing import Any

from app.sso_settings import Settings

APPLY_REQUEST_NAME = "apply-infra.request"
APPLY_STATUS_NAME = "apply-infra.status"
APPLY_LOG_NAME = "apply-infra.log"
APPLY_META_NAME = "apply-infra.meta.json"

# Status values written by dispatch scripts / this module.
STATUS_PENDING = "pending"
STATUS_OK = "ok"
STATUS_ERROR = "error"
STATUS_UNKNOWN = "unknown"


def infra_data_dir(settings: Settings) -> Path:
    """Directory shared with the host for apply-infra request/status files."""
    data = Path(settings.portal_data_dir).expanduser()
    exports = Path(settings.exports_dir).expanduser()
    try:
        if exports.resolve().is_relative_to(data.resolve()):
            return data.resolve()
    except (OSError, ValueError, AttributeError):
        pass
    # Fallback when portal_data_dir is unset/mismatched: parent of exports
    # (Docker: /var/lib/sso-portal/exports → /var/lib/sso-portal).
    return exports.resolve().parent


def request_path(settings: Settings) -> Path:
    return infra_data_dir(settings) / APPLY_REQUEST_NAME


def status_path(settings: Settings) -> Path:
    return infra_data_dir(settings) / APPLY_STATUS_NAME


def log_path(settings: Settings) -> Path:
    return infra_data_dir(settings) / APPLY_LOG_NAME


def meta_path(settings: Settings) -> Path:
    return infra_data_dir(settings) / APPLY_META_NAME


def request_host_apply(settings: Settings, *, exported_files: int = 0) -> dict[str, Any]:
    """Write apply-infra.request so the host watcher can sync oauth2 + compose.

    nginx conf.d is also refreshed by bastion-nginx ``watch-exports-reload``
    (~2s) when export files change — that path does not need this signal.
    oauth2-proxy-core sync / secondary realms / compose override need the host script.
    """
    data = infra_data_dir(settings)
    exports = Path(settings.exports_dir).expanduser().resolve()
    req = data / APPLY_REQUEST_NAME
    status = data / APPLY_STATUS_NAME
    log = data / APPLY_LOG_NAME
    meta = data / APPLY_META_NAME
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        data.mkdir(parents=True, exist_ok=True)
        # Content = export dir path (bare-metal dispatch) + timestamp line for PathChanged.
        req.write_text(f"{exports}\n# requested_at={now}\n", encoding="utf-8")
        status.write_text(STATUS_PENDING + "\n", encoding="utf-8")
        log.write_text(
            (
                f"Demande d'apply hôte envoyée à {now} "
                f"({exported_files} fichier(s) exportés).\n"
                "En attente du watcher systemd (apply-infra-docker-dispatch) "
                "ou d'un lancement manuel de scripts/apply-infra-docker.sh.\n"
            ),
            encoding="utf-8",
        )
        meta.write_text(
            (
                "{\n"
                f'  "requested_at": "{now}",\n'
                f'  "exports_dir": "{exports.as_posix()}",\n'
                f'  "exported_files": {int(exported_files)}\n'
                "}\n"
            ),
            encoding="utf-8",
        )
    except OSError as exc:
        return {
            "ok": False,
            "pending": False,
            "path": str(req),
            "message": f"Impossible d'écrire {APPLY_REQUEST_NAME}: {exc}",
        }

    return {
        "ok": True,
        "pending": True,
        "path": str(req),
        "message": (
            "Demande d'application hôte envoyée. "
            "nginx: reload auto via bastion-nginx (~2s). "
            "oauth2-proxy / compose: watcher hôte ou scripts/apply-infra-docker.sh."
        ),
    }


def read_host_apply_status(settings: Settings, *, log_max_chars: int = 4000) -> dict[str, Any]:
    """Read apply-infra.status / .log written by the host dispatch script."""
    status_file = status_path(settings)
    log_file = log_path(settings)
    req = request_path(settings)

    status = STATUS_UNKNOWN
    if status_file.is_file():
        try:
            raw = status_file.read_text(encoding="utf-8", errors="replace").strip().splitlines()
            status = (raw[0] if raw else STATUS_UNKNOWN).strip().lower() or STATUS_UNKNOWN
        except OSError:
            status = STATUS_UNKNOWN

    log_text = ""
    log_exists = log_file.is_file()
    if log_exists:
        try:
            log_text = log_file.read_text(encoding="utf-8", errors="replace")
            if len(log_text) > log_max_chars:
                log_text = "…\n" + log_text[-log_max_chars:]
        except OSError:
            log_text = ""

    request_pending = req.is_file() and status == STATUS_PENDING
    # If request file still present after ok/error, watcher may not have consumed it yet
    # or PathChanged did not fire — still show request presence.
    if req.is_file() and status == STATUS_UNKNOWN:
        request_pending = True
        status = STATUS_PENDING

    badge = {
        STATUS_OK: "ok",
        STATUS_ERROR: "err",
        STATUS_PENDING: "warn",
    }.get(status, "muted")

    labels = {
        STATUS_OK: "Appliqué sur l'hôte",
        STATUS_ERROR: "Échec apply hôte",
        STATUS_PENDING: "En attente apply hôte",
        STATUS_UNKNOWN: "Jamais appliqué sur l'hôte",
    }

    return {
        "status": status,
        "status_label": labels.get(status, status),
        "badge": badge,
        "request_pending": request_pending,
        "request_path": str(req),
        "request_exists": req.is_file(),
        "status_path": str(status_file),
        "log_path": str(log_file),
        "log_exists": log_exists,
        "log_text": log_text,
        "data_dir": str(infra_data_dir(settings)),
    }


# Max time the apply-wait UI keeps polling before giving up.
HOST_APPLY_WAIT_TIMEOUT_SEC = 180.0
# Browser / server poll interval while waiting.
HOST_APPLY_WAIT_POLL_SEC = 2.0


def host_apply_is_terminal(status: str | None) -> bool:
    return (status or "").strip().lower() in {STATUS_OK, STATUS_ERROR}


def wait_for_host_apply(
    settings: Settings, *, timeout_sec: float = 10.0, poll_interval_sec: float = 0.25
) -> dict[str, Any]:
    """Wait for host apply to leave pending and return the latest status."""
    deadline = time.monotonic() + max(0.0, timeout_sec)
    while True:
        state = read_host_apply_status(settings)
        if host_apply_is_terminal(state.get("status")):
            return state
        if time.monotonic() >= deadline:
            return state
        time.sleep(max(0.05, poll_interval_sec))
