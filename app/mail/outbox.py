"""In-process mail outbox (S2) — SMTP never runs on a request path.

A single background thread drains a bounded queue: a burst of notifications
cannot hold request workers (SMTP timeout is 20 s) nor grow without limit.
Best-effort by design: queued mails are lost on restart, a full queue drops new
mails (logged). The worker opens its own DB session to read SMTP settings.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor

logger = logging.getLogger(__name__)

MAX_QUEUED_MAILS = 100

_executor: ThreadPoolExecutor | None = None
_executor_lock = threading.Lock()
_slots = threading.BoundedSemaphore(MAX_QUEUED_MAILS)


def _get_executor() -> ThreadPoolExecutor:
    global _executor
    with _executor_lock:
        if _executor is None:
            _executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="mail-outbox")
        return _executor


def _send_now(*, to_email: str, subject: str, body_text: str) -> None:
    from app.database import SessionLocal
    from app.mail.smtp_service import send_email, smtp_configured
    from app.portal_settings_service import ensure_portal_settings
    from app.sso_settings import get_settings

    settings = get_settings()
    db = SessionLocal()
    try:
        row = ensure_portal_settings(db, settings)
        if not smtp_configured(row):
            return
        send_email(row, settings, to_email=to_email, subject=subject, body_text=body_text)
    finally:
        db.close()


# Overridable in tests (e.g. to capture instead of sending).
_sender: Callable[..., None] = _send_now


def enqueue_mail(*, to_email: str, subject: str, body_text: str) -> Future | None:
    """Queue one mail. Returns the future, or ``None`` when the queue is full."""
    if not _slots.acquire(blocking=False):
        logger.warning("mail outbox full — dropping notification")
        return None

    def _job() -> None:
        try:
            _sender(to_email=to_email, subject=subject, body_text=body_text)
        except Exception:  # noqa: BLE001 — never kill the worker thread
            logger.exception("mail outbox send failed")
        finally:
            _slots.release()

    try:
        return _get_executor().submit(_job)
    except RuntimeError:  # interpreter shutting down
        _slots.release()
        return None
