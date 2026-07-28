"""HTTP API for the admin notification center."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.web.notifications import build_notification_feed
from app.web.user_context import require_admin

router = APIRouter(
    prefix="/api/admin/notifications",
    tags=["admin-notifications"],
    dependencies=[Depends(require_admin)],
)


@router.get("")
def list_notifications(db: Session = Depends(get_db)) -> dict:
    return build_notification_feed(db)
