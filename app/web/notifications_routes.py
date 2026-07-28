"""HTTP API for the admin notification center."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.web.notifications import (
    build_notification_feed,
    dismiss_all_notifications,
    dismiss_notification,
)
from app.web.user_context import UserContext, require_admin

router = APIRouter(
    prefix="/api/admin/notifications",
    tags=["admin-notifications"],
    dependencies=[Depends(require_admin)],
)


class DismissBody(BaseModel):
    item_id: str = Field(min_length=1, max_length=200)
    fingerprint: str = Field(default="", max_length=500)


@router.get("")
@router.get("/")
def list_notifications(
    db: Session = Depends(get_db),
    user: UserContext = Depends(require_admin),
) -> dict:
    return build_notification_feed(db, user_email=user.email)


@router.post("/dismiss")
def dismiss_one(
    body: DismissBody,
    db: Session = Depends(get_db),
    user: UserContext = Depends(require_admin),
) -> dict:
    try:
        dismiss_notification(
            db,
            user_email=user.email,
            item_id=body.item_id,
            fingerprint=body.fingerprint,
            actor=user.email,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    feed = build_notification_feed(db, user_email=user.email)
    return {"ok": True, **feed}


@router.post("/dismiss-all")
def dismiss_all(
    db: Session = Depends(get_db),
    user: UserContext = Depends(require_admin),
) -> dict:
    feed = build_notification_feed(db, user_email=user.email)
    n = dismiss_all_notifications(
        db,
        user_email=user.email,
        items=list(feed.get("items") or []),
        actor=user.email,
    )
    feed = build_notification_feed(db, user_email=user.email)
    return {"ok": True, "dismissed": n, **feed}
