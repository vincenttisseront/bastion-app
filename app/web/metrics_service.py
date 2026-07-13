"""Dashboard metrics API — real database values only."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import App, AuditLog
from app.web.sessions_service import get_active_sessions
from app.web.user_context import require_user

router = APIRouter(prefix="/api", tags=["metrics"])


def get_dashboard_metrics(db: Session) -> dict:
    blocked = (
        db.query(AuditLog)
        .filter(
            AuditLog.action.like("%login_failed%")
            | AuditLog.action.like("%blocked%")
        )
        .count()
    )
    enabled_apps = db.query(App).filter_by(enabled=True).count()
    total_apps = db.query(App).count()

    return {
        "active_sessions": len(get_active_sessions()),
        "blocked_attempts": blocked,
        "enabled_apps": enabled_apps,
        "total_apps": total_apps,
    }


@router.get("/metrics")
def get_metrics(
    db: Session = Depends(get_db),
    _user=Depends(require_user),
):
    return get_dashboard_metrics(db)
