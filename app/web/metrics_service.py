"""Dashboard metrics API."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import App, AuditLog
from app.web.sessions_service import get_active_sessions
from app.web.user_context import require_user

router = APIRouter(prefix="/api", tags=["metrics"])


def get_dashboard_metrics(db: Session) -> dict:
    active_sessions = len(get_active_sessions())
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
    health_score = 100 if total_apps == 0 else min(100, 70 + enabled_apps * 5)

    return {
        "active_sessions": active_sessions,
        "blocked_attempts": blocked,
        "blocked_delta": min(blocked, 99),
        "health_score": health_score,
        "anomalies": 0,
    }


@router.get("/metrics")
def get_metrics(
    db: Session = Depends(get_db),
    _user=Depends(require_user),
):
    return get_dashboard_metrics(db)
