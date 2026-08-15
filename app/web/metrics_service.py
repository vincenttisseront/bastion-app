"""Dashboard metrics API — real database values only."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.db.hot_store import hot_read
from app.models import App, AuditLog
from app.web.sessions_service import count_active_sessions
from app.web.user_context import require_admin

# Router-level admin guard — metrics are operational/security sensitive.
router = APIRouter(
    prefix="/api",
    tags=["metrics"],
    dependencies=[Depends(require_admin)],
)


def get_dashboard_metrics(db: Session) -> dict:
    # audit_logs is a hot table: keep the rest of the dashboard alive without it.
    blocked = hot_read(
        lambda: db.query(AuditLog)
        .filter(
            AuditLog.action.like("%login_failed%")
            | AuditLog.action.like("%blocked%")
        )
        .count(),
        default=None,
        what="blocked attempts",
        db=db,
    )
    enabled_apps = db.query(App).filter_by(enabled=True).count()
    total_apps = db.query(App).count()

    return {
        "active_sessions": count_active_sessions(db),
        "blocked_attempts": blocked,
        "enabled_apps": enabled_apps,
        "total_apps": total_apps,
    }


@router.get("/metrics")
def get_metrics(db: Session = Depends(get_db)):
    return get_dashboard_metrics(db)
