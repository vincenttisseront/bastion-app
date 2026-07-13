"""Active sessions — backed by session registry (empty until Phase 4+ integration)."""

from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.audit import log_action
from app.database import get_db
from app.web.user_context import require_admin, require_user

# TODO(phase4): connect to oauth2-proxy session store or bastion session registry via SSE/WebSocket


@dataclass
class ActiveSession:
    id: str
    user: str
    realm: str
    protocol: str
    target: str
    source_ip: str
    duration: str
    status: str = "active"


_sessions: list[ActiveSession] = []


def get_active_sessions() -> list[dict[str, Any]]:
    return [
        {
            "id": s.id,
            "user": s.user,
            "realm": s.realm,
            "protocol": s.protocol,
            "target": s.target,
            "source_ip": s.source_ip,
            "duration": s.duration,
            "status": s.status,
        }
        for s in _sessions
    ]


def _find_session(session_id: str) -> ActiveSession | None:
    for s in _sessions:
        if s.id == session_id:
            return s
    return None


router = APIRouter(tags=["sessions"])


@router.get("/api/sessions")
def list_sessions(_user=Depends(require_user)):
    return {"sessions": get_active_sessions()}


@router.post("/admin/sessions/{session_id}/isolate")
def isolate_session(
    session_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    session = _find_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    session.status = "isolated"
    log_action(
        db,
        actor=user.email,
        action="session.isolated",
        target=session.target,
        details={"session_id": session_id},
        ip_address=request.headers.get("X-Real-IP"),
    )
    return {"status": "ok", "session_id": session_id}


@router.post("/admin/sessions/{session_id}/rotate-keys")
def rotate_keys(
    session_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    session = _find_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    log_action(
        db,
        actor=user.email,
        action="session.rotate_keys",
        target=session.target,
        details={"session_id": session_id},
        ip_address=request.headers.get("X-Real-IP"),
    )
    return {"status": "ok", "session_id": session_id}
