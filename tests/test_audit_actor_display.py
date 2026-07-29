"""Readable audit Acteur column — Keycloak sub stays in details only."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.audit import OPAQUE_SSO_ACTOR, log_action, normalize_audit_actor
from app.models import AuditLog
from app.web.admin_logs_query import serialize_audit_row

KC_SUB = "e189ed16-79f0-4fa1-85ee-1bb7ff28052c"


def test_normalize_audit_actor_moves_uuid_to_details():
    actor, details = normalize_audit_actor(KC_SUB, {"family": "sso"})
    assert actor == OPAQUE_SSO_ACTOR
    assert details["keycloak_user_id"] == KC_SUB
    assert details["family"] == "sso"


def test_normalize_audit_actor_prefers_detail_username():
    actor, details = normalize_audit_actor(
        KC_SUB,
        {"username": "vincent.tisseront@ar-systems.fr", "family": "sso"},
    )
    assert actor == "vincent.tisseront@ar-systems.fr"
    assert details["keycloak_user_id"] == KC_SUB


def test_normalize_audit_actor_prefers_robotic_username():
    actor, details = normalize_audit_actor(
        KC_SUB,
        {
            "robotic_username": "vincent.tisseront@ar-systems.fr",
            "driver": "generic_form",
        },
    )
    assert actor == "vincent.tisseront@ar-systems.fr"
    assert details["keycloak_user_id"] == KC_SUB


def test_log_action_persists_readable_actor(db_session: Session):
    entry = log_action(
        db_session,
        actor=KC_SUB,
        action="session_fingerprint_drift",
        target="abc",
        details={"family": "sso", "username": "alice@example.com"},
    )
    assert entry is not None
    assert entry.actor == "alice@example.com"
    assert entry.details["keycloak_user_id"] == KC_SUB


def test_serialize_rewrites_legacy_uuid_actor_rows(db_session: Session):
    """Rows written before normalize_audit_actor still render a readable Acteur."""
    row = AuditLog(
        actor=KC_SUB,
        action="session_fingerprint_drift",
        target="deadbeef",
        details={
            "family": "sso",
            "username": "vincent.tisseront@ar-systems.fr",
            "subnet": "192.168.2.0/24",
        },
    )
    db_session.add(row)
    db_session.commit()
    db_session.refresh(row)

    payload = serialize_audit_row(row)
    assert payload["actor"] == "vincent.tisseront@ar-systems.fr"
    assert KC_SUB not in payload["actor"]
    assert "keycloak_user_id" in (payload["detail_full"] or "")
    assert KC_SUB in (payload["detail_full"] or "")
