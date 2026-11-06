"""ActiveSync — per-app « admin approval only » for new devices."""

from __future__ import annotations

import re

import pytest
from sqlalchemy.orm import Session

from app.models import ActiveSyncDevice, App
from app.subdomain import activesync_device_service as device_service
from tests.test_activesync_devices import (  # noqa: F401  (autouse fixture re-exported)
    ADMIN_HEADERS,
    EAS_HOST,
    EAS_USER,
    USER_HEADERS,
    _audit,
    _devices,
    _reset_device_throttles,
    _sync,
)

OWNER_HEADERS = {
    "X-Email": EAS_USER,
    "X-Preferred-Username": "bob",
    "X-User-Id": "kc-eas-approval-1",
    "X-Groups": "users",
}


@pytest.fixture()
def eas_app(db_session: Session) -> App:
    app = App(
        slug="mail",
        label="Mail",
        upstream_url="https://10.0.0.9/",
        access_mode="subdomain_proxy",
        public_fqdn=EAS_HOST,
        allow_activesync=True,
        enabled=True,
    )
    db_session.add(app)
    db_session.commit()
    db_session.refresh(app)
    return app


def _pending(db: Session, app: App, device_id: str = "PENDING1") -> ActiveSyncDevice:
    device = ActiveSyncDevice(
        application_id=app.id,
        user_key=EAS_USER,
        device_id=device_id,
        status="pending",
        source="observed",
    )
    db.add(device)
    db.commit()
    db.refresh(device)
    return device


def _admin_only(db: Session, app: App, *, control: bool = True) -> None:
    app.activesync_device_control = control
    app.activesync_admin_approval_only = True
    db.commit()


def _csrf(page_text: str) -> str:
    match = re.search(r'name="csrf-token" content="([^"]+)"', page_text)
    assert match
    return match.group(1)


# --- service -----------------------------------------------------------------


def test_owner_cannot_self_approve_when_admin_only(db_session, eas_app):
    _admin_only(db_session, eas_app)
    device = _pending(db_session, eas_app)
    with pytest.raises(device_service.DeviceDecisionError, match="administrateur"):
        device_service.user_approve_device(db_session, device, actor=EAS_USER)
    db_session.refresh(device)
    assert device.status == "pending"
    assert _audit(db_session, "activesync.device_approved") == []


def test_owner_can_still_refuse_and_revoke_when_admin_only(db_session, eas_app):
    _admin_only(db_session, eas_app)
    refused = _pending(db_session, eas_app, "NOTME1")
    device_service.user_reject_device(db_session, refused, actor=EAS_USER)
    assert refused.status == "rejected"

    mine = _pending(db_session, eas_app, "MINE1")
    device_service.admin_approve_device(db_session, mine, actor="admin")
    device_service.user_revoke_device(db_session, mine, actor=EAS_USER)
    assert mine.status != "approved"


def test_default_mode_keeps_self_approval(db_session, eas_app):
    eas_app.activesync_device_control = True
    db_session.commit()
    device = _pending(db_session, eas_app)
    device_service.user_approve_device(db_session, device, actor=EAS_USER)
    assert device.status == "approved"


def test_set_admin_approval_only_audits_once(db_session, eas_app):
    assert device_service.set_admin_approval_only(
        db_session, eas_app, enabled=True, actor="admin@example.com"
    ) is True
    assert device_service.set_admin_approval_only(
        db_session, eas_app, enabled=True, actor="admin@example.com"
    ) is False
    rows = _audit(db_session, "activesync.approval_mode_changed")
    assert len(rows) == 1
    assert rows[0].event_code == "BST-AUTH-1005"
    assert rows[0].details["admin_approval_only"] is True


def test_owner_notice_does_not_invite_self_approval():
    subject, body = device_service._pending_notice("iPhone", "https://p/profile", admin_only=True)
    assert "en attente de validation" in subject
    assert "Un administrateur doit le valider" in body
    assert "pour l'approuver" not in body
    _subject, default_body = device_service._pending_notice(
        "iPhone", "https://p/profile", admin_only=False
    )
    assert "pour l'approuver ou le refuser" in default_body


# --- admin route -------------------------------------------------------------


def test_admin_route_switches_mode(client, db_session, eas_app):
    url = f"/admin/apps/{eas_app.slug}/activesync/devices/approval-mode"
    on = client.post(url, data={"admin_only": "1"}, headers=ADMIN_HEADERS, follow_redirects=False)
    assert on.status_code == 302
    db_session.refresh(eas_app)
    assert eas_app.activesync_admin_approval_only is True

    page = client.get(
        f"/admin/apps/{eas_app.slug}/activesync/devices/preview", headers=ADMIN_HEADERS
    )
    assert page.status_code == 200
    assert "Approbation des nouveaux appareils" in page.text
    assert re.search(r'name="admin_only" value="1"\s+checked', page.text)

    off = client.post(url, data={"admin_only": "0"}, headers=ADMIN_HEADERS, follow_redirects=False)
    assert off.status_code == 302
    db_session.refresh(eas_app)
    assert eas_app.activesync_admin_approval_only is False


def test_non_admin_cannot_switch_mode(client, db_session, eas_app):
    resp = client.post(
        f"/admin/apps/{eas_app.slug}/activesync/devices/approval-mode",
        data={"admin_only": "1"},
        headers=USER_HEADERS,
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303, 403)
    db_session.refresh(eas_app)
    assert eas_app.activesync_admin_approval_only is False


# --- portal ------------------------------------------------------------------


def test_profile_offers_refuse_but_not_approve(client, db_session, eas_app):
    _admin_only(db_session, eas_app)
    device = _pending(db_session, eas_app)

    page = client.get("/profile", headers=OWNER_HEADERS)
    assert page.status_code == 200
    assert f"/profile/activesync/devices/{device.id}/reject" in page.text
    assert f"/profile/activesync/devices/{device.id}/approve" not in page.text
    assert "Validation par un administrateur" in page.text
    assert "en attente de validation par un administrateur" in page.text

    # A hand-crafted POST is refused server-side too.
    resp = client.post(
        f"/profile/activesync/devices/{device.id}/approve",
        data={"csrf_token": _csrf(page.text)},
        headers=OWNER_HEADERS,
        follow_redirects=False,
    )
    assert resp.status_code == 302
    db_session.refresh(device)
    assert device.status == "pending"


def test_end_to_end_new_phone_waits_for_admin(client, db_session, eas_app):
    _admin_only(db_session, eas_app)

    assert _sync(client).status_code == 403
    device = _devices(db_session)[0]
    assert device.status == "pending"

    with pytest.raises(device_service.DeviceDecisionError):
        device_service.user_approve_device(db_session, device, actor=EAS_USER)

    device_service.admin_approve_device(db_session, device, actor="admin")
    device_service.reset_sighting_cache()
    assert _sync(client).status_code == 200
