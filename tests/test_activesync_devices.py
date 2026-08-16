"""ActiveSync device inventory (lot 1) — extraction, inventory, admin block."""

from __future__ import annotations

import base64
import re

import pytest
import respx
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.access_modes import activesync_flags_for
from app.models import ActiveSyncDevice, App, AuditLog, RealmConfig
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings
from app.subdomain import activesync_device_service as device_service
from app.subdomain.activesync_auth import reset_allow_log_throttle
from app.subdomain import eas_device
from app.subdomain.eas_device import (
    QUERY_SAMPLE_MAX,
    explain_eas_device_miss,
    extract_eas_device,
    is_autodiscover_uri,
    query_sample,
)

ADMIN_HEADERS = {"X-Email": "admin@example.com", "X-Groups": "portal-admins"}
USER_HEADERS = {"X-Email": "user@example.com", "X-Groups": "transfer-users"}

EAS_HOST = "webmail.example.fr"
EAS_USER = "herve@example.fr"


@pytest.fixture(autouse=True)
def _reset_device_throttles():
    # Every throttle here is module-level and monotonic-clock based, so it
    # leaks between tests unless cleared.
    device_service.reset_sighting_cache()
    reset_allow_log_throttle()
    yield
    device_service.reset_sighting_cache()
    reset_allow_log_throttle()


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


def _basic(user: str = EAS_USER, password: str = "secret") -> str:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Basic {token}"


def _sync(
    client: TestClient,
    *,
    uri: str = f"/Microsoft-Server-ActiveSync?Cmd=Ping&User={EAS_USER}&DeviceId=ApplC39ZH2VJJCM3&DeviceType=iPhone",
    user: str = EAS_USER,
    method: str | None = "POST",
    client_ip: str = "203.0.113.10",
    user_agent: str = "Apple-iPhone/1601.405",
):
    headers = {
        "X-Original-Host": EAS_HOST,
        "X-Original-URI": uri,
        "User-Agent": user_agent,
        "X-Real-IP": client_ip,
        "Authorization": _basic(user),
    }
    if method is not None:
        headers["X-Original-Method"] = method
    return client.get("/internal/activesync-auth", headers=headers)


def _devices(db: Session) -> list[ActiveSyncDevice]:
    return db.query(ActiveSyncDevice).order_by(ActiveSyncDevice.id).all()


def _audit(db: Session, action: str) -> list[AuditLog]:
    return db.query(AuditLog).filter_by(action=action).order_by(AuditLog.id).all()


# --- extractor ---------------------------------------------------------------


def test_extract_named_query_preserves_case():
    device_id, device_type = extract_eas_device(
        "/Microsoft-Server-ActiveSync?Cmd=Sync&DeviceId=ApplC39ZH2VJJCM3&DeviceType=iPhone"
    )
    assert device_id == "ApplC39ZH2VJJCM3"
    assert device_type == "iPhone"


def test_extract_returns_none_without_device():
    assert extract_eas_device("/Microsoft-Server-ActiveSync?Cmd=Options") == (None, None)
    assert extract_eas_device("/Microsoft-Server-ActiveSync") == (None, None)
    assert extract_eas_device("") == (None, None)


def test_extract_base64_ms_ashttp_query():
    # protocol 141, command 9 (Sync), locale 1033, DeviceID 4 bytes, no policy
    # key, DeviceType "iPhone".
    raw = bytes([141, 9, 0x04, 0x09, 4]) + b"\xde\xad\xbe\xef" + bytes([0, 6]) + b"iPhone"
    query = base64.b64encode(raw).decode()
    device_id, device_type = extract_eas_device(f"/Microsoft-Server-ActiveSync?{query}")
    assert device_id == "DEADBEEF"
    assert device_type == "iPhone"


def test_extract_undecodable_base64_is_fail_safe():
    assert extract_eas_device("/Microsoft-Server-ActiveSync?!!!notbase64!!!") == (
        None,
        None,
    )
    # Valid base64 but truncated before the DeviceID.
    truncated = base64.b64encode(bytes([141, 9, 0x04])).decode()
    assert extract_eas_device(f"/Microsoft-Server-ActiveSync?{truncated}") == (None, None)


def test_miss_reason_names_the_failing_parse_path():
    named = "/Microsoft-Server-ActiveSync?Cmd=Ping&User=x@y.fr"
    assert explain_eas_device_miss(named) == "named_query_without_device_id"
    assert explain_eas_device_miss("/Microsoft-Server-ActiveSync") == "no_query"
    assert explain_eas_device_miss("/Microsoft-Server-ActiveSync?!!!nope!!!") == (
        "query_not_base64"
    )
    truncated = base64.b64encode(bytes([141, 9, 0x04])).decode()
    assert explain_eas_device_miss(f"/Microsoft-Server-ActiveSync?{truncated}") == (
        "base64_truncated"
    )
    ok = "/Microsoft-Server-ActiveSync?DeviceId=ApplC39ZH2VJJCM3"
    assert explain_eas_device_miss(ok) == "none"


def test_every_miss_reason_belongs_to_a_family():
    """The two families drive opposite switchover decisions (spec §10.bis).

    A new reason must be classified deliberately, not silently defaulted.
    """
    reasons = {
        value
        for name, value in vars(eas_device).items()
        if name.startswith("MISS_") and not name.startswith("MISS_FAMILY")
        and isinstance(value, str)
    }
    assert reasons == set(eas_device._MISS_FAMILIES)

    decoder = {r for r in reasons if eas_device.miss_family(r) == "decoder_failure"}
    no_device = {r for r in reasons if eas_device.miss_family(r) == "no_device_sent"}
    assert decoder == {
        "base64_undecodable",
        "base64_truncated",
        "query_not_base64",
        "parse_error",
    }
    assert no_device == {
        "no_query",
        "named_query_without_device_id",
        "base64_empty_device_id",
    }
    assert eas_device.miss_family("none") == "none"


def test_query_sample_is_bounded_and_marked():
    short = "/Microsoft-Server-ActiveSync?Cmd=Ping"
    assert query_sample(short) == "Cmd=Ping"
    long_query = "A" * 400
    sample = query_sample(f"/Microsoft-Server-ActiveSync?{long_query}")
    assert len(sample) == QUERY_SAMPLE_MAX + 1
    assert sample.endswith("…")
    assert query_sample("/Microsoft-Server-ActiveSync") is None


def test_is_autodiscover_uri():
    assert is_autodiscover_uri("/Autodiscover/Autodiscover.xml")
    assert is_autodiscover_uri("/autodiscover/autodiscover.xml?x=1")
    assert not is_autodiscover_uri("/Microsoft-Server-ActiveSync")


# --- inventory ---------------------------------------------------------------


def test_unknown_device_is_inventoried_without_blocking(client, db_session, eas_app):
    resp = _sync(client)
    assert resp.status_code == 200
    assert resp.headers.get("x-auth-source") == "basic"

    devices = _devices(db_session)
    assert len(devices) == 1
    device = devices[0]
    assert device.device_id == "ApplC39ZH2VJJCM3"
    assert device.device_type == "iPhone"
    assert device.user_key == EAS_USER
    assert device.status == "pending"
    assert device.source == "observed"
    assert device.blocked_by_admin is False
    assert device.application_id == eas_app.id

    discovered = _audit(db_session, "activesync.device_discovered")
    assert len(discovered) == 1
    assert discovered[0].event_code == "BST-AUTH-0009"


def test_first_sighting_is_written_without_delay(client, db_session, eas_app):
    """The write throttle must never defer the *first* sighting.

    At lot 2 a new device is refused on that very request; if its row appeared
    up to a minute later, the owner would get an error with nothing to approve
    in the portal and would report an outage.
    """
    assert _devices(db_session) == []
    _sync(client)
    devices = _devices(db_session)
    assert len(devices) == 1
    assert devices[0].status == "pending"
    assert len(_audit(db_session, "activesync.device_discovered")) == 1


def test_repeated_pings_keep_one_row_with_accurate_count(
    client, db_session, eas_app, monkeypatch
):
    for i in range(120):
        assert _sync(client, client_ip=f"198.51.100.{i % 40}").status_code == 200

    devices = _devices(db_session)
    assert len(devices) == 1
    device = devices[0]
    # 120 Pings, 2 writes: creation, then the first re-sighting. The rest are
    # held in memory — that is the whole point of the throttle.
    assert device.request_count == 2
    assert len(device.sample_source_ips or []) <= 10

    monkeypatch.setattr(device_service, "SIGHTING_WRITE_INTERVAL_SEC", 0.0)
    assert _sync(client, client_ip="198.51.100.200").status_code == 200
    db_session.expire_all()
    device = _devices(db_session)[0]
    # Nothing was lost: 121 requests, 121 counted.
    assert device.request_count == 121
    assert len(_devices(db_session)) == 1
    assert len(_audit(db_session, "activesync.device_discovered")) == 1


def test_two_devices_same_user_same_ip_are_both_logged(client, db_session, eas_app):
    base = f"/Microsoft-Server-ActiveSync?Cmd=Ping&User={EAS_USER}&DeviceType=iPhone&DeviceId="
    assert _sync(client, uri=base + "PHONE1").status_code == 200
    assert _sync(client, uri=base + "PHONE2").status_code == 200

    assert {d.device_id for d in _devices(db_session)} == {"PHONE1", "PHONE2"}
    allowed = _audit(db_session, "activesync.allowed")
    # The allow-log throttle keys on device_id: the second phone must not be
    # masked by the first one behind the same NAT.
    assert {row.details.get("device_id") for row in allowed} == {"PHONE1", "PHONE2"}


def test_mixed_case_device_id_is_one_row_with_case_preserved(client, db_session, eas_app):
    uri = f"/Microsoft-Server-ActiveSync?Cmd=Ping&User={EAS_USER}&DeviceId=ApplXyZ123"
    _sync(client, uri=uri)
    _sync(client, uri=uri)
    devices = _devices(db_session)
    assert len(devices) == 1
    assert devices[0].device_id == "ApplXyZ123"


def test_allowed_log_carries_device_fields(client, db_session, eas_app):
    _sync(client)
    row = _audit(db_session, "activesync.allowed")[-1]
    assert row.details.get("device_id") == "ApplC39ZH2VJJCM3"
    assert row.details.get("device_type") == "iPhone"
    assert row.details.get("device_status") == "pending"
    assert row.details.get("activesync_device_control") is False


def test_unidentified_device_passes_and_is_logged(client, db_session, eas_app):
    resp = _sync(client, uri="/Microsoft-Server-ActiveSync?Cmd=Ping")
    assert resp.status_code == 200
    assert _devices(db_session) == []
    rows = _audit(db_session, "activesync.device_unidentified")
    assert len(rows) == 1
    assert rows[0].event_code == "BST-AUTH-2009"


def test_unidentified_log_captures_the_query_and_the_reason(client, db_session, eas_app):
    blob = base64.b64encode(bytes([141, 9, 0x04])).decode()
    _sync(client, uri=f"/Microsoft-Server-ActiveSync?{blob}")
    detail = _audit(db_session, "activesync.device_unidentified")[-1].details
    assert detail["query_sample"] == blob
    assert detail["query_len"] == len(blob)
    assert detail["miss_reason"] == "base64_truncated"
    assert detail["miss_family"] == "decoder_failure"
    assert detail["path"] == "/Microsoft-Server-ActiveSync"
    assert detail["user_agent"] == "Apple-iPhone/1601.405"


def test_client_sending_no_device_is_flagged_as_such(client, db_session, eas_app):
    """The family that lot 2 will cut off, distinguished from a decoder bug."""
    _sync(client, uri="/Microsoft-Server-ActiveSync?Cmd=Ping&User=herve@example.fr")
    detail = _audit(db_session, "activesync.device_unidentified")[-1].details
    assert detail["miss_reason"] == "named_query_without_device_id"
    assert detail["miss_family"] == "no_device_sent"


def test_unidentified_log_never_carries_credentials(client, db_session, eas_app):
    _sync(client, uri="/Microsoft-Server-ActiveSync?Cmd=Ping", user="herve@example.fr")
    detail = _audit(db_session, "activesync.device_unidentified")[-1].details
    # Credentials travel in Authorization; the sample must not leak them back in.
    assert "secret" not in str(detail)
    assert "authorization" not in {k.lower() for k in detail}


def test_unidentified_sample_is_throttled_per_user_agent(client, db_session, eas_app):
    for _ in range(5):
        _sync(client, uri="/Microsoft-Server-ActiveSync?Cmd=Ping")
    assert len(_audit(db_session, "activesync.device_unidentified")) == 1
    _sync(client, uri="/Microsoft-Server-ActiveSync?Cmd=Ping", user_agent="Android/14")
    assert len(_audit(db_session, "activesync.device_unidentified")) == 2


def test_options_and_autodiscover_are_exempt(client, db_session, eas_app):
    assert (
        _sync(
            client, uri="/Microsoft-Server-ActiveSync", method="OPTIONS"
        ).status_code
        == 200
    )
    assert (
        _sync(client, uri="/Autodiscover/Autodiscover.xml", method="POST").status_code
        == 200
    )
    assert _audit(db_session, "activesync.device_unidentified") == []
    assert _devices(db_session) == []


def test_inventory_failure_does_not_change_the_response(
    client, db_session, eas_app, monkeypatch
):
    def _boom(*args, **kwargs):
        raise RuntimeError("inventory down")

    monkeypatch.setattr(device_service, "record_sighting", _boom)
    resp = _sync(client)
    assert resp.status_code == 200
    assert resp.headers.get("x-auth-source") == "basic"
    assert _devices(db_session) == []


# --- admin blocking ----------------------------------------------------------


def test_blocked_device_gets_403_never_401(client, db_session, eas_app):
    _sync(client)
    device = _devices(db_session)[0]
    device_service.admin_block_device(
        db_session, device, actor="admin@example.com", reason="téléphone volé"
    )
    device_service.reset_sighting_cache()

    resp = _sync(client)
    assert resp.status_code == 403
    assert resp.headers.get("x-auth-error") == "activesync-device-not-approved"
    assert "www-authenticate" not in {k.lower() for k in resp.headers}

    denied = _audit(db_session, "activesync.device_denied")[-1]
    assert denied.details.get("reason") == "device_blocked_by_admin"
    assert denied.details.get("device_id") == "ApplC39ZH2VJJCM3"
    assert denied.event_code == "BST-AUTH-2006"

    blocked = _audit(db_session, "activesync.device_blocked")
    assert len(blocked) == 1
    assert blocked[0].event_code == "BST-AUTH-2008"


def test_block_requires_a_reason(db_session, eas_app):
    device = ActiveSyncDevice(
        application_id=eas_app.id,
        user_key=EAS_USER,
        device_id="PHONE9",
        first_seen_at=None,
        last_seen_at=None,
    )
    device.first_seen_at = device.last_seen_at = device_service._utcnow()
    db_session.add(device)
    db_session.commit()
    with pytest.raises(device_service.DeviceDecisionError):
        device_service.admin_block_device(db_session, device, actor="admin", reason="  ")
    assert device.blocked_by_admin is False


def test_unblock_restores_access(client, db_session, eas_app):
    _sync(client)
    device = _devices(db_session)[0]
    device_service.admin_block_device(
        db_session, device, actor="admin", reason="perdu puis retrouvé"
    )
    device_service.reset_sighting_cache()
    assert _sync(client).status_code == 403

    device_service.admin_unblock_device(db_session, device, actor="admin")
    device_service.reset_sighting_cache()
    assert _sync(client).status_code == 200
    assert _audit(db_session, "activesync.device_unblocked")[0].event_code == "BST-AUTH-1004"


def test_admin_routes_refuse_non_admin(client, db_session, eas_app):
    _sync(client)
    device = _devices(db_session)[0]
    resp = client.post(
        f"/admin/activesync/devices/{device.id}/block",
        data={"reason": "test"},
        headers=USER_HEADERS,
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303, 403)
    db_session.refresh(device)
    assert device.blocked_by_admin is False


def test_admin_can_block_from_the_fiche(client, db_session, eas_app):
    _sync(client)
    device = _devices(db_session)[0]
    resp = client.post(
        f"/admin/activesync/devices/{device.id}/block",
        data={"reason": "téléphone volé", "redirect_url": "/admin/rbac/users"},
        headers=ADMIN_HEADERS,
        follow_redirects=False,
    )
    assert resp.status_code == 302
    db_session.expire_all()
    device = _devices(db_session)[0]
    assert device.blocked_by_admin is True
    assert device.status == "blocked"
    assert device.decision_note == "téléphone volé"


# --- admin fiche -------------------------------------------------------------

KC_BASE = "https://kc.example.com"
KC_ADMIN = f"{KC_BASE}/admin/realms/AR-SYSTEMS"
TOKEN_URL = f"{KC_BASE}/realms/AR-SYSTEMS/protocol/openid-connect/token"


def _realm(db_session: Session) -> RealmConfig:
    s = Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
    )
    realm = RealmConfig(
        slug="ar-systems",
        name="AR-SYSTEMS",
        issuer_url=f"{KC_BASE}/realms/AR-SYSTEMS",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", s),
        redirect_uri="https://portal.test/oauth2/ar-systems/callback",
        oauth2_proxy_port=4180,
        enabled=True,
        keycloak_admin_client_id="bastion-admin-sync",
        keycloak_admin_client_secret_encrypted=encrypt_secret("sync-secret", s),
    )
    db_session.add(realm)
    db_session.commit()
    db_session.refresh(realm)
    return realm


def _mock_keycloak_user():
    respx.post(TOKEN_URL).respond(200, json={"access_token": "tok"})
    respx.get(f"{KC_ADMIN}/users/kc-eas-1").respond(
        200,
        json={
            "id": "kc-eas-1",
            "username": "herve",
            "email": EAS_USER,
            "enabled": True,
            "requiredActions": [],
        },
    )
    respx.get(url__regex=rf"{re.escape(KC_ADMIN)}/users/kc-eas-1/groups.*").respond(
        200, json=[]
    )


def _fiche(client: TestClient, realm: RealmConfig):
    return client.get(
        f"/admin/rbac/users/view?realm_id={realm.id}&keycloak_user_id=kc-eas-1",
        headers=ADMIN_HEADERS,
    )


@respx.mock
def test_fiche_lists_devices_and_backfills_keycloak_id(client, db_session, eas_app):
    realm = _realm(db_session)
    _mock_keycloak_user()
    _sync(client)

    resp = _fiche(client, realm)
    assert resp.status_code == 200
    assert "Appareils ActiveSync" in resp.text
    assert "ApplC39ZH2VJJCM3" in resp.text

    db_session.expire_all()
    device = _devices(db_session)[0]
    # The fiche is the only place that knows both identities, so it links them.
    assert device.keycloak_user_id == "kc-eas-1"
    assert device.realm_id == realm.id


def test_normalize_user_key_strips_windows_domain_prefix():
    assert device_service.normalize_user_key(
        r"AR-SYSTEMS\herve@example.fr"
    ) == "herve@example.fr"
    assert device_service.normalize_user_key(
        r"a.r. systems\herve@example.fr"
    ) == "herve@example.fr"
    assert device_service.normalize_user_key("herve@example.fr") == "herve@example.fr"
    assert device_service.normalize_user_key(r"DOMAIN\sam") == "sam"


@respx.mock
def test_fiche_finds_device_stored_under_domain_prefix(client, db_session, eas_app):
    """Outlook often sends DOMAIN\\email — the fiche must still join on the email."""
    realm = _realm(db_session)
    _mock_keycloak_user()
    dirty = ActiveSyncDevice(
        application_id=eas_app.id,
        user_key=r"ar-systems.fr\herve@example.fr",
        device_id="ApplC39ZH2VJJCM3",
        device_type="iPhone",
        status="pending",
        source="observed",
        request_count=3,
    )
    db_session.add(dirty)
    db_session.commit()

    resp = _fiche(client, realm)
    assert resp.status_code == 200
    assert "ApplC39ZH2VJJCM3" in resp.text
    assert "Aucun appareil ActiveSync observé" not in resp.text

    db_session.expire_all()
    device = _devices(db_session)[0]
    assert device.user_key == "herve@example.fr"
    assert device.keycloak_user_id == "kc-eas-1"


@respx.mock
def test_sighting_with_domain_prefix_rewrites_legacy_row(client, db_session, eas_app):
    dirty = ActiveSyncDevice(
        application_id=eas_app.id,
        user_key=r"AR-SYSTEMS\herve@example.fr",
        device_id="ApplC39ZH2VJJCM3",
        status="pending",
        source="observed",
        request_count=1,
    )
    db_session.add(dirty)
    db_session.commit()

    resp = _sync(client, user=r"AR-SYSTEMS\herve@example.fr")
    assert resp.status_code == 200

    devices = _devices(db_session)
    assert len(devices) == 1
    assert devices[0].user_key == "herve@example.fr"
    assert devices[0].request_count >= 2


@respx.mock
def test_fiche_merges_duplicate_device_id_rows(client, db_session, eas_app):
    """Same DeviceId under email and DOMAIN\\email must collapse to one row."""
    realm = _realm(db_session)
    _mock_keycloak_user()
    approved = ActiveSyncDevice(
        application_id=eas_app.id,
        user_key="herve@example.fr",
        device_id="FBJV9GQUIC5K",
        device_type="iPhone",
        status="approved",
        source="admin",
        decided_by="admin",
        request_count=10,
    )
    pending_twin = ActiveSyncDevice(
        application_id=eas_app.id,
        user_key=r"ar-systems.fr\herve@example.fr",
        device_id="FBJV9GQUIC5K",
        device_type="iPhone",
        status="pending",
        source="observed",
        request_count=2,
    )
    db_session.add_all([approved, pending_twin])
    db_session.commit()

    resp = _fiche(client, realm)
    assert resp.status_code == 200
    assert "Approuvé" in resp.text
    assert "Approuver" not in resp.text
    # One row in the devices table (tbody), not a twin DeviceId under DOMAIN\email.
    assert resp.text.count("/admin/activesync/devices/") == 1

    devices = _devices(db_session)
    assert len(devices) == 1
    assert devices[0].user_key == "herve@example.fr"
    assert devices[0].status == "approved"
    assert devices[0].request_count == 12


def test_merge_prefers_blocked_over_approved(db_session, eas_app):
    blocked = ActiveSyncDevice(
        application_id=eas_app.id,
        user_key="herve@example.fr",
        device_id="DEVBLOCK1",
        status="blocked",
        source="admin",
        blocked_by_admin=True,
        request_count=1,
    )
    approved = ActiveSyncDevice(
        application_id=eas_app.id,
        user_key=r"DOMAIN\herve@example.fr",
        device_id="DEVBLOCK1",
        status="approved",
        source="admin",
        request_count=5,
    )
    db_session.add_all([blocked, approved])
    db_session.commit()

    survivors = device_service.merge_device_duplicates(
        db_session, [blocked, approved]
    )
    assert len(survivors) == 1
    assert survivors[0].status == "blocked"
    assert survivors[0].blocked_by_admin is True
    assert survivors[0].user_key == "herve@example.fr"
    assert survivors[0].request_count == 6
    assert len(_devices(db_session)) == 1


@respx.mock
def test_sighting_does_not_create_twin_when_sibling_exists(client, db_session, eas_app):
    db_session.add(
        ActiveSyncDevice(
            application_id=eas_app.id,
            user_key=r"AR-SYSTEMS\herve@example.fr",
            device_id="ApplTWIN001",
            status="approved",
            source="admin",
            request_count=3,
        )
    )
    db_session.commit()

    resp = _sync(
        client,
        user="herve@example.fr",
        uri=(
            f"/Microsoft-Server-ActiveSync?Cmd=Ping&User={EAS_USER}"
            "&DeviceId=ApplTWIN001&DeviceType=iPhone"
        ),
    )
    assert resp.status_code == 200

    devices = _devices(db_session)
    assert len(devices) == 1
    assert devices[0].user_key == "herve@example.fr"
    assert devices[0].status == "approved"
    assert devices[0].request_count >= 4


@respx.mock
def test_fiche_hides_the_tab_without_any_activesync_app(client, db_session):
    realm = _realm(db_session)
    _mock_keycloak_user()
    resp = _fiche(client, realm)
    assert resp.status_code == 200
    assert "Appareils ActiveSync" not in resp.text
    assert 'data-panel="appareils"' not in resp.text


# --- consistency guards ------------------------------------------------------


def test_device_control_cannot_outlive_activesync():
    assert activesync_flags_for(
        "subdomain_proxy", allow_activesync=True, device_control=True
    ) == (True, True)
    assert activesync_flags_for(
        "subdomain_proxy", allow_activesync=False, device_control=True
    ) == (False, False)
    assert activesync_flags_for(
        "sso_gate", allow_activesync=True, device_control=True
    ) == (False, False)


# --- non-regression: anti-brute-force stays out of the EAS path --------------


def test_activesync_path_is_not_a_sensitive_path():
    from app.security.banning.engine import is_login_path, is_sensitive_path

    assert not is_sensitive_path("/internal/activesync-auth")
    assert not is_login_path("/internal/activesync-auth", "POST")


def test_denied_activesync_never_records_a_login_attempt(
    client, db_session, eas_app, monkeypatch
):
    from app.security.banning import engine

    calls: list[str] = []
    monkeypatch.setattr(
        engine,
        "evaluate_login_attempt",
        lambda *a, **kw: calls.append("login") or None,
    )
    monkeypatch.setattr(
        engine,
        "record_sensitive_request",
        lambda *a, **kw: calls.append("sensitive") or None,
    )
    resp = client.get(
        "/internal/activesync-auth",
        headers={
            "X-Original-Host": EAS_HOST,
            "X-Original-URI": "/Microsoft-Server-ActiveSync?DeviceId=PHONE1",
            "X-Real-IP": "203.0.113.99",
        },
    )
    assert resp.status_code == 401
    assert calls == []


# --- Lot 2: device control gate ---------------------------------------------


def test_pending_device_allowed_while_control_off(client, db_session, eas_app):
    resp = _sync(client)
    assert resp.status_code == 200
    device = _devices(db_session)[0]
    assert device.status == "pending"
    assert eas_app.activesync_device_control is False


def test_pending_device_gets_403_when_control_on(client, db_session, eas_app):
    _sync(client)
    eas_app.activesync_device_control = True
    db_session.commit()
    device_service.reset_sighting_cache()

    resp = _sync(client)
    assert resp.status_code == 403
    assert resp.headers.get("x-auth-error") == "activesync-device-not-approved"
    assert "www-authenticate" not in {k.lower() for k in resp.headers}
    denied = _audit(db_session, "activesync.device_denied")[-1]
    assert denied.details.get("reason") == "device_status_pending"
    assert denied.event_code == "BST-AUTH-2006"


def test_approved_device_passes_when_control_on(client, db_session, eas_app):
    _sync(client)
    device = _devices(db_session)[0]
    device_service.admin_approve_device(db_session, device, actor="admin@example.com")
    eas_app.activesync_device_control = True
    db_session.commit()
    device_service.reset_sighting_cache()

    resp = _sync(client)
    assert resp.status_code == 200


def test_unidentified_fails_closed_when_control_on(client, db_session, eas_app):
    eas_app.activesync_device_control = True
    db_session.commit()
    resp = _sync(
        client,
        uri="/Microsoft-Server-ActiveSync?Cmd=Options",
        method="POST",
    )
    # OPTIONS is exempt — use a non-OPTIONS path without DeviceId
    resp = client.get(
        "/internal/activesync-auth",
        headers={
            "X-Original-Host": EAS_HOST,
            "X-Original-URI": "/Microsoft-Server-ActiveSync?Cmd=Ping",
            "X-Original-Method": "POST",
            "Authorization": _basic(),
            "User-Agent": "Apple-iPhone/1601.405",
            "X-Real-IP": "203.0.113.10",
        },
    )
    assert resp.status_code == 403
    assert resp.headers.get("x-auth-error") == "activesync-device-unidentified"


def test_unidentified_still_open_when_control_off(client, db_session, eas_app):
    resp = client.get(
        "/internal/activesync-auth",
        headers={
            "X-Original-Host": EAS_HOST,
            "X-Original-URI": "/Microsoft-Server-ActiveSync?Cmd=Ping",
            "X-Original-Method": "POST",
            "Authorization": _basic(),
            "User-Agent": "Apple-iPhone/1601.405",
            "X-Real-IP": "203.0.113.10",
        },
    )
    assert resp.status_code == 200


def test_serialize_inventorie_vs_en_attente(db_session, eas_app):
    from app.admin.activesync_devices import serialize_device

    device = ActiveSyncDevice(
        application_id=eas_app.id,
        user_key=EAS_USER,
        device_id="LABELTEST1",
        status="pending",
        source="observed",
    )
    db_session.add(device)
    db_session.commit()

    eas_app.activesync_device_control = False
    row = serialize_device(device, eas_app)
    assert row["status_label"] == "Inventorié"

    eas_app.activesync_device_control = True
    row = serialize_device(device, eas_app)
    assert row["status_label"] == "En attente de validation"


def test_backfill_enable_is_idempotent(db_session, eas_app):
    pending = ActiveSyncDevice(
        application_id=eas_app.id,
        user_key=EAS_USER,
        device_id="BFILL1",
        status="pending",
        source="observed",
        request_count=3,
    )
    blocked = ActiveSyncDevice(
        application_id=eas_app.id,
        user_key="other@example.fr",
        device_id="BFILL2",
        status="blocked",
        source="admin",
        blocked_by_admin=True,
        request_count=1,
    )
    db_session.add_all([pending, blocked])
    db_session.commit()

    r1 = device_service.enable_device_control(
        db_session, eas_app, actor="admin", pending_device_ids=["BFILL1"]
    )
    assert r1["approved_from_pending"] == 1
    assert eas_app.activesync_device_control is True
    db_session.refresh(pending)
    db_session.refresh(blocked)
    assert pending.status == "approved"
    assert pending.source == "backfill"
    assert blocked.status == "blocked"

    r2 = device_service.enable_device_control(
        db_session, eas_app, actor="admin", pending_device_ids=["BFILL1"]
    )
    assert r2["approved_from_pending"] == 0
    events = _audit(db_session, "activesync.device_control_enabled")
    assert len(events) >= 2
    assert events[0].event_code == "BST-AUTH-1003"


def test_backfill_enable_uses_frozen_preview_list_not_live_pending(db_session, eas_app):
    """TOCTOU: a pending row appearing after preview must not be auto-approved."""
    seen = ActiveSyncDevice(
        application_id=eas_app.id,
        user_key=EAS_USER,
        device_id="SEENATPREVIEW",
        status="pending",
        source="observed",
        request_count=2,
    )
    db_session.add(seen)
    db_session.commit()

    freeze = [d.device_id for d in device_service.preview_device_control(db_session, eas_app)["pending"]]
    assert freeze == ["SEENATPREVIEW"]

    late = ActiveSyncDevice(
        application_id=eas_app.id,
        user_key="late@example.fr",
        device_id="APPEAREDAFTER",
        status="pending",
        source="observed",
        request_count=1,
    )
    db_session.add(late)
    db_session.commit()

    result = device_service.enable_device_control(
        db_session, eas_app, actor="admin", pending_device_ids=freeze
    )
    assert result["approved_from_pending"] == 1
    assert result["left_pending"] == 1
    db_session.refresh(seen)
    db_session.refresh(late)
    assert seen.status == "approved"
    assert late.status == "pending"
    assert eas_app.activesync_device_control is True


def test_backfill_enable_does_not_resurrect_blocked_between_preview_and_confirm(
    db_session, eas_app
):
    """Stolen phone: block between GET preview and POST must not be undone by freeze."""
    phone = ActiveSyncDevice(
        application_id=eas_app.id,
        user_key=EAS_USER,
        device_id="STOLENPHONE1",
        status="pending",
        source="observed",
        request_count=5,
    )
    other = ActiveSyncDevice(
        application_id=eas_app.id,
        user_key="ok@example.fr",
        device_id="KEEPSYNC1",
        status="pending",
        source="observed",
        request_count=2,
    )
    db_session.add_all([phone, other])
    db_session.commit()

    freeze = [
        d.device_id
        for d in device_service.preview_device_control(db_session, eas_app)["pending"]
    ]
    assert set(freeze) == {"STOLENPHONE1", "KEEPSYNC1"}

    device_service.admin_block_device(
        db_session, phone, actor="admin", reason="téléphone volé"
    )
    db_session.refresh(phone)
    assert phone.status == "blocked"
    assert phone.blocked_by_admin is True

    result = device_service.enable_device_control(
        db_session, eas_app, actor="admin", pending_device_ids=freeze
    )
    assert result["approved_from_pending"] == 1
    assert result["skipped_not_pending"] >= 1
    db_session.refresh(phone)
    db_session.refresh(other)
    assert phone.status == "blocked"
    assert phone.blocked_by_admin is True
    assert other.status == "approved"
    assert eas_app.activesync_device_control is True


def test_backfill_enable_rejects_missing_freeze_when_pending_exist(db_session, eas_app):
    db_session.add(
        ActiveSyncDevice(
            application_id=eas_app.id,
            user_key=EAS_USER,
            device_id="NEEDFREEZE",
            status="pending",
            source="observed",
        )
    )
    db_session.commit()
    with pytest.raises(device_service.DeviceDecisionError):
        device_service.enable_device_control(
            db_session, eas_app, actor="admin", pending_device_ids=None
        )
    with pytest.raises(device_service.DeviceDecisionError):
        device_service.enable_device_control(
            db_session, eas_app, actor="admin", pending_device_ids=[]
        )
    assert eas_app.activesync_device_control is False


def test_merge_never_promotes_different_device_id(db_session, eas_app):
    a = ActiveSyncDevice(
        application_id=eas_app.id,
        user_key=EAS_USER,
        device_id="ExactCaseID",
        status="approved",
        source="admin",
        request_count=1,
    )
    forged = ActiveSyncDevice(
        application_id=eas_app.id,
        user_key=EAS_USER,
        device_id="exactcaseid",
        status="pending",
        source="observed",
        request_count=1,
    )
    db_session.add_all([a, forged])
    db_session.commit()
    survivors = device_service.merge_device_duplicates(db_session, [a, forged])
    assert len(survivors) == 2
    assert len(_devices(db_session)) == 2


def test_user_cannot_approve_admin_blocked(db_session, eas_app):
    device = ActiveSyncDevice(
        application_id=eas_app.id,
        user_key=EAS_USER,
        device_id="STOLEN1",
        status="blocked",
        source="admin",
        blocked_by_admin=True,
    )
    db_session.add(device)
    db_session.commit()
    with pytest.raises(device_service.DeviceDecisionError):
        device_service.user_approve_device(db_session, device, actor=EAS_USER)


def test_user_revoke_then_sync_denied(client, db_session, eas_app):
    _sync(client)
    device = _devices(db_session)[0]
    device_service.admin_approve_device(db_session, device, actor="admin")
    eas_app.activesync_device_control = True
    db_session.commit()
    device_service.user_revoke_device(db_session, device, actor=EAS_USER)
    device_service.reset_sighting_cache()
    resp = _sync(client)
    assert resp.status_code == 403
    revoked = _audit(db_session, "activesync.device_revoked")
    assert revoked[-1].event_code == "BST-AUTH-1002"


def test_portal_approve_csrf_ownership_and_happy_path(client, db_session, eas_app):
    import re

    device = ActiveSyncDevice(
        application_id=eas_app.id,
        user_key=EAS_USER,
        device_id="PORTAL1",
        status="pending",
        source="observed",
    )
    foreign = ActiveSyncDevice(
        application_id=eas_app.id,
        user_key="other@example.fr",
        device_id="PORTAL2",
        status="pending",
        source="observed",
    )
    db_session.add_all([device, foreign])
    db_session.commit()

    assert device_service.device_owned_by_session(
        device, email=EAS_USER, username="herve", keycloak_user_id="kc-eas-1"
    )
    assert not device_service.device_owned_by_session(
        foreign, email=EAS_USER, username="herve", keycloak_user_id="kc-eas-1"
    )

    headers = {
        "X-Email": EAS_USER,
        "X-Preferred-Username": "herve",
        "X-User-Id": "kc-eas-1",
        "X-Groups": "users",
    }
    page = client.get("/profile", headers=headers)
    assert page.status_code == 200
    assert "Mes appareils mobiles" in page.text
    match = re.search(r'name="csrf-token" content="([^"]+)"', page.text)
    assert match
    csrf = match.group(1)

    bad = client.post(
        f"/profile/activesync/devices/{device.id}/approve",
        data={"csrf_token": "not-valid"},
        headers=headers,
        follow_redirects=False,
    )
    # Authenticated HTML 403s are redirected to /apps by the global handler.
    assert bad.status_code == 302
    assert (bad.headers.get("location") or "").endswith("/apps")
    db_session.refresh(device)
    assert device.status == "pending"

    missing = client.post(
        f"/profile/activesync/devices/{foreign.id}/approve",
        data={"csrf_token": csrf},
        headers=headers,
        follow_redirects=False,
    )
    assert missing.status_code == 404

    ok = client.post(
        f"/profile/activesync/devices/{device.id}/approve",
        data={"csrf_token": csrf},
        headers=headers,
        follow_redirects=False,
    )
    assert ok.status_code == 302
    assert "#section-devices" in (ok.headers.get("location") or "")
    db_session.refresh(device)
    assert device.status == "approved"
    assert device.source == "user"
    approved = _audit(db_session, "activesync.device_approved")
    assert approved[-1].details.get("by") == "user"