"""Regression tests — review findings S2 (anonymous ActiveSync abuse), S4 (hop
cookie readable + portal tokens forwarded upstream) and S7 (shared secret)."""

from __future__ import annotations

import base64
import re
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy.orm import Session
from starlette.requests import Request

from app.models import (
    ACTIVESYNC_DEVICE_PENDING,
    ActiveSyncDevice,
    App,
    BastionAccount,
)
from app.sso_settings import Settings
from app.subdomain import activesync_device_service as device_service

ROOT = Path(__file__).resolve().parents[2]
TOKEN = "internal-nginx-token-for-tests"


def _settings(**extra) -> Settings:
    base = dict(
        environment="test",
        vault_portal_internal_token=TOKEN,
        session_hop_secret="hop-hmac-secret-for-pytest",
        portal_domain="portal.example.com",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
    )
    base.update(extra)
    return Settings(**base)


# --- S7 : dedicated signing secret, one key per usage -------------------------


def test_s7_signing_secret_equal_to_internal_token_is_refused():
    with pytest.raises(ValidationError):
        _settings(portal_signing_secret=TOKEN)


def test_s7_signing_key_is_not_the_internal_token():
    from app.web.csrf import portal_signing_secret

    for settings in (_settings(), _settings(portal_signing_secret="dedicated-signing-secret")):
        key = portal_signing_secret(settings)
        assert key and key != TOKEN


def test_s7_csrf_forged_with_internal_token_is_rejected():
    from app.web.csrf import CSRF_COOKIE, make_csrf_token, portal_signing_secret, verify_csrf_token

    settings = _settings(portal_signing_secret="dedicated-signing-secret")
    req = Request({"type": "http", "headers": [(b"cookie", f"{CSRF_COOKIE}=nonce1".encode())]})
    forged = make_csrf_token(req, TOKEN)  # attacker who only leaked the nginx token
    assert not verify_csrf_token(req, portal_signing_secret(settings), forged)
    good = make_csrf_token(req, portal_signing_secret(settings))
    assert verify_csrf_token(req, portal_signing_secret(settings), good)


def test_s7_one_key_per_usage():
    from app.web.csrf import portal_signing_secret

    settings = _settings(portal_signing_secret="dedicated-signing-secret")
    keys = {
        portal_signing_secret(settings, purpose=p)
        for p in ("portal", "mfa-cookie", "webauthn-challenge", "hot-store-fingerprint")
    }
    assert len(keys) == 4


def test_s7_production_without_signing_secret_fails_closed():
    from app.runtime_secrets_service import reset_runtime_secrets_cache_for_tests
    from app.web.csrf import portal_signing_secret

    reset_runtime_secrets_cache_for_tests()
    with pytest.raises(RuntimeError):
        portal_signing_secret(_settings(environment="production"))


def test_s7_runtime_secret_generated_distinct_and_persisted(db_session: Session):
    from app.runtime_secrets_service import (
        ensure_portal_runtime_secrets,
        get_cached_portal_signing_secret,
        get_db_portal_signing_secret,
        reset_runtime_secrets_cache_for_tests,
    )
    from app.web.csrf import portal_signing_secret

    reset_runtime_secrets_cache_for_tests()
    settings = _settings(environment="production")
    try:
        ensure_portal_runtime_secrets(db_session, settings, actor="pytest")
        stored = get_db_portal_signing_secret(db_session, settings)
        assert stored and stored != TOKEN
        assert get_cached_portal_signing_secret() == stored
        portal_signing_secret(settings)  # production now resolves
    finally:
        reset_runtime_secrets_cache_for_tests()


# --- S4 : hop cookie encrypted + host-bound; tokens never sent upstream ----


def test_s4_hop_cookie_does_not_expose_session_values():
    from app.robotic.session_cookie_hop import seal_session_hop_payload

    secret_value = "TARGET-SESSION-VALUE-123"
    token = seal_session_hop_payload(
        cookies={"sessionid": secret_value},
        target_url="https://app.example.com/",
        slug="demo",
        settings=_settings(),
        fqdn="app.example.com",
    )
    assert secret_value not in token
    for chunk in token.split("."):
        try:
            decoded = base64.urlsafe_b64decode(chunk + "=" * (-len(chunk) % 4))
        except ValueError:
            continue
        assert secret_value.encode() not in decoded


def test_s4_hop_cookie_bound_to_target_fqdn():
    from app.robotic.session_cookie_hop import seal_session_hop_payload, unseal_session_hop_payload

    settings = _settings()
    token = seal_session_hop_payload(
        cookies={"sessionid": "abc"},
        target_url="/",
        slug="demo",
        settings=settings,
        fqdn="app.example.com",
    )
    body, reason = unseal_session_hop_payload(token, settings, expected_host="other.example.com")
    assert body is None and reason == "wrong_host"
    body, reason = unseal_session_hop_payload(token, settings, expected_host="APP.example.com:443")
    assert reason == "" and body is not None


def test_s4_hop_endpoint_refuses_sibling_host(client: TestClient):
    from app.robotic.session_cookie_hop import HOP_COOKIE_NAME, seal_session_hop_payload

    live = _settings(
        vault_portal_internal_token="test-secret",
        session_hop_secret="test-session-hop-secret-for-pytest",
    )
    token = seal_session_hop_payload(
        cookies={"sessionid": "SIBLING01"},
        target_url="/",
        slug="demo",
        settings=live,
        fqdn="app.example.com",
    )
    resp = client.get(
        "/api/internal/session-cookie-hop",
        cookies={HOP_COOKIE_NAME: token},
        headers={"Host": "evil.example.com", "X-Forwarded-Host": "evil.example.com"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert not any("SIBLING01" in h for h in resp.headers.get_list("set-cookie"))


def _apply_nginx_cookie_maps(cookie: str) -> str:
    """Python replay of the nginx map chain (PCRE ≈ re for these patterns)."""
    text = (ROOT / "docker/nginx/includes/nginx-subdomain-auth.map.conf").read_text(
        encoding="utf-8"
    )
    block = text[text.index("$bastion_upck1") - 30 :]
    patterns = re.findall(r'"~(\^.*?\$)"\s+"([^"]*)";', block)
    assert len(patterns) >= 7
    value = cookie
    for pattern, _replacement in patterns:
        regex = re.compile(pattern.replace("\\\\", "\\").replace("(?<", "(?P<"))
        m = regex.match(value)
        if m:
            value = "".join(v or "" for v in m.groupdict().values())
    return value


@pytest.mark.parametrize(
    ("cookie", "expected"),
    [
        ("a=1; bastion_session=JWT; b=2", "a=1; b=2"),
        ("bastion_session=J1; x=1; bastion_session=J2; bg_session=B; bastion_session_hop=H", "x=1"),
        ("_oauth2_proxy=O; _oauth2_proxy_csrf=C; keep=1", "keep=1"),
        ("xbastion_session=keep; bastion_mfa_ok=M", "xbastion_session=keep"),
        ("sessionid=abc; csrftoken=xyz", "sessionid=abc; csrftoken=xyz"),
    ],
)
def test_s4_nginx_map_strips_portal_tokens(cookie, expected):
    assert _apply_nginx_cookie_maps(cookie) == expected


def test_s4_both_map_files_define_filtered_cookie():
    for rel in (
        "docker/nginx/includes/nginx-subdomain-auth.map.conf",
        "nginx/maps/nginx-subdomain-auth.map.conf",
    ):
        assert "$bastion_upstream_app_cookie" in (ROOT / rel).read_text(encoding="utf-8")


def _block(app: App) -> str:
    from app.bastion.nginx_subdomain_export import generate_subdomain_server_block

    return generate_subdomain_server_block(
        app, Settings(portal_domain="portal.example.com", exports_dir="data/test-exports")
    )


def test_s4_upstream_locations_never_forward_raw_cookie_header():
    app = App(
        slug="wiki",
        label="Wiki",
        upstream_url="https://10.0.0.5/",
        access_mode="subdomain_proxy",
        public_fqdn="wiki.example.com",
        allow_activesync=True,
        enabled=True,
    )
    conf = _block(app)
    raw_lines = [i for i, line in enumerate(conf.splitlines()) if "Cookie $http_cookie" in line]
    lines = conf.splitlines()
    for idx in raw_lines:
        # Only the /.bastion/* locations (proxied to the portal) keep it.
        opener = next(lines[j] for j in range(idx, -1, -1) if "location" in lines[j])
        assert "/.bastion/" in opener, opener
    assert conf.count("proxy_set_header Cookie $bastion_upstream_app_cookie;") >= 3


def test_s4_legacy_path_proxy_filters_cookie():
    from app.bastion.nginx_enforcement import proxy_location_lines

    app = App(
        slug="legacy",
        label="Legacy",
        upstream_url="http://10.0.0.7/",
        access_mode="legacy_path_proxy",
        enabled=True,
    )
    assert "    proxy_set_header Cookie $bastion_upstream_app_cookie;" in proxy_location_lines(app)


# --- S2 : anonymous ActiveSync path ------------------------------------------


@pytest.fixture()
def eas_app(db_session: Session) -> App:
    app = App(
        slug="mail",
        label="Mail",
        upstream_url="https://10.0.0.9/",
        access_mode="subdomain_proxy",
        public_fqdn="webmail.example.fr",
        allow_activesync=True,
        activesync_device_control=True,
        enabled=True,
    )
    db_session.add(app)
    db_session.commit()
    db_session.refresh(app)
    device_service.reset_notify_quota_for_tests()
    device_service.reset_sighting_cache()
    yield app
    device_service.reset_notify_quota_for_tests()
    device_service.reset_sighting_cache()


def _device(app: App, user_key: str, ip: str = "203.0.113.10", n: int = 0) -> ActiveSyncDevice:
    return ActiveSyncDevice(
        application_id=app.id,
        user_key=user_key,
        device_id=f"Dev{n:04d}",
        status=ACTIVESYNC_DEVICE_PENDING,
        source="observed",
        last_ip=ip,
        request_count=1,
    )


def test_s2_no_mail_to_unknown_address(db_session: Session, eas_app: App):
    sent: list[dict] = []
    device = _device(eas_app, "victim@elsewhere.example")
    with patch("app.mail.outbox.enqueue_mail", side_effect=lambda **k: sent.append(k)):
        device_service.maybe_notify_owner_new_pending(db_session, device=device, app=eas_app)
    assert sent == []


def _known_account(db: Session, email: str) -> None:
    from app.models import RealmConfig
    from app.secret_crypto import encrypt_secret

    s = _settings()
    realm = RealmConfig(
        slug="corp",
        name="CORP",
        issuer_url="https://kc.example/realms/corp",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("x", s),
        redirect_uri="https://portal.example.com/cb",
        oauth2_proxy_port=4180,
        enabled=True,
    )
    db.add(realm)
    db.commit()
    db.add(BastionAccount(realm_id=realm.id, username="bob", email=email, status="active", created_by="pytest"))
    db.commit()


def test_s2_known_account_mail_is_queued_and_rate_limited(db_session: Session, eas_app: App):
    _known_account(db_session, "Bob@Example.fr")
    sent: list[dict] = []
    with (
        patch("app.mail.outbox.enqueue_mail", side_effect=lambda **k: sent.append(k)),
        patch("app.mail.smtp_service.send_email", side_effect=AssertionError("SMTP inline")),
    ):
        for n in range(device_service.NOTIFY_MAX_PER_ADDRESS_PER_HOUR + 2):
            device_service.maybe_notify_owner_new_pending(
                db_session, device=_device(eas_app, "bob@example.fr", n=n), app=eas_app
            )
    assert len(sent) == device_service.NOTIFY_MAX_PER_ADDRESS_PER_HOUR
    assert sent[0]["to_email"] == "bob@example.fr"


def test_s2_mail_outbox_sends_off_request_thread():
    import threading

    from app.mail import outbox

    seen: list[threading.Thread] = []
    with patch.object(outbox, "_sender", lambda **_k: seen.append(threading.current_thread())):
        fut = outbox.enqueue_mail(to_email="a@b.c", subject="s", body_text="b")
        assert fut is not None
        fut.result(timeout=5)
    assert seen and seen[0] is not threading.current_thread()


def test_s2_pending_devices_capped_per_ip(db_session: Session, eas_app: App):
    for n in range(device_service.PENDING_MAX_PER_IP_PER_DAY):
        db_session.add(_device(eas_app, f"u{n}@x.example", n=n))
    db_session.commit()
    with pytest.raises(device_service.PendingDeviceCapExceeded):
        device_service._assert_pending_capacity(db_session, app=eas_app, client_ip="203.0.113.10")
    # Another source IP is not affected.
    device_service._assert_pending_capacity(db_session, app=eas_app, client_ip="198.51.100.7")


def test_s2_forged_basic_flood_is_denied_without_new_rows(
    client: TestClient, db_session: Session, eas_app: App
):
    for n in range(device_service.PENDING_MAX_PER_IP_PER_DAY):
        db_session.add(_device(eas_app, f"u{n}@x.example", n=n))
    db_session.commit()
    before = db_session.query(ActiveSyncDevice).count()
    token = base64.b64encode(b"spam-target@victim.example:anything").decode()
    resp = client.get(
        "/internal/activesync-auth",
        headers={
            "X-Original-Host": "webmail.example.fr",
            "X-Original-URI": "/Microsoft-Server-ActiveSync?Cmd=Sync&DeviceId=NewForged999&DeviceType=iPhone",
            "X-Original-Method": "POST",
            "X-Real-IP": "203.0.113.10",
            "User-Agent": "Apple-iPhone/1601.405",
            "Authorization": f"Basic {token}",
        },
    )
    assert resp.status_code == 403
    db_session.expire_all()
    assert db_session.query(ActiveSyncDevice).count() == before


def test_s2_activesync_locations_rate_limited():
    from app.bastion.nginx_waf_export import render_rate_limits_conf
    from app.models import WafProfile

    app = App(
        slug="mail",
        label="Mail",
        upstream_url="https://10.0.0.9/",
        access_mode="subdomain_proxy",
        public_fqdn="webmail.example.fr",
        allow_activesync=True,
        enabled=True,
    )
    conf = _block(app)
    assert conf.count("limit_req zone=activesync_auth") == 2
    assert "zone=activesync_auth" in render_rate_limits_conf(WafProfile())
    defaults = (ROOT / "docker/nginx/includes/nginx-portal-rate-limits.conf").read_text(
        encoding="utf-8"
    )
    assert "zone=activesync_auth" in defaults
