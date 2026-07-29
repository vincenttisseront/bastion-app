"""Generic session cookie hop — host-only target cookies on app FQDN."""

from __future__ import annotations

from fastapi.responses import Response

from app.robotic.session_cookie_hop import (
    HOP_COOKIE_NAME,
    apply_host_only_session_cookies,
    attach_session_hop_portal_cookies,
    seal_session_hop_payload,
    session_hop_url,
    unseal_session_hop_payload,
)
from app.sso_settings import Settings


def _settings() -> Settings:
    return Settings(
        environment="test",
        vault_portal_internal_token="hop-test-secret",
        session_hop_secret="hop-hmac-secret-for-pytest",
        portal_domain="portal.ar-systems.fr",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
    )


def test_seal_unseal_roundtrip_any_cookies():
    settings = _settings()
    token = seal_session_hop_payload(
        cookies={"sessionid": "abc", "csrftoken": "xyz"},
        target_url="https://app.ar-systems.fr/",
        slug="demo",
        settings=settings,
    )
    body, reason = unseal_session_hop_payload(token, settings)
    assert reason == ""
    assert body is not None
    assert body["c"]["sessionid"] == "abc"
    assert body["c"]["csrftoken"] == "xyz"


def test_unseal_rejects_tampered_token():
    settings = _settings()
    token = seal_session_hop_payload(
        cookies={"sessionid": "abc"},
        target_url="/",
        slug="demo",
        settings=settings,
    )
    body, reason = unseal_session_hop_payload(token[:-4] + "dead", settings)
    assert body is None
    assert reason == "bad_signature"


def test_session_hop_url():
    assert session_hop_url("app.ar-systems.fr") == (
        "https://app.ar-systems.fr/.bastion/session-cookies"
    )


def test_attach_portal_hop_clears_parent_session_cookies():
    settings = _settings()
    response = Response()
    attach_session_hop_portal_cookies(
        response,
        cookies={"sessionid": "S1", "csrftoken": "T1"},
        target_url="https://app.ar-systems.fr/",
        slug="demo",
        fqdn="app.ar-systems.fr",
        settings=settings,
    )
    headers = response.headers.getlist("set-cookie")
    assert any(h.startswith(f"{HOP_COOKIE_NAME}=") for h in headers)
    assert any(
        h.startswith("sessionid=") and ("Max-Age=0" in h or "max-age=0" in h)
        for h in headers
    )


def test_apply_host_only_no_domain_on_session_cookies():
    response = Response()
    apply_host_only_session_cookies(
        response,
        {"sessionid": "HOSTONLY1"},
        shared_parent="ar-systems.fr",
    )
    headers = response.headers.getlist("set-cookie")
    session = [h for h in headers if "HOSTONLY1" in h]
    assert session
    assert not any("Domain=" in h or "domain=" in h for h in session)


def test_session_cookie_hop_endpoint_sets_host_only(client):
    live = Settings(
        environment="test",
        vault_portal_internal_token="test-secret",
        session_hop_secret="test-session-hop-secret-for-pytest",
        portal_domain="portal.ar-systems.fr",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
    )
    token = seal_session_hop_payload(
        cookies={"sessionid": "ENDPOINT99"},
        target_url="/dashboard",
        slug="demo",
        settings=live,
    )
    resp = client.get(
        "/api/internal/session-cookie-hop",
        cookies={HOP_COOKIE_NAME: token},
        headers={"Host": "app.ar-systems.fr", "X-Forwarded-Host": "app.ar-systems.fr"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "https://app.ar-systems.fr/dashboard"
    set_cookies = resp.headers.get_list("set-cookie")
    host_only = [h for h in set_cookies if "ENDPOINT99" in h]
    assert host_only
    assert not any("Domain=" in h or "domain=" in h for h in host_only)


def test_session_cookie_hop_rejected_goes_to_portal_apps(client):
    resp = client.get(
        "/api/internal/session-cookie-hop",
        headers={
            "Host": "portal.ar-systems.fr",
            "X-Forwarded-Host": "grommunio.ar-systems.fr",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    loc = resp.headers["location"]
    assert loc == "/apps" or loc.endswith("/apps")


def test_legacy_crush_hop_alias_still_works(client):
    live = Settings(
        environment="test",
        vault_portal_internal_token="test-secret",
        session_hop_secret="test-session-hop-secret-for-pytest",
        portal_domain="portal.ar-systems.fr",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
    )
    token = seal_session_hop_payload(
        cookies={"CrushAuth": "LEGACYCOOKIE01", "currentAuth": "01"},
        target_url="/WebInterface/new-ui/index.html",
        slug="transfer",
        settings=live,
    )
    resp = client.get(
        "/api/internal/crush-cookie-hop",
        cookies={HOP_COOKIE_NAME: token},
        headers={
            "Host": "transfer.ar-systems.fr",
            "X-Forwarded-Host": "transfer.ar-systems.fr",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == (
        "https://transfer.ar-systems.fr/WebInterface/new-ui/index.html"
    )
    assert any("LEGACYCOOKIE01" in h for h in resp.headers.get_list("set-cookie"))
