"""Nginx per-app access logs viewer (Admin → Logs → Accès apps)."""

from __future__ import annotations

from pathlib import Path

from app.models import App
from app.sso_settings import Settings

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="test",
        vault_portal_internal_token="test-secret",
        breakglass_jwt_secret="test-bg-jwt-secret",
        breakglass_jwt_secret_fallback_enabled=True,
        session_hop_secret="test-session-hop-secret-for-pytest",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
        portal_data_dir=str(tmp_path / "data"),
        nginx_app_logs_dir=str(tmp_path / "nginx-logs"),
    )


def test_app_access_logs_tab_lists_apps(client, db_session, tmp_path, monkeypatch):
    from app.main import app as fastapi_app
    from app.sso_settings import get_settings

    logs_dir = tmp_path / "nginx-logs"
    logs_dir.mkdir()
    (logs_dir / "overseerr.access.log").write_text(
        '1.2.3.4 - - [05/Aug/2026:14:00:00 +0000] host=overseerr.example.test '
        '"GET / HTTP/1.1" 200 42 "-" "curl/8" rt=0.01\n',
        encoding="utf-8",
    )
    db_session.add(
        App(
            slug="overseerr",
            label="Overseerr",
            access_mode="public_proxy",
            public_fqdn="overseerr.example.test",
            upstream_url="https://172.24.0.109",
            enabled=True,
        )
    )
    db_session.commit()

    def override_settings():
        return _settings(tmp_path)

    fastapi_app.dependency_overrides[get_settings] = override_settings
    try:
        page = client.get("/admin/logs", headers=ADMIN_HEADERS)
        assert page.status_code == 200
        assert 'id="tab-app-access"' in page.text
        assert "Accès apps" in page.text
        assert "overseerr" in page.text

        resp = client.get(
            "/admin/logs/apps/overseerr/access",
            headers=ADMIN_HEADERS,
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["slug"] == "overseerr"
        assert "GET /" in body["text"]
        assert "1.2.3.4" in body["text"]
        assert body["meta"]["exists"] is True
        assert body["meta"]["size_bytes"] > 0
    finally:
        # Restore client fixture override shape
        fastapi_app.dependency_overrides[get_settings] = lambda: Settings(
            environment="test",
            vault_portal_internal_token="test-secret",
            breakglass_jwt_secret="test-bg-jwt-secret",
            breakglass_jwt_secret_fallback_enabled=True,
            session_hop_secret="test-session-hop-secret-for-pytest",
            portal_secret_encryption_key="test-encryption-key-for-pytest-only",
            database_url="sqlite://",
        )


def test_app_access_logs_forbids_unknown_slug(client, db_session):
    resp = client.get(
        "/admin/logs/apps/not-a-real-app/access",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
    )
    assert resp.status_code == 403
    assert resp.json().get("detail") == "Forbidden"


def test_read_access_log_tail_units(tmp_path):
    from app.web.nginx_app_logs import read_access_log_tail, resolve_nginx_app_logs_dir

    s = _settings(tmp_path)
    root = resolve_nginx_app_logs_dir(s)
    root.mkdir(parents=True)
    path = root / "demo.access.log"
    path.write_text("line1\nline2\nline3\n", encoding="utf-8")
    text = read_access_log_tail(s, "demo", lines=2)
    assert "line2" in text
    assert "line3" in text
    assert "line1" not in text


def test_empty_access_log_message_diagnostics(tmp_path):
    from app.web.nginx_app_logs import describe_access_log, empty_access_log_message

    s = _settings(tmp_path)
    root = tmp_path / "nginx-logs"
    root.mkdir()
    (root / "other.access.log").write_text("x\n", encoding="utf-8")

    meta = describe_access_log(s, "overseerr")
    assert meta["exists"] is False
    assert meta["root_exists"] is True
    assert "other.access.log" in meta["sibling_access_logs"]
    msg = empty_access_log_message(s, "overseerr")
    assert "chemin:" in msg
    assert "other.access.log" in msg
    assert "astuce:" in msg
