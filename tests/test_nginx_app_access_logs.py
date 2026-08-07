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
        '"GET / HTTP/1.1" 200 42 "-" "curl/8" '
        "rt=0.01 upstream=172.24.0.109:443 us=200 ut=0.01 auth_err=-\n",
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
        assert 'id="app-access-table"' in page.text

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
        assert isinstance(body["entries"], list)
        assert body["entries"]
        assert body["entries"][0]["ecosystem"] == "nginx_access"
        assert body["entries"][0]["method"] == "GET"
        assert body.get("message") in (None, "")
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


def test_parse_app_access_line_nominal():
    from app.web.nginx_app_logs import parse_app_access_line, parse_app_access_text

    line = (
        "92.184.121.16 - - [05/Aug/2026:15:20:07 +0000] host=overseerr.ar-systems.fr "
        '"GET /api/v1/status?checkUpdateAvailable=true HTTP/1.1" 200 140 '
        '"https://overseerr.ar-systems.fr/" '
        '"Mozilla/5.0 (iPhone)" '
        "rt=0.023 upstream=172.24.0.109:443 us=200 ut=0.023 auth_err=-"
    )
    e = parse_app_access_line(line, index=3)
    assert e is not None
    assert e["parse_ok"] is True
    assert e["ecosystem"] == "nginx_access"
    assert e["remote_addr"] == "92.184.121.16"
    assert e["host"] == "overseerr.ar-systems.fr"
    assert e["method"] == "GET"
    assert e["path"].startswith("/api/v1/status")
    assert e["status"] == "200"
    assert e["status_class"] == "ok"
    assert e["upstream_addr"] == "172.24.0.109:443"
    assert e["is_internal_hop"] is False

    internal = parse_app_access_line(
        line.replace("upstream=172.24.0.109:443", "upstream=127.0.0.1:8080")
    )
    assert internal["is_internal_hop"] is True

    text = line + "\n" + line.replace("172.24.0.109:443", "127.0.0.1:8080") + "\n"
    entries = parse_app_access_text(text)
    assert len(entries) == 2


def test_parse_app_access_activesync_user_and_empty_auth_err():
    """ActiveSync: remote_user may include spaces + \\x5C; auth_err may be empty."""
    from app.web.nginx_app_logs import parse_app_access_line

    line = (
        r"92.184.121.16 - ar-systems.fr\x5Cvincent.tisseront@ar-systems.fr "
        "[05/Aug/2026:15:36:10 +0000] host=webmail.ar-systems.fr "
        '"POST /Microsoft-Server-ActiveSync?User=vincent.tisseront@ar-systems.fr'
        '&DeviceID=FBJV9GQU3D7890K74K10V5IC5K&DeviceType=iPhone&Cmd=Sync HTTP/1.1" '
        '200 0 "-" "Apple-iPhone13C4/2306.84" '
        "rt=0.760 upstream=172.24.10.104:443 us=200 ut=0.322 auth_err="
    )
    e = parse_app_access_line(line)
    assert e is not None
    assert e["parse_ok"] is True
    assert e["remote_addr"] == "92.184.121.16"
    assert e["remote_user"] == r"ar-systems.fr\vincent.tisseront@ar-systems.fr"
    assert e["host"] == "webmail.ar-systems.fr"
    assert e["method"] == "POST"
    assert e["path"].startswith("/Microsoft-Server-ActiveSync")
    assert e["status"] == "200"
    assert e["upstream_addr"] == "172.24.10.104:443"
    assert e["auth_err"] == ""

    with_email = (
        "127.0.0.1 - - [07/Aug/2026:08:02:01 +0000] host=wikijs.ar-systems.fr "
        '"GET / HTTP/1.1" 304 0 "-" '
        '"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0" '
        "rt=0.090 upstream=10.0.31.112:443 us=304 ut=0.058 "
        "auth_err= auth_email=vincent.tisseront@ar-systems.fr"
    )
    e_email = parse_app_access_line(with_email)
    assert e_email is not None
    assert e_email["parse_ok"] is True
    assert e_email["status"] == "304"
    assert e_email["auth_err"] == ""
    assert e_email["auth_email"] == "vincent.tisseront@ar-systems.fr"
    assert e_email["upstream_addr"] == "10.0.31.112:443"

    spaced = (
        r"172.24.1.230 - A.R. Systems\x5Ccherve.tisseront@ar-systems.fr "
        "[05/Aug/2026:15:36:10 +0000] host=webmail.ar-systems.fr "
        '"POST /Microsoft-Server-ActiveSync?Cmd=Sync HTTP/1.1" 200 0 "-" "Apple" '
        "rt=0.1 upstream=172.24.10.104:443 us=200 ut=0.1 auth_err="
    )
    e2 = parse_app_access_line(spaced)
    assert e2 is not None
    assert e2["parse_ok"] is True
    assert e2["remote_user"] == r"A.R. Systems\cherve.tisseront@ar-systems.fr"
    assert e2["method"] == "POST"
