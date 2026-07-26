"""ContainerLogsSettings: DB config for /admin/logs Containers tab."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import AuditLog, ContainerLogsSettings
from app.web.container_logs_settings import (
    ContainerLogsConfig,
    ensure_container_logs_settings,
    get_container_logs_config,
    seed_values_from_environ,
    update_container_logs_settings,
)
from app.web.docker_logs import assert_container_allowed

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}


def test_seed_from_env_enables_when_proxy_set():
    seed = seed_values_from_environ(
        {
            "DOCKER_LOGS_PROXY_URL": "http://docker-proxy:2375",
            "DOCKER_LOGS_WHITELIST": "bastion-app,nginx",
            "DOCKER_LOGS_TAIL_LINES": "150",
        }
    )
    assert seed["enabled"] is True
    assert seed["proxy_url"] == "http://docker-proxy:2375"
    assert seed["allowed_containers"] == ["bastion-app", "nginx"]
    assert seed["tail_lines"] == 150


def test_seed_from_env_disabled_without_proxy():
    seed = seed_values_from_environ({})
    assert seed["enabled"] is False
    assert seed["proxy_url"] == ""
    assert "bastion-app" in seed["allowed_containers"]


def test_ensure_defaults_disabled(db_session: Session, monkeypatch):
    monkeypatch.delenv("DOCKER_LOGS_PROXY_URL", raising=False)
    row = ensure_container_logs_settings(db_session)
    assert row.id == 1
    assert row.enabled is False
    assert row.proxy_url == ""


def test_admin_security_save_takes_effect_immediately(
    client: TestClient, db_session: Session
):
    page = client.get("/admin/security", headers=ADMIN_HEADERS)
    assert page.status_code == 200
    assert 'id="tab-container-logs"' in page.text

    resp = client.post(
        "/admin/security/container-logs",
        headers=ADMIN_HEADERS,
        data={
            "enabled": "on",
            "proxy_url": "http://docker-proxy.test:2375",
            "tail_lines": "200",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "#container-logs" in (resp.headers.get("location") or "")

    add = client.post(
        "/admin/security/container-logs/containers/add",
        headers=ADMIN_HEADERS,
        data={"name": "bastion-app"},
        follow_redirects=False,
    )
    assert add.status_code == 302

    cfg = get_container_logs_config(db_session)
    assert cfg.active is True
    assert cfg.proxy_url == "http://docker-proxy.test:2375"
    assert "bastion-app" in cfg.allowed_containers

    logs = client.get("/admin/logs", headers=ADMIN_HEADERS)
    assert logs.status_code == 200
    assert 'id="container-select"' in logs.text
    assert "Logs containers désactivés" not in logs.text

    db_session.expire_all()
    audit = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "security.container_logs_settings.updated")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None


def test_whitelist_403_uses_db_config(client: TestClient, db_session: Session):
    update_container_logs_settings(
        db_session,
        enabled=True,
        proxy_url="http://docker-proxy.test:2375",
        actor="admin@example.com",
    )
    from app.web.container_logs_settings import add_allowed_container

    add_allowed_container(db_session, "nginx", actor="admin@example.com")

    page = client.get("/admin/logs", headers=ADMIN_HEADERS)
    assert 'value="nginx"' in page.text
    assert 'value="secret-db"' not in page.text

    denied = client.get(
        "/admin/logs/containers/secret-db/logs",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
    )
    assert denied.status_code == 403


def test_assert_container_allowed_casefold():
    cfg = ContainerLogsConfig(
        enabled=True,
        proxy_url="http://x",
        allowed_containers=["bastion-app", "nginx"],
        tail_lines=200,
    )
    assert assert_container_allowed("Bastion-App", cfg) == "bastion-app"
    import pytest

    with pytest.raises(Exception) as exc:
        assert_container_allowed("other", cfg)
    assert getattr(exc.value, "status_code", None) == 403


def test_logs_disabled_message_points_to_security(client: TestClient, db_session: Session):
    ensure_container_logs_settings(db_session)
    row = db_session.query(ContainerLogsSettings).filter_by(id=1).one()
    row.enabled = False
    row.proxy_url = ""
    db_session.commit()

    page = client.get("/admin/logs", headers=ADMIN_HEADERS)
    assert page.status_code == 200
    assert "/admin/security#container-logs" in page.text
    assert "DOCKER_LOGS_PROXY_URL" not in page.text
