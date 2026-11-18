"""External Ollama connection (URL, token, TLS) and automatic WAF threat analysis."""

from __future__ import annotations

import json
from datetime import timedelta

import httpx
import pytest
from sqlalchemy.orm import Session

import app.llm.client as client_mod
import app.llm.service as service_mod
from app.llm.client import LlmClient, LlmConfig, _short_error
from app.models import AuditLog, LlmInsight, PortalSettings, SecurityBan, utcnow
from app.portal_settings_service import ensure_portal_settings
from app.sso_settings import Settings, get_settings
from tests.conftest import csrf_token_for

ADMIN = {"X-Email": "admin@example.com", "X-Groups": "portal-admins"}


def _settings(**extra) -> Settings:
    base = {"environment": "test", "portal_secret_encryption_key": "test-encryption-key-for-pytest-only"}
    base.update(extra)
    return Settings(**base)


@pytest.fixture(autouse=True)
def _fresh_clients():
    client_mod.reset_llm_clients()
    yield
    client_mod.reset_llm_clients()


class Server:
    """Fake Ollama: /api/tags + /api/chat, records requests."""

    def __init__(self, models=("qwen3:14b", "llama3.1:8b"), answer=None, status=200):
        self.models = list(models)
        self.answer = answer
        self.status = status
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.status != 200:
            return httpx.Response(self.status, text="nope")
        if request.url.path.endswith("/api/tags"):
            return httpx.Response(200, json={"models": [{"name": m} for m in self.models]})
        body = json.loads(request.content)
        answer = self.answer(body) if callable(self.answer) else self.answer
        return httpx.Response(200, json={"message": {"content": json.dumps(answer)}})


def _route_through(monkeypatch, server: Server) -> None:
    """Every client built from a config talks to the fake server (config kept)."""
    cache: dict[LlmConfig, LlmClient] = {}

    def fake_client_for(config: LlmConfig) -> LlmClient:
        if config not in cache:
            cache[config] = LlmClient(config, transport=httpx.MockTransport(server))
        return cache[config]

    monkeypatch.setattr(service_mod, "client_for", fake_client_for)


def _client_settings(client) -> Settings:
    return client.app.dependency_overrides[get_settings]()


# ── URL validation & config ────────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("10.0.0.20:11434", "http://10.0.0.20:11434"),
        ("https://ollama.example.com:11434/", "https://ollama.example.com:11434"),
        ("https://gw.example.com/ollama/api", "https://gw.example.com/ollama"),
        ("http://[2001:db8::1]:11434", "http://[2001:db8::1]:11434"),
    ],
)
def test_base_url_normalised(raw, expected):
    assert service_mod.validate_base_url(raw) == expected


@pytest.mark.parametrize(
    "raw",
    ["", "ftp://x", "https://user:pw@ollama.example.com", "https://h/?a=1", "https://h/a/../b",
     "https://h:99999"],
)
def test_base_url_rejected(raw):
    with pytest.raises(ValueError):
        service_mod.validate_base_url(raw)


def test_effective_config_uses_db_connection(db_session):
    settings = _settings()
    row = ensure_portal_settings(db_session, settings)
    service_mod.save_llm_connection(
        db_session, settings, actor="a", base_url="https://ollama.lab:11434",
        api_token="tok-123", tls_verify=False,
    )
    assert row.llm_api_token_encrypted and "tok-123" not in row.llm_api_token_encrypted
    cfg = service_mod.effective_config(settings, row)
    assert cfg.url == "https://ollama.lab:11434"
    assert cfg.api_token == "tok-123" and cfg.verify_tls is False
    assert cfg.model == ""  # remote server: no model until one is chosen
    assert "tok-123" not in repr(cfg)
    audit = db_session.query(AuditLog).filter_by(action="portal_settings.llm_connection").one()
    assert audit.event_code == "BST-ADM-1041"
    assert "tok-123" not in json.dumps(audit.details)


def test_http_client_sends_token_and_tls_choice(monkeypatch):
    captured = {}

    class Spy:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(client_mod.httpx, "AsyncClient", Spy)
    LlmClient(LlmConfig(url="https://o", api_token="t0k", verify_tls=False))._http(5.0)
    assert captured["headers"]["Authorization"] == "Bearer t0k"
    assert captured["verify"] is False
    assert captured["trust_env"] is False and captured["follow_redirects"] is False


def test_friendly_errors():
    req = httpx.Request("GET", "https://o/api/tags")
    tls = httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] self-signed certificate", request=req)
    assert "auto-signé" in _short_error(tls)
    resp = httpx.Response(401, request=req)
    assert "jeton" in _short_error(httpx.HTTPStatusError("x", request=req, response=resp))


# ── admin flow: connect → list models → choose → enable ───────────────────


def test_connection_flow(client, db_engine, monkeypatch):
    server = Server()
    _route_through(monkeypatch, server)
    r = client.post(
        "/admin/configuration/llm/connection",
        data={"llm_base_url": "ollama.lab:11434", "llm_api_token": "secret-tok",
              "csrf_token": csrf_token_for(client)},  # TLS box unticked
        headers=ADMIN, follow_redirects=False,
    )
    assert r.status_code == 302 and r.headers["location"].endswith("#llm")
    assert server.requests[0].headers["authorization"] == "Bearer secret-tok"
    assert str(server.requests[0].url) == "http://ollama.lab:11434/api/tags"
    with Session(db_engine) as db:
        row = db.get(PortalSettings, 1)
        assert row.llm_base_url == "http://ollama.lab:11434"
        assert row.llm_tls_verify is False
        assert row.llm_models_json == ["llama3.1:8b", "qwen3:14b"]
        assert row.llm_last_probe_ok is True
        probe = db.query(AuditLog).filter_by(action="llm.probe").one()
        assert "secret-tok" not in json.dumps(probe.details)

    page = client.get("/admin/configuration", headers=ADMIN)
    assert '<option value="qwen3:14b"' in page.text
    assert "Le jeton circule en clair" in page.text  # token over http:// warning

    # Unknown model refused, known model accepted, then enabled.
    bad = client.post("/admin/configuration/llm", data={"llm_model": "gpt-4", "llm_enabled": "on"},
                      headers=ADMIN, follow_redirects=False)
    assert bad.status_code == 302
    with Session(db_engine) as db:
        assert db.get(PortalSettings, 1).llm_enabled is False
    ok = client.post("/admin/configuration/llm",
                     data={"llm_model": "qwen3:14b", "llm_enabled": "on", "llm_waf_auto_enabled": "on"},
                     headers=ADMIN, follow_redirects=False)
    assert ok.status_code == 302
    with Session(db_engine) as db:
        row = db.get(PortalSettings, 1)
        assert row.llm_enabled is True and row.llm_model == "qwen3:14b" and row.llm_waf_auto_enabled


def test_enable_without_model_refused(db_session):
    settings = _settings()
    service_mod.save_llm_connection(db_session, settings, actor="a", base_url="https://o.lab")
    with pytest.raises(ValueError):
        service_mod.update_llm_settings(db_session, settings, actor="a", enabled=True, model="")


def test_failed_connection_is_reported(client, db_engine, monkeypatch):
    _route_through(monkeypatch, Server(status=401))
    client.post("/admin/configuration/llm/connection",
                data={"llm_base_url": "https://ollama.lab", "llm_tls_verify": "on"},
                headers=ADMIN, follow_redirects=False)
    with Session(db_engine) as db:
        row = db.get(PortalSettings, 1)
        assert row.llm_last_probe_ok is False and "jeton" in row.llm_last_probe_error
        assert row.llm_models_json is None
    page = client.get("/admin/configuration", headers=ADMIN)
    assert 'id="llm-last-probe"' in page.text and "Dernier test en échec" in page.text


def test_changing_server_resets_model(db_session):
    settings = _settings()
    row = ensure_portal_settings(db_session, settings)
    service_mod.save_llm_connection(db_session, settings, actor="a", base_url="https://a.lab")
    row.llm_models_json = ["qwen3:14b"]
    row.llm_model = "qwen3:14b"
    db_session.commit()
    service_mod.save_llm_connection(db_session, settings, actor="a", base_url="https://b.lab")
    assert row.llm_model is None and row.llm_models_json is None


def test_kill_switch_blocks_everything(db_session):
    killed = _settings(llm_enabled=False)
    row = ensure_portal_settings(db_session, killed)
    row.llm_enabled = True
    db_session.commit()
    assert service_mod.llm_enabled(killed, db_session) is False
    assert service_mod.llm_enabled(_settings(), db_session) is True  # unset = admin toggle


# ── automatic WAF threat analysis ──────────────────────────────────────────


def _events(now):
    sqli = [{
        "timestamp": (now - timedelta(minutes=i)).isoformat(), "client_ip": "203.0.113.9",
        "host": "shop.example.fr", "uri": f"/api/orders?id=1%27%20OR%201=1--&token=abc{i}",
        "rule_id": "942100", "all_rule_ids": ["942100", "949110"], "score": 10, "blocked": True,
        "critical": True, "message": "SQL Injection Attack Detected via libinjection",
        "families": ["sqli"], "matched_scope_kind": "args", "matched_target_name": "id",
    } for i in range(6)]
    internal = [{
        "timestamp": (now - timedelta(minutes=2)).isoformat(), "client_ip": "10.0.0.5",
        "host": "wiki.example.fr", "uri": "/search?q=select", "rule_id": "942100",
        "all_rule_ids": ["942100"], "score": 5, "blocked": False, "critical": False,
        "message": "SQLi", "families": ["sqli"],
    }]
    return sqli + internal


def _answer(body):
    return {"threats": [
        {"client_ip": "203.0.113.9", "category": "injection_sql", "severity": "critique",
         "confidence": "elevee", "summary": "Injection SQL répétée sur id", "evidence": ["942100 x6"],
         "recommended_action": "bannir_temporairement", "ban_minutes": 720},
        {"client_ip": "10.0.0.5", "category": "faux_positif", "severity": "elevee",
         "confidence": "moyenne", "summary": "Recherche interne", "evidence": [],
         "recommended_action": "bannir_temporairement", "ban_minutes": 60},
        {"client_ip": "198.51.100.66", "category": "autre", "severity": "critique",
         "confidence": "elevee", "summary": "inventé", "evidence": [],
         "recommended_action": "bannir_temporairement", "ban_minutes": 60},
    ]}


@pytest.fixture
def waf_on(db_session, monkeypatch):
    settings = _settings(llm_model="qwen3:14b")
    row = ensure_portal_settings(db_session, settings)
    row.llm_enabled = True
    db_session.commit()
    state = {"recent_events": _events(utcnow())}
    monkeypatch.setattr(
        "app.bastion.modsec_audit_aggregator.read_aggregator_state", lambda s: state
    )
    server = Server(answer=_answer)
    _route_through(monkeypatch, server)
    return settings, row, server, state


async def test_waf_threats_classified_and_bounded(db_session, waf_on):
    from app.llm.features.waf_threats import analyse_waf_threats

    settings, row, server, _ = waf_on
    stored = await analyse_waf_threats(db_session, settings)
    by_ip = {i.subject_id: i for i in stored}
    assert set(by_ip) == {"203.0.113.9", "10.0.0.5"}  # invented IP dropped
    public = by_ip["203.0.113.9"]
    assert public.status == "proposed" and public.payload["proposed_ban"]["ban_minutes"] == 720
    assert public.payload["category"] == "injection_sql"
    assert by_ip["10.0.0.5"].status == "info"  # private IP: never a ban proposal
    assert "proposed_ban" not in by_ip["10.0.0.5"].payload
    sent = server.requests[-1].content.decode()
    assert "abc0" not in sent  # token=… in URIs is redacted before sending
    assert db_session.query(SecurityBan).count() == 0  # nothing applied
    assert row.llm_waf_last_event_at is not None


async def test_waf_threats_cursor_avoids_reanalysis(db_session, waf_on):
    from app.llm.features.waf_threats import analyse_waf_threats

    settings, _, server, _ = waf_on
    await analyse_waf_threats(db_session, settings)
    calls = len(server.requests)
    assert await analyse_waf_threats(db_session, settings) == []
    assert len(server.requests) == calls  # no new events → no call


async def test_waf_threats_respect_auto_toggle_and_bans(db_session, waf_on):
    from app.llm.features.waf_threats import analyse_waf_threats

    settings, row, server, _ = waf_on
    row.llm_waf_auto_enabled = False
    db_session.commit()
    assert await analyse_waf_threats(db_session, settings) == []
    assert server.requests == []
    db_session.add(SecurityBan(target_type="ip", target="203.0.113.9", reason="x", permanent=True))
    db_session.commit()
    stored = await analyse_waf_threats(db_session, settings, force=True)  # manual button
    public = next(i for i in stored if i.subject_id == "203.0.113.9")
    assert public.status == "info"  # already banned: no new proposal


def test_waf_page_shows_threats_and_ban_flow(client, db_engine):
    base = _client_settings(client).model_copy(update={"llm_model": "qwen3:14b"})
    client.app.dependency_overrides[get_settings] = lambda: base
    with Session(db_engine) as db:
        row = ensure_portal_settings(db, base)
        row.llm_enabled = True
        db.add(LlmInsight(kind="waf_threat", subject_type="ip", subject_id="203.0.113.9",
                          status="accepted", payload={
                              "summary": "SQLi <b>x</b>", "category": "injection_sql",
                              "severity": "critique", "confidence": "elevee", "evidence": [],
                              "stats": {"evenements": 6, "bloques": 6},
                              "proposed_ban": {"ip": "203.0.113.9", "ban_minutes": 720,
                                               "reason": "IA (validé) — injection_sql"}}))
        db.commit()
    page = client.get("/admin/security/waf", headers=ADMIN)
    assert page.status_code == 200
    assert 'id="llm-threats"' in page.text
    assert "SQLi &lt;b&gt;x&lt;/b&gt;" in page.text
    assert 'action="/admin/security/waf/actions/ban-ip"' in page.text and "Bannir maintenant" in page.text


def test_waf_threats_route_off_redirects(client):
    r = client.post("/admin/assistant/waf/threats", headers=ADMIN, follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/admin/security/waf#llm-threats"
