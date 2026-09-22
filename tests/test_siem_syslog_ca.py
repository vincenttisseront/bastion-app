"""Syslog TLS CA validation, atomic store, and worker safety invariants."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.siem import syslog_ca as ca
from app.sso_settings import Settings, get_settings


def _settings(tmp_path: Path) -> Settings:
    get_settings.cache_clear()
    return Settings(
        portal_domain="portal.example.com",
        sso_portal_default_realm_slug="default",
        exports_dir=str(tmp_path / "exports"),
        portal_data_dir=str(tmp_path / "data"),
        vault_portal_internal_token="test-secret",
    )  # type: ignore[call-arg]


def _build_ca(
    *,
    cn: str = "Example Syslog CA",
    days_valid: int = 365,
    days_ago_start: int = 1,
    is_ca: bool = True,
) -> tuple[bytes, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=days_ago_start))
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None),
            critical=True,
        )
    )
    if is_ca:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    cert = builder.sign(key, hashes.SHA256())
    pem = cert.public_bytes(serialization.Encoding.PEM)
    fp = ca.parse_and_validate_ca_pem(pem).fingerprint_sha256 if is_ca and days_valid > 0 and days_ago_start >= 0 else ""
    if is_ca and days_valid > 0 and days_ago_start >= 0:
        # not yet valid case uses days_ago_start negative via caller
        pass
    try:
        info = ca.parse_and_validate_ca_pem(pem)
        fp = info.fingerprint_sha256
    except ca.SyslogCaError:
        fp = ""
    return pem, fp


def _build_ca_unchecked(
    *,
    cn: str = "Example Syslog CA",
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    is_ca: bool = True,
) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    nb = not_before or (now - timedelta(days=1))
    na = not_after or (now + timedelta(days=365))
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None),
            critical=True,
        )
    )
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM)


def _private_key_pem() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def test_parse_valid_ca_extracts_subject_issuer_fingerprint():
    pem, _ = _build_ca(cn="Example Syslog CA")
    info = ca.parse_and_validate_ca_pem(pem)
    assert "CN=Example Syslog CA" in info.subject
    assert "CN=Example Syslog CA" in info.issuer
    assert info.basic_constraints_ca is True
    assert len(info.fingerprint_sha256.replace(":", "")) == 64
    assert b"BEGIN CERTIFICATE" in info.pem_bytes


def test_reject_empty_file():
    with pytest.raises(ca.SyslogCaError, match="vide"):
        ca.parse_and_validate_ca_pem(b"")


def test_reject_private_key():
    pem = _private_key_pem()
    with pytest.raises(ca.SyslogCaError, match="clé privée"):
        ca.parse_and_validate_ca_pem(pem)


def test_reject_bundle_with_private_key():
    pem, _ = _build_ca()
    blob = pem + b"\n" + _private_key_pem()
    with pytest.raises(ca.SyslogCaError, match="clé privée"):
        ca.parse_and_validate_ca_pem(blob)


def test_reject_non_ca_certificate():
    pem = _build_ca_unchecked(cn="Leaf Host", is_ca=False)
    with pytest.raises(ca.SyslogCaError, match="non-CA"):
        ca.parse_and_validate_ca_pem(pem)


def test_reject_expired_ca():
    now = datetime.now(timezone.utc)
    pem = _build_ca_unchecked(
        not_before=now - timedelta(days=30),
        not_after=now - timedelta(days=1),
    )
    with pytest.raises(ca.SyslogCaError, match="expiré"):
        ca.parse_and_validate_ca_pem(pem)


def test_reject_not_yet_valid_ca():
    now = datetime.now(timezone.utc)
    pem = _build_ca_unchecked(
        not_before=now + timedelta(days=1),
        not_after=now + timedelta(days=30),
    )
    with pytest.raises(ca.SyslogCaError, match="pas encore valide"):
        ca.parse_and_validate_ca_pem(pem)


def test_reject_oversized():
    with pytest.raises(ca.SyslogCaError, match="volumineux"):
        ca.parse_and_validate_ca_pem(b"X" * (ca.MAX_CA_BYTES + 1))


def test_path_traversal_rejected(tmp_path):
    settings = _settings(tmp_path)
    with pytest.raises(ca.SyslogCaError):
        ca.resolve_ca_path(settings, relative_path="../etc/passwd.pem")
    with pytest.raises(ca.SyslogCaError):
        ca.normalize_relative_path("/abs/certs/siem/syslog-collector-ca.pem")


def test_resolve_uses_portal_data_dir_only(tmp_path):
    settings = _settings(tmp_path)
    path = ca.resolve_ca_path(settings, relative_path=ca.DEFAULT_RELATIVE_PATH)
    assert path == (tmp_path / "data" / ca.DEFAULT_RELATIVE_PATH).resolve()
    assert path.name == ca.ACTIVE_BASENAME


def test_atomic_commit_and_fingerprint(tmp_path):
    settings = _settings(tmp_path)
    active = ca.resolve_ca_path(settings)
    pem, fp = _build_ca(cn="Example Syslog CA")
    ca.write_staging_ca(active, pem)
    assert ca.staging_path_for(active).is_file()
    assert not active.is_file()
    ca.commit_staging_to_active(active, expected_fingerprint=fp)
    assert active.is_file()
    assert not ca.staging_path_for(active).is_file()
    info = ca.read_ca_file_info(active)
    assert info.fingerprint_sha256 == fp


def test_worker_must_not_read_staging(tmp_path):
    settings = _settings(tmp_path)
    active = ca.resolve_ca_path(settings)
    pem, _ = _build_ca()
    staging = ca.write_staging_ca(active, pem)
    with pytest.raises(ca.SyslogCaError, match="actif"):
        ca.read_ca_file_info(staging)


def test_invalid_ca_never_replaces_active(tmp_path):
    settings = _settings(tmp_path)
    active = ca.resolve_ca_path(settings)
    good_pem, good_fp = _build_ca(cn="Good CA")
    ca.write_staging_ca(active, good_pem)
    ca.commit_staging_to_active(active, expected_fingerprint=good_fp)

    bad = _build_ca_unchecked(cn="Leaf", is_ca=False)
    with pytest.raises(ca.SyslogCaError, match="non-CA"):
        ca.parse_and_validate_ca_pem(bad)

    # Bypass validation and attempt commit of invalid staging — must restore good CA.
    ca.write_staging_ca(active, bad)
    with pytest.raises(ca.SyslogCaError):
        ca.commit_staging_to_active(
            active, expected_fingerprint="00:" * 31 + "00"
        )
    assert ca.read_ca_file_info(active).fingerprint_sha256 == good_fp


def test_probe_failure_discards_staging_keeps_active(tmp_path):
    settings = _settings(tmp_path)
    active = ca.resolve_ca_path(settings)
    good_pem, good_fp = _build_ca(cn="Good CA")
    ca.write_staging_ca(active, good_pem)
    ca.commit_staging_to_active(active, expected_fingerprint=good_fp)

    new_pem, new_fp = _build_ca(cn="Other CA")
    staging = ca.write_staging_ca(active, new_pem)

    def boom():
        raise TimeoutError("timeout")

    with pytest.raises(ca.SyslogCaError, match="délai"):
        ca.probe_tls_handshake(
            host="10.0.0.10",
            port=6514,
            cafile=staging,
            sock_factory=boom,
        )
    ca.discard_staging(active)
    assert ca.read_ca_file_info(active).fingerprint_sha256 == good_fp
    assert not staging.is_file()


def test_rollback_after_failed_fingerprint(tmp_path):
    settings = _settings(tmp_path)
    active = ca.resolve_ca_path(settings)
    good_pem, good_fp = _build_ca(cn="Good CA")
    ca.write_staging_ca(active, good_pem)
    ca.commit_staging_to_active(active, expected_fingerprint=good_fp)

    other_pem, _ = _build_ca(cn="Other CA")
    ca.write_staging_ca(active, other_pem)
    with pytest.raises(ca.SyslogCaError, match="empreinte"):
        ca.commit_staging_to_active(active, expected_fingerprint="00:" * 31 + "00")
    assert ca.read_ca_file_info(active).fingerprint_sha256 == good_fp


def test_audit_details_never_include_pem():
    pem, _ = _build_ca()
    info = ca.parse_and_validate_ca_pem(pem)
    details = ca.audit_safe_ca_details(info, result="ok", pem=pem.decode())
    assert "pem" not in details
    assert "BEGIN CERTIFICATE" not in str(details)
    assert details["destination"] == "syslog_tls"
    assert details["subject"]


def test_derive_status_from_file_not_db_flag(tmp_path):
    settings = _settings(tmp_path)
    st = ca.derive_ca_status(settings, relative_path=ca.DEFAULT_RELATIVE_PATH)
    assert st["configured"] is False
    assert st["badge"] == "missing"

    pem, _ = _build_ca()
    active = ca.resolve_ca_path(settings)
    ca.write_staging_ca(active, pem)
    info = ca.parse_and_validate_ca_pem(pem)
    ca.commit_staging_to_active(active, expected_fingerprint=info.fingerprint_sha256)
    st2 = ca.derive_ca_status(settings, relative_path=ca.DEFAULT_RELATIVE_PATH)
    assert st2["configured"] is True
    assert st2["valid"] is True
    assert "CN=Example Syslog CA" in st2["subject"]


def test_ssl_context_rejects_unknown_basename(tmp_path):
    settings = _settings(tmp_path)
    active = ca.resolve_ca_path(settings)
    pem, _ = _build_ca()
    weird = active.parent / "evil.pem"
    weird.parent.mkdir(parents=True, exist_ok=True)
    weird.write_bytes(pem)
    with pytest.raises(ca.SyslogCaError, match="non autorisé"):
        ca.build_ssl_context_for_cafile(weird)


def test_two_idempotent_commits(tmp_path):
    settings = _settings(tmp_path)
    active = ca.resolve_ca_path(settings)
    pem, fp = _build_ca()
    for _ in range(2):
        ca.write_staging_ca(active, pem)
        ca.commit_staging_to_active(active, expected_fingerprint=fp)
    assert ca.read_ca_file_info(active).fingerprint_sha256 == fp


def test_transport_never_uses_staging_path(tmp_path, monkeypatch):
    """Worker resolve path must be ACTIVE basename only."""
    from app.siem.settings_service import SiemForwardingConfig
    from app.siem.transport import SiemDeliveryError, deliver_syslog_tls

    settings = _settings(tmp_path)
    active = ca.resolve_ca_path(settings)
    pem, fp = _build_ca()
    ca.write_staging_ca(active, pem)
    # Leave only staging — no active file.
    assert not active.is_file()

    config = SiemForwardingConfig(
        enabled=True,
        protocol="syslog_tls",
        syslog_host="10.0.0.10",
        syslog_port=6514,
        syslog_tls_verify=True,
        webhook_url="",
        webhook_auth_type="none",
        webhook_auth_configured=False,
        filter_mode="denylist",
        filter_actions=[],
        retry_max_queue_size=100,
        retry_max_age_minutes=60,
        last_success_at=None,
        syslog_ca_relative_path=ca.DEFAULT_RELATIVE_PATH,
        syslog_ca_valid=False,
    )
    with pytest.raises(SiemDeliveryError):
        deliver_syslog_tls(
            {"action": "siem.connectivity.test", "id": 1},
            config,
            settings=settings,
            sock_factory=lambda: MagicMock(),
        )


def test_install_probe_fail_keeps_previous_ca(db_session, tmp_path):
    from app.siem.ca_service import install_syslog_ca
    from app.siem.settings_service import get_siem_config, update_siem_settings

    settings = _settings(tmp_path)
    update_siem_settings(
        db_session,
        settings,
        enabled=True,
        protocol="syslog_tls",
        syslog_host="10.0.0.10",
        syslog_port=6514,
        syslog_tls_verify=True,
        webhook_url="",
        webhook_auth_type="none",
        webhook_auth_secret=None,
        clear_webhook_secret=False,
        filter_mode="denylist",
        filter_actions=[],
        retry_max_queue_size=100,
        retry_max_age_minutes=60,
        actor="admin@example.com",
    )
    good, _ = _build_ca(cn="Good CA")
    install_syslog_ca(
        db_session,
        settings,
        raw=good,
        filename="good.pem",
        actor="admin@example.com",
        skip_tls_probe=True,
    )
    active = ca.resolve_ca_path(settings)
    good_fp = ca.read_ca_file_info(active).fingerprint_sha256
    other, _ = _build_ca(cn="Other CA")

    def fail_probe(**kwargs):
        raise ca.SyslogCaError("délai dépassé")

    with pytest.raises(ca.SyslogCaError, match="délai"):
        install_syslog_ca(
            db_session,
            settings,
            raw=other,
            filename="other.pem",
            actor="admin@example.com",
            probe_fn=fail_probe,
        )
    assert ca.read_ca_file_info(active).fingerprint_sha256 == good_fp
    assert not ca.staging_path_for(active).is_file()
    cfg = get_siem_config(db_session, settings=settings)
    assert cfg.syslog_ca_valid is True
    assert cfg.syslog_tls_verify is True


def test_db_update_failure_restores_previous_file(db_session, tmp_path, monkeypatch):
    from app.siem.ca_service import install_syslog_ca
    from app.siem.settings_service import get_siem_config, update_siem_settings

    settings = _settings(tmp_path)
    update_siem_settings(
        db_session,
        settings,
        enabled=True,
        protocol="syslog_tls",
        syslog_host="10.0.0.10",
        syslog_port=6514,
        syslog_tls_verify=True,
        webhook_url="",
        webhook_auth_type="none",
        webhook_auth_secret=None,
        clear_webhook_secret=False,
        filter_mode="denylist",
        filter_actions=[],
        retry_max_queue_size=100,
        retry_max_age_minutes=60,
        actor="admin@example.com",
    )
    good, _ = _build_ca(cn="Good CA")
    install_syslog_ca(
        db_session,
        settings,
        raw=good,
        filename="good.pem",
        actor="admin@example.com",
        skip_tls_probe=True,
    )
    active = ca.resolve_ca_path(settings)
    good_fp = ca.read_ca_file_info(active).fingerprint_sha256
    other, _ = _build_ca(cn="Other CA")

    real_commit = db_session.commit
    state = {"fail_next_ca_meta": False}

    def selective_commit():
        if state["fail_next_ca_meta"]:
            state["fail_next_ca_meta"] = False
            raise RuntimeError("db boom")
        return real_commit()

    monkeypatch.setattr(db_session, "commit", selective_commit)
    state["fail_next_ca_meta"] = True
    with pytest.raises(ca.SyslogCaError, match="mise à jour"):
        install_syslog_ca(
            db_session,
            settings,
            raw=other,
            filename="other.pem",
            actor="admin@example.com",
            skip_tls_probe=True,
        )
    monkeypatch.setattr(db_session, "commit", real_commit)
    assert ca.read_ca_file_info(active).fingerprint_sha256 == good_fp
    cfg = get_siem_config(db_session, settings=settings)
    assert cfg.syslog_ca_valid is True
    assert cfg.syslog_tls_verify is True
    assert cfg.active is True


def test_worker_config_inactive_without_ca(db_session, tmp_path):
    from app.siem.settings_service import get_siem_config, update_siem_settings

    settings = _settings(tmp_path)
    update_siem_settings(
        db_session,
        settings,
        enabled=True,
        protocol="syslog_tls",
        syslog_host="10.0.0.10",
        syslog_port=6514,
        syslog_tls_verify=False,
        webhook_url="",
        webhook_auth_type="none",
        webhook_auth_secret=None,
        clear_webhook_secret=False,
        filter_mode="denylist",
        filter_actions=[],
        retry_max_queue_size=100,
        retry_max_age_minutes=60,
        actor="admin@example.com",
    )
    cfg = get_siem_config(db_session, settings=settings)
    assert cfg.syslog_tls_verify is True
    assert cfg.syslog_ca_valid is False
    assert cfg.active is False


def test_api_ca_get_requires_admin(client):
    r = client.get("/api/admin/siem/syslog-tls/ca")
    assert r.status_code in (401, 403, 302)


def test_api_ca_upload_with_skip_probe(client, db_session, tmp_path, monkeypatch):
    from app.main import app
    from app.siem.settings_service import update_siem_settings
    from app.sso_settings import get_settings as gs

    settings = _settings(tmp_path)
    app.dependency_overrides[gs] = lambda: settings
    try:
        update_siem_settings(
            db_session,
            settings,
            enabled=True,
            protocol="syslog_tls",
            syslog_host="10.0.0.10",
            syslog_port=6514,
            syslog_tls_verify=True,
            webhook_url="",
            webhook_auth_type="none",
            webhook_auth_secret=None,
            clear_webhook_secret=False,
            filter_mode="denylist",
            filter_actions=[],
            retry_max_queue_size=100,
            retry_max_age_minutes=60,
            actor="admin@example.com",
        )

        def _install(db, settings, **kw):
            from app.siem.ca_service import install_syslog_ca as real

            kw["skip_tls_probe"] = True
            return real(db, settings, **kw)

        monkeypatch.setattr("app.web.admin_siem_ca.install_syslog_ca", _install)
        headers = {"X-Email": "admin@example.com", "X-Groups": "portal-admins"}
        pem, _ = _build_ca()
        up = client.post(
            "/api/admin/siem/syslog-tls/ca",
            headers=headers,
            files={"file": ("ca.pem", pem, "application/x-pem-file")},
        )
        assert up.status_code == 200, up.text
        body = up.json()
        assert body["configured"] is True
        assert "BEGIN CERTIFICATE" not in str(body)
        assert body.get("fingerprint_sha256")
        page = client.get("/admin/configuration", headers=headers)
        assert page.status_code == 200
        assert "Autorité de certification TLS Syslog" in page.text
        assert 'id="siem-ca-section"' in page.text
        assert 'id="siem-ca-tls-test-btn"' in page.text
        assert 'id="siem-test-btn"' in page.text
    finally:
        app.dependency_overrides.pop(gs, None)


def test_api_ca_get_delete_test_and_bad_upload(client, db_session, tmp_path, monkeypatch):
    from app.main import app
    from app.sso_settings import get_settings as gs

    settings = _settings(tmp_path)
    app.dependency_overrides[gs] = lambda: settings
    headers = {"X-Email": "admin@example.com", "X-Groups": "portal-admins"}
    try:
        _enable_syslog_tls(db_session, settings)

        def _install(db, settings, **kw):
            from app.siem.ca_service import install_syslog_ca as real

            kw["skip_tls_probe"] = True
            return real(db, settings, **kw)

        monkeypatch.setattr("app.web.admin_siem_ca.install_syslog_ca", _install)

        got = client.get("/api/admin/siem/syslog-tls/ca", headers=headers)
        assert got.status_code == 200
        assert got.json()["configured"] is False

        bad = client.post(
            "/api/admin/siem/syslog-tls/ca",
            headers=headers,
            files={"file": ("bad.pem", b"not-a-cert", "application/x-pem-file")},
        )
        assert bad.status_code == 400
        assert bad.json()["ok"] is False

        pem, _ = _build_ca(cn="API CA")
        up = client.post(
            "/api/admin/siem/syslog-tls/ca",
            headers=headers,
            files={"file": ("api.pem", pem, "application/x-pem-file")},
        )
        assert up.status_code == 200, up.text

        class _SslSock:
            def __enter__(self):
                return self

            def __exit__(self, *_a):
                return False

            def cipher(self):
                return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        monkeypatch.setattr(
            "app.web.admin_siem_ca.run_syslog_tls_ca_test",
            lambda *a, **k: (True, "ok", ["✓"]),
        )
        probe = client.post("/api/admin/siem/syslog-tls/test", headers=headers)
        assert probe.status_code == 200
        assert probe.json()["ok"] is True

        deleted = client.delete("/api/admin/siem/syslog-tls/ca", headers=headers)
        assert deleted.status_code == 200
        assert deleted.json()["configured"] is False
    finally:
        app.dependency_overrides.pop(gs, None)


def test_install_rejects_when_syslog_host_missing_for_probe(db_session, tmp_path):
    from app.siem.ca_service import install_syslog_ca
    from app.siem.settings_service import update_siem_settings

    settings = _settings(tmp_path)
    update_siem_settings(
        db_session,
        settings,
        enabled=True,
        protocol="syslog_tls",
        syslog_host="",
        syslog_port=6514,
        syslog_tls_verify=True,
        webhook_url="",
        webhook_auth_type="none",
        webhook_auth_secret=None,
        clear_webhook_secret=False,
        filter_mode="denylist",
        filter_actions=[],
        retry_max_queue_size=100,
        retry_max_age_minutes=60,
        actor="admin@example.com",
    )
    pem, _ = _build_ca(cn="No Host CA")
    with pytest.raises(ca.SyslogCaError, match="hôte Syslog"):
        install_syslog_ca(
            db_session,
            settings,
            raw=pem,
            filename="nohost.pem",
            actor="admin@example.com",
            skip_tls_probe=False,
        )


def test_get_ca_api_status_fingerprint_mismatch_badge(db_session, tmp_path):
    from app.siem.ca_service import get_ca_api_status, install_syslog_ca
    from app.siem.settings_service import ensure_siem_settings

    settings = _settings(tmp_path)
    _enable_syslog_tls(db_session, settings)
    pem, _ = _build_ca(cn="Mismatch CA")
    install_syslog_ca(
        db_session,
        settings,
        raw=pem,
        filename="mm.pem",
        actor="admin@example.com",
        skip_tls_probe=True,
    )
    row = ensure_siem_settings(db_session)
    row.syslog_ca_fingerprint_sha256 = "AA:BB:CC:DD"
    db_session.commit()
    status = get_ca_api_status(db_session, settings)
    assert status["configured"] is True
    assert status["badge"] == "configured"


def test_run_syslog_tls_ca_test_missing_host(db_session, tmp_path, monkeypatch):
    from app.siem import ca_service
    from app.siem.ca_service import run_syslog_tls_ca_test

    settings = _settings(tmp_path)
    _enable_syslog_tls(db_session, settings)

    cfg = MagicMock(
        protocol="syslog_tls",
        syslog_host="",
        syslog_port=6514,
        syslog_tls_verify=True,
        syslog_ca_valid=True,
        syslog_ca_relative_path=ca.DEFAULT_RELATIVE_PATH,
    )
    monkeypatch.setattr(ca_service, "get_siem_config", lambda *_a, **_k: cfg)
    ok, msg, lines = run_syslog_tls_ca_test(
        db_session, settings, actor="admin@example.com"
    )
    assert ok is False
    assert "syslog_host" in msg
    assert any("✗" in line for line in lines)


def test_run_syslog_tls_ca_test_tls_verify_disabled(db_session, tmp_path, monkeypatch):
    from app.siem import ca_service
    from app.siem.ca_service import run_syslog_tls_ca_test

    settings = _settings(tmp_path)
    _enable_syslog_tls(db_session, settings)
    cfg = MagicMock(
        protocol="syslog_tls",
        syslog_host="10.0.0.10",
        syslog_port=6514,
        syslog_tls_verify=False,
        syslog_ca_valid=True,
        syslog_ca_relative_path=ca.DEFAULT_RELATIVE_PATH,
    )
    monkeypatch.setattr(ca_service, "get_siem_config", lambda *_a, **_k: cfg)
    ok, msg, _ = run_syslog_tls_ca_test(db_session, settings, actor="admin@example.com")
    assert ok is False
    assert "tls_verify" in msg


def _enable_syslog_tls(db_session, settings, *, host: str = "10.0.0.10") -> None:
    from app.siem.settings_service import update_siem_settings

    update_siem_settings(
        db_session,
        settings,
        enabled=True,
        protocol="syslog_tls",
        syslog_host=host,
        syslog_port=6514,
        syslog_tls_verify=True,
        webhook_url="",
        webhook_auth_type="none",
        webhook_auth_secret=None,
        clear_webhook_secret=False,
        filter_mode="denylist",
        filter_actions=[],
        retry_max_queue_size=100,
        retry_max_age_minutes=60,
        actor="admin@example.com",
    )


def test_sanitize_logical_name_accepts_crt_suffix():
    assert ca.sanitize_logical_name("collector.crt") == "collector.crt"
    assert ca.sanitize_logical_name("bad.exe") == ca.ACTIVE_BASENAME


def test_get_ca_api_status_and_delete(db_session, tmp_path):
    from app.siem.ca_service import delete_syslog_ca, get_ca_api_status, install_syslog_ca

    settings = _settings(tmp_path)
    _enable_syslog_tls(db_session, settings)
    missing = get_ca_api_status(db_session, settings)
    assert missing["configured"] is False
    assert missing["logical_name"] is None

    pem, _ = _build_ca(cn="Status CA")
    installed = install_syslog_ca(
        db_session,
        settings,
        raw=pem,
        filename="status.pem",
        actor="admin@example.com",
        skip_tls_probe=True,
    )
    assert installed["configured"] is True
    assert installed["logical_name"] == "status.pem"

    deleted = delete_syslog_ca(
        db_session, settings, actor="admin@example.com", ip_address="10.0.0.1"
    )
    assert deleted["configured"] is False
    active = ca.resolve_ca_path(settings)
    assert not active.is_file()


def test_run_syslog_tls_ca_test_prechecks_and_success(db_session, tmp_path):
    from app.siem.ca_service import install_syslog_ca, run_syslog_tls_ca_test
    from app.siem.settings_service import update_siem_settings

    settings = _settings(tmp_path)
    update_siem_settings(
        db_session,
        settings,
        enabled=True,
        protocol="webhook_https",
        syslog_host="",
        syslog_port=6514,
        syslog_tls_verify=True,
        webhook_url="https://siem.example.com/hook",
        webhook_auth_type="none",
        webhook_auth_secret=None,
        clear_webhook_secret=False,
        filter_mode="denylist",
        filter_actions=[],
        retry_max_queue_size=100,
        retry_max_age_minutes=60,
        actor="admin@example.com",
    )
    ok, msg, lines = run_syslog_tls_ca_test(
        db_session, settings, actor="admin@example.com"
    )
    assert ok is False
    assert "Syslog TCP+TLS" in msg
    assert any("✗" in line for line in lines)

    _enable_syslog_tls(db_session, settings)
    ok, msg, _ = run_syslog_tls_ca_test(db_session, settings, actor="admin@example.com")
    assert ok is False
    assert "aucune CA" in msg

    pem, _ = _build_ca(cn="Probe CA")
    install_syslog_ca(
        db_session,
        settings,
        raw=pem,
        filename="probe.pem",
        actor="admin@example.com",
        skip_tls_probe=True,
    )

    class _SslSock:
        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def cipher(self):
            return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    ok, msg, lines = run_syslog_tls_ca_test(
        db_session,
        settings,
        actor="admin@example.com",
        sock_factory=lambda: _SslSock(),
    )
    assert ok is True
    assert "Négociation TLS OK" in msg
    assert any("✓" in line for line in lines)


def test_run_syslog_tls_ca_test_probe_failure(db_session, tmp_path):
    from app.siem.ca_service import install_syslog_ca, run_syslog_tls_ca_test

    settings = _settings(tmp_path)
    _enable_syslog_tls(db_session, settings)
    pem, _ = _build_ca(cn="Fail Probe CA")
    install_syslog_ca(
        db_session,
        settings,
        raw=pem,
        filename="fail.pem",
        actor="admin@example.com",
        skip_tls_probe=True,
    )

    def boom():
        raise ca.SyslogCaError("refus de connexion")

    ok, msg, lines = run_syslog_tls_ca_test(
        db_session, settings, actor="admin@example.com", sock_factory=boom
    )
    assert ok is False
    assert "refus de connexion" in msg
    assert any("✗" in line for line in lines)


def test_sanitize_logical_name_empty_and_unsafe():
    assert ca.sanitize_logical_name(None) == ca.ACTIVE_BASENAME
    assert ca.sanitize_logical_name("") == ca.ACTIVE_BASENAME
    assert ca.sanitize_logical_name("bad name.pem") == ca.ACTIVE_BASENAME
    assert ca.sanitize_logical_name("ok.pem") == "ok.pem"


def test_normalize_relative_path_rejects_bad_inputs():
    with pytest.raises(ca.SyslogCaError, match="invalide"):
        ca.normalize_relative_path("certs/../siem/syslog-collector-ca.pem")
    with pytest.raises(ca.SyslogCaError, match="invalide"):
        ca.normalize_relative_path("certs/siem/syslog-collector-ca.crt")
    with pytest.raises(ca.SyslogCaError, match="invalide"):
        ca.normalize_relative_path("/abs/certs/siem/syslog-collector-ca.pem")


def test_resolve_rejects_wrong_basename(tmp_path):
    settings = _settings(tmp_path)
    with pytest.raises(ca.SyslogCaError, match="seul le fichier"):
        ca.resolve_ca_path(settings, relative_path="certs/siem/other-ca.pem")


def test_parse_rejects_non_pem_and_multi_cert():
    with pytest.raises(ca.SyslogCaError, match="non PEM"):
        ca.parse_and_validate_ca_pem(b"not-a-certificate")
    pem, _ = _build_ca(cn="One")
    pem2, _ = _build_ca(cn="Two")
    with pytest.raises(ca.SyslogCaError, match="un seul certificat"):
        ca.parse_and_validate_ca_pem(pem + b"\n" + pem2)
    with pytest.raises(ca.SyslogCaError, match="invalide"):
        ca.parse_and_validate_ca_pem(
            b"-----BEGIN CERTIFICATE-----\nbm90LWEtdmFsaWQtY2VydA==\n-----END CERTIFICATE-----\n"
        )


def test_read_ca_file_info_absent_and_wrong_name(tmp_path):
    settings = _settings(tmp_path)
    active = ca.resolve_ca_path(settings)
    with pytest.raises(ca.SyslogCaError, match="absent"):
        ca.read_ca_file_info(active)
    staging = active.with_name(ca.STAGING_BASENAME)
    staging.parent.mkdir(parents=True, exist_ok=True)
    staging.write_bytes(b"x")
    with pytest.raises(ca.SyslogCaError, match="réservée"):
        ca.read_ca_file_info(staging)


def test_is_active_ca_valid_false_when_missing(tmp_path):
    settings = _settings(tmp_path)
    assert ca.is_active_ca_valid(settings) is False


def test_derive_ca_status_badges_expired_invalid_test_required(tmp_path):
    settings = _settings(tmp_path)
    active = ca.resolve_ca_path(settings)
    active.parent.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc)
    expired = _build_ca_unchecked(
        cn="Expired CA",
        not_before=now - timedelta(days=30),
        not_after=now - timedelta(days=1),
    )
    active.write_bytes(expired)
    st = ca.derive_ca_status(settings)
    assert st["configured"] is True
    assert st["valid"] is False
    assert st["badge"] == "expired"

    active.write_bytes(
        b"-----BEGIN CERTIFICATE-----\nbm90LWEtdmFsaWQtY2VydA==\n-----END CERTIFICATE-----\n"
    )
    st2 = ca.derive_ca_status(settings)
    assert st2["configured"] is True
    assert st2["valid"] is False
    assert st2["badge"] == "invalid"

    pem, _ = _build_ca(cn="Good Badge CA")
    active.write_bytes(pem)
    st3 = ca.derive_ca_status(settings, tls_test_ok=False)
    assert st3["configured"] is True
    assert st3["valid"] is True
    assert st3["badge"] == "test_required"
    st4 = ca.derive_ca_status(settings, tls_test_ok=True)
    assert st4["badge"] == "valid"


def test_derive_ca_status_missing_file(tmp_path):
    settings = _settings(tmp_path)
    st = ca.derive_ca_status(settings)
    assert st["configured"] is False
    assert st["badge"] == "missing"


def test_ca_without_key_usage_extension_still_parses():
    """CA signed without KeyUsage still validates; SKI/AKI may be absent."""
    pem = _build_ca_unchecked(cn="Minimal CA", is_ca=True)
    info = ca.parse_and_validate_ca_pem(pem)
    assert info.basic_constraints_ca is True
    assert isinstance(info.key_usage, list)
