"""Versioned files — AccessGrant, per-file channel, SemVer, encryption, download audit."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.files.service import (
    archive_file_version,
    assign_beta_channel,
    compute_sha256,
    create_file_resource,
    get_effective_file_channel,
    get_effective_file_version,
    get_effective_files_for_user,
    iter_version_plaintext,
    promote_file_version,
    store_file_version,
    user_can_download_file,
    validate_version_label,
)
from app.models import AccessGrant, AuditLog, FileChannelAssignment, RBACGroup
from app.rbac.grants_service import AccessGrantCreate, create_grant
from app.sso_settings import get_settings


def _file(db: Session, *, slug: str = "client-installer", label: str = "Installateur"):
    return create_file_resource(
        db, slug=slug, label=label, created_by="admin@test"
    )


def _group(db: Session, *, name: str = "beta-testers") -> RBACGroup:
    group = RBACGroup(name=name, path=f"/{name}")
    db.add(group)
    db.flush()
    return group


def test_file_access_grant_create_and_effective(db_session: Session):
    fr = _file(db_session)
    group = _group(db_session)
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="group",
            rbac_group_id=group.id,
            resource_type="file",
            file_id=fr.id,
            access_level="launch",
        ),
        "admin@test",
    )
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id="user-1",
            resource_type="file",
            file_id=fr.id,
            access_level="view",
        ),
        "admin@test",
    )
    db_session.commit()

    via_group = get_effective_files_for_user(db_session, group_names=[group.name])
    assert len(via_group) == 1
    assert via_group[0].can_launch is True

    via_user = get_effective_files_for_user(
        db_session, keycloak_user_id="user-1", group_names=[]
    )
    assert via_user[0].can_launch is False
    assert user_can_download_file(db_session, file_id=fr.id, group_names=[group.name])
    assert not user_can_download_file(
        db_session, file_id=fr.id, keycloak_user_id="user-1"
    )


def test_file_access_grant_check_rejects_mixed_resources(db_session: Session):
    fr = _file(db_session)
    with pytest.raises(ValidationError):
        AccessGrantCreate.model_validate(
            {
                "subject_type": "user",
                "keycloak_user_id": "u1",
                "resource_type": "file",
                "file_id": fr.id,
                "application_id": 1,
            }
        )

    grant = AccessGrant(
        subject_type="user",
        keycloak_user_id="u1",
        resource_type="file",
        file_id=fr.id,
        system_role="portal_admin",
        granted_by="admin",
    )
    db_session.add(grant)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_file_channel_resolution_per_file(db_session: Session):
    fr_a = _file(db_session, slug="agent-a", label="A")
    fr_b = _file(db_session, slug="agent-b", label="B")
    group = _group(db_session, name="qa-beta")

    channel, sources = get_effective_file_channel(
        db_session, file_id=fr_a.id, keycloak_user_id="u-stable", group_names=[]
    )
    assert channel == "stable"
    assert sources == ["default"]

    assign_beta_channel(
        db_session,
        file_id=fr_a.id,
        subject_type="group",
        rbac_group_id=group.id,
        assigned_by="admin@test",
    )
    assign_beta_channel(
        db_session,
        file_id=fr_a.id,
        subject_type="user",
        keycloak_user_id="u-beta",
        user_display_cache="beta.user",
        assigned_by="admin@test",
    )
    db_session.commit()

    # Group beta on A only — B stays stable
    channel_a, sources_a = get_effective_file_channel(
        db_session, file_id=fr_a.id, keycloak_user_id="u-other", group_names=[group.name]
    )
    assert channel_a == "beta"
    channel_b, _ = get_effective_file_channel(
        db_session, file_id=fr_b.id, keycloak_user_id="u-other", group_names=[group.name]
    )
    assert channel_b == "stable"

    channel, sources = get_effective_file_channel(
        db_session, file_id=fr_a.id, keycloak_user_id="u-beta", group_names=[]
    )
    assert channel == "beta"
    assert "direct" in sources


def test_file_channel_assignment_check_rejects_stable(db_session: Session):
    fr = _file(db_session)
    row = FileChannelAssignment(
        file_id=fr.id,
        subject_type="user",
        keycloak_user_id="u1",
        channel="stable",
        assigned_by="admin",
    )
    db_session.add(row)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_file_effective_version_semver(db_session: Session, monkeypatch, tmp_path):
    monkeypatch.setenv("FILES_STORAGE_DIR", str(tmp_path / "files"))
    get_settings.cache_clear()
    settings = get_settings()

    fr = _file(db_session)
    store_file_version(
        db_session,
        file=fr,
        channel="stable",
        version_label="1.0.0",
        filename="a.bin",
        content_type=None,
        data=b"v100",
        uploaded_by="admin",
        settings=settings,
    )
    store_file_version(
        db_session,
        file=fr,
        channel="beta",
        version_label="1.1.0-rc1",
        filename="b.bin",
        content_type=None,
        data=b"v110rc",
        uploaded_by="admin",
        settings=settings,
    )
    store_file_version(
        db_session,
        file=fr,
        channel="stable",
        version_label="1.0.1",
        filename="c.bin",
        content_type=None,
        data=b"v101",
        uploaded_by="admin",
        settings=settings,
    )
    db_session.commit()

    # SemVer: 1.0.1 > 1.0.0 for stable channel (ignore newer beta pre-release)
    eff = get_effective_file_version(db_session, fr, "stable")
    assert eff is not None
    assert eff.version_label == "1.0.1"
    assert eff.channel == "stable"

    # Beta channel: 1.1.0-rc1 < 1.0.1? No — packaging: 1.1.0rc1 > 1.0.1
    eff_beta = get_effective_file_version(db_session, fr, "beta")
    assert eff_beta is not None
    assert eff_beta.version_label == "1.1.0-rc1"

    # Stable never sees beta even if beta is higher
    store_file_version(
        db_session,
        file=fr,
        channel="beta",
        version_label="2.0.0-rc1",
        filename="d.bin",
        content_type=None,
        data=b"v200rc",
        uploaded_by="admin",
        settings=settings,
    )
    db_session.commit()
    assert get_effective_file_version(db_session, fr, "stable").version_label == "1.0.1"
    assert get_effective_file_version(db_session, fr, "beta").version_label == "2.0.0-rc1"

    with pytest.raises(ValueError):
        validate_version_label("not-a-version")


def test_file_version_promotion(db_session: Session, monkeypatch, tmp_path):
    monkeypatch.setenv("FILES_STORAGE_DIR", str(tmp_path / "files"))
    get_settings.cache_clear()
    settings = get_settings()

    fr = _file(db_session)
    stable = store_file_version(
        db_session,
        file=fr,
        channel="stable",
        version_label="1.0.0",
        filename="s.bin",
        content_type=None,
        data=b"stable",
        uploaded_by="admin",
        settings=settings,
    )
    beta = store_file_version(
        db_session,
        file=fr,
        channel="beta",
        version_label="2.0.0-rc1",
        filename="b.bin",
        content_type=None,
        data=b"beta",
        uploaded_by="admin",
        settings=settings,
    )
    db_session.commit()

    promote_file_version(db_session, beta)
    db_session.commit()
    db_session.refresh(stable)
    db_session.refresh(beta)
    assert beta.channel == "stable"
    assert beta.status == "active"
    # Previous stable stays active until explicitly archived (spec §1.2)
    assert stable.status == "active"
    assert get_effective_file_version(db_session, fr, "stable").version_label == "2.0.0-rc1"

    archive_file_version(db_session, stable)
    db_session.commit()
    assert get_effective_file_version(db_session, fr, "stable").id == beta.id


def test_file_blob_encryption_roundtrip(db_session: Session, monkeypatch, tmp_path):
    monkeypatch.setenv("FILES_STORAGE_DIR", str(tmp_path / "files"))
    get_settings.cache_clear()
    settings = get_settings()

    fr = _file(db_session)
    payload = b"secret-binary-content-" + (b"x" * 2000)
    version = store_file_version(
        db_session,
        file=fr,
        channel="stable",
        version_label="1.0.0",
        filename="secret.bin",
        content_type=None,
        data=payload,
        uploaded_by="admin",
        settings=settings,
        encrypt=True,
    )
    db_session.commit()
    assert version.encrypted is True
    on_disk = (tmp_path / "files" / version.storage_path).read_bytes()
    assert payload not in on_disk
    assert b"".join(iter_version_plaintext(version, settings)) == payload


def test_file_effective_version_semver_beats_upload_date(
    db_session: Session, monkeypatch, tmp_path
):
    """Higher SemVer wins even if uploaded earlier than a lower number."""
    monkeypatch.setenv("FILES_STORAGE_DIR", str(tmp_path / "files"))
    get_settings.cache_clear()
    settings = get_settings()

    fr = _file(db_session, slug="semver-order")
    older_higher = store_file_version(
        db_session,
        file=fr,
        channel="stable",
        version_label="2.0.0",
        filename="a.bin",
        content_type=None,
        data=b"v2",
        uploaded_by="admin",
        settings=settings,
    )
    # Force older upload timestamp on the higher SemVer
    older_higher.uploaded_at = datetime.now(timezone.utc) - timedelta(days=30)
    db_session.flush()

    newer_lower = store_file_version(
        db_session,
        file=fr,
        channel="stable",
        version_label="1.9.9",
        filename="b.bin",
        content_type=None,
        data=b"v199",
        uploaded_by="admin",
        settings=settings,
    )
    newer_lower.uploaded_at = datetime.now(timezone.utc)
    db_session.commit()

    eff = get_effective_file_version(db_session, fr, "stable")
    assert eff is not None
    assert eff.version_label == "2.0.0"
    assert eff.id == older_higher.id


def test_file_blob_reencrypt_script_idempotent(
    db_session: Session, monkeypatch, tmp_path
):
    monkeypatch.setenv("FILES_STORAGE_DIR", str(tmp_path / "files"))
    get_settings.cache_clear()
    settings = get_settings()

    fr = _file(db_session, slug="plain-then-enc")
    version = store_file_version(
        db_session,
        file=fr,
        channel="stable",
        version_label="1.0.0",
        filename="p.bin",
        content_type=None,
        data=b"plain-payload",
        uploaded_by="admin",
        settings=settings,
        encrypt=False,
    )
    db_session.commit()
    assert version.encrypted is False
    plain_on_disk = (tmp_path / "files" / version.storage_path).read_bytes()
    assert plain_on_disk == b"plain-payload"

    from scripts.reencrypt_file_blobs import reencrypt_versions

    n1 = reencrypt_versions(db_session)
    assert n1 == 1
    db_session.refresh(version)
    assert version.encrypted is True
    assert b"".join(iter_version_plaintext(version, settings)) == b"plain-payload"
    assert (tmp_path / "files" / version.storage_path).read_bytes() != b"plain-payload"

    n2 = reencrypt_versions(db_session)
    assert n2 == 0


def test_file_blob_streaming_decrypt_no_full_buffer(
    db_session: Session, monkeypatch, tmp_path
):
    """Decrypt yields chunks; never materializes full plaintext in one buffer in the generator."""
    monkeypatch.setenv("FILES_STORAGE_DIR", str(tmp_path / "files"))
    monkeypatch.setenv("FILE_ENCRYPTION_CHUNK_SIZE", str(64 * 1024))
    get_settings.cache_clear()
    settings = get_settings()

    fr = _file(db_session, slug="big-stream")
    # ~256 KiB → several Fernet chunks at 64 KiB
    payload = os.urandom(256 * 1024)
    version = store_file_version(
        db_session,
        file=fr,
        channel="stable",
        version_label="1.0.0",
        filename="big.bin",
        content_type=None,
        data=payload,
        uploaded_by="admin",
        settings=settings,
        encrypt=True,
    )
    db_session.commit()

    chunks = list(iter_version_plaintext(version, settings))
    assert len(chunks) >= 3
    assert max(len(c) for c in chunks) <= 64 * 1024
    assert b"".join(chunks) == payload
    assert compute_sha256(payload) == version.checksum_sha256


def test_file_download_audit(client, db_session: Session, monkeypatch, tmp_path):
    monkeypatch.setenv("FILES_STORAGE_DIR", str(tmp_path / "files"))
    get_settings.cache_clear()
    settings = get_settings()

    fr = _file(db_session, slug="vpn-client")
    version = store_file_version(
        db_session,
        file=fr,
        channel="stable",
        version_label="3.2.1",
        filename="vpn-setup.exe",
        content_type="application/octet-stream",
        data=b"payload-bytes",
        uploaded_by="admin@test",
        settings=settings,
    )
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="user",
            keycloak_user_id="kc-user-dl",
            resource_type="file",
            file_id=fr.id,
            access_level="launch",
        ),
        "admin@test",
    )
    db_session.commit()

    resp = client.get(
        f"/files/{fr.slug}/download",
        headers={
            "X-Email": "dl@example.com",
            "X-Preferred-Username": "dl.user",
            "X-User-Id": "kc-user-dl",
            "X-Groups": "",
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.content == b"payload-bytes"
    assert resp.headers.get("X-Content-SHA256") == version.checksum_sha256

    entries = (
        db_session.query(AuditLog).filter(AuditLog.action == "file.downloaded").all()
    )
    assert len(entries) >= 1
    details = entries[-1].details or {}
    assert details.get("version_id") == version.id
    assert details.get("version_label") == "3.2.1"
    assert details.get("keycloak_user_id") == "kc-user-dl"


def test_file_download_requires_launch(client, db_session: Session, monkeypatch, tmp_path):
    monkeypatch.setenv("FILES_STORAGE_DIR", str(tmp_path / "files"))
    get_settings.cache_clear()
    settings = get_settings()

    fr = _file(db_session, slug="secret-doc")
    store_file_version(
        db_session,
        file=fr,
        channel="stable",
        version_label="1.0.0",
        filename="doc.pdf",
        content_type="application/pdf",
        data=b"%PDF",
        uploaded_by="admin",
        settings=settings,
    )
    group = _group(db_session, name="viewers-only")
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="group",
            rbac_group_id=group.id,
            resource_type="file",
            file_id=fr.id,
            access_level="view",
        ),
        "admin@test",
    )
    db_session.commit()

    resp = client.get(
        f"/files/{fr.slug}/download",
        headers={
            "X-Email": "v@example.com",
            "X-Preferred-Username": "viewer",
            "X-User-Id": "kc-viewer",
            "X-Groups": "viewers-only",
        },
    )
    assert resp.status_code == 403


ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}


def test_files_deposit_new(client, db_session: Session, monkeypatch, tmp_path):
    monkeypatch.setenv("FILES_STORAGE_DIR", str(tmp_path / "files"))
    get_settings.cache_clear()

    resp = client.post(
        "/admin/files/deposit",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
        data={
            "mode": "new",
            "label": "Client Installer",
            "slug": "client-installer",
            "description": "Installateur",
            "version_label": "2.4.0",
            "channel": "stable",
            "changelog": "first",
        },
        files={"upload": ("client-installer-2.4.0.zip", b"zip-bytes", "application/zip")},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["file"]["slug"] == "client-installer"
    assert body["version"]["version_label"] == "2.4.0"

    from app.models import FileResource, FileVersion

    fr = db_session.query(FileResource).filter_by(slug="client-installer").one()
    versions = db_session.query(FileVersion).filter_by(file_id=fr.id).all()
    assert len(versions) == 1
    assert versions[0].version_label == "2.4.0"
    assert versions[0].channel == "stable"


def test_files_deposit_existing(client, db_session: Session, monkeypatch, tmp_path):
    monkeypatch.setenv("FILES_STORAGE_DIR", str(tmp_path / "files"))
    get_settings.cache_clear()
    settings = get_settings()

    fr = _file(db_session, slug="vpn-client", label="VPN Client")
    store_file_version(
        db_session,
        file=fr,
        channel="stable",
        version_label="1.0.0",
        filename="vpn-1.0.0.exe",
        content_type="application/octet-stream",
        data=b"v1",
        uploaded_by="admin@test",
        settings=settings,
    )
    db_session.commit()
    file_id = fr.id

    from app.models import FileResource, FileVersion

    before = db_session.query(FileResource).count()

    resp = client.post(
        "/admin/files/deposit",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
        data={
            "mode": "existing",
            "file_id": str(file_id),
            "version_label": "1.1.0",
            "channel": "beta",
            "changelog": "bump",
        },
        files={"upload": ("vpn-1.1.0.exe", b"v2-bytes", "application/octet-stream")},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["file"]["id"] == file_id
    assert body["version"]["version_label"] == "1.1.0"
    assert body["version"]["channel"] == "beta"

    db_session.expire_all()
    assert db_session.query(FileResource).count() == before
    labels = {
        v.version_label
        for v in db_session.query(FileVersion).filter_by(file_id=file_id).all()
    }
    assert labels == {"1.0.0", "1.1.0"}


def test_files_deposit_rollback(client, db_session: Session, monkeypatch, tmp_path):
    """mode=new must not leave an orphan FileResource if version creation fails."""
    monkeypatch.setenv("FILES_STORAGE_DIR", str(tmp_path / "files"))
    get_settings.cache_clear()

    from app.models import FileResource, FileVersion

    before_files = db_session.query(FileResource).count()
    before_versions = db_session.query(FileVersion).count()

    # Invalid SemVer → store_file_version fails after FileResource flush.
    resp = client.post(
        "/admin/files/deposit",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
        data={
            "mode": "new",
            "label": "Orphan Candidate",
            "slug": "orphan-candidate",
            "version_label": "not-a-semver",
            "channel": "stable",
        },
        files={"upload": ("orphan.bin", b"data", "application/octet-stream")},
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["ok"] is False

    db_session.expire_all()
    assert db_session.query(FileResource).filter_by(slug="orphan-candidate").first() is None
    assert db_session.query(FileResource).count() == before_files
    assert db_session.query(FileVersion).count() == before_versions

    # Same orchestration path when version_label is already used (simulated).
    def _boom(*_a, **_k):
        raise ValueError("La version « 9.9.9 » existe déjà pour ce fichier")

    monkeypatch.setattr("app.admin.files.store_file_version", _boom)
    resp2 = client.post(
        "/admin/files/deposit",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
        data={
            "mode": "new",
            "label": "Boom File",
            "slug": "boom-file",
            "version_label": "9.9.9",
            "channel": "stable",
        },
        files={"upload": ("boom.bin", b"boom", "application/octet-stream")},
    )
    assert resp2.status_code == 400, resp2.text
    db_session.expire_all()
    assert db_session.query(FileResource).filter_by(slug="boom-file").first() is None
    assert db_session.query(FileResource).count() == before_files


def test_files_resolve_name(client, db_session: Session):
    _file(db_session, slug="client-installer", label="Client Installer")
    _file(db_session, slug="other-tool", label="Other Tool")
    db_session.commit()

    resp = client.get(
        "/admin/files/resolve-name",
        params={"q": "client-installer"},
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["best"] is not None
    assert body["best"]["slug"] == "client-installer"
    assert any(r["slug"] == "client-installer" for r in body["results"])
