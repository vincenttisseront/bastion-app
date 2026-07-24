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


def test_file_effective_version_numeric(db_session: Session, monkeypatch, tmp_path):
    monkeypatch.setenv("FILES_STORAGE_DIR", str(tmp_path / "files"))
    get_settings.cache_clear()
    settings = get_settings()

    fr = _file(db_session)
    store_file_version(
        db_session,
        file=fr,
        channel="stable",
        version_label="1",
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
        version_label="3",
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
        version_label="2",
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
    assert eff.version_label == "2"
    assert eff.channel == "stable"

    # Beta channel: 1.1.0-rc1 < 1.0.1? No — packaging: 1.1.0rc1 > 1.0.1
    eff_beta = get_effective_file_version(db_session, fr, "beta")
    assert eff_beta is not None
    assert eff_beta.version_label == "3"

    # Stable never sees beta even if beta is higher
    store_file_version(
        db_session,
        file=fr,
        channel="beta",
        version_label="4",
        filename="d.bin",
        content_type=None,
        data=b"v200rc",
        uploaded_by="admin",
        settings=settings,
    )
    db_session.commit()
    assert get_effective_file_version(db_session, fr, "stable").version_label == "2"
    assert get_effective_file_version(db_session, fr, "beta").version_label == "4"

    assert validate_version_label("2.4.0-rc1") == "2.4.0-rc1"
    with pytest.raises(ValueError):
        validate_version_label("  ")


def test_file_version_promotion(db_session: Session, monkeypatch, tmp_path):
    monkeypatch.setenv("FILES_STORAGE_DIR", str(tmp_path / "files"))
    get_settings.cache_clear()
    settings = get_settings()

    fr = _file(db_session)
    stable = store_file_version(
        db_session,
        file=fr,
        channel="stable",
        version_label="1",
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
        version_label="4",
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
    assert get_effective_file_version(db_session, fr, "stable").version_label == "4"

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
        version_label="1",
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


def test_file_effective_version_numeric_beats_upload_date(
    db_session: Session, monkeypatch, tmp_path
):
    """Higher numeric version wins even if uploaded earlier."""
    monkeypatch.setenv("FILES_STORAGE_DIR", str(tmp_path / "files"))
    get_settings.cache_clear()
    settings = get_settings()

    fr = _file(db_session, slug="numeric-order")
    older_higher = store_file_version(
        db_session,
        file=fr,
        channel="stable",
        version_label="2",
        filename="a.bin",
        content_type=None,
        data=b"v2",
        uploaded_by="admin",
        settings=settings,
    )
    # Force older upload timestamp on the higher version
    older_higher.uploaded_at = datetime.now(timezone.utc) - timedelta(days=30)
    db_session.flush()

    newer_lower = store_file_version(
        db_session,
        file=fr,
        channel="stable",
        version_label="1",
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
    assert eff.version_label == "2"
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
        version_label="1",
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
        version_label="1",
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
        version_label="1",
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
    assert details.get("version_label") == "1"
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
        version_label="1",
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


def test_files_deposit_new_folder_scoped(client, db_session: Session, monkeypatch, tmp_path):
    monkeypatch.setenv("FILES_STORAGE_DIR", str(tmp_path / "files"))
    get_settings.cache_clear()

    from app.files.service import create_folder
    from app.models import FileResource

    a = create_folder(db_session, name="A", parent_folder_id=None, created_by="admin")
    b = create_folder(db_session, name="B", parent_folder_id=None, created_by="admin")
    db_session.commit()

    for folder in (a, b):
        resp = client.post(
            "/files/upload",
            headers={**ADMIN_HEADERS, "Accept": "application/json"},
            data={"folder_id": str(folder.id)},
            files={"upload": ("same-name.zip", b"payload", "application/zip")},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["ok"] is True

    db_session.expire_all()
    rows = db_session.query(FileResource).filter_by(label="same-name.zip").all()
    assert len(rows) == 2
    assert {r.folder_id for r in rows} == {a.id, b.id}


def test_files_deposit_auto_version(client, db_session: Session, monkeypatch, tmp_path):
    monkeypatch.setenv("FILES_STORAGE_DIR", str(tmp_path / "files"))
    get_settings.cache_clear()

    from app.models import FileResource, FileVersion

    resp1 = client.post(
        "/files/upload",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
        data={},
        files={"upload": ("client.zip", b"v1", "application/zip")},
    )
    assert resp1.status_code == 200, resp1.text
    body1 = resp1.json()
    assert body1["version"]["version_label"] == "1"
    assert body1["version"]["channel"] == "stable"
    assert body1["created_new_file"] is True

    resp2 = client.post(
        "/files/upload",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
        data={},
        files={"upload": ("client.zip", b"v2", "application/zip")},
    )
    assert resp2.status_code == 200, resp2.text
    body2 = resp2.json()
    assert body2["version"]["version_label"] == "2"
    assert body2["version"]["channel"] == "stable"
    assert body2["created_new_file"] is False

    db_session.expire_all()
    fr = db_session.query(FileResource).filter_by(label="client.zip").one()
    labels = {
        v.version_label
        for v in db_session.query(FileVersion).filter_by(file_id=fr.id).all()
    }
    assert labels == {"1", "2"}


def test_files_rights_inherited_from_folder(db_session: Session, monkeypatch, tmp_path):
    monkeypatch.setenv("FILES_STORAGE_DIR", str(tmp_path / "files"))
    get_settings.cache_clear()
    settings = get_settings()

    from app.files.service import create_folder, deposit_file, get_effective_access_on_file

    root = create_folder(db_session, name="Root", parent_folder_id=None, created_by="admin")
    child = create_folder(
        db_session, name="Nested", parent_folder_id=root.id, created_by="admin"
    )
    fr, _version, _ = deposit_file(
        db_session,
        folder_id=child.id,
        filename="deep.bin",
        content_type=None,
        data=b"x",
        uploaded_by="admin",
        is_portal_admin=True,
        settings=settings,
    )
    group = _group(db_session, name="folder-managers")
    create_grant(
        db_session,
        AccessGrantCreate(
            subject_type="group",
            rbac_group_id=group.id,
            resource_type="folder",
            folder_id=root.id,
            access_level="manage",
        ),
        "admin@test",
    )
    db_session.commit()

    access = get_effective_access_on_file(
        db_session,
        file=fr,
        group_names=["folder-managers"],
    )
    assert access.can_manage
    assert any("via dossier" in s for s in access.sources)


def test_files_rights_no_access_hidden(db_session: Session, monkeypatch, tmp_path):
    monkeypatch.setenv("FILES_STORAGE_DIR", str(tmp_path / "files"))
    get_settings.cache_clear()
    settings = get_settings()

    from app.files.service import create_folder, deposit_file, list_folder_contents

    folder = create_folder(
        db_session, name="Secret", parent_folder_id=None, created_by="admin"
    )
    deposit_file(
        db_session,
        folder_id=folder.id,
        filename="hidden.bin",
        content_type=None,
        data=b"secret",
        uploaded_by="admin",
        is_portal_admin=True,
        settings=settings,
    )
    db_session.commit()

    listing = list_folder_contents(
        db_session,
        folder_id=None,
        keycloak_user_id="kc-nobody",
        group_names=[],
        is_portal_admin=False,
    )
    assert listing["folders"] == []
    assert listing["files"] == []

    nested = list_folder_contents(
        db_session,
        folder_id=folder.id,
        keycloak_user_id="kc-nobody",
        group_names=[],
        is_portal_admin=False,
    )
    assert nested["files"] == []


def test_files_browser_reachable_for_breakglass(client):
    """Regression: break-glass must not be bounced /files → /dashboard."""
    headers = {
        "X-Email": "admin@breakglass.local",
        "X-Preferred-Username": "bg-admin",
        "X-Groups": "portal-admins",
        "X-Portal-Auth-Source": "breakglass",
    }
    for path in ("/files", "/admin/files"):
        resp = client.get(path, headers=headers, follow_redirects=False)
        assert resp.status_code == 200, f"{path} -> {resp.status_code}"
        assert "/dashboard" not in (resp.headers.get("location") or "")
