"""Versioned file catalogue — storage, channel resolution, effective access."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Sequence

from packaging.version import InvalidVersion, Version
from sqlalchemy.orm import Session

from app.files.blob_crypto import (
    DEFAULT_CHUNK_SIZE,
    iter_decrypted_chunks,
    write_encrypted_blob,
    write_plaintext_blob,
)
from app.models import (
    AccessGrant,
    FileChannelAssignment,
    FileResource,
    FileVersion,
    RBACGroup,
    utcnow,
)
from app.rbac.effective_access_service import ACCESS_LEVEL_RANK
from app.sso_settings import Settings, get_settings

FILE_STORAGE_SUBDIR = Path("private") / "files"
_SAFE_SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
# SemVer core + optional pre-release / build metadata (spec §9.2).
_SEMVER = re.compile(
    r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$"
)
CHANNELS = frozenset({"beta", "stable"})
VERSION_STATUSES = frozenset({"active", "archived"})


@dataclass
class EffectiveFileAccess:
    """One active file with the user's highest effective access level."""

    file: FileResource
    access_level: str
    channel: str
    effective_version: FileVersion | None
    sources: list[str] = field(default_factory=list)
    grant_ids: list[int] = field(default_factory=list)

    @property
    def can_launch(self) -> bool:
        return ACCESS_LEVEL_RANK.get(self.access_level, 0) >= ACCESS_LEVEL_RANK["launch"]

    @property
    def file_id(self) -> int:
        return self.file.id


def _rank(level: str | None) -> int:
    return ACCESS_LEVEL_RANK.get(level or "", 0)


def get_files_storage_root(settings: Settings | None = None) -> Path:
    """Root for blob storage — FILES_STORAGE_DIR or PORTAL_DATA_DIR/private/files."""
    settings = settings or get_settings()
    dedicated = (getattr(settings, "files_storage_dir", None) or "").strip()
    if dedicated:
        return Path(dedicated)
    return Path(settings.portal_data_dir) / FILE_STORAGE_SUBDIR


def ensure_files_storage_dir(settings: Settings | None = None) -> Path:
    root = get_files_storage_root(settings)
    root.mkdir(parents=True, exist_ok=True)
    return root


def resolve_storage_path(
    storage_path: str,
    settings: Settings | None = None,
) -> Path:
    """Absolute path for a stored blob. ``storage_path`` is relative under the files root."""
    rel = (storage_path or "").strip().replace("\\", "/")
    if not rel or rel.startswith("/") or ".." in rel.split("/"):
        raise ValueError("Invalid storage_path")
    root = get_files_storage_root(settings).resolve()
    absolute = (root / rel).resolve()
    if not str(absolute).startswith(str(root)):
        raise ValueError("Invalid storage_path")
    return absolute


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_slug(slug: str) -> str:
    value = (slug or "").strip().lower()
    if not _SAFE_SLUG.match(value):
        raise ValueError(
            "slug must be lowercase alphanumeric with single hyphens (e.g. client-installer)"
        )
    return value


def validate_version_label(label: str) -> str:
    value = (label or "").strip()
    if not _SEMVER.match(value):
        raise ValueError(
            "version_label must be SemVer (ex: 1.2.3, 1.2.3-rc1, 1.2.3+build)"
        )
    try:
        Version(value)
    except InvalidVersion as exc:
        raise ValueError(
            "version_label must be SemVer (ex: 1.2.3, 1.2.3-rc1, 1.2.3+build)"
        ) from exc
    return value


def _semver_key(label: str) -> Version:
    try:
        return Version(label)
    except InvalidVersion:
        # Legacy free-form labels from §7bis — sort below any valid SemVer.
        return Version("0.0.0")


def get_effective_file_channel(
    db: Session,
    *,
    file_id: int,
    keycloak_user_id: str | None = None,
    group_names: Sequence[str] | None = None,
) -> tuple[str, list[str]]:
    """Resolve beta|stable for a subject **on one file**.

    Union of direct user assignment + assignments of all matching Keycloak groups
    for this file_id. Beta wins if present.
    """
    sources: list[str] = []
    names = [n for n in (group_names or []) if n]

    if keycloak_user_id:
        direct = (
            db.query(FileChannelAssignment)
            .filter(
                FileChannelAssignment.file_id == file_id,
                FileChannelAssignment.subject_type == "user",
                FileChannelAssignment.keycloak_user_id == keycloak_user_id,
                FileChannelAssignment.channel == "beta",
            )
            .first()
        )
        if direct:
            sources.append("direct")

    if names:
        groups = db.query(RBACGroup).filter(RBACGroup.name.in_(names)).all()
        group_ids = [g.id for g in groups]
        group_by_id = {g.id: g for g in groups}
        if group_ids:
            group_rows = (
                db.query(FileChannelAssignment)
                .filter(
                    FileChannelAssignment.file_id == file_id,
                    FileChannelAssignment.subject_type == "group",
                    FileChannelAssignment.rbac_group_id.in_(group_ids),
                    FileChannelAssignment.channel == "beta",
                )
                .all()
            )
            for row in group_rows:
                group = group_by_id.get(row.rbac_group_id) if row.rbac_group_id else None
                source = f"via groupe {group.name}" if group else "via groupe"
                if source not in sources:
                    sources.append(source)

    if sources:
        return "beta", sources
    return "stable", ["default"]


def get_effective_file_version(
    db: Session,
    file: FileResource | int,
    channel: str,
) -> FileVersion | None:
    """Pick the highest SemVer among active candidates for the user's channel.

    stable → candidates {stable}
    beta   → candidates {beta, stable}
    """
    file_id = file.id if isinstance(file, FileResource) else int(file)
    channel = (channel or "stable").strip().lower()
    if channel not in CHANNELS:
        channel = "stable"
    candidates = ("beta", "stable") if channel == "beta" else ("stable",)

    rows = (
        db.query(FileVersion)
        .filter(
            FileVersion.file_id == file_id,
            FileVersion.status == "active",
            FileVersion.channel.in_(candidates),
        )
        .all()
    )
    if not rows:
        return None
    return max(rows, key=lambda v: (_semver_key(v.version_label), v.uploaded_at or utcnow()))


def _merge_file_candidate(
    by_file: dict[int, EffectiveFileAccess],
    *,
    file: FileResource,
    access_level: str,
    channel: str,
    effective_version: FileVersion | None,
    source: str,
    grant_id: int,
) -> None:
    existing = by_file.get(file.id)
    if existing is None:
        by_file[file.id] = EffectiveFileAccess(
            file=file,
            access_level=access_level,
            channel=channel,
            effective_version=effective_version,
            sources=[source],
            grant_ids=[grant_id],
        )
        return
    if _rank(access_level) > _rank(existing.access_level):
        existing.access_level = access_level
    if source not in existing.sources:
        existing.sources.append(source)
    if grant_id not in existing.grant_ids:
        existing.grant_ids.append(grant_id)


def get_effective_files_for_user(
    db: Session,
    *,
    keycloak_user_id: str | None = None,
    group_names: Sequence[str] | None = None,
) -> list[EffectiveFileAccess]:
    """Return active files the user can access, with per-file channel + version."""
    by_file: dict[int, EffectiveFileAccess] = {}
    names = [n for n in (group_names or []) if n]

    if keycloak_user_id:
        direct = (
            db.query(AccessGrant)
            .filter(
                AccessGrant.subject_type == "user",
                AccessGrant.keycloak_user_id == keycloak_user_id,
                AccessGrant.resource_type == "file",
                AccessGrant.file_id.is_not(None),
            )
            .all()
        )
        for grant in direct:
            fr = (
                db.query(FileResource)
                .filter_by(id=grant.file_id, is_active=True)
                .first()
            )
            if not fr:
                continue
            channel, _ = get_effective_file_channel(
                db,
                file_id=fr.id,
                keycloak_user_id=keycloak_user_id,
                group_names=group_names,
            )
            _merge_file_candidate(
                by_file,
                file=fr,
                access_level=grant.access_level or "view",
                channel=channel,
                effective_version=get_effective_file_version(db, fr, channel),
                source="direct",
                grant_id=grant.id,
            )

    if names:
        groups = db.query(RBACGroup).filter(RBACGroup.name.in_(names)).all()
        group_ids = [g.id for g in groups]
        group_by_id = {g.id: g for g in groups}
        if group_ids:
            group_grants = (
                db.query(AccessGrant)
                .filter(
                    AccessGrant.subject_type == "group",
                    AccessGrant.rbac_group_id.in_(group_ids),
                    AccessGrant.resource_type == "file",
                    AccessGrant.file_id.is_not(None),
                )
                .all()
            )
            for grant in group_grants:
                fr = (
                    db.query(FileResource)
                    .filter_by(id=grant.file_id, is_active=True)
                    .first()
                )
                if not fr:
                    continue
                channel, _ = get_effective_file_channel(
                    db,
                    file_id=fr.id,
                    keycloak_user_id=keycloak_user_id,
                    group_names=group_names,
                )
                group = group_by_id.get(grant.rbac_group_id) if grant.rbac_group_id else None
                source = f"via groupe {group.name}" if group else "via groupe"
                _merge_file_candidate(
                    by_file,
                    file=fr,
                    access_level=grant.access_level or "view",
                    channel=channel,
                    effective_version=get_effective_file_version(db, fr, channel),
                    source=source,
                    grant_id=grant.id,
                )

    return sorted(by_file.values(), key=lambda e: (e.file.label or "").lower())


def user_can_download_file(
    db: Session,
    *,
    file_id: int,
    keycloak_user_id: str | None = None,
    group_names: Sequence[str] | None = None,
) -> bool:
    """True if effective AccessGrant grants at least ``launch`` on this file."""
    for entry in get_effective_files_for_user(
        db,
        keycloak_user_id=keycloak_user_id,
        group_names=group_names,
    ):
        if entry.file_id == file_id and entry.can_launch:
            return True
    return False


def create_file_resource(
    db: Session,
    *,
    slug: str,
    label: str,
    description: str | None = None,
    category: str | None = None,
    is_active: bool = True,
    created_by: str,
) -> FileResource:
    slug = validate_slug(slug)
    existing = db.query(FileResource).filter_by(slug=slug).first()
    if existing:
        raise ValueError(f"Un fichier avec le slug « {slug} » existe déjà")
    fr = FileResource(
        slug=slug,
        label=(label or "").strip() or slug,
        description=(description or "").strip() or None,
        category=(category or "").strip() or None,
        is_active=bool(is_active),
        created_by=created_by,
    )
    db.add(fr)
    db.flush()
    return fr


def store_file_version(
    db: Session,
    *,
    file: FileResource,
    channel: str,
    version_label: str,
    filename: str,
    content_type: str | None,
    data: bytes,
    uploaded_by: str,
    changelog: str | None = None,
    settings: Settings | None = None,
    encrypt: bool = True,
) -> FileVersion:
    settings = settings or get_settings()
    channel = (channel or "").strip().lower()
    if channel not in CHANNELS:
        raise ValueError("channel must be beta or stable")
    label = validate_version_label(version_label)
    if not data:
        raise ValueError("empty upload")

    dup = (
        db.query(FileVersion)
        .filter_by(file_id=file.id, version_label=label)
        .first()
    )
    if dup:
        raise ValueError(f"La version « {label} » existe déjà pour ce fichier")

    checksum = compute_sha256(data)
    ensure_files_storage_dir(settings)

    # Placeholder path until we have version.id (spec: {file_id}/{version_id}_{sha12}).
    version = FileVersion(
        file_id=file.id,
        channel=channel,
        version_label=label,
        status="active",
        original_filename=(filename or "upload.bin").strip() or "upload.bin",
        content_type=content_type,
        size_bytes=len(data),
        checksum_sha256=checksum,
        storage_path=f"{file.id}/pending_{checksum[:12]}",
        encrypted=bool(encrypt),
        uploaded_at=utcnow(),
        uploaded_by=uploaded_by,
        changelog=(changelog or "").strip() or None,
    )
    db.add(version)
    db.flush()

    rel = f"{file.id}/{version.id}_{checksum[:12]}"
    absolute = resolve_storage_path(rel, settings)
    if encrypt:
        write_encrypted_blob(absolute, data, settings=settings)
    else:
        write_plaintext_blob(absolute, data)
    version.storage_path = rel
    db.flush()
    return version


def promote_file_version(db: Session, version: FileVersion) -> FileVersion:
    """Promote beta → stable. Does not archive previous stables (explicit archive)."""
    if version.channel != "beta":
        raise ValueError("Seule une version beta peut être promue")
    if version.status != "active":
        raise ValueError("Seule une version active peut être promue")
    version.channel = "stable"
    db.flush()
    return version


def archive_file_version(db: Session, version: FileVersion) -> FileVersion:
    version.status = "archived"
    db.flush()
    return version


def assign_beta_channel(
    db: Session,
    *,
    file_id: int,
    subject_type: str,
    rbac_group_id: int | None = None,
    keycloak_user_id: str | None = None,
    user_display_cache: str | None = None,
    assigned_by: str,
) -> FileChannelAssignment:
    if subject_type == "group":
        if not rbac_group_id or keycloak_user_id:
            raise ValueError("group assignments require rbac_group_id only")
        existing = (
            db.query(FileChannelAssignment)
            .filter(
                FileChannelAssignment.file_id == file_id,
                FileChannelAssignment.subject_type == "group",
                FileChannelAssignment.rbac_group_id == rbac_group_id,
            )
            .first()
        )
    elif subject_type == "user":
        if not keycloak_user_id or rbac_group_id:
            raise ValueError("user assignments require keycloak_user_id only")
        existing = (
            db.query(FileChannelAssignment)
            .filter(
                FileChannelAssignment.file_id == file_id,
                FileChannelAssignment.subject_type == "user",
                FileChannelAssignment.keycloak_user_id == keycloak_user_id,
            )
            .first()
        )
    else:
        raise ValueError("subject_type must be group or user")

    if existing:
        return existing

    row = FileChannelAssignment(
        file_id=file_id,
        subject_type=subject_type,
        rbac_group_id=rbac_group_id,
        keycloak_user_id=keycloak_user_id,
        user_display_cache=user_display_cache,
        channel="beta",
        assigned_by=assigned_by,
    )
    db.add(row)
    db.flush()
    return row


def delete_channel_assignment(
    db: Session, assignment_id: int
) -> FileChannelAssignment | None:
    row = db.query(FileChannelAssignment).filter_by(id=assignment_id).first()
    if row:
        db.delete(row)
        db.flush()
    return row


def iter_version_plaintext(
    version: FileVersion,
    settings: Settings | None = None,
) -> Iterator[bytes]:
    settings = settings or get_settings()
    path = resolve_storage_path(version.storage_path, settings)
    if not path.is_file():
        raise FileNotFoundError(f"Stored blob missing for version {version.id}")
    if version.encrypted:
        yield from iter_decrypted_chunks(path, settings=settings)
    else:
        # Legacy plaintext (§7bis) — stream in chunks without loading whole file.
        with path.open("rb") as fh:
            while True:
                block = fh.read(DEFAULT_CHUNK_SIZE)
                if not block:
                    break
                yield block
