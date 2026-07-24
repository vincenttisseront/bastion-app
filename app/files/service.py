"""Folder-scoped file browser — deposit, inherited access, channels, versions."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Sequence

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
    FileFolder,
    FileResource,
    FileVersion,
    RBACGroup,
    utcnow,
)
from app.rbac.effective_access_service import ACCESS_LEVEL_RANK
from app.sso_settings import Settings, get_settings

FILE_STORAGE_SUBDIR = Path("private") / "files"
_SAFE_SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
CHANNELS = frozenset({"beta", "stable"})
VERSION_STATUSES = frozenset({"active", "archived"})


@dataclass
class EffectiveAccess:
    """Resolved access level with provenance labels."""

    access_level: str | None
    sources: list[str] = field(default_factory=list)
    grant_ids: list[int] = field(default_factory=list)

    @property
    def rank(self) -> int:
        return ACCESS_LEVEL_RANK.get(self.access_level or "", 0)

    @property
    def can_view(self) -> bool:
        return self.rank >= ACCESS_LEVEL_RANK["view"]

    @property
    def can_launch(self) -> bool:
        return self.rank >= ACCESS_LEVEL_RANK["launch"]

    @property
    def can_manage(self) -> bool:
        return self.rank >= ACCESS_LEVEL_RANK["manage"]


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


def slugify_label(label: str) -> str:
    value = (label or "").strip().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = re.sub(r"-{2,}", "-", value).strip("-")
    return value or "file"


def generate_unique_slug(db: Session, folder_id: int | None, label: str) -> str:
    base = slugify_label(label)
    prefix = f"f{folder_id}-" if folder_id is not None else "root-"
    candidate = validate_slug(f"{prefix}{base}"[:180])
    if not db.query(FileResource).filter_by(slug=candidate).first():
        return candidate
    n = 2
    while True:
        candidate = validate_slug(f"{prefix}{base}-{n}"[:180])
        if not db.query(FileResource).filter_by(slug=candidate).first():
            return candidate
        n += 1


def parse_numeric_version(label: str | None) -> int | None:
    try:
        return int(str(label or "").strip())
    except (TypeError, ValueError):
        return None


def max_numeric_version_label(db: Session, file_id: int) -> int | None:
    best: int | None = None
    for (lab,) in db.query(FileVersion.version_label).filter_by(file_id=file_id).all():
        n = parse_numeric_version(lab)
        if n is None:
            continue
        if best is None or n > best:
            best = n
    return best


def _version_sort_key(version: FileVersion) -> tuple:
    n = parse_numeric_version(version.version_label)
    return (n if n is not None else -1, version.uploaded_at or utcnow())


def folder_ancestor_ids(db: Session, folder_id: int | None) -> list[int]:
    """Return [folder_id, parent, ..., root] for a folder (empty if folder_id is None)."""
    if folder_id is None:
        return []
    out: list[int] = []
    seen: set[int] = set()
    current = folder_id
    while current is not None:
        if current in seen:
            break
        seen.add(current)
        out.append(current)
        row = db.query(FileFolder).filter_by(id=current).first()
        if not row:
            break
        current = row.parent_folder_id
    return out


def folder_path_segments(db: Session, folder_id: int | None) -> list[dict]:
    """Breadcrumb segments from root to folder (excluding virtual Accueil)."""
    ids = list(reversed(folder_ancestor_ids(db, folder_id)))
    segments: list[dict] = []
    for fid in ids:
        row = db.query(FileFolder).filter_by(id=fid).first()
        if row:
            segments.append({"id": row.id, "name": row.name})
    return segments


def folder_path_label(db: Session, folder_id: int | None) -> str:
    segs = folder_path_segments(db, folder_id)
    if not segs:
        return "Accueil"
    return " / ".join(s["name"] for s in segs)


def _subject_grant_filters(
    *,
    keycloak_user_id: str | None,
    group_ids: list[int],
):
    clauses = []
    if keycloak_user_id:
        clauses.append(
            (
                AccessGrant.subject_type == "user",
                AccessGrant.keycloak_user_id == keycloak_user_id,
            )
        )
    if group_ids:
        clauses.append(
            (
                AccessGrant.subject_type == "group",
                AccessGrant.rbac_group_id.in_(group_ids),
            )
        )
    return clauses


def _collect_grants_for_targets(
    db: Session,
    *,
    keycloak_user_id: str | None,
    group_names: Sequence[str] | None,
    file_id: int | None = None,
    folder_ids: Sequence[int] | None = None,
) -> list[tuple[AccessGrant, str]]:
    """Return (grant, provenance_label) pairs applicable to file and/or folders."""
    names = [n for n in (group_names or []) if n]
    groups = db.query(RBACGroup).filter(RBACGroup.name.in_(names)).all() if names else []
    group_ids = [g.id for g in groups]
    group_by_id = {g.id: g for g in groups}
    results: list[tuple[AccessGrant, str]] = []

    def _add(grant: AccessGrant, source: str) -> None:
        results.append((grant, source))

    if keycloak_user_id:
        if file_id is not None:
            for g in (
                db.query(AccessGrant)
                .filter(
                    AccessGrant.subject_type == "user",
                    AccessGrant.keycloak_user_id == keycloak_user_id,
                    AccessGrant.resource_type == "file",
                    AccessGrant.file_id == file_id,
                )
                .all()
            ):
                _add(g, "direct sur le fichier")
        if folder_ids:
            for g in (
                db.query(AccessGrant)
                .filter(
                    AccessGrant.subject_type == "user",
                    AccessGrant.keycloak_user_id == keycloak_user_id,
                    AccessGrant.resource_type == "folder",
                    AccessGrant.folder_id.in_(list(folder_ids)),
                )
                .all()
            ):
                path = folder_path_label(db, g.folder_id)
                _add(g, f"via dossier {path}")

    if group_ids:
        if file_id is not None:
            for g in (
                db.query(AccessGrant)
                .filter(
                    AccessGrant.subject_type == "group",
                    AccessGrant.rbac_group_id.in_(group_ids),
                    AccessGrant.resource_type == "file",
                    AccessGrant.file_id == file_id,
                )
                .all()
            ):
                group = group_by_id.get(g.rbac_group_id) if g.rbac_group_id else None
                src = f"direct sur le fichier (via groupe {group.name})" if group else "direct sur le fichier"
                _add(g, src)
        if folder_ids:
            for g in (
                db.query(AccessGrant)
                .filter(
                    AccessGrant.subject_type == "group",
                    AccessGrant.rbac_group_id.in_(group_ids),
                    AccessGrant.resource_type == "folder",
                    AccessGrant.folder_id.in_(list(folder_ids)),
                )
                .all()
            ):
                path = folder_path_label(db, g.folder_id)
                group = group_by_id.get(g.rbac_group_id) if g.rbac_group_id else None
                src = (
                    f"via dossier {path} (groupe {group.name})"
                    if group
                    else f"via dossier {path}"
                )
                _add(g, src)

    return results


def get_effective_access_on_folder(
    db: Session,
    *,
    folder_id: int | None,
    keycloak_user_id: str | None = None,
    group_names: Sequence[str] | None = None,
    is_portal_admin: bool = False,
) -> EffectiveAccess:
    if is_portal_admin:
        return EffectiveAccess(access_level="manage", sources=["portal_admin"])
    ancestor_ids = folder_ancestor_ids(db, folder_id)
    # Root (None): only grants on nothing apply unless we treat "manage everywhere"
    # via portal_admin. Root listing uses grants on any root-child visibility separately.
    pairs = _collect_grants_for_targets(
        db,
        keycloak_user_id=keycloak_user_id,
        group_names=group_names,
        folder_ids=ancestor_ids,
    )
    best: str | None = None
    sources: list[str] = []
    grant_ids: list[int] = []
    for grant, source in pairs:
        level = grant.access_level or "view"
        if _rank(level) > _rank(best):
            best = level
        if source not in sources:
            sources.append(source)
        if grant.id not in grant_ids:
            grant_ids.append(grant.id)
    return EffectiveAccess(access_level=best, sources=sources, grant_ids=grant_ids)


def get_effective_access_on_file(
    db: Session,
    *,
    file: FileResource | int,
    keycloak_user_id: str | None = None,
    group_names: Sequence[str] | None = None,
    is_portal_admin: bool = False,
) -> EffectiveAccess:
    if is_portal_admin:
        return EffectiveAccess(access_level="manage", sources=["portal_admin"])
    fr = file if isinstance(file, FileResource) else db.query(FileResource).filter_by(id=file).first()
    if not fr:
        return EffectiveAccess(access_level=None)
    ancestor_ids = folder_ancestor_ids(db, fr.folder_id)
    pairs = _collect_grants_for_targets(
        db,
        keycloak_user_id=keycloak_user_id,
        group_names=group_names,
        file_id=fr.id,
        folder_ids=ancestor_ids,
    )
    best: str | None = None
    sources: list[str] = []
    grant_ids: list[int] = []
    for grant, source in pairs:
        level = grant.access_level or "view"
        if _rank(level) > _rank(best):
            best = level
        if source not in sources:
            sources.append(source)
        if grant.id not in grant_ids:
            grant_ids.append(grant.id)
    return EffectiveAccess(access_level=best, sources=sources, grant_ids=grant_ids)


def get_effective_file_channel(
    db: Session,
    *,
    file_id: int,
    keycloak_user_id: str | None = None,
    group_names: Sequence[str] | None = None,
) -> tuple[str, list[str]]:
    """Resolve beta|stable: union of assignments on the file + ancestor folders."""
    fr = db.query(FileResource).filter_by(id=file_id).first()
    if not fr:
        return "stable", ["default"]

    sources: list[str] = []
    names = [n for n in (group_names or []) if n]
    groups = db.query(RBACGroup).filter(RBACGroup.name.in_(names)).all() if names else []
    group_ids = [g.id for g in groups]
    group_by_id = {g.id: g for g in groups}
    folder_ids = folder_ancestor_ids(db, fr.folder_id)

    target_filters = [FileChannelAssignment.file_id == file_id]
    if folder_ids:
        target_filters.append(FileChannelAssignment.folder_id.in_(folder_ids))

    from sqlalchemy import or_

    base = db.query(FileChannelAssignment).filter(
        FileChannelAssignment.channel == "beta",
        or_(*target_filters),
    )

    if keycloak_user_id:
        for row in base.filter(
            FileChannelAssignment.subject_type == "user",
            FileChannelAssignment.keycloak_user_id == keycloak_user_id,
        ).all():
            if row.file_id:
                src = "direct"
            else:
                src = f"via dossier {folder_path_label(db, row.folder_id)}"
            if src not in sources:
                sources.append(src)

    if group_ids:
        for row in base.filter(
            FileChannelAssignment.subject_type == "group",
            FileChannelAssignment.rbac_group_id.in_(group_ids),
        ).all():
            group = group_by_id.get(row.rbac_group_id) if row.rbac_group_id else None
            if row.file_id:
                src = f"via groupe {group.name}" if group else "via groupe"
            else:
                path = folder_path_label(db, row.folder_id)
                src = (
                    f"via dossier {path} (groupe {group.name})"
                    if group
                    else f"via dossier {path}"
                )
            if src not in sources:
                sources.append(src)

    if sources:
        return "beta", sources
    return "stable", ["default"]


def get_effective_file_version(
    db: Session,
    file: FileResource | int,
    channel: str,
) -> FileVersion | None:
    """Highest numeric version among active candidates for the user's channel."""
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
    return max(rows, key=_version_sort_key)


def get_effective_files_for_user(
    db: Session,
    *,
    keycloak_user_id: str | None = None,
    group_names: Sequence[str] | None = None,
    is_portal_admin: bool = False,
) -> list[EffectiveFileAccess]:
    """All active files the user can at least view (direct or via folder inheritance)."""
    files = db.query(FileResource).filter_by(is_active=True).all()
    out: list[EffectiveFileAccess] = []
    for fr in files:
        access = get_effective_access_on_file(
            db,
            file=fr,
            keycloak_user_id=keycloak_user_id,
            group_names=group_names,
            is_portal_admin=is_portal_admin,
        )
        if not access.can_view:
            continue
        channel, _ = get_effective_file_channel(
            db,
            file_id=fr.id,
            keycloak_user_id=keycloak_user_id,
            group_names=group_names,
        )
        out.append(
            EffectiveFileAccess(
                file=fr,
                access_level=access.access_level or "view",
                channel=channel,
                effective_version=get_effective_file_version(db, fr, channel),
                sources=list(access.sources),
                grant_ids=list(access.grant_ids),
            )
        )
    return sorted(out, key=lambda e: (e.file.label or "").lower())


def user_can_download_file(
    db: Session,
    *,
    file_id: int,
    keycloak_user_id: str | None = None,
    group_names: Sequence[str] | None = None,
    is_portal_admin: bool = False,
) -> bool:
    access = get_effective_access_on_file(
        db,
        file=file_id,
        keycloak_user_id=keycloak_user_id,
        group_names=group_names,
        is_portal_admin=is_portal_admin,
    )
    return access.can_launch


def _folder_has_visible_descendant(
    db: Session,
    folder_id: int,
    *,
    keycloak_user_id: str | None,
    group_names: Sequence[str] | None,
    is_portal_admin: bool,
    cache: dict[int, bool],
) -> bool:
    if folder_id in cache:
        return cache[folder_id]
    for child in db.query(FileFolder).filter_by(parent_folder_id=folder_id).all():
        child_access = get_effective_access_on_folder(
            db,
            folder_id=child.id,
            keycloak_user_id=keycloak_user_id,
            group_names=group_names,
            is_portal_admin=is_portal_admin,
        )
        if child_access.can_view:
            cache[folder_id] = True
            return True
        if _folder_has_visible_descendant(
            db,
            child.id,
            keycloak_user_id=keycloak_user_id,
            group_names=group_names,
            is_portal_admin=is_portal_admin,
            cache=cache,
        ):
            cache[folder_id] = True
            return True
    for fr in db.query(FileResource).filter_by(folder_id=folder_id, is_active=True).all():
        access = get_effective_access_on_file(
            db,
            file=fr,
            keycloak_user_id=keycloak_user_id,
            group_names=group_names,
            is_portal_admin=is_portal_admin,
        )
        if access.can_view:
            cache[folder_id] = True
            return True
    cache[folder_id] = False
    return False


def list_folder_contents(
    db: Session,
    *,
    folder_id: int | None,
    keycloak_user_id: str | None = None,
    group_names: Sequence[str] | None = None,
    is_portal_admin: bool = False,
    q: str | None = None,
) -> dict:
    """Folders + files visible in one directory for the caller."""
    query = (q or "").strip().casefold()
    descendant_cache: dict[int, bool] = {}

    folders_out: list[dict] = []
    for folder in (
        db.query(FileFolder)
        .filter(FileFolder.parent_folder_id == folder_id)
        .order_by(FileFolder.name)
        .all()
    ):
        access = get_effective_access_on_folder(
            db,
            folder_id=folder.id,
            keycloak_user_id=keycloak_user_id,
            group_names=group_names,
            is_portal_admin=is_portal_admin,
        )
        visible = access.can_view or _folder_has_visible_descendant(
            db,
            folder.id,
            keycloak_user_id=keycloak_user_id,
            group_names=group_names,
            is_portal_admin=is_portal_admin,
            cache=descendant_cache,
        )
        if not visible:
            continue
        if query and query not in (folder.name or "").casefold():
            continue
        folders_out.append(
            {
                "id": folder.id,
                "name": folder.name,
                "kind": "folder",
                "access_level": access.access_level,
                "can_manage": access.can_manage,
                "sources": access.sources,
            }
        )

    files_out: list[dict] = []
    for fr in (
        db.query(FileResource)
        .filter(FileResource.folder_id == folder_id, FileResource.is_active.is_(True))
        .order_by(FileResource.label)
        .all()
    ):
        access = get_effective_access_on_file(
            db,
            file=fr,
            keycloak_user_id=keycloak_user_id,
            group_names=group_names,
            is_portal_admin=is_portal_admin,
        )
        if not access.can_view:
            continue
        if query and query not in (fr.label or "").casefold():
            continue
        channel, _ = get_effective_file_channel(
            db,
            file_id=fr.id,
            keycloak_user_id=keycloak_user_id,
            group_names=group_names,
        )
        version = get_effective_file_version(db, fr, channel)
        files_out.append(
            {
                "id": fr.id,
                "label": fr.label,
                "slug": fr.slug,
                "kind": "file",
                "access_level": access.access_level,
                "can_manage": access.can_manage,
                "can_download": access.can_launch and version is not None,
                "channel": channel,
                "version_label": version.version_label if version else None,
                "version_id": version.id if version else None,
                "size_bytes": version.size_bytes if version else None,
                "uploaded_at": version.uploaded_at.isoformat() if version and version.uploaded_at else None,
                "sources": access.sources,
            }
        )

    parent_access = get_effective_access_on_folder(
        db,
        folder_id=folder_id,
        keycloak_user_id=keycloak_user_id,
        group_names=group_names,
        is_portal_admin=is_portal_admin,
    )
    # Root: allow manage for portal_admin; for others, manage if they have manage
    # on any grant that would let them create at root — treated as portal_admin only
    # unless they have a folder grant (root has no folder_id). Creating at root
    # requires portal_admin OR we introduce virtual root grants later.
    can_manage_here = parent_access.can_manage or (
        folder_id is None and is_portal_admin
    )

    return {
        "folder_id": folder_id,
        "breadcrumb": folder_path_segments(db, folder_id),
        "can_manage": can_manage_here,
        "folders": folders_out,
        "files": files_out,
    }


def create_folder(
    db: Session,
    *,
    name: str,
    parent_folder_id: int | None,
    created_by: str,
) -> FileFolder:
    name = (name or "").strip()
    if not name:
        raise ValueError("Le nom du dossier est obligatoire")
    if parent_folder_id is not None:
        parent = db.query(FileFolder).filter_by(id=parent_folder_id).first()
        if not parent:
            raise ValueError("Dossier parent introuvable")
    existing = (
        db.query(FileFolder)
        .filter_by(parent_folder_id=parent_folder_id, name=name)
        .first()
    )
    if existing:
        raise ValueError(f"Un dossier « {name} » existe déjà ici")
    folder = FileFolder(
        parent_folder_id=parent_folder_id,
        name=name,
        created_by=created_by,
    )
    db.add(folder)
    db.flush()
    return folder


def create_file_resource(
    db: Session,
    *,
    slug: str | None = None,
    label: str,
    description: str | None = None,
    category: str | None = None,
    is_active: bool = True,
    created_by: str,
    folder_id: int | None = None,
) -> FileResource:
    label = (label or "").strip()
    if not label:
        raise ValueError("Le nom du fichier est obligatoire")
    existing = (
        db.query(FileResource)
        .filter_by(folder_id=folder_id, label=label)
        .first()
    )
    if existing:
        raise ValueError(f"Un fichier « {label} » existe déjà dans ce dossier")
    if slug:
        slug = validate_slug(slug)
        if db.query(FileResource).filter_by(slug=slug).first():
            raise ValueError(f"Un fichier avec le slug « {slug} » existe déjà")
    else:
        slug = generate_unique_slug(db, folder_id, label)
    fr = FileResource(
        folder_id=folder_id,
        slug=slug,
        label=label,
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
    label = (version_label or "").strip()
    if not label:
        raise ValueError("version_label is required")
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


def deposit_file(
    db: Session,
    *,
    folder_id: int | None,
    filename: str,
    content_type: str | None,
    data: bytes,
    uploaded_by: str,
    keycloak_user_id: str | None = None,
    group_names: Sequence[str] | None = None,
    is_portal_admin: bool = False,
    settings: Settings | None = None,
) -> tuple[FileResource, FileVersion, bool]:
    """Zero-form deposit: same (folder_id, label) → auto-increment version.

    Returns (file_resource, version, created_new_file).
    """
    label = (filename or "").strip() or "upload.bin"
    if folder_id is not None:
        folder = db.query(FileFolder).filter_by(id=folder_id).first()
        if not folder:
            raise ValueError("Dossier introuvable")

    existing = (
        db.query(FileResource)
        .filter_by(folder_id=folder_id, label=label, is_active=True)
        .first()
    )

    if existing is None:
        folder_access = get_effective_access_on_folder(
            db,
            folder_id=folder_id,
            keycloak_user_id=keycloak_user_id,
            group_names=group_names,
            is_portal_admin=is_portal_admin,
        )
        if not folder_access.can_manage and not (
            folder_id is None and is_portal_admin
        ):
            raise PermissionError("Droit manage requis pour créer un fichier ici")
        fr = create_file_resource(
            db,
            label=label,
            folder_id=folder_id,
            created_by=uploaded_by,
        )
        created_new = True
        next_version = 1
    else:
        file_access = get_effective_access_on_file(
            db,
            file=existing,
            keycloak_user_id=keycloak_user_id,
            group_names=group_names,
            is_portal_admin=is_portal_admin,
        )
        if not file_access.can_manage:
            raise PermissionError("Droit manage requis pour publier une version")
        fr = existing
        created_new = False
        next_version = (max_numeric_version_label(db, fr.id) or 0) + 1

    version = store_file_version(
        db,
        file=fr,
        channel="stable",
        version_label=str(next_version),
        filename=label,
        content_type=content_type,
        data=data,
        uploaded_by=uploaded_by,
        settings=settings,
        encrypt=True,
    )
    return fr, version, created_new


def set_version_channel(db: Session, version: FileVersion, channel: str) -> FileVersion:
    channel = (channel or "").strip().lower()
    if channel not in CHANNELS:
        raise ValueError("channel must be beta or stable")
    if version.status != "active":
        raise ValueError("Seule une version active peut changer de canal")
    version.channel = channel
    db.flush()
    return version


def rename_version_label(db: Session, version: FileVersion, new_label: str) -> FileVersion:
    label = (new_label or "").strip()
    if not label:
        raise ValueError("Libellé de version obligatoire")
    dup = (
        db.query(FileVersion)
        .filter(
            FileVersion.file_id == version.file_id,
            FileVersion.version_label == label,
            FileVersion.id != version.id,
        )
        .first()
    )
    if dup:
        raise ValueError(f"La version « {label} » existe déjà pour ce fichier")
    version.version_label = label
    db.flush()
    return version


def rename_file_resource(db: Session, file: FileResource, new_label: str) -> FileResource:
    label = (new_label or "").strip()
    if not label:
        raise ValueError("Nom de fichier obligatoire")
    dup = (
        db.query(FileResource)
        .filter(
            FileResource.folder_id == file.folder_id,
            FileResource.label == label,
            FileResource.id != file.id,
        )
        .first()
    )
    if dup:
        raise ValueError(f"Un fichier « {label} » existe déjà dans ce dossier")
    file.label = label
    db.flush()
    return file


def archive_file_resource(db: Session, file: FileResource) -> FileResource:
    file.is_active = False
    db.flush()
    return file


def promote_file_version(db: Session, version: FileVersion) -> FileVersion:
    """Legacy promote beta → stable (also used by toggle toward stable)."""
    return set_version_channel(db, version, "stable")


def archive_file_version(db: Session, version: FileVersion) -> FileVersion:
    version.status = "archived"
    db.flush()
    return version


def assign_beta_channel(
    db: Session,
    *,
    file_id: int | None = None,
    folder_id: int | None = None,
    subject_type: str,
    rbac_group_id: int | None = None,
    keycloak_user_id: str | None = None,
    user_display_cache: str | None = None,
    assigned_by: str,
) -> FileChannelAssignment:
    if (file_id is None) == (folder_id is None):
        raise ValueError("Provide exactly one of file_id or folder_id")
    if subject_type == "group":
        if not rbac_group_id or keycloak_user_id:
            raise ValueError("group assignments require rbac_group_id only")
        q = db.query(FileChannelAssignment).filter(
            FileChannelAssignment.subject_type == "group",
            FileChannelAssignment.rbac_group_id == rbac_group_id,
        )
    elif subject_type == "user":
        if not keycloak_user_id or rbac_group_id:
            raise ValueError("user assignments require keycloak_user_id only")
        q = db.query(FileChannelAssignment).filter(
            FileChannelAssignment.subject_type == "user",
            FileChannelAssignment.keycloak_user_id == keycloak_user_id,
        )
    else:
        raise ValueError("subject_type must be group or user")

    if file_id is not None:
        q = q.filter(FileChannelAssignment.file_id == file_id)
    else:
        q = q.filter(FileChannelAssignment.folder_id == folder_id)

    existing = q.first()
    if existing:
        return existing

    row = FileChannelAssignment(
        file_id=file_id,
        folder_id=folder_id,
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


def list_file_versions(db: Session, file_id: int) -> list[FileVersion]:
    return (
        db.query(FileVersion)
        .filter_by(file_id=file_id)
        .order_by(FileVersion.uploaded_at.desc())
        .all()
    )


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
        with path.open("rb") as fh:
            while True:
                block = fh.read(DEFAULT_CHUNK_SIZE)
                if not block:
                    break
                yield block


def validate_version_label(label: str) -> str:
    """Free-form version label (auto-numeric at deposit; rename may set any text)."""
    value = (label or "").strip()
    if not value:
        raise ValueError("version_label is required")
    return value
