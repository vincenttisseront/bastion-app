"""Parse local Python/npm dependencies and refresh latest versions from registries."""

from __future__ import annotations

import json
import logging
import os
import re
import tomllib
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.models import DependencySnapshot, utcnow
from app.testing_framework.throttle import throttle_retry_after

logger = logging.getLogger(__name__)

LOOKUP_TIMEOUT_SECONDS = 5.0
REFRESH_THROTTLE_SECONDS = 30.0

# Declared name (after stripping extras) → importlib.metadata distribution name.
_PYTHON_DIST_ALIASES: dict[str, str] = {
    "pyjwt": "PyJWT",
    "pillow": "Pillow",
    "pyyaml": "PyYAML",
}

_REQ_NAME_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?",
)
_SEMVER_RE = re.compile(
    r"^v?(?P<major>\d+)(?:\.(?P<minor>\d+))?(?:\.(?P<patch>\d+))?",
)


class ManifestMissingError(FileNotFoundError):
    """Raised when pyproject.toml / package.json is not present in the runtime image."""

    def __init__(self, path: Path, *, hint: str | None = None):
        self.path = path
        msg = (
            f"{path.name} introuvable ({path}) — "
            + (hint or "vérifier le Dockerfile (COPY des manifestes vers BASTION_MANIFEST_ROOT)")
        )
        super().__init__(msg)


@dataclass(frozen=True)
class LocalDependency:
    ecosystem: str  # python | npm
    name: str
    declared_version: str  # constraint from manifest
    current_version: str  # installed / locked
    dep_type: str  # runtime | dev
    notes: str | None = None
    is_direct: bool = True  # False = npm lockfile transitive


def resolve_manifest_root() -> Path:
    """
    Locate directory that holds pyproject.toml / package.json.

    Docker runtime installs the app into site-packages, so Path(__file__) is NOT
    the repo root — manifests are copied to /app (BASTION_MANIFEST_ROOT).
    """
    env = (os.environ.get("BASTION_MANIFEST_ROOT") or "").strip()
    if env:
        return Path(env)
    source_root = Path(__file__).resolve().parents[2]
    for candidate in (Path("/app"), Path.cwd(), source_root):
        if (candidate / "pyproject.toml").is_file() or (candidate / "package.json").is_file():
            return candidate
    return Path("/app")


def pyproject_path(root: Path | None = None) -> Path:
    return (root or resolve_manifest_root()) / "pyproject.toml"


def package_json_path(root: Path | None = None) -> Path:
    return (root or resolve_manifest_root()) / "package.json"


def compute_status(current: str | None, latest: str | None) -> str:
    """Compare SemVer-ish versions → up_to_date / outdated_* / unknown."""
    cur = _parse_semver(current)
    lat = _parse_semver(latest)
    if cur is None or lat is None:
        return "unknown"
    if lat <= cur:
        return "up_to_date"
    if lat[0] > cur[0]:
        return "outdated_major"
    if lat[1] > cur[1]:
        return "outdated_minor"
    return "outdated_patch"


def _parse_semver(value: str | None) -> tuple[int, int, int] | None:
    if not value:
        return None
    cleaned = value.strip()
    cleaned = cleaned.split("+", 1)[0]
    cleaned = cleaned.split("!", 1)[0]
    m = _SEMVER_RE.match(cleaned)
    if not m:
        return None
    return (
        int(m.group("major")),
        int(m.group("minor") or 0),
        int(m.group("patch") or 0),
    )


def _requirement_name(spec: str) -> str | None:
    m = _REQ_NAME_RE.match(spec.strip())
    return m.group(1) if m else None


def _declared_constraint(spec: str, name: str) -> str:
    """Return constraint part of a requirement (e.g. '>=0.115' or '[standard]>=0.49')."""
    s = spec.strip()
    m = re.match(rf"(?i)^{re.escape(name)}(\[[^\]]*\])?(.*)$", s)
    if not m:
        return s
    extras = m.group(1) or ""
    rest = (m.group(2) or "").strip()
    if extras and rest:
        return f"{extras}{rest}"
    if extras:
        return extras
    return rest or s


def _resolve_python_installed(declared_name: str) -> str | None:
    """Return installed distribution version, or None if not found."""
    candidates = [declared_name]
    alias = _PYTHON_DIST_ALIASES.get(declared_name.lower())
    if alias and alias not in candidates:
        candidates.append(alias)
    for candidate in candidates:
        try:
            return importlib_metadata.version(candidate)
        except importlib_metadata.PackageNotFoundError:
            continue
    return None


def parse_python_dependencies(
    pyproject_file: Path | None = None,
    *,
    version_resolver=_resolve_python_installed,
    require_manifest: bool = True,
) -> list[LocalDependency]:
    path = pyproject_file or pyproject_path()
    if not path.is_file():
        msg = (
            f"pyproject.toml introuvable dans le conteneur ({path}) — "
            "vérifier le Dockerfile"
        )
        logger.error(msg)
        if require_manifest:
            raise ManifestMissingError(path, hint="vérifier le Dockerfile")
        return []
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    project = data.get("project") or {}
    runtime_specs = list(project.get("dependencies") or [])
    optional = project.get("optional-dependencies") or {}
    dev_specs = list(optional.get("dev") or [])

    out: list[LocalDependency] = []
    seen: set[str] = set()

    def add(spec: str, dep_type: str) -> None:
        name = _requirement_name(spec)
        if not name:
            return
        key = name.lower()
        if key in seen:
            return
        seen.add(key)
        declared = _declared_constraint(str(spec), name)
        installed = version_resolver(name)
        if installed:
            current = installed
            notes = None
        else:
            current = "—"
            notes = "not_installed"
        out.append(
            LocalDependency(
                ecosystem="python",
                name=name,
                declared_version=declared,
                current_version=current,
                dep_type=dep_type,
                notes=notes,
            )
        )

    for spec in runtime_specs:
        add(str(spec), "runtime")
    for spec in dev_specs:
        add(str(spec), "dev")
    return out


def _parse_pnpm_lock_versions(path: Path) -> dict[str, str]:
    """Best-effort parse of pnpm-lock.yaml without a YAML dependency for package versions."""
    versions: dict[str, str] = {}
    pkg_re = re.compile(
        r"^\s{2}['\"]?(?:/(?P<scoped>@[^/@]+/[^/@]+)|(?P<name>[^/@][^@]*))@(?P<ver>[^:'\"]+)"
    )
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return versions
    in_packages = False
    for line in text.splitlines():
        if line.startswith("packages:"):
            in_packages = True
            continue
        if in_packages and line and not line.startswith(" ") and not line.startswith("\t"):
            break
        if not in_packages:
            continue
        m = pkg_re.match(line)
        if not m:
            continue
        name = m.group("scoped") or m.group("name")
        ver = m.group("ver")
        if name and ver and name not in versions:
            versions[name] = ver
    return versions


def _load_npm_lock_entries(repo_root: Path) -> dict[str, dict[str, Any]] | None:
    """
    Return package name → {version, dep_type} for top-level lockfile entries.
    None if no lockfile is present.
    """
    lock_path = repo_root / "package-lock.json"
    pnpm_path = repo_root / "pnpm-lock.yaml"
    if lock_path.is_file():
        data = json.loads(lock_path.read_text(encoding="utf-8"))
        packages = data.get("packages") or {}
        entries: dict[str, dict[str, Any]] = {}
        for key, meta in packages.items():
            if not key or key == "":
                continue
            prefix = "node_modules/"
            if not key.startswith(prefix):
                continue
            rest = key[len(prefix) :]
            # Prefer top-level installs (skip nested node_modules copies)
            if "/node_modules/" in rest:
                continue
            ver = (meta or {}).get("version")
            if not ver:
                continue
            is_dev = bool((meta or {}).get("dev"))
            entries[rest] = {
                "version": str(ver),
                "dep_type": "dev" if is_dev else "runtime",
            }
        return entries
    if pnpm_path.is_file():
        versions = _parse_pnpm_lock_versions(pnpm_path)
        return {
            name: {"version": ver, "dep_type": "runtime"}
            for name, ver in versions.items()
        }
    return None


def parse_npm_dependencies(
    package_json_file: Path | None = None,
    *,
    repo_root: Path | None = None,
    require_manifest: bool = True,
) -> list[LocalDependency]:
    """
    Inventory npm packages from the lockfile (all resolved deps) when present.

    package.json only marks which packages are direct (is_direct) and their
    declared ranges; transitive lockfile packages are included with is_direct=False.
    """
    root = repo_root or resolve_manifest_root()
    pkg_path = package_json_file or (root / "package.json")
    if not pkg_path.is_file():
        msg = (
            f"package.json introuvable dans le conteneur ({pkg_path}) — "
            "vérifier le Dockerfile"
        )
        logger.error(msg)
        if require_manifest:
            raise ManifestMissingError(pkg_path, hint="vérifier le Dockerfile")
        return []
    data = json.loads(pkg_path.read_text(encoding="utf-8"))
    deps = dict(data.get("dependencies") or {})
    dev_deps = dict(data.get("devDependencies") or {})
    direct_specs: dict[str, tuple[str, str]] = {}
    for name, spec in deps.items():
        direct_specs[str(name)] = (str(spec), "runtime")
    for name, spec in dev_deps.items():
        direct_specs[str(name)] = (str(spec), "dev")

    locked = _load_npm_lock_entries(root)
    out: list[LocalDependency] = []

    if locked is None:
        # No lockfile: fall back to package.json directs only
        for name, (declared, dep_type) in sorted(direct_specs.items()):
            out.append(
                LocalDependency(
                    ecosystem="npm",
                    name=name,
                    declared_version=declared,
                    current_version=declared,
                    dep_type=dep_type,
                    notes="unlocked",
                    is_direct=True,
                )
            )
        return out

    # Lockfile is source of truth: every top-level package entry
    all_names = set(locked.keys()) | set(direct_specs.keys())
    for name in sorted(all_names):
        is_direct = name in direct_specs
        if is_direct:
            declared, dep_type = direct_specs[name]
        else:
            declared = ""
            dep_type = locked.get(name, {}).get("dep_type", "runtime")
        if name in locked:
            current = locked[name]["version"]
            notes = None
        else:
            # Declared in package.json but missing from lock (edge case)
            current = declared or "—"
            notes = "unlocked"
        out.append(
            LocalDependency(
                ecosystem="npm",
                name=name,
                declared_version=declared,
                current_version=current,
                dep_type=dep_type,
                notes=notes,
                is_direct=is_direct,
            )
        )
    return out


def fetch_pypi_latest(name: str, *, client: httpx.Client | None = None) -> str:
    url = f"https://pypi.org/pypi/{name}/json"
    own = client is None
    http = client or httpx.Client(timeout=LOOKUP_TIMEOUT_SECONDS)
    try:
        resp = http.get(url)
        resp.raise_for_status()
        info = resp.json().get("info") or {}
        version = info.get("version")
        if not version:
            raise ValueError("missing info.version")
        return str(version)
    finally:
        if own:
            http.close()


def fetch_npm_latest(name: str, *, client: httpx.Client | None = None) -> str:
    encoded = name.replace("/", "%2F")
    url = f"https://registry.npmjs.org/{encoded}/latest"
    own = client is None
    http = client or httpx.Client(timeout=LOOKUP_TIMEOUT_SECONDS)
    try:
        resp = http.get(url)
        resp.raise_for_status()
        version = resp.json().get("version")
        if not version:
            raise ValueError("missing version")
        return str(version)
    finally:
        if own:
            http.close()


def sync_local_to_db(
    db: Session,
    *,
    python_deps: list[LocalDependency] | None = None,
    npm_deps: list[LocalDependency] | None = None,
) -> list[DependencySnapshot]:
    """Upsert local inventory rows; preserve latest_version / last_checked when present."""
    locals_ = list(python_deps if python_deps is not None else parse_python_dependencies())
    locals_ += list(npm_deps if npm_deps is not None else parse_npm_dependencies())

    existing = {
        (row.ecosystem, row.name): row
        for row in db.query(DependencySnapshot).all()
    }
    keep_keys = {(d.ecosystem, d.name) for d in locals_}
    rows: list[DependencySnapshot] = []

    for dep in locals_:
        key = (dep.ecosystem, dep.name)
        row = existing.get(key)
        if row is None:
            row = DependencySnapshot(
                ecosystem=dep.ecosystem,
                name=dep.name,
                declared_version=dep.declared_version,
                current_version=dep.current_version,
                dep_type=dep.dep_type,
                is_direct=dep.is_direct,
                status="unknown",
                notes=dep.notes,
            )
            db.add(row)
        else:
            row.declared_version = dep.declared_version
            row.current_version = dep.current_version
            row.dep_type = dep.dep_type
            row.is_direct = dep.is_direct
            row.notes = dep.notes
            if row.latest_version:
                row.status = compute_status(row.current_version, row.latest_version)
            else:
                row.status = "unknown"
        rows.append(row)

    for key, row in existing.items():
        if key not in keep_keys:
            db.delete(row)

    db.flush()
    return rows


def refresh_latest_versions(
    db: Session,
    *,
    client: httpx.Client | None = None,
    python_deps: list[LocalDependency] | None = None,
    npm_deps: list[LocalDependency] | None = None,
    skip_throttle: bool = False,
) -> dict[str, Any]:
    """
    Sync local packages then lookup latest versions on PyPI / npm registry.
    Returns summary dict; never raises for per-package lookup failures.
    Raises ManifestMissingError when manifests cannot be read (unless deps injected).
    """
    if not skip_throttle:
        wait = throttle_retry_after(
            "dependencies",
            "refresh",
            min_interval_seconds=REFRESH_THROTTLE_SECONDS,
        )
        if wait is not None:
            return {
                "ok": False,
                "throttled": True,
                "retry_after": wait,
                "checked": 0,
                "errors": 0,
                "message": f"Trop de rafraîchissements — réessayez dans {wait:.0f}s",
            }

    rows = sync_local_to_db(db, python_deps=python_deps, npm_deps=npm_deps)
    own_client = client is None
    http = client or httpx.Client(timeout=LOOKUP_TIMEOUT_SECONDS)
    checked = 0
    errors = 0
    now = utcnow()

    try:
        for row in rows:
            try:
                if row.ecosystem == "python":
                    latest = fetch_pypi_latest(row.name, client=http)
                elif row.ecosystem == "npm":
                    latest = fetch_npm_latest(row.name, client=http)
                else:
                    raise ValueError(f"unknown ecosystem: {row.ecosystem}")
                row.latest_version = latest
                row.status = compute_status(row.current_version, latest)
                row.check_error = None
                row.last_checked_at = now
                checked += 1
            except Exception as exc:  # noqa: BLE001 — per-package isolation
                errors += 1
                row.status = "unknown"
                row.check_error = str(exc)[:500]
                row.last_checked_at = now
                logger.warning(
                    "dependency lookup failed ecosystem=%s name=%s: %s",
                    row.ecosystem,
                    row.name,
                    exc,
                )
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        if own_client:
            http.close()

    return {
        "ok": True,
        "throttled": False,
        "checked": checked,
        "errors": errors,
        "total": len(rows),
        "message": (
            f"{checked} paquet(s) vérifié(s)"
            + (f", {errors} erreur(s)" if errors else "")
        ),
    }


def list_snapshots(
    db: Session,
    *,
    ecosystem: str | None = None,
    outdated_only: bool = False,
) -> list[DependencySnapshot]:
    q = db.query(DependencySnapshot).order_by(
        DependencySnapshot.ecosystem.asc(),
        DependencySnapshot.name.asc(),
    )
    if ecosystem:
        q = q.filter(DependencySnapshot.ecosystem == ecosystem)
    if outdated_only:
        q = q.filter(
            DependencySnapshot.status.in_(
                ("outdated_patch", "outdated_minor", "outdated_major")
            )
        )
    return q.all()


def snapshots_to_export(
    rows: list[DependencySnapshot],
    *,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    ts = generated_at or datetime.now(timezone.utc)
    return {
        "generated_at": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "packages": [
            {
                "ecosystem": r.ecosystem,
                "name": r.name,
                "type": r.dep_type,
                "is_direct": bool(r.is_direct),
                "declared_version": r.declared_version,
                "current_version": r.current_version,
                "latest_version": r.latest_version,
                "status": r.status,
                "last_checked_at": (
                    r.last_checked_at.strftime("%Y-%m-%dT%H:%M:%SZ")
                    if r.last_checked_at
                    else None
                ),
                "notes": r.notes,
                "check_error": r.check_error,
            }
            for r in rows
        ],
    }


def last_checked_summary(rows: list[DependencySnapshot]) -> datetime | None:
    times = [r.last_checked_at for r in rows if r.last_checked_at]
    return max(times) if times else None


def count_summary(rows: list[DependencySnapshot]) -> dict[str, int]:
    outdated = sum(1 for r in rows if (r.status or "").startswith("outdated_"))
    up_to_date = sum(1 for r in rows if r.status == "up_to_date")
    return {
        "total": len(rows),
        "outdated": outdated,
        "up_to_date": up_to_date,
        "unknown": len(rows) - outdated - up_to_date,
    }
