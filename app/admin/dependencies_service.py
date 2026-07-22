"""Parse local Python/npm dependencies and refresh latest versions from registries."""

from __future__ import annotations

import json
import logging
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

REPO_ROOT = Path(__file__).resolve().parents[2]
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"
PACKAGE_JSON_PATH = REPO_ROOT / "package.json"
PACKAGE_LOCK_PATH = REPO_ROOT / "package-lock.json"
PNPM_LOCK_PATH = REPO_ROOT / "pnpm-lock.yaml"

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


@dataclass(frozen=True)
class LocalDependency:
    ecosystem: str  # python | npm
    name: str
    current_version: str
    dep_type: str  # runtime | dev
    notes: str | None = None


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
    # Drop PEP 440 local/dev suffixes after + or common prerelease markers for core compare
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


def _resolve_python_installed(declared_name: str) -> str | None:
    """Return installed distribution version, or None if not found."""
    candidates = [declared_name]
    alias = _PYTHON_DIST_ALIASES.get(declared_name.lower())
    if alias and alias not in candidates:
        candidates.append(alias)
    # importlib often accepts canonical case-insensitive names
    for candidate in candidates:
        try:
            return importlib_metadata.version(candidate)
        except importlib_metadata.PackageNotFoundError:
            continue
    return None


def parse_python_dependencies(
    pyproject_path: Path | None = None,
    *,
    version_resolver=_resolve_python_installed,
) -> list[LocalDependency]:
    path = pyproject_path or PYPROJECT_PATH
    if not path.is_file():
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
        installed = version_resolver(name)
        if installed:
            current = installed
            notes = None
        else:
            current = spec.strip()
            notes = "not_installed"
        out.append(
            LocalDependency(
                ecosystem="python",
                name=name,
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


def _load_npm_lock_versions(repo_root: Path) -> dict[str, str] | None:
    """Return package name → locked version, or None if no lockfile."""
    lock_path = repo_root / "package-lock.json"
    pnpm_path = repo_root / "pnpm-lock.yaml"
    if lock_path.is_file():
        data = json.loads(lock_path.read_text(encoding="utf-8"))
        packages = data.get("packages") or {}
        versions: dict[str, str] = {}
        for key, meta in packages.items():
            if not key or key == "":
                continue
            # packages["node_modules/foo"] or packages["node_modules/@scope/pkg"]
            prefix = "node_modules/"
            if not key.startswith(prefix):
                continue
            rest = key[len(prefix) :]
            # Skip nested deps under another package's node_modules
            if "/node_modules/" in rest:
                continue
            ver = (meta or {}).get("version")
            if ver:
                versions[rest] = str(ver)
        return versions
    if pnpm_path.is_file():
        # Minimal pnpm lock support: importers / packages blocks vary by lockfileVersion.
        # Prefer npm lock in this repo; if only pnpm exists, parse packages: keys.
        versions = _parse_pnpm_lock_versions(pnpm_path)
        return versions
    return None


def _parse_pnpm_lock_versions(path: Path) -> dict[str, str]:
    """Best-effort parse of pnpm-lock.yaml without a YAML dependency for package versions."""
    versions: dict[str, str] = {}
    # Match lines like:  /@playwright/test@1.49.0:  or  playwright@1.49.0:
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


def parse_npm_dependencies(
    package_json_path: Path | None = None,
    *,
    repo_root: Path | None = None,
) -> list[LocalDependency]:
    pkg_path = package_json_path or PACKAGE_JSON_PATH
    root = repo_root or (pkg_path.parent if package_json_path else REPO_ROOT)
    if not pkg_path.is_file():
        return []
    data = json.loads(pkg_path.read_text(encoding="utf-8"))
    deps = dict(data.get("dependencies") or {})
    dev_deps = dict(data.get("devDependencies") or {})
    locked = _load_npm_lock_versions(root)

    out: list[LocalDependency] = []
    seen: set[str] = set()

    def add(name: str, range_spec: str, dep_type: str) -> None:
        if name in seen:
            return
        seen.add(name)
        if locked is None:
            current = str(range_spec)
            notes = "unlocked"
        elif name in locked:
            current = locked[name]
            notes = None
        else:
            current = str(range_spec)
            notes = "unlocked"
        out.append(
            LocalDependency(
                ecosystem="npm",
                name=name,
                current_version=current,
                dep_type=dep_type,
                notes=notes,
            )
        )

    for name, spec in deps.items():
        add(str(name), str(spec), "runtime")
    for name, spec in dev_deps.items():
        add(str(name), str(spec), "dev")
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
    # Scoped packages need encoding: @scope/pkg → @scope%2Fpkg
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
                current_version=dep.current_version,
                dep_type=dep.dep_type,
                status="unknown",
                notes=dep.notes,
            )
            db.add(row)
        else:
            row.current_version = dep.current_version
            row.dep_type = dep.dep_type
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
