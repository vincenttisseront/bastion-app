"""Tests for admin Dependencies inventory (Python + npm)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.admin.dependencies_service import (
    LocalDependency,
    ManifestMissingError,
    compute_status,
    fetch_npm_latest,
    fetch_pypi_latest,
    parse_npm_dependencies,
    parse_python_dependencies,
    refresh_latest_versions,
    snapshots_to_export,
    sync_local_to_db,
)
from app.models import DependencySnapshot
from app.testing_framework.throttle import reset_throttles

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}
USER_HEADERS = {
    "X-Email": "user@example.com",
    "X-Groups": "transfer-users",
}


@pytest.fixture(autouse=True)
def _reset_dep_throttle():
    reset_throttles()
    yield
    reset_throttles()


def _dep(
    ecosystem: str,
    name: str,
    current: str,
    dep_type: str,
    *,
    declared: str | None = None,
    is_direct: bool = True,
) -> LocalDependency:
    return LocalDependency(
        ecosystem=ecosystem,
        name=name,
        declared_version=declared if declared is not None else current,
        current_version=current,
        dep_type=dep_type,
        is_direct=is_direct,
    )


# ---------------------------------------------------------------------------
# Unit: SemVer status
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "current,latest,expected",
    [
        ("1.2.3", "1.2.3", "up_to_date"),
        ("1.2.3", "1.2.4", "outdated_patch"),
        ("1.2.3", "1.3.0", "outdated_minor"),
        ("1.2.3", "2.0.0", "outdated_major"),
        ("2.0.0", "1.9.9", "up_to_date"),
        ("1.2.3", None, "unknown"),
        (None, "1.0.0", "unknown"),
        ("not-a-version", "1.0.0", "unknown"),
        ("v1.0.0", "v1.0.1", "outdated_patch"),
    ],
)
def test_compute_status(current, latest, expected):
    assert compute_status(current, latest) == expected


# ---------------------------------------------------------------------------
# Unit: Python parsing
# ---------------------------------------------------------------------------


def test_parse_python_dependencies_nominal(tmp_path: Path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
dependencies = [
  "fastapi>=0.115",
  "uvicorn[standard]>=0.49",
  "PyJWT>=2.9",
]
[project.optional-dependencies]
dev = [
  "pytest>=8.0",
]
""",
        encoding="utf-8",
    )

    versions = {
        "fastapi": "0.115.0",
        "uvicorn": "0.49.0",
        "PyJWT": "2.9.0",
        "pytest": "8.3.3",
    }

    def resolver(name: str):
        return versions.get(name) or versions.get(
            {"PyJWT": "PyJWT"}.get(name, name)
        )

    deps = parse_python_dependencies(pyproject, version_resolver=resolver)
    by_name = {d.name: d for d in deps}
    assert by_name["fastapi"].current_version == "0.115.0"
    assert by_name["fastapi"].declared_version == ">=0.115"
    assert by_name["fastapi"].dep_type == "runtime"
    assert by_name["uvicorn"].current_version == "0.49.0"
    assert by_name["uvicorn"].declared_version == "[standard]>=0.49"
    assert by_name["PyJWT"].current_version == "2.9.0"
    assert by_name["pytest"].dep_type == "dev"
    assert by_name["pytest"].current_version == "8.3.3"


def test_parse_python_missing_package_no_crash(tmp_path: Path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
dependencies = ["totally-missing-pkg>=1.0"]
""",
        encoding="utf-8",
    )
    deps = parse_python_dependencies(
        pyproject, version_resolver=lambda _n: None
    )
    assert len(deps) == 1
    assert deps[0].name == "totally-missing-pkg"
    assert deps[0].notes == "not_installed"
    assert deps[0].declared_version == ">=1.0"
    assert deps[0].current_version == "—"


def test_parse_python_manifest_missing_raises(tmp_path: Path):
    missing = tmp_path / "no-such-pyproject.toml"
    with pytest.raises(ManifestMissingError) as exc:
        parse_python_dependencies(missing)
    assert "pyproject.toml" in str(exc.value).lower() or "introuvable" in str(exc.value)


def test_parse_python_manifest_missing_silent_when_optional(tmp_path: Path):
    missing = tmp_path / "no-such-pyproject.toml"
    assert parse_python_dependencies(missing, require_manifest=False) == []


def test_parse_python_real_pyproject():
    """Smoke: real repo pyproject.toml is parseable without crashing."""
    deps = parse_python_dependencies()
    names = {d.name.lower() for d in deps}
    assert "fastapi" in names
    assert "pytest" in names
    assert all(d.declared_version for d in deps)


# ---------------------------------------------------------------------------
# Unit: npm parsing
# ---------------------------------------------------------------------------


def test_parse_npm_with_lockfile(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "demo",
                "dependencies": {"left-pad": "^1.3.0"},
                "devDependencies": {"@playwright/test": "^1.49.0"},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "demo"},
                    "node_modules/left-pad": {"version": "1.3.0"},
                    "node_modules/@playwright/test": {
                        "version": "1.49.1",
                        "dev": True,
                    },
                    "node_modules/playwright": {
                        "version": "1.49.1",
                        "dev": True,
                    },
                    "node_modules/playwright-core": {
                        "version": "1.49.1",
                        "dev": True,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    deps = parse_npm_dependencies(tmp_path / "package.json", repo_root=tmp_path)
    by_name = {d.name: d for d in deps}
    assert set(by_name) == {
        "left-pad",
        "@playwright/test",
        "playwright",
        "playwright-core",
    }
    assert by_name["left-pad"].current_version == "1.3.0"
    assert by_name["left-pad"].declared_version == "^1.3.0"
    assert by_name["left-pad"].dep_type == "runtime"
    assert by_name["left-pad"].is_direct is True
    assert by_name["@playwright/test"].current_version == "1.49.1"
    assert by_name["@playwright/test"].dep_type == "dev"
    assert by_name["@playwright/test"].is_direct is True
    assert by_name["@playwright/test"].notes is None
    assert by_name["playwright"].is_direct is False
    assert by_name["playwright"].declared_version == ""
    assert by_name["playwright"].current_version == "1.49.1"
    assert by_name["playwright"].dep_type == "dev"
    assert by_name["playwright-core"].is_direct is False


def test_parse_npm_without_lockfile_unlocked(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        json.dumps({"devDependencies": {"@playwright/test": "^1.49.0"}}),
        encoding="utf-8",
    )
    deps = parse_npm_dependencies(tmp_path / "package.json", repo_root=tmp_path)
    assert len(deps) == 1
    assert deps[0].notes == "unlocked"
    assert deps[0].declared_version == "^1.49.0"
    assert deps[0].current_version == "^1.49.0"
    assert deps[0].is_direct is True


def test_parse_npm_manifest_missing_raises(tmp_path: Path):
    with pytest.raises(ManifestMissingError):
        parse_npm_dependencies(tmp_path / "missing-package.json", repo_root=tmp_path)


def test_parse_npm_real_package_json():
    deps = parse_npm_dependencies()
    by_name = {d.name: d for d in deps}
    assert "@playwright/test" in by_name
    pw = by_name["@playwright/test"]
    assert pw.notes is None
    assert pw.current_version
    assert pw.declared_version.startswith("^")
    assert pw.is_direct is True
    # Transitives from package-lock.json (Playwright chain)
    assert "playwright" in by_name
    assert by_name["playwright"].is_direct is False
    assert "playwright-core" in by_name
    assert by_name["playwright-core"].is_direct is False
    assert len(deps) >= 3


# ---------------------------------------------------------------------------
# Unit: registry lookups (mocked)
# ---------------------------------------------------------------------------


@respx.mock
def test_fetch_pypi_latest_ok():
    respx.get("https://pypi.org/pypi/fastapi/json").mock(
        return_value=httpx.Response(200, json={"info": {"version": "0.118.2"}})
    )
    assert fetch_pypi_latest("fastapi") == "0.118.2"


@respx.mock
def test_fetch_npm_latest_ok():
    respx.get("https://registry.npmjs.org/@playwright%2Ftest/latest").mock(
        return_value=httpx.Response(200, json={"version": "1.61.1"})
    )
    assert fetch_npm_latest("@playwright/test") == "1.61.1"


@respx.mock
def test_fetch_pypi_404():
    respx.get("https://pypi.org/pypi/no-such-pkg/json").mock(
        return_value=httpx.Response(404, json={"message": "Not Found"})
    )
    with pytest.raises(httpx.HTTPStatusError):
        fetch_pypi_latest("no-such-pkg")


@respx.mock
def test_fetch_pypi_timeout():
    respx.get("https://pypi.org/pypi/fastapi/json").mock(
        side_effect=httpx.TimeoutException("timed out")
    )
    with pytest.raises(httpx.TimeoutException):
        fetch_pypi_latest("fastapi")


@respx.mock
def test_refresh_latest_versions_partial_errors(db_session: Session):
    python_deps = [
        _dep("python", "fastapi", "0.115.0", "runtime", declared=">=0.115"),
        _dep("python", "missing-pkg", "1.0.0", "runtime", declared=">=1.0"),
    ]
    npm_deps = [
        _dep("npm", "@playwright/test", "1.49.0", "dev", declared="^1.49.0"),
    ]
    respx.get("https://pypi.org/pypi/fastapi/json").mock(
        return_value=httpx.Response(200, json={"info": {"version": "0.118.2"}})
    )
    respx.get("https://pypi.org/pypi/missing-pkg/json").mock(
        return_value=httpx.Response(404, json={"message": "Not Found"})
    )
    respx.get("https://registry.npmjs.org/@playwright%2Ftest/latest").mock(
        return_value=httpx.Response(200, json={"version": "1.61.1"})
    )

    result = refresh_latest_versions(
        db_session,
        python_deps=python_deps,
        npm_deps=npm_deps,
        skip_throttle=True,
    )
    assert result["ok"] is True
    assert result["checked"] == 2
    assert result["errors"] == 1

    rows = {r.name: r for r in db_session.query(DependencySnapshot).all()}
    assert rows["fastapi"].status == "outdated_minor"
    assert rows["fastapi"].latest_version == "0.118.2"
    assert rows["fastapi"].declared_version == ">=0.115"
    assert rows["missing-pkg"].status == "unknown"
    assert rows["missing-pkg"].check_error
    assert rows["@playwright/test"].status == "outdated_minor"


def test_export_structure(db_session: Session):
    sync_local_to_db(
        db_session,
        python_deps=[_dep("python", "fastapi", "0.115.0", "runtime", declared=">=0.115")],
        npm_deps=[],
    )
    row = db_session.query(DependencySnapshot).one()
    row.latest_version = "0.118.2"
    row.status = "outdated_minor"
    db_session.commit()

    payload = snapshots_to_export([row])
    assert "generated_at" in payload
    pkg = payload["packages"][0]
    assert pkg["ecosystem"] == "python"
    assert pkg["name"] == "fastapi"
    assert pkg["type"] == "runtime"
    assert pkg["declared_version"] == ">=0.115"
    assert pkg["status"] == "outdated_minor"
    assert pkg["is_direct"] is True


def test_export_outdated_filter_only(db_session: Session):
    sync_local_to_db(
        db_session,
        python_deps=[
            _dep("python", "fastapi", "0.115.0", "runtime", declared=">=0.115"),
            _dep("python", "httpx", "0.28.0", "runtime", declared=">=0.28"),
        ],
        npm_deps=[
            _dep("npm", "playwright", "1.49.0", "dev", declared="", is_direct=False),
        ],
    )
    rows = {r.name: r for r in db_session.query(DependencySnapshot).all()}
    rows["fastapi"].latest_version = "0.118.2"
    rows["fastapi"].status = "outdated_minor"
    rows["httpx"].latest_version = "0.28.0"
    rows["httpx"].status = "up_to_date"
    rows["playwright"].latest_version = "1.61.1"
    rows["playwright"].status = "outdated_minor"
    db_session.commit()

    from app.admin.dependencies_service import list_snapshots

    outdated = list_snapshots(db_session, outdated_only=True)
    names = {r.name for r in outdated}
    assert names == {"fastapi", "playwright"}
    payload = snapshots_to_export(outdated)
    assert all(p["status"].startswith("outdated_") for p in payload["packages"])
    assert {p["name"]: p["is_direct"] for p in payload["packages"]} == {
        "fastapi": True,
        "playwright": False,
    }


# ---------------------------------------------------------------------------
# HTTP routes
# ---------------------------------------------------------------------------


def test_dependencies_forbidden_for_non_admin(client: TestClient):
    resp = client.get("/admin/dependencies", headers=USER_HEADERS, follow_redirects=False)
    assert resp.status_code in (302, 403)


def test_dependencies_ok_for_admin(client: TestClient):
    resp = client.get("/admin/dependencies", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "Dépendances" in resp.text
    assert "Python (backend)" in resp.text
    assert "npm (tests e2e)" in resp.text
    assert "Export MAJ" in resp.text
    assert "Export tout" in resp.text
    assert "Plan de MAJ" in resp.text


def test_dependencies_export_forbidden(client: TestClient):
    resp = client.get(
        "/admin/dependencies/export.json",
        headers=USER_HEADERS,
        follow_redirects=False,
    )
    assert resp.status_code in (302, 403)


def test_refresh_flash_on_missing_manifest(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    missing = tmp_path / "pyproject.toml"

    def boom(*_a, **_k):
        raise ManifestMissingError(missing)

    monkeypatch.setattr(
        "app.web.admin_dependencies.refresh_latest_versions",
        boom,
    )
    resp = client.post(
        "/admin/dependencies/refresh",
        headers=ADMIN_HEADERS,
        follow_redirects=False,
    )
    assert resp.status_code == 302
    # Flash is in signed cookie — follow redirect to see message, or check Set-Cookie
    assert "portal_flash" in resp.cookies or "set-cookie" in {k.lower() for k in resp.headers}


@respx.mock
def test_dependencies_export_and_page_after_refresh(
    client: TestClient, db_session: Session
):
    respx.get(url__regex=r"https://pypi\.org/pypi/.+/json").mock(
        return_value=httpx.Response(200, json={"info": {"version": "9.9.9"}})
    )
    respx.get(url__regex=r"https://registry\.npmjs\.org/.+/latest").mock(
        return_value=httpx.Response(200, json={"version": "9.9.9"})
    )

    refresh = client.post(
        "/admin/dependencies/refresh",
        headers=ADMIN_HEADERS,
        follow_redirects=False,
    )
    assert refresh.status_code == 302
    assert refresh.headers["location"] == "/admin/dependencies"

    page = client.get("/admin/dependencies", headers=ADMIN_HEADERS)
    assert page.status_code == 200
    assert "fastapi" in page.text.lower() or "FastAPI" in page.text
    assert "@playwright/test" in page.text
    assert "playwright-core" in page.text or "playwright" in page.text
    assert "direct" in page.text
    assert "transitif" in page.text
    assert "Déclaré" in page.text
    assert "Installé" in page.text
    assert "MAJ disponible" in page.text or "MAJ disponibles" in page.text

    export = client.get("/admin/dependencies/export.json", headers=ADMIN_HEADERS)
    assert export.status_code == 200
    assert "attachment" in export.headers.get("content-disposition", "")
    data = export.json()
    assert "generated_at" in data
    assert isinstance(data["packages"], list)
    assert any(p["name"].lower() == "fastapi" for p in data["packages"])
    assert any(p["name"] == "@playwright/test" for p in data["packages"])
    assert any(p["name"] == "playwright" and p["is_direct"] is False for p in data["packages"])
    assert all("declared_version" in p and "is_direct" in p for p in data["packages"])

    outdated = client.get(
        "/admin/dependencies/export.json?status=outdated",
        headers=ADMIN_HEADERS,
    )
    assert outdated.status_code == 200
    assert "outdated" in outdated.headers.get("content-disposition", "")
    for pkg in outdated.json()["packages"]:
        assert pkg["status"].startswith("outdated_")
