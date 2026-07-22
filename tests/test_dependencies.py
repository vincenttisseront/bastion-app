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
    assert by_name["fastapi"].dep_type == "runtime"
    assert by_name["uvicorn"].current_version == "0.49.0"
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
    assert "totally-missing-pkg" in deps[0].current_version


def test_parse_python_real_pyproject():
    """Smoke: real repo pyproject.toml is parseable without crashing."""
    deps = parse_python_dependencies()
    names = {d.name.lower() for d in deps}
    assert "fastapi" in names
    assert "pytest" in names


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
                    "node_modules/@playwright/test": {"version": "1.49.1"},
                },
            }
        ),
        encoding="utf-8",
    )
    deps = parse_npm_dependencies(tmp_path / "package.json", repo_root=tmp_path)
    by_name = {d.name: d for d in deps}
    assert by_name["left-pad"].current_version == "1.3.0"
    assert by_name["left-pad"].dep_type == "runtime"
    assert by_name["@playwright/test"].current_version == "1.49.1"
    assert by_name["@playwright/test"].dep_type == "dev"
    assert by_name["@playwright/test"].notes is None


def test_parse_npm_without_lockfile_unlocked(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        json.dumps({"devDependencies": {"@playwright/test": "^1.49.0"}}),
        encoding="utf-8",
    )
    deps = parse_npm_dependencies(tmp_path / "package.json", repo_root=tmp_path)
    assert len(deps) == 1
    assert deps[0].notes == "unlocked"
    assert deps[0].current_version == "^1.49.0"


def test_parse_npm_real_package_json():
    deps = parse_npm_dependencies()
    names = {d.name for d in deps}
    assert "@playwright/test" in names
    pw = next(d for d in deps if d.name == "@playwright/test")
    assert pw.notes is None  # package-lock.json present at repo root
    assert pw.current_version  # locked version


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
        LocalDependency("python", "fastapi", "0.115.0", "runtime"),
        LocalDependency("python", "missing-pkg", "1.0.0", "runtime"),
    ]
    npm_deps = [
        LocalDependency("npm", "@playwright/test", "1.49.0", "dev"),
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
    assert rows["missing-pkg"].status == "unknown"
    assert rows["missing-pkg"].check_error
    assert rows["@playwright/test"].status == "outdated_minor"


def test_export_structure(db_session: Session):
    sync_local_to_db(
        db_session,
        python_deps=[LocalDependency("python", "fastapi", "0.115.0", "runtime")],
        npm_deps=[],
    )
    row = db_session.query(DependencySnapshot).one()
    row.latest_version = "0.118.2"
    row.status = "outdated_minor"
    db_session.commit()

    payload = snapshots_to_export([row])
    assert "generated_at" in payload
    assert payload["packages"][0]["ecosystem"] == "python"
    assert payload["packages"][0]["name"] == "fastapi"
    assert payload["packages"][0]["type"] == "runtime"
    assert payload["packages"][0]["status"] == "outdated_minor"


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


def test_dependencies_export_forbidden(client: TestClient):
    resp = client.get(
        "/admin/dependencies/export.json",
        headers=USER_HEADERS,
        follow_redirects=False,
    )
    assert resp.status_code in (302, 403)


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

    export = client.get("/admin/dependencies/export.json", headers=ADMIN_HEADERS)
    assert export.status_code == 200
    assert "attachment" in export.headers.get("content-disposition", "")
    data = export.json()
    assert "generated_at" in data
    assert isinstance(data["packages"], list)
    assert any(p["name"] == "fastapi" or p["name"].lower() == "fastapi" for p in data["packages"])
    assert any(p["name"] == "@playwright/test" for p in data["packages"])

    outdated = client.get(
        "/admin/dependencies/export.json?status=outdated",
        headers=ADMIN_HEADERS,
    )
    assert outdated.status_code == 200
    for pkg in outdated.json()["packages"]:
        assert pkg["status"].startswith("outdated_")
