"""Regression tests — review findings E1 (validation errors → 500 / input echo)
and S8 (download file name not encoded: non-latin-1 → 500, quote injection)."""

from __future__ import annotations

from urllib.parse import unquote

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel, field_validator


ADMIN_HEADERS = {"X-Email": "admin@example.com", "X-Groups": "portal-admins"}
PASSWORD = "S3cr3t-Pa55word!"


class _ProbeBody(BaseModel):
    password: str
    name: str

    @field_validator("name")
    @classmethod
    def _check(cls, v: str) -> str:
        if v == "bad":
            raise ValueError("nom refusé")
        return v


def _e1_client() -> TestClient:
    """Tiny app using the portal's real RequestValidationError handler.

    Kept off the global app so route-coverage tests never see a probe route.
    """
    from fastapi import FastAPI
    from fastapi.exceptions import RequestValidationError

    from app.main import validation_exception_handler

    probe = FastAPI()
    probe.add_exception_handler(RequestValidationError, validation_exception_handler)

    @probe.post("/api/_test/e1-validation")
    async def _probe(body: _ProbeBody):
        return {"ok": True}

    return TestClient(probe, raise_server_exceptions=False)


def _raw(client: TestClient) -> TestClient:
    # Surface server errors as HTTP 500 instead of re-raising in the test.
    return TestClient(client.app, raise_server_exceptions=False)


def _post(payload: dict):
    return _e1_client().post(
        "/api/_test/e1-validation", json=payload, headers={"Accept": "application/json"}
    )


# --- E1 -----------------------------------------------------------------------


def test_e1_value_error_in_field_validator_is_422_not_500():
    resp = _post({"password": PASSWORD, "name": "bad"})
    assert resp.status_code == 422, resp.text
    body = resp.json()
    assert body["code"] == "validation_error"
    err = body["errors"][0]
    assert err["loc"] == ["body", "name"]
    assert set(err) == {"loc", "type", "msg"}


@pytest.mark.parametrize(
    "payload",
    [
        {"password": PASSWORD},  # missing field → pydantic's input is the whole body
        {"password": PASSWORD, "name": 123},
        {"password": PASSWORD, "name": "bad"},
    ],
)
def test_e1_submitted_values_never_echoed(payload):
    resp = _post(payload)
    assert resp.status_code == 422
    assert PASSWORD not in resp.text
    assert all("input" not in e and "ctx" not in e for e in resp.json()["errors"])


def test_e1_public_validation_errors_shape():
    from app.api_errors import public_validation_errors

    out = public_validation_errors(
        [{"loc": ("body", 0), "type": "value_error", "msg": "m", "input": "x", "ctx": {"error": ValueError()}}]
    )
    assert out == [{"loc": ["body", "0"], "type": "value_error", "msg": "m"}]


# --- S8 -----------------------------------------------------------------------


def _upload_and_rename(client: TestClient, db_session, stored_name: str) -> int:
    from app.models import FileVersion

    up = client.post(
        "/files/upload",
        headers={**ADMIN_HEADERS, "Accept": "application/json"},
        data={},
        files={"upload": ("plain.txt", b"payload", "text/plain")},
    )
    assert up.status_code == 200, up.text
    vid = up.json()["version"]["id"]
    # Store the raw name as a non-browser client (curl) could send it.
    row = db_session.get(FileVersion, vid)
    row.original_filename = stored_name
    db_session.commit()
    return vid


@pytest.mark.parametrize(
    "stored_name",
    ["rapport-été.txt", "rapport-€-数据.txt", 'evil".txt; filename="x.html', "a\r\nSet-Cookie: x=1.txt"],
)
def test_s8_download_filename_is_encoded(
    client: TestClient, db_session, monkeypatch, tmp_path, stored_name
):
    from app.sso_settings import get_settings

    monkeypatch.setenv("FILES_STORAGE_DIR", str(tmp_path / "files"))
    get_settings.cache_clear()
    vid = _upload_and_rename(client, db_session, stored_name)
    resp = _raw(client).get(
        f"/files/download/{vid}",
        headers={**ADMIN_HEADERS, "X-Portal-Internal-Token": "test-secret"},
    )
    assert resp.status_code == 200
    assert resp.content == b"payload"
    cd = resp.headers["content-disposition"]
    cd.encode("ascii")  # pure ASCII header
    assert cd.startswith("attachment; filename=\"")
    # Exactly the two expected parameters — nothing injected by the name.
    assert cd.count("filename=") == 1 and cd.count("filename*=") == 1
    assert "\r" not in cd and "\n" not in cd
    encoded = cd.split("filename*=UTF-8''", 1)[1]
    expected = stored_name.replace("\r", "").replace("\n", "")
    assert unquote(encoded) == expected
