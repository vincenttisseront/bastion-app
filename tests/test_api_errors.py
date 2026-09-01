"""Unified API error JSON responses."""

from __future__ import annotations

from app.api_errors import api_error_from_detail, api_error_response


def test_api_error_response_minimal():
    import json

    resp = api_error_response(status_code=403, message="Accès refusé.")
    assert resp.status_code == 403
    body = json.loads(resp.body)
    assert body == {"code": "forbidden", "message": "Accès refusé."}


def test_api_error_response_with_errors():
    resp = api_error_response(
        status_code=422,
        code="validation_error",
        message="Données invalides.",
        errors={"email": "Format invalide"},
    )
    import json

    body = json.loads(resp.body)
    assert body["code"] == "validation_error"
    assert body["errors"]["email"] == "Format invalide"


def test_api_error_from_detail_string():
    resp = api_error_from_detail(status_code=404, detail="Not found")
    import json

    body = json.loads(resp.body)
    assert body["code"] == "not_found"
    assert body["message"] == "Not found"
    assert "errors" not in body


def test_api_error_from_detail_list():
    detail = [{"loc": ["body", "email"], "msg": "field required", "type": "value_error"}]
    resp = api_error_from_detail(status_code=422, detail=detail)
    import json

    body = json.loads(resp.body)
    assert body["code"] == "validation_error"
    assert body["errors"] == detail
