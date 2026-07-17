"""OIDC connection test for realm admin — uses shared ConnectionTestResult."""

from __future__ import annotations

import time

import httpx

from app.testing_framework.connection_test import (
    CheckStatus,
    CheckStep,
    ConnectionTestResult,
    overall_from_checks,
)


def _to_oidc_api_dict(result: ConnectionTestResult) -> dict:
    """Preserve legacy OIDC JSON contract for the realm admin UI.

    - check status ``warn`` is serialized as ``warning``
    - overall ignores warn (only ``error`` fails activation); matches pre-Phase-5 behaviour
    """
    checks = []
    for step in result.checks:
        status = "warning" if step.status == CheckStatus.WARN else step.status.value
        checks.append({"name": step.name, "status": status, "message": step.message})
    overall = (
        "error"
        if any(c["status"] == "error" for c in checks)
        else "ok"
    )
    return {"status": overall, "checks": checks}


async def test_oidc_connection_result(
    issuer_url: str,
    client_id: str,
    client_secret: str,
    *,
    resource_id: str | int = "draft",
) -> ConnectionTestResult:
    """Run OIDC checks and return a ConnectionTestResult (no secrets in detail)."""
    checks: list[CheckStep] = []
    start = time.monotonic()

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"{issuer_url.rstrip('/')}/.well-known/openid-configuration"
            )
        if resp.status_code != 200:
            checks.append(
                CheckStep(
                    name="discovery",
                    status=CheckStatus.ERROR,
                    message=f"HTTP {resp.status_code} sur .well-known/openid-configuration",
                )
            )
            return ConnectionTestResult(
                resource_type="oidc_realm",
                resource_id=resource_id,
                overall_status=overall_from_checks(checks),
                checks=checks,
                latency_ms=int((time.monotonic() - start) * 1000),
            )
        metadata = resp.json()
        checks.append(
            CheckStep(name="discovery", status=CheckStatus.OK, message="Discovery OK")
        )
    except httpx.RequestError as exc:
        checks.append(
            CheckStep(
                name="discovery",
                status=CheckStatus.ERROR,
                message=f"Injoignable : {exc}",
            )
        )
        return ConnectionTestResult(
            resource_type="oidc_realm",
            resource_id=resource_id,
            overall_status=overall_from_checks(checks),
            checks=checks,
            latency_ms=int((time.monotonic() - start) * 1000),
        )

    required = ["authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"]
    missing = [field for field in required if field not in metadata]
    if missing:
        checks.append(
            CheckStep(
                name="metadata",
                status=CheckStatus.ERROR,
                message=f"Champs manquants dans la discovery : {missing}",
            )
        )
        return ConnectionTestResult(
            resource_type="oidc_realm",
            resource_id=resource_id,
            overall_status=overall_from_checks(checks),
            checks=checks,
            latency_ms=int((time.monotonic() - start) * 1000),
        )
    checks.append(
        CheckStep(name="metadata", status=CheckStatus.OK, message="Métadonnées complètes")
    )

    if metadata["issuer"].rstrip("/") != issuer_url.rstrip("/"):
        checks.append(
            CheckStep(
                name="issuer_match",
                status=CheckStatus.WARN,
                message=(
                    f"issuer déclaré ({metadata['issuer']}) diffère de l'URL saisie"
                ),
            )
        )
    else:
        checks.append(
            CheckStep(
                name="issuer_match",
                status=CheckStatus.OK,
                message="issuer cohérent",
            )
        )

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            jwks_resp = await client.get(metadata["jwks_uri"])
        if jwks_resp.status_code == 200 and jwks_resp.json().get("keys"):
            checks.append(
                CheckStep(
                    name="jwks",
                    status=CheckStatus.OK,
                    message="Clés JWKS accessibles",
                )
            )
        else:
            checks.append(
                CheckStep(
                    name="jwks",
                    status=CheckStatus.ERROR,
                    message="JWKS invalide ou vide",
                )
            )
    except httpx.RequestError as exc:
        checks.append(
            CheckStep(
                name="jwks",
                status=CheckStatus.ERROR,
                message=f"jwks_uri injoignable : {exc}",
            )
        )

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            token_resp = await client.post(
                metadata["token_endpoint"],
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                },
            )
        content_type = token_resp.headers.get("content-type", "")
        body = token_resp.json() if content_type.startswith("application/json") else {}
        error = body.get("error", "")
        if token_resp.status_code == 200:
            checks.append(
                CheckStep(
                    name="client_credentials",
                    status=CheckStatus.OK,
                    message="Client credentials valides",
                )
            )
        elif error == "invalid_client":
            checks.append(
                CheckStep(
                    name="client_credentials",
                    status=CheckStatus.ERROR,
                    message="client_id ou client_secret invalide",
                )
            )
        elif error in ("unauthorized_client", "invalid_grant", "unsupported_grant_type"):
            checks.append(
                CheckStep(
                    name="client_credentials",
                    status=CheckStatus.OK,
                    message=(
                        "Credentials acceptés (grant client_credentials non "
                        "activé sur ce client, normal pour un client confidentiel "
                        "destiné au flux Authorization Code)"
                    ),
                )
            )
        else:
            checks.append(
                CheckStep(
                    name="client_credentials",
                    status=CheckStatus.WARN,
                    message=f"Réponse inattendue : {error or token_resp.status_code}",
                )
            )
    except httpx.RequestError as exc:
        checks.append(
            CheckStep(
                name="client_credentials",
                status=CheckStatus.ERROR,
                message=f"token_endpoint injoignable : {exc}",
            )
        )

    return ConnectionTestResult(
        resource_type="oidc_realm",
        resource_id=resource_id,
        overall_status=overall_from_checks(checks),
        checks=checks,
        latency_ms=int((time.monotonic() - start) * 1000),
    )


async def test_oidc_connection(
    issuer_url: str, client_id: str, client_secret: str
) -> dict:
    """Legacy entrypoint — same JSON shape as before Phase 5."""
    result = await test_oidc_connection_result(issuer_url, client_id, client_secret)
    return _to_oidc_api_dict(result)
