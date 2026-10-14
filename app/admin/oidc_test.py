"""OIDC connection test for realm admin — uses shared ConnectionTestResult."""

from __future__ import annotations

import time
from urllib.parse import urlsplit

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



def _oidc_result(
    checks: list[CheckStep],
    *,
    resource_id: str | int,
    start: float,
) -> ConnectionTestResult:
    return ConnectionTestResult(
        resource_type="oidc_realm",
        resource_id=resource_id,
        overall_status=overall_from_checks(checks),
        checks=checks,
        latency_ms=int((time.monotonic() - start) * 1000),
    )


def _append_issuer_match(checks: list[CheckStep], metadata: dict, issuer_url: str) -> None:
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


def _same_host(url: str, issuer_url: str) -> bool:
    target, issuer = urlsplit(url), urlsplit(issuer_url)
    return target.scheme == "https" and target.netloc.lower() == issuer.netloc.lower()


async def _check_jwks(checks: list[CheckStep], client: httpx.AsyncClient, jwks_uri: str) -> None:
    if urlsplit(jwks_uri).scheme != "https":
        checks.append(
            CheckStep(name="jwks", status=CheckStatus.ERROR, message="jwks_uri doit être en https://")
        )
        return
    try:
        jwks_resp = await client.get(jwks_uri)
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
                message=f"jwks_uri injoignable ({type(exc).__name__})",
            )
        )


async def _check_client_credentials(
    checks: list[CheckStep],
    client: httpx.AsyncClient,
    *,
    issuer_url: str,
    token_endpoint: str,
    client_id: str,
    client_secret: str,
) -> None:
    # The client secret is posted here: never let a discovery document send it elsewhere.
    if not _same_host(token_endpoint, issuer_url):
        checks.append(
            CheckStep(
                name="client_credentials",
                status=CheckStatus.ERROR,
                message="token_endpoint hors de l'hôte de l'issuer — secret non envoyé",
            )
        )
        return
    try:
        token_resp = await client.post(
            token_endpoint,
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
                message=f"token_endpoint injoignable ({type(exc).__name__})",
            )
        )


async def test_oidc_connection_result(
    issuer_url: str,
    client_id: str,
    client_secret: str,
    *,
    resource_id: str | int = "draft",
) -> ConnectionTestResult:
    """Run OIDC checks and return a ConnectionTestResult (no secrets in detail)."""
    start = time.monotonic()
    async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
        checks = await _run_checks(client, issuer_url, client_id, client_secret)
    return _oidc_result(checks, resource_id=resource_id, start=start)


async def _run_checks(
    client: httpx.AsyncClient, issuer_url: str, client_id: str, client_secret: str
) -> list[CheckStep]:
    checks: list[CheckStep] = []
    try:
        resp = await client.get(f"{issuer_url.rstrip('/')}/.well-known/openid-configuration")
        if resp.status_code != 200:
            checks.append(
                CheckStep(
                    name="discovery",
                    status=CheckStatus.ERROR,
                    message=f"HTTP {resp.status_code} sur .well-known/openid-configuration",
                )
            )
            return checks
        metadata = resp.json()
        checks.append(
            CheckStep(name="discovery", status=CheckStatus.OK, message="Discovery OK")
        )
    except httpx.RequestError as exc:
        checks.append(
            CheckStep(
                name="discovery",
                status=CheckStatus.ERROR,
                message=f"Injoignable ({type(exc).__name__})",
            )
        )
        return checks
    except ValueError:
        checks.append(
            CheckStep(name="discovery", status=CheckStatus.ERROR, message="Discovery non-JSON")
        )
        return checks

    required = ["authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"]
    if not isinstance(metadata, dict):
        metadata = {}
    missing = [field for field in required if field not in metadata]
    if missing:
        checks.append(
            CheckStep(
                name="metadata",
                status=CheckStatus.ERROR,
                message=f"Champs manquants dans la discovery : {missing}",
            )
        )
        return checks
    checks.append(
        CheckStep(name="metadata", status=CheckStatus.OK, message="Métadonnées complètes")
    )

    _append_issuer_match(checks, metadata, issuer_url)
    await _check_jwks(checks, client, str(metadata["jwks_uri"]))
    await _check_client_credentials(
        checks,
        client,
        issuer_url=issuer_url,
        token_endpoint=str(metadata["token_endpoint"]),
        client_id=client_id,
        client_secret=client_secret,
    )
    return checks


async def test_oidc_connection(
    issuer_url: str, client_id: str, client_secret: str
) -> dict:
    """Legacy entrypoint — same JSON shape as before."""
    result = await test_oidc_connection_result(issuer_url, client_id, client_secret)
    return _to_oidc_api_dict(result)
