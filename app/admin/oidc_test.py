"""OIDC connection test for realm admin."""

from __future__ import annotations

import httpx


async def test_oidc_connection(
    issuer_url: str, client_id: str, client_secret: str
) -> dict:
    checks: list[dict[str, str]] = []

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{issuer_url.rstrip('/')}/.well-known/openid-configuration")
        if resp.status_code != 200:
            checks.append(
                {
                    "name": "discovery",
                    "status": "error",
                    "message": f"HTTP {resp.status_code} sur .well-known/openid-configuration",
                }
            )
            return {"status": "error", "checks": checks}
        metadata = resp.json()
        checks.append(
            {"name": "discovery", "status": "ok", "message": "Discovery OK"}
        )
    except httpx.RequestError as exc:
        checks.append(
            {
                "name": "discovery",
                "status": "error",
                "message": f"Injoignable : {exc}",
            }
        )
        return {"status": "error", "checks": checks}

    required = ["authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"]
    missing = [field for field in required if field not in metadata]
    if missing:
        checks.append(
            {
                "name": "metadata",
                "status": "error",
                "message": f"Champs manquants dans la discovery : {missing}",
            }
        )
        return {"status": "error", "checks": checks}
    checks.append(
        {"name": "metadata", "status": "ok", "message": "Métadonnées complètes"}
    )

    if metadata["issuer"].rstrip("/") != issuer_url.rstrip("/"):
        checks.append(
            {
                "name": "issuer_match",
                "status": "warning",
                "message": (
                    f"issuer déclaré ({metadata['issuer']}) diffère de l'URL saisie"
                ),
            }
        )
    else:
        checks.append(
            {"name": "issuer_match", "status": "ok", "message": "issuer cohérent"}
        )

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            jwks_resp = await client.get(metadata["jwks_uri"])
        if jwks_resp.status_code == 200 and jwks_resp.json().get("keys"):
            checks.append(
                {"name": "jwks", "status": "ok", "message": "Clés JWKS accessibles"}
            )
        else:
            checks.append(
                {"name": "jwks", "status": "error", "message": "JWKS invalide ou vide"}
            )
    except httpx.RequestError as exc:
        checks.append(
            {
                "name": "jwks",
                "status": "error",
                "message": f"jwks_uri injoignable : {exc}",
            }
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
                {
                    "name": "client_credentials",
                    "status": "ok",
                    "message": "Client credentials valides",
                }
            )
        elif error == "invalid_client":
            checks.append(
                {
                    "name": "client_credentials",
                    "status": "error",
                    "message": "client_id ou client_secret invalide",
                }
            )
        elif error in ("unauthorized_client", "invalid_grant", "unsupported_grant_type"):
            checks.append(
                {
                    "name": "client_credentials",
                    "status": "ok",
                    "message": (
                        "Credentials acceptés (grant client_credentials non "
                        "activé sur ce client, normal pour un client confidentiel "
                        "destiné au flux Authorization Code)"
                    ),
                }
            )
        else:
            checks.append(
                {
                    "name": "client_credentials",
                    "status": "warning",
                    "message": f"Réponse inattendue : {error or token_resp.status_code}",
                }
            )
    except httpx.RequestError as exc:
        checks.append(
            {
                "name": "client_credentials",
                "status": "error",
                "message": f"token_endpoint injoignable : {exc}",
            }
        )

    overall = "error" if any(check["status"] == "error" for check in checks) else "ok"
    return {"status": overall, "checks": checks}
