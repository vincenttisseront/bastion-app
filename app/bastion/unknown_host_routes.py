"""bastion-nginx unknown-Host discovery — records PendingHost + returns a neutral 403.

Public clients must not learn that a SSO portal / bastion sits behind the edge,
nor see Admin → Domaines onboarding copy. Discovery still lands in PendingHost
+ audit for operators.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.bastion.pending_host_service import record_unknown_host
from app.database import get_db
from app.request_client_ip import client_ip_from_request
from app.security import require_nginx_internal_token

router = APIRouter(tags=["unknown-host"])

# Self-contained: unknown Host also breaks same-origin /static. No product,
# company, or portal wording — looks like a generic edge denial.
_FORBIDDEN_HTML = """\
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow">
  <title>403 Forbidden</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0; min-height: 100vh;
      display: flex; align-items: center; justify-content: center;
      font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
      background: #f4f4f5; color: #18181b;
      padding: 1.5rem;
    }
    main { text-align: center; max-width: 22rem; }
    .code {
      font-size: 2.75rem; font-weight: 700; letter-spacing: .04em;
      color: #71717a; margin: 0 0 .5rem; line-height: 1;
    }
    h1 { margin: 0 0 .5rem; font-size: 1.25rem; font-weight: 600; }
    p { margin: 0; font-size: .95rem; line-height: 1.5; color: #52525b; }
  </style>
</head>
<body>
  <main>
    <p class="code" aria-hidden="true">403</p>
    <h1>Forbidden</h1>
    <p>Access to this resource is denied.</p>
  </main>
</body>
</html>
"""


def render_unknown_host_page(
    *,
    hostname: str = "",
    settings: object | None = None,
    branding: dict | None = None,
) -> str:
    """Neutral 403 HTML for unknown Host responses.

    ``hostname`` / ``settings`` / ``branding`` are accepted for call-site
    compatibility and ignored so the page never leaks identity or ops hints.
    """
    del hostname, settings, branding
    return _FORBIDDEN_HTML


@router.api_route("/internal/unknown-host", methods=["GET", "POST", "HEAD"])
def unknown_host_gateway(
    request: Request,
    db: Session = Depends(get_db),
    _token: str = Depends(require_nginx_internal_token),
) -> HTMLResponse:
    hostname = (
        request.headers.get("x-discovered-host")
        or request.headers.get("host")
        or ""
    )
    uri = request.headers.get("x-original-uri") or request.url.path
    record_unknown_host(
        db,
        hostname=hostname,
        client_ip=client_ip_from_request(request),
        user_agent=request.headers.get("user-agent"),
        uri=uri,
    )
    return HTMLResponse(
        content=render_unknown_host_page(),
        status_code=403,
        headers={"Cache-Control": "no-store"},
    )
