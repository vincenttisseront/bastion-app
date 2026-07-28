"""bastion-nginx unknown-Host discovery — records PendingHost + returns stub page."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.bastion.pending_host_service import record_unknown_host
from app.database import get_db
from app.request_client_ip import client_ip_from_request
from app.security import require_nginx_internal_token

router = APIRouter(tags=["unknown-host"])

_STUB_HTML = """\
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Hôte non enregistré</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 0; padding: 3rem 1.5rem;
           background: #0f1419; color: #e7ecf3; }}
    main {{ max-width: 36rem; margin: 0 auto; }}
    h1 {{ font-size: 1.35rem; font-weight: 600; margin: 0 0 .75rem; }}
    p {{ line-height: 1.5; color: #a8b3c4; margin: 0 0 .75rem; }}
    code {{ color: #9ecbff; word-break: break-all; }}
  </style>
</head>
<body>
  <main>
    <h1>Hôte non enregistré</h1>
    <p>Le domaine <code>{hostname}</code> n’est pas encore approuvé sur le bastion.</p>
    <p>Un administrateur peut l’accepter dans <strong>Admin → Domaines découverts</strong>
       (mode proxy public), puis appliquer l’infrastructure nginx.</p>
  </main>
</body>
</html>
"""


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
    host_display = (hostname or "").split(":")[0].strip() or "(inconnu)"
    return HTMLResponse(
        content=_STUB_HTML.format(hostname=host_display),
        status_code=503,
        headers={"Cache-Control": "no-store", "X-Bastion-Unknown-Host": "1"},
    )
