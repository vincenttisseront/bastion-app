"""bastion-nginx unknown-Host discovery — records PendingHost + returns stub page."""

from __future__ import annotations

from html import escape

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.bastion.pending_host_service import record_unknown_host
from app.branding import get_branding_settings
from app.database import get_db
from app.request_client_ip import client_ip_from_request
from app.security import require_nginx_internal_token
from app.sso_settings import Settings, get_settings

router = APIRouter(tags=["unknown-host"])

# Self-contained page: this Host is unknown, so /static on the same origin
# would also hit the discovery rewrite. Inline CSS + absolute portal links.
_STUB_HTML = """\
<!DOCTYPE html>
<html lang="fr" data-theme="{theme}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow">
  <title>Hôte non enregistré — {company}</title>
  <style>
    :root {{
      --bg: #020d18; --card: #0c1f35; --tertiary: #0f2640;
      --border: #1e3a5f; --border-muted: rgba(30,58,95,.5);
      --text: #e2e8f0; --text-2: #94a3b8; --text-3: #475569;
      {css_vars}
      --warn: #f59e0b; --warn-bg: rgba(245,158,11,.12);
      --font: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
      --mono: ui-monospace, "Cascadia Code", "SF Mono", Menlo, Consolas, monospace;
      --r: 12px; --sh: 0 2px 8px rgba(0,0,0,.4), inset 0 1px 0 rgba(255,255,255,.04);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0; min-height: 100vh; font-family: var(--font); color: var(--text);
      background:
        radial-gradient(ellipse 80% 50% at 50% -10%, var(--portal-hero-glow, rgba(16,185,129,.12)), transparent 55%),
        var(--bg);
      display: flex; align-items: center; justify-content: center;
      padding: 1.5rem;
    }}
    .shell {{ width: 100%; max-width: 28rem; }}
    .brand {{
      display: flex; align-items: center; gap: .75rem;
      margin-bottom: 1.25rem; justify-content: center;
    }}
    .brand-mark {{
      width: 2.25rem; height: 2.25rem; border-radius: 10px;
      background: var(--accent);
      display: flex; align-items: center; justify-content: center;
      box-shadow: var(--accent-glow, 0 0 20px rgba(16,185,129,.25));
    }}
    .brand-mark svg {{ display: block; }}
    .brand-name {{ font-size: 1.05rem; font-weight: 700; letter-spacing: -.02em; }}
    .brand-name span {{ color: var(--accent-h); }}
    .card {{
      background: var(--card); border: 1px solid var(--border); border-radius: 16px;
      box-shadow: var(--sh); overflow: hidden;
    }}
    .card-head {{
      padding: 1.25rem 1.5rem; border-bottom: 1px solid var(--border-muted);
      background: var(--tertiary);
    }}
    .badge {{
      display: inline-flex; align-items: center; gap: .4rem;
      font-size: .7rem; font-weight: 700; letter-spacing: .06em; text-transform: uppercase;
      color: var(--warn); background: var(--warn-bg); border: 1px solid rgba(245,158,11,.25);
      border-radius: 999px; padding: .25rem .65rem; margin-bottom: .75rem;
    }}
    .badge-dot {{
      width: 6px; height: 6px; border-radius: 50%; background: var(--warn);
      box-shadow: 0 0 0 3px rgba(245,158,11,.2);
    }}
    h1 {{ margin: 0; font-size: 1.25rem; font-weight: 700; letter-spacing: -.02em; }}
    .card-body {{ padding: 1.5rem; }}
    .lead {{ margin: 0 0 1rem; color: var(--text-2); font-size: .9rem; line-height: 1.55; }}
    .host-box {{
      padding: .85rem 1rem; margin: 0 0 1.25rem;
      background: var(--tertiary); border: 1px dashed var(--border); border-radius: var(--r);
    }}
    .host-label {{
      display: block; font-size: .65rem; font-weight: 700; letter-spacing: .08em;
      text-transform: uppercase; color: var(--text-3); margin-bottom: .35rem;
    }}
    .host-value {{
      font-family: var(--mono); font-size: .95rem; font-weight: 600; color: var(--accent-h);
      word-break: break-all; line-height: 1.35;
    }}
    .steps {{
      list-style: none; margin: 0 0 1.25rem; padding: 0;
      display: flex; flex-direction: column; gap: .65rem;
    }}
    .steps li {{
      display: flex; gap: .75rem; align-items: flex-start;
      font-size: .85rem; color: var(--text-2); line-height: 1.45;
    }}
    .step-n {{
      flex-shrink: 0; width: 1.35rem; height: 1.35rem; border-radius: 50%;
      background: var(--accent-muted); color: var(--accent-h);
      font-size: .7rem; font-weight: 700;
      display: flex; align-items: center; justify-content: center;
      margin-top: .1rem;
    }}
    .actions {{ display: flex; flex-wrap: wrap; gap: .65rem; }}
    .btn {{
      display: inline-flex; align-items: center; justify-content: center; gap: .4rem;
      padding: .65rem 1rem; border-radius: 8px; font-size: .875rem; font-weight: 600;
      text-decoration: none; border: 1px solid transparent; cursor: pointer;
      transition: background .15s, border-color .15s, color .15s;
    }}
    .btn-primary {{
      background: var(--accent); color: #042f1e; border-color: var(--accent);
    }}
    .btn-primary:hover {{ background: var(--accent-h); }}
    .btn-ghost {{
      background: transparent; color: var(--text-2); border-color: var(--border);
    }}
    .btn-ghost:hover {{ color: var(--text); border-color: var(--border); background: rgba(255,255,255,.04); }}
    .foot {{
      margin-top: 1rem; text-align: center; font-size: .75rem; color: var(--text-3);
      line-height: 1.4;
    }}
  </style>
</head>
<body>
  <div class="shell">
    <div class="brand">
      <div class="brand-mark" aria-hidden="true">
        <svg width="18" height="18" fill="none" stroke="#fff" stroke-width="2" viewBox="0 0 24 24">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
      </div>
      <div class="brand-name">{brand_html}</div>
    </div>

    <div class="card">
      <div class="card-head">
        <div class="badge"><span class="badge-dot" aria-hidden="true"></span> En attente d’approbation</div>
        <h1>Hôte non enregistré</h1>
      </div>
      <div class="card-body">
        <p class="lead">
          Ce domaine a été vu par le portail mais n’est pas encore publié.
          Un administrateur doit l’approuver (Admin → Domaines). nginx recharge
          ensuite la conf automatiquement sous quelques secondes.
        </p>
        <div class="host-box">
          <span class="host-label">Domaine demandé</span>
          <div class="host-value">{hostname}</div>
        </div>
        <ol class="steps">
          <li><span class="step-n">1</span><span>Ouvrir <strong>Admin → Domaines découverts</strong> sur le portail.</span></li>
          <li><span class="step-n">2</span><span>Approuver en <strong>proxy public</strong> et renseigner l’URL backend.</span></li>
          <li><span class="step-n">3</span><span>Attendre quelques secondes — nginx recharge la conf tout seul.</span></li>
        </ol>
        <div class="actions">
          <a class="btn btn-primary" href="{pending_url}">Ouvrir Domaines découverts</a>
          <a class="btn btn-ghost" href="{portal_url}">Aller au portail</a>
        </div>
      </div>
    </div>
    <p class="foot">Réponse 503 · découverte automatique · X-Portal-Unknown-Host</p>
  </div>
</body>
</html>
"""


def _portal_base(settings: Settings) -> str:
    domain = (settings.portal_domain or "portal.ar-systems.fr").strip()
    if domain.startswith("http://") or domain.startswith("https://"):
        return domain.rstrip("/")
    return f"https://{domain}"


def render_unknown_host_page(
    *,
    hostname: str,
    settings: Settings,
    branding: dict | None = None,
) -> str:
    base = _portal_base(settings)
    branding = branding or get_branding_settings(None)
    if branding.get("show_product_branding"):
        brand_html = "Bastion <span>Pro</span>"
        company = "Bastion Pro"
    else:
        company = escape(branding.get("company_name") or "Portail sécurisé")
        brand_html = company
    theme = escape(branding.get("default_theme") or "dark")
    css_vars = branding.get("css_vars") or ""
    # css_vars is generated server-side from validated hex colors only
    return _STUB_HTML.format(
        hostname=escape(hostname),
        portal_url=escape(base + "/"),
        pending_url=escape(base + "/admin/pending-hosts?status=pending"),
        company=company,
        brand_html=brand_html,
        css_vars=css_vars,
        theme=theme,
    )


@router.api_route("/internal/unknown-host", methods=["GET", "POST", "HEAD"])
def unknown_host_gateway(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
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
    branding = get_branding_settings(db)
    return HTMLResponse(
        content=render_unknown_host_page(
            hostname=host_display, settings=settings, branding=branding
        ),
        status_code=503,
        headers={"Cache-Control": "no-store", "X-Portal-Unknown-Host": "1"},
    )
