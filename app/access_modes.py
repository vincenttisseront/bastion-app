"""Application access modes — internal slug vs public URL semantics."""

from __future__ import annotations

from urllib.parse import urlparse

ACCESS_MODES: tuple[str, ...] = (
    "sso_gate",
    "subdomain_proxy",
    "legacy_path_proxy",
    "public_proxy",
)

ACCESS_MODE_LABELS: dict[str, str] = {
    "sso_gate": "SSO Gate (lanceur)",
    "subdomain_proxy": "Sous-domaine dédié (reverse proxy)",
    "legacy_path_proxy": "Chemin /proxy/ (legacy, avancé)",
    "public_proxy": "Proxy public (sans auth)",
}

ACCESS_MODE_DESCRIPTIONS: dict[str, str] = {
    "sso_gate": "L'utilisateur est redirigé vers l'URL publique après validation SSO. Aucun proxy.",
    "subdomain_proxy": "Proxy transparent sur un FQDN dédié (modèle CrushFTP Phase 3).",
    "legacy_path_proxy": "Proxy sous /proxy/{slug}/ — uniquement si l'app supporte un base_path.",
    "public_proxy": (
        "Reverse proxy simple sans authentification bastion — hors catalogue utilisateur."
    ),
}

LEGACY_ACCESS_MODE_MAP: dict[str, str] = {
    "sso": "sso_gate",
    "direct": "sso_gate",
    "robotic": "sso_gate",
    "subdomain": "subdomain_proxy",
}

# Modes that generate bastion nginx proxy locations with optional robotic auth_request.
PROXY_ACCESS_MODES: frozenset[str] = frozenset({"subdomain_proxy", "legacy_path_proxy"})

# Modes that require a dedicated public FQDN (vhost server_name).
FQDN_REQUIRED_ACCESS_MODES: frozenset[str] = frozenset(
    {"subdomain_proxy", "public_proxy"}
)

# Structurally excluded from user catalogue /apps (and API catalogue views).
CATALOGUE_EXCLUDED_ACCESS_MODES: frozenset[str] = frozenset({"public_proxy"})


def normalize_access_mode(value: str | None) -> str:
    if not value:
        return "sso_gate"
    if value in ACCESS_MODES:
        return value
    return LEGACY_ACCESS_MODE_MAP.get(value, "sso_gate")


def is_user_catalogue_mode(access_mode: str | None) -> bool:
    """False for modes that must never appear in Mes applications / API catalogue."""
    return normalize_access_mode(access_mode) not in CATALOGUE_EXCLUDED_ACCESS_MODES


def upstream_entry_path(app) -> str:
    """
    Browser entry path on the public FQDN (e.g. ``/web/`` for grommunio).

    Prefer ``login_form_url`` path; else a non-root path on ``upstream_url``.
    Nginx still proxies origin-only — this is only for redirects / probes.
    """
    for raw in (
        (getattr(app, "login_form_url", None) or "").strip(),
        (getattr(app, "upstream_url", None) or "").strip(),
    ):
        if not raw:
            continue
        path = urlparse(raw).path or "/"
        if path not in ("", "/"):
            return path if path.endswith("/") else f"{path}/"
    return "/"


def public_app_entry_url(app, *, root_trailing_slash: bool = False) -> str | None:
    """``https://{public_fqdn}`` or ``https://{public_fqdn}/web/`` when an entry path exists."""
    fqdn = (getattr(app, "public_fqdn", None) or "").strip()
    if not fqdn:
        return None
    path = upstream_entry_path(app)
    if path == "/":
        return f"https://{fqdn}/" if root_trailing_slash else f"https://{fqdn}"
    return f"https://{fqdn}{path}"


def validate_app_access_fields(
    access_mode: str,
    upstream_url: str,
    public_fqdn: str | None,
) -> dict[str, str]:
    errors: dict[str, str] = {}
    mode = normalize_access_mode(access_mode)
    if mode not in ACCESS_MODES:
        errors["access_mode"] = "Mode d'accès invalide."
    if not upstream_url.strip():
        errors["upstream_url"] = "L'URL est requise."
    if mode in FQDN_REQUIRED_ACCESS_MODES:
        fqdn = (public_fqdn or "").strip()
        if not fqdn:
            errors["public_fqdn"] = "Le domaine public dédié est requis pour ce mode."
        elif " " in fqdn or "/" in fqdn:
            errors["public_fqdn"] = "Saisissez un FQDN valide (ex: app.example.fr)."
        # Path inside upstream_url breaks proxy_pass $var (Grommunio/Teleport 301 loops).
        path = urlparse(upstream_url.strip()).path or ""
        if path not in ("", "/"):
            errors["upstream_url"] = (
                "Origine uniquement (scheme://host[:port]/ — sans chemin "
                "(ex. https://10.x.x.x/ et non …/web/). Le chemin d’entrée "
                "appartient à login_form_url ou à l’URL navigateur."
            )
    return errors


def app_launch_url(app) -> str:
    driver = getattr(app, "robotic_driver", None)

    # Drivers that set session cookies require an impersonation round-trip first.
    if driver in ("crushftp", "generic_form"):
        return f"/api/internal/impersonate/{app.slug}"

    # generic_basic_auth / generic_wsse: Nginx auth_request injects on each
    # request — direct link (no cookie impersonation round-trip).
    mode = normalize_access_mode(app.access_mode)
    if mode == "sso_gate":
        return app.upstream_url
    if mode in ("subdomain_proxy", "public_proxy") and app.public_fqdn:
        return public_app_entry_url(app) or f"https://{app.public_fqdn.strip()}"
    if mode == "legacy_path_proxy":
        return f"/proxy/{app.slug}/"
    return app.upstream_url
