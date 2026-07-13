"""Application access modes — internal slug vs public URL semantics."""

from __future__ import annotations

ACCESS_MODES: tuple[str, ...] = (
    "sso_gate",
    "subdomain_proxy",
    "legacy_path_proxy",
)

ACCESS_MODE_LABELS: dict[str, str] = {
    "sso_gate": "SSO Gate (lanceur)",
    "subdomain_proxy": "Sous-domaine dédié (reverse proxy)",
    "legacy_path_proxy": "Chemin /proxy/ (legacy, avancé)",
}

ACCESS_MODE_DESCRIPTIONS: dict[str, str] = {
    "sso_gate": "L'utilisateur est redirigé vers l'URL publique après validation SSO. Aucun proxy.",
    "subdomain_proxy": "Proxy transparent sur un FQDN dédié (modèle CrushFTP Phase 3).",
    "legacy_path_proxy": "Proxy sous /proxy/{slug}/ — uniquement si l'app supporte un base_path.",
}

LEGACY_ACCESS_MODE_MAP: dict[str, str] = {
    "sso": "sso_gate",
    "direct": "sso_gate",
    "robotic": "sso_gate",
    "subdomain": "subdomain_proxy",
}

PROXY_ACCESS_MODES: frozenset[str] = frozenset({"subdomain_proxy", "legacy_path_proxy"})


def normalize_access_mode(value: str | None) -> str:
    if not value:
        return "sso_gate"
    if value in ACCESS_MODES:
        return value
    return LEGACY_ACCESS_MODE_MAP.get(value, "sso_gate")


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
    if mode == "subdomain_proxy":
        fqdn = (public_fqdn or "").strip()
        if not fqdn:
            errors["public_fqdn"] = "Le sous-domaine public est requis pour ce mode."
        elif " " in fqdn or "/" in fqdn:
            errors["public_fqdn"] = "Saisissez un FQDN valide (ex: app.example.fr)."
    return errors


def app_launch_url(app) -> str:
    mode = normalize_access_mode(app.access_mode)
    if mode == "sso_gate":
        return app.upstream_url
    if mode == "subdomain_proxy" and app.public_fqdn:
        return f"https://{app.public_fqdn.strip()}"
    if mode == "legacy_path_proxy":
        return f"/proxy/{app.slug}/"
    return app.upstream_url
