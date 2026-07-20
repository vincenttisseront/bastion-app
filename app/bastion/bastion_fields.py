"""Bastion app auth-mode constants and generic driver field validation."""

from __future__ import annotations

import json

AUTH_MODES: tuple[str, ...] = (
    "sso",
    "generic_form",
    "generic_basic_auth",
)

AUTH_MODE_LABELS: dict[str, str] = {
    "sso": "SSO",
    "generic_form": "Vault — Formulaire de login",
    "generic_basic_auth": "Vault — Basic Auth",
}

# Legacy DB values treated as SSO.
_AUTH_MODE_ALIASES: dict[str, str] = {
    "oidc": "sso",
    "": "sso",
}

ROBOTIC_DRIVERS: frozenset[str] = frozenset(
    {"crushftp", "generic_form", "generic_basic_auth"}
)

LOGIN_HTTP_METHODS: frozenset[str] = frozenset({"POST", "GET"})


def normalize_auth_mode(value: str | None) -> str:
    if not value:
        return "sso"
    lowered = value.strip().lower()
    if lowered in AUTH_MODES:
        return lowered
    return _AUTH_MODE_ALIASES.get(lowered, "sso")


def resolve_robotic_driver(auth_mode: str, existing: str | None = None) -> str | None:
    """Map auth_mode to robotic_driver; preserve crushftp when auth_mode stays SSO."""
    mode = normalize_auth_mode(auth_mode)
    if mode == "generic_form":
        return "generic_form"
    if mode == "generic_basic_auth":
        return "generic_basic_auth"
    if mode == "sso" and (existing or "").strip().lower() == "crushftp":
        return "crushftp"
    return None


def vault_enabled_for_app(auth_mode: str | None, robotic_driver: str | None) -> bool:
    driver = (robotic_driver or "").strip().lower()
    if driver in ROBOTIC_DRIVERS:
        return True
    return normalize_auth_mode(auth_mode) in ("generic_form", "generic_basic_auth")


def validate_generic_form_fields(
    login_form_url: str | None,
    login_username_field: str | None,
    login_password_field: str | None,
    login_http_method: str | None,
    login_extra_fields: str | None,
) -> dict[str, str]:
    errors: dict[str, str] = {}
    if not (login_form_url or "").strip():
        errors["login_form_url"] = "L'URL du formulaire de login est requise."
    method = (login_http_method or "POST").strip().upper()
    if method not in LOGIN_HTTP_METHODS:
        errors["login_http_method"] = "Méthode HTTP invalide (POST ou GET)."
    if not (login_username_field or "").strip():
        errors["login_username_field"] = "Le nom du champ utilisateur est requis."
    if not (login_password_field or "").strip():
        errors["login_password_field"] = "Le nom du champ mot de passe est requis."
    extra = (login_extra_fields or "").strip()
    if extra:
        try:
            parsed = json.loads(extra)
            if not isinstance(parsed, dict):
                errors["login_extra_fields"] = "Le JSON doit être un objet (clé/valeur)."
        except json.JSONDecodeError:
            errors["login_extra_fields"] = "JSON invalide pour les champs supplémentaires."
    return errors


def parse_login_extra_fields(raw: str | None) -> dict[str, str]:
    text = (raw or "").strip()
    if not text:
        return {}
    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise ValueError("login_extra_fields must be a JSON object")
    return {str(k): str(v) for k, v in parsed.items()}
