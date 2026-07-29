"""Bastion app auth-mode constants and generic driver field validation."""

from __future__ import annotations

import json

AUTH_MODES: tuple[str, ...] = (
    "sso",
    "generic_form",
    "generic_basic_auth",
    "generic_wsse",
)

AUTH_MODE_LABELS: dict[str, str] = {
    "sso": "SSO",
    "generic_form": "Vault — Formulaire de login",
    "generic_basic_auth": "Vault — Basic Auth",
    "generic_wsse": "Vault — X-WSSE (UsernameToken)",
}

# Legacy DB values treated as SSO.
_AUTH_MODE_ALIASES: dict[str, str] = {
    "oidc": "sso",
    "": "sso",
}

ROBOTIC_DRIVERS: frozenset[str] = frozenset(
    {"crushftp", "generic_form", "generic_basic_auth", "generic_wsse"}
)

CREDENTIAL_MODES: tuple[str, ...] = (
    "shared",
    "individual_required",
    "identite_utilisateur",
)

CREDENTIAL_MODE_LABELS: dict[str, str] = {
    "shared": "Partagé (par défaut)",
    "individual_required": "Individuel obligatoire",
    "identite_utilisateur": "Identité utilisateur (mot de passe à la demande)",
}

# How identite_utilisateur maps OIDC session → robotic/LDAPS login name.
IDENTITY_FORMATS: tuple[str, ...] = (
    "email",  # UPN / mail — default (Grommunio, most LDAPS)
    "username",  # short preferred_username / sAMAccountName-style
)

IDENTITY_FORMAT_LABELS: dict[str, str] = {
    "email": "Email / UPN complet (ex. user@domaine.fr)",
    "username": "Identifiant court (preferred_username)",
}

LOGIN_HTTP_METHODS: frozenset[str] = frozenset({"POST", "GET"})


def normalize_auth_mode(value: str | None) -> str:
    if not value:
        return "sso"
    lowered = value.strip().lower()
    if lowered in AUTH_MODES:
        return lowered
    return _AUTH_MODE_ALIASES.get(lowered, "sso")


def normalize_credential_mode(value: str | None) -> str:
    if not value:
        return "shared"
    lowered = value.strip().lower()
    if lowered in CREDENTIAL_MODES:
        return lowered
    return "shared"


def normalize_identity_format(value: str | None) -> str:
    if not value:
        return "email"
    lowered = value.strip().lower()
    if lowered in IDENTITY_FORMATS:
        return lowered
    return "email"


def resolve_identity_login_username(
    *,
    email: str | None,
    username: str | None,
    identity_format: str | None = "email",
) -> str:
    """
    Build the robotic/LDAPS login id from the OIDC session.

    Default ``email`` matches sessions/audit (user.email) and LDAPS UPN apps
    such as Grommunio. ``username`` keeps the short preferred_username.

    Never treat a Keycloak subject UUID as an email/UPN (oauth2-proxy can put
    ``sub`` into X-Auth-Request-Email when the email claim is missing).
    """
    from app.web.user_context import looks_like_uuid

    fmt = normalize_identity_format(identity_format)
    mail = (email or "").strip()
    short = (username or "").strip()
    if looks_like_uuid(mail):
        mail = ""
    if looks_like_uuid(short):
        short = ""

    if fmt == "username":
        if short and "@" not in short:
            return short
        if mail and "@" in mail:
            return mail.split("@", 1)[0]
        return short or mail

    # email / UPN
    if mail and "@" in mail:
        return mail
    if short and "@" in short:
        return short
    return mail or short


def resolve_robotic_driver(auth_mode: str, existing: str | None = None) -> str | None:
    """Map auth_mode to robotic_driver; preserve crushftp when auth_mode stays SSO."""
    mode = normalize_auth_mode(auth_mode)
    if mode == "generic_form":
        return "generic_form"
    if mode == "generic_basic_auth":
        return "generic_basic_auth"
    if mode == "generic_wsse":
        return "generic_wsse"
    if mode == "sso" and (existing or "").strip().lower() == "crushftp":
        return "crushftp"
    return None


def vault_enabled_for_app(auth_mode: str | None, robotic_driver: str | None) -> bool:
    driver = (robotic_driver or "").strip().lower()
    if driver in ROBOTIC_DRIVERS:
        return True
    return normalize_auth_mode(auth_mode) in (
        "generic_form",
        "generic_basic_auth",
        "generic_wsse",
    )


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
