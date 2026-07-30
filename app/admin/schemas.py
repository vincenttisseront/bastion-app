"""Pydantic validation for RealmConfig admin forms."""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ValidationError, field_validator

SLUG_PATTERN = re.compile(r"^[a-z0-9-]{2,40}$")


class RealmConfigBase(BaseModel):
    name: str
    issuer_url: str
    client_id: str
    oauth2_proxy_port: int
    scopes: str = "openid profile email"
    is_default: bool = False
    enabled: bool = False
    keycloak_admin_client_id: str | None = None
    keycloak_admin_client_secret: str | None = None
    # Provisioning (WRITE) service account — distinct from the sync account above.
    keycloak_provision_client_id: str | None = None
    keycloak_provision_client_secret: str | None = None
    # Explicit opt-in checkbox — never auto-derived from credentials presence.
    provisioning_enabled: bool = False

    @field_validator("keycloak_provision_client_id", "keycloak_provision_client_secret")
    @classmethod
    def _strip_provision_fields(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        return stripped or None

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("Le nom est requis")
        if len(stripped) > 100:
            raise ValueError("Le nom ne doit pas dépasser 100 caractères")
        return stripped

    @field_validator("issuer_url")
    @classmethod
    def validate_issuer_url(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped.startswith("https://"):
            raise ValueError("L'URL doit commencer par https://")
        return stripped.rstrip("/")

    @field_validator("client_id")
    @classmethod
    def validate_client_id(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("Client ID requis")
        return stripped

    @field_validator("oauth2_proxy_port")
    @classmethod
    def validate_oauth2_proxy_port(cls, value: int) -> int:
        if value < 4180 or value > 4299:
            raise ValueError("Le port doit être entre 4180 et 4299")
        return value

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, value: str) -> str:
        if "openid" not in value.split():
            raise ValueError("Le scope openid est obligatoire")
        return value.strip()


class RealmConfigCreate(RealmConfigBase):
    slug: str
    client_secret: str

    @field_validator("slug")
    @classmethod
    def validate_slug(cls, value: str) -> str:
        stripped = value.strip().lower()
        if not SLUG_PATTERN.match(stripped):
            raise ValueError(
                "Slug invalide : lettres minuscules, chiffres, tirets uniquement"
            )
        return stripped

    @field_validator("client_secret")
    @classmethod
    def validate_client_secret(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Client secret requis")
        return value

    @field_validator("keycloak_admin_client_id")
    @classmethod
    def validate_keycloak_admin_client_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        return stripped or None

    @field_validator("keycloak_admin_client_secret")
    @classmethod
    def validate_keycloak_admin_client_secret(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        return stripped or None


class RealmConfigUpdate(RealmConfigBase):
    client_secret: str | None = None

    @field_validator("client_secret")
    @classmethod
    def validate_client_secret(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            return None
        return value

    @field_validator("keycloak_admin_client_secret")
    @classmethod
    def validate_keycloak_admin_client_secret(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            return None
        return value


class RealmTestBody(BaseModel):
    issuer_url: str
    client_id: str
    client_secret: str

    @field_validator("issuer_url")
    @classmethod
    def validate_issuer_url(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped.startswith("https://"):
            raise ValueError("L'URL doit commencer par https://")
        return stripped.rstrip("/")

    @field_validator("client_id")
    @classmethod
    def validate_client_id(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("Client ID requis")
        return stripped

    @field_validator("client_secret")
    @classmethod
    def validate_client_secret(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Client secret requis")
        return value


def validation_errors_response(exc: ValidationError) -> dict[str, Any]:
    errors: dict[str, str] = {}
    for err in exc.errors():
        field = err["loc"][0] if err["loc"] else "_form"
        if field not in errors:
            errors[str(field)] = err["msg"]
    return {"ok": False, "errors": errors}


def slug_error_message() -> str:
    return "Slug invalide : lettres minuscules, chiffres, tirets uniquement"


class PortTestBody(BaseModel):
    port: int

    @field_validator("port")
    @classmethod
    def validate_port(cls, value: int) -> int:
        # Range is enforced server-side with Settings too; keep a safe default here.
        if value < 1 or value > 65535:
            raise ValueError("Port invalide")
        return value
