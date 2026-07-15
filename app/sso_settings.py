"""Portal configuration via environment variables."""

from functools import lru_cache
from typing import Annotated, Any

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


def _parse_csv_or_json_list(value: Any, default: list[str]) -> list[str]:
    if value is None:
        return default
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if not isinstance(value, str):
        return default
    stripped = value.strip()
    if not stripped:
        return default
    if stripped.startswith("["):
        import json

        parsed = json.loads(stripped)
        if isinstance(parsed, list):
            return [str(item).strip() for item in parsed if str(item).strip()]
    return [part.strip() for part in stripped.split(",") if part.strip()]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
        populate_by_name=True,
    )

    portal_domain: str = Field(
        default="portal.ar-systems.fr",
        validation_alias=AliasChoices("PORTAL_DOMAIN", "portal_domain"),
    )
    sso_portal_default_realm_slug: str = Field(
        default="ar-systems",
        validation_alias=AliasChoices(
            "SSO_PORTAL_DEFAULT_REALM_SLUG",
            "PORTAL_DEFAULT_REALM_SLUG",
            "sso_portal_default_realm_slug",
        ),
    )

    vault_portal_internal_token: str = Field(
        default="",
        validation_alias=AliasChoices(
            "VAULT_PORTAL_INTERNAL_TOKEN",
            "PORTAL_INTERNAL_TOKEN",
            "vault_portal_internal_token",
        ),
    )
    vault_sso_portal_oidc_client_secret: str = Field(
        default="",
        validation_alias=AliasChoices(
            "VAULT_SSO_PORTAL_OIDC_CLIENT_SECRET",
            "OIDC_CLIENT_SECRET",
            "vault_sso_portal_oidc_client_secret",
        ),
    )
    vault_portal_vault_fernet_key: str = Field(
        default="",
        validation_alias=AliasChoices(
            "VAULT_PORTAL_VAULT_FERNET_KEY",
            "PORTAL_VAULT_FERNET_KEY",
            "vault_portal_vault_fernet_key",
        ),
    )
    portal_secret_encryption_key: str = Field(
        default="",
        validation_alias=AliasChoices(
            "PORTAL_SECRET_ENCRYPTION_KEY",
            "portal_secret_encryption_key",
        ),
    )

    database_url: str = Field(
        default="sqlite:///var/lib/sso-portal/portal.db",
        validation_alias=AliasChoices("DATABASE_URL", "database_url"),
    )
    exports_dir: str = Field(
        default="./exports",
        validation_alias=AliasChoices("EXPORTS_DIR", "NGINX_EXPORT_DIR", "exports_dir"),
    )

    subdomain_sso_enabled: bool = False
    subdomain_auth_enabled: bool = False

    oauth2_proxy_default_url: str = Field(
        default="http://127.0.0.1:4180",
        validation_alias=AliasChoices("OAUTH2_PROXY_DEFAULT_URL", "oauth2_proxy_default_url"),
    )

    oauth2_proxy_port_min: int = Field(
        default=4180,
        validation_alias=AliasChoices("OAUTH2_PROXY_PORT_MIN", "oauth2_proxy_port_min"),
    )
    oauth2_proxy_port_max: int = Field(
        default=4299,
        validation_alias=AliasChoices("OAUTH2_PROXY_PORT_MAX", "oauth2_proxy_port_max"),
    )
    oauth2_core_static_enabled: bool = Field(
        default=True,
        validation_alias=AliasChoices(
            "OAUTH2_CORE_STATIC_ENABLED",
            "oauth2_core_static_enabled",
        ),
    )

    rfc1918_bypass_enabled: bool = Field(
        default=True,
        validation_alias=AliasChoices(
            "RFC1918_BYPASS_ENABLED",
            "PORTAL_RFC1918_BYPASS_AUTH",
            "rfc1918_bypass_enabled",
        ),
    )
    rfc1918_cidrs: Annotated[list[str], NoDecode] = Field(
        default=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.1/32"]
    )

    portal_admin_groups: Annotated[list[str], NoDecode] = Field(
        default=["portal-admins", "bastion-admins", "admins"]
    )

    health_probe_interval_minutes: int = Field(
        default=5,
        validation_alias=AliasChoices(
            "HEALTH_PROBE_INTERVAL_MINUTES",
            "health_probe_interval_minutes",
        ),
    )
    health_probe_leader: bool = Field(
        default=True,
        validation_alias=AliasChoices(
            "HEALTH_PROBE_LEADER",
            "health_probe_leader",
        ),
    )

    @field_validator("portal_admin_groups", mode="before")
    @classmethod
    def parse_portal_admin_groups(cls, value: Any) -> list[str]:
        return _parse_csv_or_json_list(
            value,
            default=["portal-admins", "bastion-admins", "admins"],
        )

    @field_validator("rfc1918_cidrs", mode="before")
    @classmethod
    def parse_rfc1918_cidrs(cls, value: Any) -> list[str]:
        return _parse_csv_or_json_list(
            value,
            default=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.1/32"],
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
