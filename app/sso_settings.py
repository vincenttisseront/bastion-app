"""Portal configuration via environment variables."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    portal_domain: str = "portal.ar-systems.fr"
    sso_portal_default_realm_slug: str = "ar-systems"

    vault_portal_internal_token: str = ""
    vault_sso_portal_oidc_client_secret: str = ""
    vault_portal_vault_fernet_key: str = ""

    database_url: str = "sqlite:///var/lib/sso-portal/portal.db"
    exports_dir: str = "./exports"

    subdomain_sso_enabled: bool = False
    subdomain_auth_enabled: bool = False

    oauth2_proxy_default_url: str = "http://127.0.0.1:4180"

    rfc1918_bypass_enabled: bool = True
    rfc1918_cidrs: list[str] = Field(
        default=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.1/32"]
    )

    portal_admin_groups: list[str] = Field(
        default=["portal-admins", "bastion-admins", "admins"]
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
