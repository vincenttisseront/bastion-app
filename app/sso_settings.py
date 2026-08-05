"""Portal configuration via environment variables."""

from functools import lru_cache
from typing import Annotated, Any

from pydantic import AliasChoices, Field, field_validator, model_validator
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

    # development | test | production — used for fail-closed secret checks.
    # No prior env detector existed in this repo; PORTAL_ENVIRONMENT is the canonical name.
    environment: str = Field(
        default="development",
        validation_alias=AliasChoices(
            "PORTAL_ENVIRONMENT",
            "ENVIRONMENT",
            "environment",
        ),
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
    # ALTCHA PoW captcha HMAC (empty → derived from vault_portal_internal_token).
    altcha_hmac_key: str = Field(
        default="",
        validation_alias=AliasChoices(
            "ALTCHA_HMAC_KEY",
            "altcha_hmac_key",
        ),
    )
    # PoW search space upper bound (higher = harder for bots, slower for users).
    altcha_max_number: int = Field(
        default=100_000,
        validation_alias=AliasChoices(
            "ALTCHA_MAX_NUMBER",
            "altcha_max_number",
        ),
    )
    # HMAC key for bg_session JWT — must NOT be the Bearer internal token.
    breakglass_jwt_secret: str = Field(
        default="",
        validation_alias=AliasChoices(
            "BREAKGLASS_JWT_SECRET",
            "breakglass_jwt_secret",
        ),
    )
    # Temporary: accept cookies signed with VAULT_PORTAL_INTERNAL_TOKEN during migration.
    # Forced off when environment=production (see model_validator).
    breakglass_jwt_secret_fallback_enabled: bool = Field(
        default=True,
        validation_alias=AliasChoices(
            "BREAKGLASS_JWT_SECRET_FALLBACK_ENABLED",
            "breakglass_jwt_secret_fallback_enabled",
        ),
    )
    # HMAC for robotic session-cookie hop — distinct from VAULT_PORTAL_INTERNAL_TOKEN.
    session_hop_secret: str = Field(
        default="",
        validation_alias=AliasChoices(
            "SESSION_HOP_SECRET",
            "session_hop_secret",
        ),
    )
    # Native OIDC session JWT (bastion_session cookie) — NEVER reuse break-glass
    # or VAULT_PORTAL_INTERNAL_TOKEN (see model_validator ensure_oidc_session_secret).
    oidc_session_jwt_secret: str = Field(
        default="",
        validation_alias=AliasChoices(
            "OIDC_SESSION_JWT_SECRET",
            "oidc_session_jwt_secret",
        ),
    )
    oidc_session_cookie_name: str = Field(
        default="bastion_session",
        validation_alias=AliasChoices(
            "OIDC_SESSION_COOKIE_NAME",
            "oidc_session_cookie_name",
        ),
    )
    # Seconds — aligned with oauth2-proxy cookie_expire (12h).
    oidc_session_max_age: int = Field(
        default=12 * 3600,
        validation_alias=AliasChoices(
            "OIDC_SESSION_MAX_AGE",
            "oidc_session_max_age",
        ),
    )
    # Progressive cutover — prefer Admin UI toggle on RealmConfig; CSV is ops bootstrap.
    # Example: OIDC_NATIVE_SESSION_ENABLED_REALMS=pilot-clients,sandbox
    oidc_native_session_enabled_realms: str = Field(
        default="",
        validation_alias=AliasChoices(
            "OIDC_NATIVE_SESSION_ENABLED_REALMS",
            "oidc_native_session_enabled_realms",
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
    # SQLCipher file-level key (32-byte hex). Distinct from Fernet column key.
    # Prefer keys/db_encryption.key; env used for AWX bootstrap / migration to file.
    vault_portal_db_encryption_key: str = Field(
        default="",
        validation_alias=AliasChoices(
            "VAULT_PORTAL_DB_ENCRYPTION_KEY",
            "vault_portal_db_encryption_key",
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
    # Persistent data root (SQLite, exports, uploads). Docker: /var/lib/sso-portal.
    portal_data_dir: str = Field(
        default="./data/sso-portal",
        validation_alias=AliasChoices(
            "PORTAL_DATA_DIR",
            "portal_data_dir",
        ),
    )
    # Shared with bastion-nginx /var/log/nginx/apps (per-app access logs).
    # Empty → {portal_data_dir}/nginx-logs
    nginx_app_logs_dir: str = Field(
        default="",
        validation_alias=AliasChoices(
            "NGINX_APP_LOGS_DIR",
            "nginx_app_logs_dir",
        ),
    )
    # Dedicated blob root for catalogue files (empty → {portal_data_dir}/private/files).
    files_storage_dir: str = Field(
        default="",
        validation_alias=AliasChoices(
            "FILES_STORAGE_DIR",
            "files_storage_dir",
        ),
    )
    file_encryption_chunk_size: int = Field(
        default=1_048_576,
        validation_alias=AliasChoices(
            "FILE_ENCRYPTION_CHUNK_SIZE",
            "file_encryption_chunk_size",
        ),
    )
    # Application-managed Fernet key directory (Phase B — not AWX-delivered).
    # Empty → {portal_data_dir}/keys
    vault_keys_dir: str = Field(
        default="",
        validation_alias=AliasChoices(
            "VAULT_KEYS_DIR",
            "vault_keys_dir",
        ),
    )
    vault_key_rotation_days_default: int = Field(
        default=180,
        validation_alias=AliasChoices(
            "VAULT_KEY_ROTATION_DAYS",
            "vault_key_rotation_days",
        ),
    )

    subdomain_sso_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices("SUBDOMAIN_SSO_ENABLED", "subdomain_sso_enabled"),
    )
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
    # loopback = bare-metal (127.0.0.1:port) ; docker = service DNS oauth2-proxy-{slug}:4180
    oauth2_proxy_network_mode: str = Field(
        default="loopback",
        validation_alias=AliasChoices(
            "OAUTH2_PROXY_NETWORK_MODE",
            "oauth2_proxy_network_mode",
        ),
    )
    # Emergency only: oauth2-proxy skips TLS verify toward OIDC issuer (Keycloak).
    # Prefer fixing Keycloak HTTPS / ACME for the IdP FQDN instead.
    oauth2_ssl_insecure_skip_verify: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "OAUTH2_SSL_INSECURE_SKIP_VERIFY",
            "oauth2_ssl_insecure_skip_verify",
        ),
    )

    # Shared flag for optional LAN auth shortcuts. Default false (F-04 2026-07-25):
    # disable until the reverse01 → nginx-bastion → app client-IP chain is proven.
    # Portal /internal/oauth2-auth never applies this bypass; subdomain did when true.
    rfc1918_bypass_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "RFC1918_BYPASS_ENABLED",
            "PORTAL_RFC1918_BYPASS_AUTH",
            "rfc1918_bypass_enabled",
        ),
    )
    rfc1918_cidrs: Annotated[list[str], NoDecode] = Field(
        default=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.1/32"]
    )
    # TCP peers allowed to set X-Real-IP / X-Forwarded-For (nginx-bastion → FastAPI).
    # Do NOT include the public Internet or the DMZ reverse alone — only the hop
    # that terminates TLS toward the app (docker vpcbr / loopback).
    trusted_proxy_cidrs: Annotated[list[str], NoDecode] = Field(
        default=["10.5.0.0/16", "172.17.0.0/16", "127.0.0.0/8"],
        validation_alias=AliasChoices(
            "TRUSTED_PROXY_CIDRS",
            "trusted_proxy_cidrs",
        ),
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

    log_level: str = Field(
        default="INFO",
        validation_alias=AliasChoices("LOG_LEVEL", "log_level"),
    )
    log_format: str = Field(
        default="text",
        validation_alias=AliasChoices("LOG_FORMAT", "log_format"),
    )

    # SSE timeout for /admin/logs live streams (audit + container tail).
    admin_logs_sse_timeout_seconds: int = Field(
        default=1800,
        validation_alias=AliasChoices(
            "ADMIN_LOGS_SSE_TIMEOUT_SECONDS",
            "admin_logs_sse_timeout_seconds",
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

    @field_validator("trusted_proxy_cidrs", mode="before")
    @classmethod
    def parse_trusted_proxy_cidrs(cls, value: Any) -> list[str]:
        return _parse_csv_or_json_list(
            value,
            default=["10.5.0.0/16", "172.17.0.0/16", "127.0.0.0/8"],
        )

    @field_validator("environment", mode="before")
    @classmethod
    def normalize_environment(cls, value: Any) -> str:
        raw = str(value or "development").strip().lower()
        if raw in ("prod", "production"):
            return "production"
        if raw in ("test", "testing", "pytest"):
            return "test"
        if raw in ("dev", "development", "local"):
            return "development"
        return raw or "development"

    @model_validator(mode="after")
    def ensure_oidc_session_secret(self) -> "Settings":
        """Reject shared secrets; do not mint an ephemeral HMAC here.

        Auto-minting on every process start invalidated ``bastion_session`` after
        each container rebuild while ``OidcSession`` rows stayed in SQLite
        (sessions UI still REGISTRE → forced SSO re-login). Persist via
        ``ensure_portal_runtime_secrets`` / ``resolve_oidc_session_jwt_secret``.
        """
        forbidden = {
            (self.breakglass_jwt_secret or "").strip(),
            (self.vault_portal_internal_token or "").strip(),
            (self.session_hop_secret or "").strip(),
        }
        forbidden.discard("")
        current = (self.oidc_session_jwt_secret or "").strip()
        if current and current in forbidden:
            object.__setattr__(self, "oidc_session_jwt_secret", "")
        return self

    @model_validator(mode="after")
    def enforce_production_secrets(self) -> "Settings":
        """Production: never fall back to VAULT_PORTAL_INTERNAL_TOKEN for JWT.

        HMAC values may live in SQLite (``ensure_portal_runtime_secrets``) rather
        than ``.env`` — lifespan fails closed if hop secret is still missing after
        ensure. Env SESSION_HOP_SECRET / BREAKGLASS_JWT_SECRET remain optional
        overrides (pytest / emergency / AWX).
        """
        if self.environment != "production":
            return self
        object.__setattr__(self, "breakglass_jwt_secret_fallback_enabled", False)
        return self

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def is_test(self) -> bool:
        return self.environment == "test"


@lru_cache
def get_settings() -> Settings:
    return Settings()
