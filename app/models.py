"""SQLAlchemy models for the SSO portal catalogue and admin."""

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class App(Base):
    """Application registered in the catalogue."""

    __tablename__ = "apps"

    id = Column(Integer, primary_key=True)
    slug = Column(String, unique=True, nullable=False, index=True)
    label = Column(String, nullable=False)
    upstream_url = Column(String, nullable=False)
    realm_slug = Column(String, nullable=True)
    access_mode = Column(String, default="sso_gate", nullable=False)
    public_fqdn = Column(String, nullable=True)
    auth_mode = Column(String, default="sso")
    robotic_driver = Column(String, nullable=True)
    login_form_url = Column(String, nullable=True)
    login_username_field = Column(String, default="username", nullable=False)
    login_password_field = Column(String, default="password", nullable=False)
    login_extra_fields = Column(Text, nullable=True)
    login_http_method = Column(String, default="POST", nullable=False)
    credential_mode = Column(String, default="shared", nullable=False)
    # identite_utilisateur: "email" (UPN) or "username" (short preferred_username)
    identity_format = Column(String, default="email", nullable=False)
    healthcheck_url = Column(String, nullable=True)
    enabled = Column(Boolean, default=True)
    tile_icon = Column(String, nullable=True)
    description = Column(String(140), nullable=True)
    logo_path = Column(String, nullable=True)  # filename under PORTAL_DATA_DIR/uploads/app-logos/
    last_probe_status = Column(String, nullable=True)
    last_probe_http_code = Column(Integer, nullable=True)
    last_probe_latency_ms = Column(Integer, nullable=True)
    last_probe_at = Column(DateTime(timezone=True), nullable=True)
    last_probe_error = Column(String, nullable=True)
    probe_enabled = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    groups = relationship("AppGroup", back_populates="app", cascade="all, delete-orphan")
    credentials = relationship(
        "AppCredential",
        back_populates="app",
        cascade="all, delete-orphan",
        foreign_keys="AppCredential.app_slug",
    )


class RBACGroup(Base):
    """Keycloak RBAC group (e.g. admins, transfer-users)."""

    __tablename__ = "rbac_groups"

    id = Column(Integer, primary_key=True)
    # Display name (Keycloak group name for synced groups).
    name = Column(String, nullable=False, index=True)
    # Legacy/manual linkage (kept for backward compatibility with early Phase 3 APIs).
    realm_slug = Column(String, nullable=True)

    # New multi-realm Keycloak sync fields (Phase 4).
    realm_id = Column(Integer, ForeignKey("realm_configs.id"), nullable=True, index=True)
    keycloak_group_id = Column(String, nullable=True, index=True)
    path = Column(String, nullable=True)
    member_count = Column(Integer, nullable=True)
    synced_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "realm_id",
            "keycloak_group_id",
            name="uq_realm_kc_group",
        ),
    )

    app_links = relationship("AppGroup", back_populates="group")
    access_grants = relationship(
        "AccessGrant",
        back_populates="rbac_group",
        foreign_keys="AccessGrant.rbac_group_id",
    )


class AccessGrant(Base):
    """RBAC grant — group or user subject, application or system role resource."""

    __tablename__ = "access_grants"

    id = Column(Integer, primary_key=True)
    subject_type = Column(String, nullable=False)  # group | user
    rbac_group_id = Column(Integer, ForeignKey("rbac_groups.id"), nullable=True)
    keycloak_user_id = Column(String, nullable=True)
    user_display_cache = Column(String, nullable=True)

    resource_type = Column(String, nullable=False)  # application | system_role
    application_id = Column(Integer, ForeignKey("apps.id"), nullable=True)
    system_role = Column(String, nullable=True)

    access_level = Column(String, default="view", nullable=False)
    granted_at = Column(DateTime(timezone=True), default=utcnow)
    granted_by = Column(String, nullable=False)

    rbac_group = relationship(
        "RBACGroup",
        back_populates="access_grants",
        foreign_keys=[rbac_group_id],
    )
    application = relationship("App", foreign_keys=[application_id])

    __table_args__ = (
        CheckConstraint(
            "(subject_type = 'group' AND rbac_group_id IS NOT NULL AND keycloak_user_id IS NULL) OR "
            "(subject_type = 'user' AND keycloak_user_id IS NOT NULL AND rbac_group_id IS NULL)",
            name="ck_access_grant_subject_exclusive",
        ),
        CheckConstraint(
            "(resource_type = 'application' AND application_id IS NOT NULL AND system_role IS NULL) OR "
            "(resource_type = 'system_role' AND system_role IS NOT NULL AND application_id IS NULL)",
            name="ck_access_grant_resource_exclusive",
        ),
    )


class AppGroup(Base):
    """Association App <-> RBACGroup (authorized access)."""

    __tablename__ = "app_groups"

    id = Column(Integer, primary_key=True)
    app_id = Column(Integer, ForeignKey("apps.id"), nullable=False)
    group_id = Column(Integer, ForeignKey("rbac_groups.id"), nullable=False)

    app = relationship("App", back_populates="groups")
    group = relationship("RBACGroup", back_populates="app_links")


class AppCredential(Base):
    """Encrypted robotic service-account credential (Fernet) — portal vault."""

    __tablename__ = "app_credentials"

    id = Column(Integer, primary_key=True)
    app_slug = Column(
        String,
        ForeignKey("apps.slug"),
        nullable=False,
        unique=True,
        index=True,
    )
    robotic_username = Column(String, nullable=False)
    encrypted_password = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    rotated_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)

    app = relationship("App", back_populates="credentials", foreign_keys=[app_slug])


class UserAppCredential(Base):
    """Per-user vault override for an application (Fernet) — optional."""

    __tablename__ = "user_app_credentials"

    id = Column(Integer, primary_key=True)
    app_slug = Column(
        String,
        ForeignKey("apps.slug"),
        nullable=False,
        index=True,
    )
    keycloak_user_id = Column(String, nullable=False, index=True)
    robotic_username = Column(String, nullable=False)
    encrypted_password = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    rotated_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "app_slug",
            "keycloak_user_id",
            name="uq_user_app_credential",
        ),
    )

    app = relationship("App", foreign_keys=[app_slug])


class RealmConfig(Base):
    """OIDC realm configuration for multi-realm oauth2-proxy."""

    __tablename__ = "realm_configs"

    id = Column(Integer, primary_key=True)
    slug = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    issuer_url = Column(String, nullable=False)
    client_id = Column(String, nullable=False)
    client_secret_encrypted = Column(String, nullable=False)
    redirect_uri = Column(String, nullable=False)
    scopes = Column(String, nullable=False, default="openid profile email")
    oauth2_proxy_port = Column(Integer, unique=True, nullable=False)
    oauth2_cookie_secret_encrypted = Column(String, nullable=True)
    is_default = Column(Boolean, default=False)
    enabled = Column(Boolean, default=False)
    last_test_status = Column(String, nullable=True)
    last_test_detail = Column(Text, nullable=True)
    last_tested_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Keycloak Admin API service account (per realm) for RBAC groups sync.
    keycloak_admin_client_id = Column(String, nullable=True)
    keycloak_admin_client_secret_encrypted = Column(String, nullable=True)
    groups_sync_enabled = Column(Boolean, default=False)
    last_groups_sync_at = Column(DateTime(timezone=True), nullable=True)
    last_groups_sync_status = Column(String, nullable=True)  # "ok" | "error"
    last_groups_sync_error = Column(String, nullable=True)

    @property
    def oauth2_proxy_url(self) -> str:
        return f"http://127.0.0.1:{self.oauth2_proxy_port}"


class BreakGlassAccount(Base):
    """Break-glass account — portal access outside Keycloak."""

    __tablename__ = "breakglass_accounts"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    hashed_password = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    """Admin action audit journal."""

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    actor = Column(String, nullable=False)
    action = Column(String, nullable=False)
    target = Column(String, nullable=True)
    details = Column(JSON, nullable=True)
    ip_address = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class ActiveSession(Base):
    """Live portal / application session registry for the Sessions UI."""

    __tablename__ = "active_sessions"

    id = Column(String, primary_key=True)
    kind = Column(String, nullable=False, index=True)  # user | app
    user_email = Column(String, nullable=False, index=True)
    username = Column(String, nullable=False)
    realm = Column(String, nullable=False)
    protocol = Column(String, nullable=False)
    target = Column(String, nullable=False)
    source_ip = Column(String, nullable=True)
    status = Column(String, nullable=False, default="active")
    started_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    details = Column(JSON, nullable=True)  # cookie diagnostics, credential source, …
    last_verified_at = Column(DateTime(timezone=True), nullable=True)
    last_verified_status = Column(String, nullable=True)  # active | invalid | unknown


class PortalSettings(Base):
    """Singleton global portal settings (id=1)."""

    __tablename__ = "portal_settings"

    id = Column(Integer, primary_key=True, default=1)
    subdomain_sso_enabled = Column(Boolean, nullable=False, default=False)
    # Recommended Fernet key rotation cadence (days). Admin-editable; never auto-rotates.
    vault_key_rotation_days = Column(Integer, nullable=False, default=180)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)
    updated_by = Column(String, nullable=True)


class EncryptionKeyVersion(Base):
    """Metadata for application-vault Fernet key versions (never stores key material)."""

    __tablename__ = "encryption_key_versions"

    id = Column(Integer, primary_key=True)
    version = Column(Integer, unique=True, nullable=False, index=True)
    status = Column(String, nullable=False, default="active")  # active | retired | pending
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    activated_at = Column(DateTime(timezone=True), nullable=True)
    retired_at = Column(DateTime(timezone=True), nullable=True)
    source = Column(String, nullable=True)  # generated | migrated_from_env | rotated


class DependencySnapshot(Base):
    """Inventory of Python / npm packages with local vs registry versions."""

    __tablename__ = "dependency_snapshots"
    __table_args__ = (
        UniqueConstraint("ecosystem", "name", name="uq_dependency_ecosystem_name"),
    )

    id = Column(Integer, primary_key=True)
    ecosystem = Column(String, nullable=False, index=True)  # python | npm
    name = Column(String, nullable=False)
    declared_version = Column(String, nullable=True)  # constraint from manifest (^x / >=y)
    current_version = Column(String, nullable=False)  # installed / locked
    latest_version = Column(String, nullable=True)
    dep_type = Column(String, nullable=False, default="runtime")  # runtime | dev
    # True = declared in pyproject.toml / package.json; False = npm lockfile transitive
    is_direct = Column(Boolean, nullable=False, default=True)
    status = Column(String, nullable=False, default="unknown")
    # up_to_date | outdated_patch | outdated_minor | outdated_major | unknown
    last_checked_at = Column(DateTime(timezone=True), nullable=True)
    check_error = Column(String, nullable=True)
    # e.g. unlocked constraint when npm lockfile is missing
    notes = Column(String, nullable=True)
