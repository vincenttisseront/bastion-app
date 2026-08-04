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
    # Account provisioning driver (None = SSO only, no local account pushed).
    # V1 values: "crushftp" | "generic" (explicit no-op). See app/bastion/drivers/registry.py.
    provisioning_driver = Column(String, nullable=True)
    # CrushFTP Admin API (Basic Auth) — shared per app, DISTINCT from AppCredential vault
    # (per-end-user robotic credentials). See creation-comptes §13.
    crushftp_admin_base_url = Column(String, nullable=True)
    crushftp_admin_server_group = Column(String, nullable=True)  # default "MainUsers" in driver
    crushftp_admin_username = Column(String, nullable=True)
    crushftp_admin_password_encrypted = Column(Text, nullable=True)
    # Physical root for company folders (e.g. /crush_data/AR-SYSTEMS) → FILE://…/SOCIETE/
    crushftp_vfs_base_path = Column(String, nullable=True)
    login_form_url = Column(String, nullable=True)
    login_username_field = Column(String, default="username", nullable=False)
    login_password_field = Column(String, default="password", nullable=False)
    login_extra_fields = Column(Text, nullable=True)
    login_http_method = Column(String, default="POST", nullable=False)
    credential_mode = Column(String, default="shared", nullable=False)
    # identite_utilisateur: "email" (UPN) or "username" (short preferred_username)
    identity_format = Column(String, default="email", nullable=False)
    # Target session cookies: host_only (default) or wide_domain (opt-in parent Domain)
    injected_cookie_scope = Column(String, default="host_only", nullable=False)
    # Mobile messaging (EAS): allow ActiveSync/Autodiscover without browser SSO redirect
    allow_activesync = Column(Boolean, default=False, nullable=False)
    # Verify upstream TLS cert from bastion (robotic httpx + nginx). Off for LAN/self-signed.
    upstream_tls_verify = Column(Boolean, default=False, nullable=False)
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
    # Optional UI metadata (RBAC UI v2 — Stitch alignment).
    group_tag = Column(String, nullable=True)  # e.g. Critical Access, Audit-Only
    description = Column(String, nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "realm_id",
            "keycloak_group_id",
            name="uq_realm_kc_group",
        ),
    )

    access_grants = relationship(
        "AccessGrant",
        back_populates="rbac_group",
        foreign_keys="AccessGrant.rbac_group_id",
    )


class PermissionModule(Base):
    """Internal Bastion Pro module for governance RBAC (not catalogue apps)."""

    __tablename__ = "permission_modules"

    id = Column(Integer, primary_key=True)
    key = Column(String, unique=True, nullable=False, index=True)
    label = Column(String, nullable=False)
    description = Column(String, nullable=True)
    icon = Column(String, nullable=True)
    sort_order = Column(Integer, default=0, nullable=False)


class RbacRole(Base):
    """Named role governing internal Bastion Pro module permissions."""

    __tablename__ = "rbac_roles"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False, index=True)
    inherits_from_id = Column(Integer, ForeignKey("rbac_roles.id"), nullable=True)
    is_critical = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    inherits_from = relationship("RbacRole", remote_side=[id], uselist=False)
    permissions = relationship(
        "RolePermission",
        back_populates="role",
        cascade="all, delete-orphan",
        foreign_keys="RolePermission.role_id",
    )


class RolePermission(Base):
    """Per-module CRUD/execute flags for an RbacRole."""

    __tablename__ = "role_permissions"

    id = Column(Integer, primary_key=True)
    role_id = Column(Integer, ForeignKey("rbac_roles.id"), nullable=False, index=True)
    module_id = Column(
        Integer, ForeignKey("permission_modules.id"), nullable=False, index=True
    )
    can_read = Column(Boolean, default=False, nullable=False)
    can_write = Column(Boolean, default=False, nullable=False)
    can_delete = Column(Boolean, default=False, nullable=False)
    can_execute = Column(Boolean, default=False, nullable=False)
    locked = Column(Boolean, default=False, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    updated_by = Column(String, nullable=True)

    role = relationship("RbacRole", back_populates="permissions", foreign_keys=[role_id])
    module = relationship("PermissionModule", foreign_keys=[module_id])

    __table_args__ = (
        UniqueConstraint("role_id", "module_id", name="uq_role_module"),
    )


class AccessGrant(Base):
    """RBAC grant — group or user subject → application, system_role, rbac_role, file, or folder."""

    __tablename__ = "access_grants"

    id = Column(Integer, primary_key=True)
    subject_type = Column(String, nullable=False)  # group | user
    rbac_group_id = Column(Integer, ForeignKey("rbac_groups.id"), nullable=True)
    keycloak_user_id = Column(String, nullable=True)
    user_display_cache = Column(String, nullable=True)

    resource_type = Column(String, nullable=False)  # application | system_role | rbac_role | file | folder
    application_id = Column(Integer, ForeignKey("apps.id"), nullable=True)
    system_role = Column(String, nullable=True)
    rbac_role_id = Column(Integer, ForeignKey("rbac_roles.id"), nullable=True)
    file_id = Column(Integer, ForeignKey("file_resources.id"), nullable=True)
    folder_id = Column(Integer, ForeignKey("file_folders.id"), nullable=True)

    access_level = Column(String, default="view", nullable=False)
    granted_at = Column(DateTime(timezone=True), default=utcnow)
    granted_by = Column(String, nullable=False)

    rbac_group = relationship(
        "RBACGroup",
        back_populates="access_grants",
        foreign_keys=[rbac_group_id],
    )
    application = relationship("App", foreign_keys=[application_id])
    rbac_role = relationship("RbacRole", foreign_keys=[rbac_role_id])
    file_resource = relationship("FileResource", foreign_keys=[file_id])
    folder = relationship("FileFolder", foreign_keys=[folder_id])

    __table_args__ = (
        CheckConstraint(
            "(subject_type = 'group' AND rbac_group_id IS NOT NULL AND keycloak_user_id IS NULL) OR "
            "(subject_type = 'user' AND keycloak_user_id IS NOT NULL AND rbac_group_id IS NULL)",
            name="ck_access_grant_subject_exclusive",
        ),
        CheckConstraint(
            "(resource_type = 'application' AND application_id IS NOT NULL "
            "AND system_role IS NULL AND rbac_role_id IS NULL AND file_id IS NULL AND folder_id IS NULL) OR "
            "(resource_type = 'system_role' AND system_role IS NOT NULL "
            "AND application_id IS NULL AND rbac_role_id IS NULL AND file_id IS NULL AND folder_id IS NULL) OR "
            "(resource_type = 'rbac_role' AND rbac_role_id IS NOT NULL "
            "AND application_id IS NULL AND system_role IS NULL AND file_id IS NULL AND folder_id IS NULL) OR "
            "(resource_type = 'file' AND file_id IS NOT NULL "
            "AND application_id IS NULL AND system_role IS NULL AND rbac_role_id IS NULL AND folder_id IS NULL) OR "
            "(resource_type = 'folder' AND folder_id IS NOT NULL "
            "AND application_id IS NULL AND system_role IS NULL AND rbac_role_id IS NULL AND file_id IS NULL)",
            name="ck_access_grant_resource_exclusive",
        ),
    )


class FileFolder(Base):
    """Folder node in the CrushFTP-style file browser tree."""

    __tablename__ = "file_folders"

    id = Column(Integer, primary_key=True)
    parent_folder_id = Column(
        Integer, ForeignKey("file_folders.id", ondelete="CASCADE"), nullable=True, index=True
    )
    name = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    created_by = Column(String, nullable=False)

    parent = relationship("FileFolder", remote_side=[id], backref="children")

    __table_args__ = (
        UniqueConstraint("parent_folder_id", "name", name="uq_folder_name_per_parent"),
    )


class FileResource(Base):
    """File identity within a folder — access via AccessGrant(file|folder) with inheritance."""

    __tablename__ = "file_resources"

    id = Column(Integer, primary_key=True)
    folder_id = Column(
        Integer, ForeignKey("file_folders.id", ondelete="SET NULL"), nullable=True, index=True
    )
    slug = Column(String, unique=True, nullable=False, index=True)
    label = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    created_by = Column(String, nullable=False)

    folder = relationship("FileFolder", foreign_keys=[folder_id])
    versions = relationship(
        "FileVersion",
        back_populates="file_resource",
        cascade="all, delete-orphan",
        foreign_keys="FileVersion.file_id",
    )
    channel_assignments = relationship(
        "FileChannelAssignment",
        back_populates="file_resource",
        cascade="all, delete-orphan",
        foreign_keys="FileChannelAssignment.file_id",
    )

    __table_args__ = (
        UniqueConstraint("folder_id", "label", name="uq_file_label_per_folder"),
    )


class FileVersion(Base):
    """One uploaded binary for a FileResource, tagged beta or stable."""

    __tablename__ = "file_versions"

    id = Column(Integer, primary_key=True)
    file_id = Column(
        Integer,
        ForeignKey("file_resources.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    channel = Column(String, nullable=False)  # beta | stable
    version_label = Column(String, nullable=False)
    status = Column(String, nullable=False, default="active")  # active | archived
    original_filename = Column(String, nullable=False)
    content_type = Column(String, nullable=True)
    size_bytes = Column(Integer, nullable=False, default=0)
    checksum_sha256 = Column(String, nullable=False)
    storage_path = Column(String, nullable=False, unique=True)
    encrypted = Column(Boolean, nullable=False, default=True)
    uploaded_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    uploaded_by = Column(String, nullable=False)
    changelog = Column(Text, nullable=True)

    file_resource = relationship(
        "FileResource",
        back_populates="versions",
        foreign_keys=[file_id],
    )

    __table_args__ = (
        UniqueConstraint("file_id", "version_label", name="uq_file_version_label"),
        CheckConstraint(
            "channel IN ('beta', 'stable')",
            name="ck_file_version_channel",
        ),
    )


class FileChannelAssignment(Base):
    """Beta channel opt-in on a file or folder (inheritance up the tree). Absence → stable."""

    __tablename__ = "file_channel_assignments"

    id = Column(Integer, primary_key=True)
    file_id = Column(
        Integer,
        ForeignKey("file_resources.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    folder_id = Column(
        Integer,
        ForeignKey("file_folders.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    subject_type = Column(String, nullable=False)  # group | user
    rbac_group_id = Column(
        Integer, ForeignKey("rbac_groups.id", ondelete="CASCADE"), nullable=True
    )
    keycloak_user_id = Column(String, nullable=True, index=True)
    user_display_cache = Column(String, nullable=True)
    channel = Column(String, nullable=False, default="beta")
    assigned_at = Column(DateTime(timezone=True), default=utcnow)
    assigned_by = Column(String, nullable=False)

    file_resource = relationship(
        "FileResource",
        back_populates="channel_assignments",
        foreign_keys=[file_id],
    )
    folder = relationship("FileFolder", foreign_keys=[folder_id])
    rbac_group = relationship("RBACGroup", foreign_keys=[rbac_group_id])

    __table_args__ = (
        CheckConstraint(
            "(file_id IS NOT NULL AND folder_id IS NULL) OR "
            "(file_id IS NULL AND folder_id IS NOT NULL)",
            name="ck_file_channel_target_exclusive",
        ),
        CheckConstraint(
            "channel = 'beta'",
            name="ck_file_channel_assignment_beta_only",
        ),
        CheckConstraint(
            "(subject_type = 'group' AND rbac_group_id IS NOT NULL AND keycloak_user_id IS NULL) OR "
            "(subject_type = 'user' AND keycloak_user_id IS NOT NULL AND rbac_group_id IS NULL)",
            name="ck_file_channel_assignment_subject_exclusive",
        ),
    )


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


class GroupAppCredential(Base):
    """Vault credential shared by all members of an RBAC group for one app.

    Priority is explicit: when a user belongs to several groups with a credential
    for the same app, the highest ``priority`` wins (then lowest id).
    """

    __tablename__ = "group_app_credentials"

    id = Column(Integer, primary_key=True)
    rbac_group_id = Column(
        Integer,
        ForeignKey("rbac_groups.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    app_slug = Column(
        String,
        ForeignKey("apps.slug"),
        nullable=False,
        index=True,
    )
    robotic_username = Column(String, nullable=False)
    encrypted_password = Column(Text, nullable=False)
    priority = Column(Integer, nullable=False, default=100)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    rotated_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "rbac_group_id",
            "app_slug",
            name="uq_group_app_credential",
        ),
    )

    rbac_group = relationship("RBACGroup", foreign_keys=[rbac_group_id])
    app = relationship("App", foreign_keys=[app_slug])
    exclusions = relationship(
        "GroupAppCredentialExclusion",
        back_populates="group_credential",
        cascade="all, delete-orphan",
        foreign_keys="GroupAppCredentialExclusion.group_app_credential_id",
    )


class GroupAppCredentialExclusion(Base):
    """User excluded from a group shared credential — must use individual override."""

    __tablename__ = "group_app_credential_exclusions"

    id = Column(Integer, primary_key=True)
    group_app_credential_id = Column(
        Integer,
        ForeignKey("group_app_credentials.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    keycloak_user_id = Column(String, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "group_app_credential_id",
            "keycloak_user_id",
            name="uq_group_app_credential_exclusion",
        ),
    )

    group_credential = relationship(
        "GroupAppCredential",
        back_populates="exclusions",
        foreign_keys=[group_app_credential_id],
    )


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
    # Pilot rollout: accept/issue bastion_session for this realm (Admin toggle).
    oidc_native_session_enabled = Column(Boolean, nullable=False, default=False)
    # Bastion-side MFA for native OIDC: enrollment UI + admin « Configurer OTP ».
    # When false, CONFIGURE_TOTP is refused; login OTP challenge still honored if IdP asks.
    oidc_mfa_enabled = Column(Boolean, nullable=False, default=True)
    # Public login chooser: show this realm among Interne / Clients / … options.
    show_on_login = Column(Boolean, nullable=False, default=True)
    # Optional short label for the login audience tabs (overrides heuristic).
    login_label = Column(String, nullable=True)
    # Native OIDC BFF client (per-realm) — secrets Fernet, never returned in clear by API/UI.
    oidc_keycloak_base_url = Column(String, nullable=True)
    oidc_bff_client_id = Column(String, nullable=True)
    oidc_bff_client_secret_encrypted = Column(Text, nullable=True)
    oidc_bff_redirect_uri = Column(String, nullable=True)
    last_test_status = Column(String, nullable=True)
    last_test_detail = Column(Text, nullable=True)
    last_tested_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Keycloak Admin API service account (per realm) for RBAC groups sync.
    keycloak_admin_client_id = Column(String, nullable=True)
    keycloak_admin_client_secret_encrypted = Column(String, nullable=True)
    groups_sync_enabled = Column(Boolean, default=False)
    # Optional allowlist: one group name or path per line. Empty = sync all groups.
    groups_sync_include = Column(Text, nullable=True)
    last_groups_sync_at = Column(DateTime(timezone=True), nullable=True)
    last_groups_sync_status = Column(String, nullable=True)  # "ok" | "error"
    last_groups_sync_error = Column(String, nullable=True)

    # Keycloak Admin API service account (per realm) for user provisioning (WRITE:
    # manage-users). Distinct from the read-oriented sync account above.
    # provisioning_enabled is an EXPLICIT opt-in (never auto-derived from the
    # credentials being present, unlike groups_sync_enabled — write access to
    # Keycloak deserves a conscious checkbox).
    keycloak_provision_client_id = Column(String, nullable=True)
    keycloak_provision_client_secret_encrypted = Column(String, nullable=True)
    provisioning_enabled = Column(Boolean, default=False, nullable=False)

    # Per-realm SMTP — used to email Keycloak credentials (create / reset) and
    # notify admins of access requests. Password Fernet-encrypted like other secrets.
    smtp_enabled = Column(Boolean, default=False, nullable=False)
    smtp_host = Column(String, nullable=True)
    smtp_port = Column(Integer, nullable=True)  # default 587 when unset
    smtp_use_tls = Column(Boolean, default=True, nullable=False)  # STARTTLS
    smtp_username = Column(String, nullable=True)
    smtp_password_encrypted = Column(Text, nullable=True)
    smtp_from_email = Column(String, nullable=True)
    smtp_from_name = Column(String, nullable=True)
    # Public « Demander un accès » form on the login page → AccessRequest queue.
    access_request_enabled = Column(Boolean, default=False, nullable=False)
    # Auto-email the temporary Keycloak password after create / reset (needs SMTP).
    send_credentials_email = Column(Boolean, default=False, nullable=False)

    @property
    def oauth2_proxy_url(self) -> str:
        return f"http://127.0.0.1:{self.oauth2_proxy_port}"


# BastionAccount lifecycle statuses (String column + Python constants, no SQL Enum —
# same convention as credential_mode / access_mode).
BASTION_ACCOUNT_STATUSES: tuple[str, ...] = (
    "pending",  # internal row created, Keycloak user not created yet (or failed)
    "keycloak_created",  # Keycloak user exists, no app provisioning attempted/pending
    "provisioned",  # all attempted app provisionings succeeded (or not_applicable)
    "partial_failure",  # at least one app provisioning failed — never masked
)

# How the account entered bastion tracking.
# - bastion: created via Admin « Nouvel utilisateur » (local form → Keycloak push)
# - keycloak: reserved if we later link an existing IdP user into BastionAccount
BASTION_ACCOUNT_ORIGINS: tuple[str, ...] = ("bastion", "keycloak")
BASTION_ACCOUNT_ORIGIN_BASTION = "bastion"
BASTION_ACCOUNT_ORIGIN_KEYCLOAK = "keycloak"

PROVISIONING_STATUSES: tuple[str, ...] = (
    "pending",
    "success",
    "failed",
    "not_applicable",
)


class BastionAccount(Base):
    """User account created from bastion-app, pushed to a Keycloak realm.

    Each pipeline step (Keycloak creation, group assignment, per-app provisioning)
    has its own visible status — never an optimistic aggregate (spec §1).
    """

    __tablename__ = "bastion_accounts"

    id = Column(Integer, primary_key=True)

    realm_id = Column(Integer, ForeignKey("realm_configs.id"), nullable=False, index=True)
    username = Column(String, nullable=False)
    email = Column(String, nullable=False)
    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    # Société / organisation — drives auto company RBAC+Keycloak group
    organization = Column(String, nullable=True)

    # Filled only after successful Keycloak creation (no phantom accounts).
    keycloak_user_id = Column(String, nullable=True, index=True)
    status = Column(String, default="pending", nullable=False)
    # bastion = form local ; keycloak = linked IdP user (see BASTION_ACCOUNT_ORIGINS)
    origin = Column(String, default=BASTION_ACCOUNT_ORIGIN_BASTION, nullable=False)
    # Targets chosen on create — kept so « Relancer Keycloak » can finish the pipeline.
    pending_group_ids = Column(JSON, nullable=True)
    pending_application_ids = Column(JSON, nullable=True)

    created_by = Column(String, nullable=False)  # bastion admin (email)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    last_error = Column(String, nullable=True)  # last blocking error message

    realm = relationship("RealmConfig", foreign_keys=[realm_id])
    provisionings = relationship(
        "BastionAccountProvisioning",
        back_populates="account",
        cascade="all, delete-orphan",
        foreign_keys="BastionAccountProvisioning.bastion_account_id",
    )

    __table_args__ = (
        UniqueConstraint("realm_id", "username", name="uq_bastion_account_realm_username"),
    )


class BastionAccountProvisioning(Base):
    """One row per (account, application) provisioning attempt — partial by nature."""

    __tablename__ = "bastion_account_provisioning"

    id = Column(Integer, primary_key=True)

    bastion_account_id = Column(
        Integer, ForeignKey("bastion_accounts.id"), nullable=False, index=True
    )
    application_id = Column(Integer, ForeignKey("apps.id"), nullable=False, index=True)

    driver_name = Column(String, nullable=False)  # "crushftp" | "generic" | "none"
    status = Column(String, default="pending", nullable=False)
    # Driver message (success or precise error) — NEVER a plaintext secret.
    detail = Column(String, nullable=True)
    attempted_at = Column(DateTime(timezone=True), default=utcnow)

    account = relationship(
        "BastionAccount", back_populates="provisionings", foreign_keys=[bastion_account_id]
    )
    application = relationship("App", foreign_keys=[application_id])

    __table_args__ = (
        UniqueConstraint(
            "bastion_account_id",
            "application_id",
            name="uq_bastion_account_provisioning_app",
        ),
    )


class BreakGlassAccount(Base):
    """Break-glass account — portal access outside Keycloak."""

    __tablename__ = "breakglass_accounts"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    hashed_password = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class BreakGlassSession(Base):
    """Break-glass JWT session registry (jti denylist for targeted revocation).

    The JWT remains the source of truth for identity/expiry. This table stores
    issued sessions so an admin can revoke one ``jti`` without rotating the
    shared HS256 secret. Rows past ``expires_at`` may be purged after a short
    retention window (see ``purge_expired_breakglass_sessions``).

    Identity-binding columns (IP subnet + fingerprint) detect session hijacking
    after theft of a still-valid cookie (see ``app.security.session_binding_service``).
    """

    __tablename__ = "breakglass_sessions"

    id = Column(Integer, primary_key=True)
    jti = Column(String, unique=True, nullable=False, index=True)
    username = Column(String, nullable=False, index=True)
    issued_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, nullable=False, default=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_by = Column(String, nullable=True)
    revoked_reason = Column(String, nullable=True)
    # Login anchor (nullable for rows created before identity-binding deploy).
    first_ip_subnet = Column(String, nullable=True)
    first_fingerprint_hash = Column(String, nullable=True)
    last_ip_subnet = Column(String, nullable=True)
    last_fingerprint_hash = Column(String, nullable=True)
    mismatch_count = Column(Integer, nullable=True, default=0)
    # Rotation chain (anti-replay): same chain_id across jti rotations from one login.
    chain_id = Column(String, nullable=True, index=True)
    superseded_by = Column(String, nullable=True, index=True)
    superseded_at = Column(DateTime(timezone=True), nullable=True)
    chain_revoked = Column(Boolean, nullable=False, default=False)


class SsoSessionAnchor(Base):
    """SSO (oauth2-proxy) identity binding keyed by cookie hash (never plaintext)."""

    __tablename__ = "sso_session_anchors"

    id = Column(Integer, primary_key=True)
    cookie_hash = Column(String, unique=True, nullable=False, index=True)
    username = Column(String, nullable=True, index=True)
    first_ip_subnet = Column(String, nullable=True)
    first_fingerprint_hash = Column(String, nullable=True)
    last_ip_subnet = Column(String, nullable=True)
    last_fingerprint_hash = Column(String, nullable=True)
    mismatch_count = Column(Integer, nullable=False, default=0)
    first_seen = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    last_seen = Column(DateTime(timezone=True), nullable=False, default=utcnow)


class OidcSession(Base):
    """Native bastion OIDC session registry (distinct from oauth2-proxy cookies).

    Mirrors ``BreakGlassSession``: JWT ``jti`` is the revocation key; identity-binding
    columns detect cookie theft (same shape as ``SsoSessionAnchor`` / break-glass).
    """

    __tablename__ = "oidc_sessions"

    id = Column(Integer, primary_key=True)
    jti = Column(String, unique=True, nullable=False, index=True)
    sub = Column(String, nullable=False, index=True)
    username = Column(String, nullable=True)
    realm = Column(String, nullable=False)
    issued_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, nullable=False, default=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_by = Column(String, nullable=True)
    revoked_reason = Column(String, nullable=True)
    # Identity binding (nullable until first successful bind).
    ip_subnet = Column(String, nullable=True)
    fingerprint_hash = Column(String, nullable=True)


class OidcLoginAttempt(Base):
    """Short-lived server-side state between password and OTP headless steps.

    Cookie jar + OTP form fields are Fernet-encrypted. Never expose to the browser.
    """

    __tablename__ = "oidc_login_attempts"

    attempt_id = Column(String, primary_key=True)
    realm = Column(String, nullable=False, index=True)
    username = Column(String, nullable=False)
    keycloak_cookies_encrypted = Column(Text, nullable=False)
    otp_form_encrypted = Column(Text, nullable=False)
    code_verifier = Column(String, nullable=False)
    state = Column(String, nullable=False)
    keycloak_base_url = Column(String, nullable=False)
    keycloak_realm = Column(String, nullable=False)
    client_id = Column(String, nullable=False)
    redirect_uri = Column(String, nullable=False)
    otp_failures = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)


class AuditLog(Base):
    """Admin action audit journal."""

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    actor = Column(String, nullable=False)
    action = Column(String, nullable=False, index=True)
    target = Column(String, nullable=True)
    details = Column(JSON, nullable=True)
    ip_address = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)


class SavedLogView(Base):
    """Per-user saved filter/column combination for /admin/logs Audit tab."""

    __tablename__ = "saved_log_views"
    __table_args__ = (
        UniqueConstraint("user_email", "name", name="uq_saved_log_view_user_name"),
    )

    id = Column(Integer, primary_key=True)
    user_email = Column(String, nullable=False, index=True)
    name = Column(String, nullable=False)
    filters_json = Column(JSON, nullable=False, default=dict)
    columns_json = Column(JSON, nullable=False, default=list)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)


class AdminLogsUserPrefs(Base):
    """Per-user column preferences for /admin/logs (not a named view)."""

    __tablename__ = "admin_logs_user_prefs"

    user_email = Column(String, primary_key=True)
    columns_json = Column(JSON, nullable=False, default=list)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)


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
    # Optional UI/Ansible-generated break-glass JWT HMAC (Fernet) when env unset.
    breakglass_jwt_secret_encrypted = Column(Text, nullable=True)
    # Previous UI secret kept for validation during rotation (never logged in clear).
    breakglass_jwt_secret_previous_encrypted = Column(Text, nullable=True)
    # Global native OIDC session JWT HMAC (Fernet) — one portal-wide signing key.
    oidc_session_jwt_secret_encrypted = Column(Text, nullable=True)
    # Session-cookie hop HMAC (Fernet) — DB source of truth; env only for pytest override.
    session_hop_secret_encrypted = Column(Text, nullable=True)
    # Optional Postgres hot store (sessions / audit / rate) — config stays on SQLite.
    hot_store_enabled = Column(Boolean, nullable=False, default=False)
    hot_store_host = Column(String, nullable=True)
    hot_store_port = Column(Integer, nullable=True)
    hot_store_database = Column(String, nullable=True)
    hot_store_user = Column(String, nullable=True)
    hot_store_password_encrypted = Column(Text, nullable=True)
    hot_store_sslmode = Column(String, nullable=True)  # prefer | require | disable
    hot_store_last_migrate_at = Column(DateTime(timezone=True), nullable=True)
    hot_store_last_migrate_summary = Column(Text, nullable=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)
    updated_by = Column(String, nullable=True)


class BrandingSettings(Base):
    """Singleton public-portal branding (id=1) — anonymized login surface."""

    __tablename__ = "branding_settings"

    id = Column(Integer, primary_key=True, default=1)

    company_name = Column(String, nullable=False, default="Portail sécurisé")
    logo_path = Column(String, nullable=True)
    favicon_path = Column(String, nullable=True)
    page_title = Column(String, nullable=False, default="Connexion")

    accent_color = Column(String, nullable=False, default="#10b981")
    # Company palette: primary (= accent_color), secondary (gradients/dim), highlight (hover/focus).
    secondary_color = Column(String, nullable=False, default="#059669")
    highlight_color = Column(String, nullable=False, default="#34d399")
    default_theme = Column(String, nullable=False, default="dark")  # dark | light
    welcome_text = Column(Text, nullable=True)

    footer_text = Column(Text, nullable=True)
    support_contact = Column(String, nullable=True)
    # False = hide product name on public pages (default for internet-facing installs).
    show_product_branding = Column(Boolean, nullable=False, default=False)

    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)
    updated_by = Column(String, nullable=True)


class SecurityPolicy(Base):
    """Singleton anti-abuse policy (id=1): enable flag + break-glass IP lists."""

    __tablename__ = "security_policy"

    id = Column(Integer, primary_key=True, default=1)
    enabled = Column(Boolean, nullable=False, default=True)
    # Empty allow list = keep default RFC1918 LAN gate. Deny always wins.
    breakglass_allow_cidrs = Column(Text, nullable=False, default="")
    breakglass_deny_cidrs = Column(Text, nullable=False, default="")
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)
    updated_by = Column(String, nullable=True)


class SecurityBanRule(Base):
    """Configurable anti-abuse rule (hammering, failed login, decoy usernames, …)."""

    __tablename__ = "security_ban_rules"
    __table_args__ = (UniqueConstraint("rule_type", name="uq_security_ban_rule_type"),)

    id = Column(Integer, primary_key=True)
    # hammering | hammering_login | failed_login | successful_login |
    # hack_username | concurrent_connections
    rule_type = Column(String, nullable=False, index=True)
    enabled = Column(Boolean, nullable=False, default=True)
    threshold = Column(Integer, nullable=False, default=0)
    window_seconds = Column(Integer, nullable=False, default=0)
    # Ban duration in minutes when ban_permanent is False. Ignored if permanent.
    ban_minutes = Column(Integer, nullable=False, default=60)
    # Explicit permanent ban (never inferred from ban_minutes=0 alone).
    ban_permanent = Column(Boolean, nullable=False, default=False)
    # Extra JSON (e.g. {"usernames": ["admin","root"]} for hack_username).
    config_json = Column(JSON, nullable=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)


class SecurityBan(Base):
    """Active or historical ban targeting an IP or username."""

    __tablename__ = "security_bans"

    id = Column(Integer, primary_key=True)
    # ip | username
    target_type = Column(String, nullable=False, index=True)
    target = Column(String, nullable=False, index=True)
    reason = Column(String, nullable=False, default="")
    # hammering | failed_login | hack_username | manual | concurrent_connections
    rule_type = Column(String, nullable=True)
    banned_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    # null + permanent=True → permanent; null + permanent=False should not occur
    expires_at = Column(DateTime(timezone=True), nullable=True)
    permanent = Column(Boolean, nullable=False, default=False)
    lifted_at = Column(DateTime(timezone=True), nullable=True)
    lifted_by = Column(String, nullable=True)
    created_by = Column(String, nullable=True)


class SecurityAllowlistEntry(Base):
    """IP or username that must never be banned."""

    __tablename__ = "security_allowlist"
    __table_args__ = (
        UniqueConstraint("entry_type", "value", name="uq_security_allowlist_type_value"),
    )

    id = Column(Integer, primary_key=True)
    # ip | username
    entry_type = Column(String, nullable=False, index=True)
    value = Column(String, nullable=False)
    comment = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    created_by = Column(String, nullable=True)


class SecurityRateEvent(Base):
    """Sliding-window rate events shared across workers (SQLite / SQLCipher)."""

    __tablename__ = "security_rate_events"

    id = Column(Integer, primary_key=True)
    # hammer | hammer_login | fail_ip | fail_user | success_ip
    kind = Column(String, nullable=False, index=True)
    key = Column(String, nullable=False, index=True)
    occurred_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, index=True)


class ContainerLogsSettings(Base):
    """Singleton config for /admin/logs Containers tab (id=1). Never mounts docker.sock."""

    __tablename__ = "container_logs_settings"

    id = Column(Integer, primary_key=True, default=1)
    enabled = Column(Boolean, nullable=False, default=False)
    # HTTP base URL of the read-only docker-socket-proxy (e.g. http://docker-socket-proxy:2375).
    proxy_url = Column(String, nullable=False, default="")
    # JSON list of Compose service / container names allowed in the UI.
    allowed_containers = Column(JSON, nullable=False, default=list)
    tail_lines = Column(Integer, nullable=False, default=200)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)
    updated_by = Column(String, nullable=True)


class SiemForwardingSettings(Base):
    """Singleton SIEM forwarder config (id=1). Disabled by default."""

    __tablename__ = "siem_forwarding_settings"

    id = Column(Integer, primary_key=True, default=1)
    enabled = Column(Boolean, nullable=False, default=False)
    # syslog_tls | webhook_https
    protocol = Column(String, nullable=False, default="webhook_https")
    syslog_host = Column(String, nullable=False, default="")
    syslog_port = Column(Integer, nullable=False, default=6514)
    syslog_tls_verify = Column(Boolean, nullable=False, default=True)
    webhook_url = Column(String, nullable=False, default="")
    # none | bearer | basic
    webhook_auth_type = Column(String, nullable=False, default="none")
    # Fernet ciphertext — never store plaintext tokens here.
    webhook_auth_secret_encrypted = Column(Text, nullable=True)
    # allowlist | denylist
    filter_mode = Column(String, nullable=False, default="denylist")
    # JSON list of audit action names
    filter_actions = Column(JSON, nullable=False, default=list)
    retry_max_queue_size = Column(Integer, nullable=False, default=5000)
    retry_max_age_minutes = Column(Integer, nullable=False, default=1440)
    last_success_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)
    updated_by = Column(String, nullable=True)


class SiemOutboxEntry(Base):
    """Persistent SIEM delivery queue (survives process restart)."""

    __tablename__ = "siem_outbox"

    id = Column(Integer, primary_key=True)
    audit_log_id = Column(Integer, nullable=False, index=True)
    action = Column(String, nullable=False, index=True)
    # Snapshot of serialize_audit_row at enqueue time (already masked details).
    payload_json = Column(JSON, nullable=False)
    attempts = Column(Integer, nullable=False, default=0)
    next_attempt_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, index=True)


class AcmeSettings(Base):
    """Singleton ACME / Let's Encrypt config for public_proxy (id=1)."""

    __tablename__ = "acme_settings"

    id = Column(Integer, primary_key=True, default=1)
    enabled = Column(Boolean, nullable=False, default=False)
    # dns_cf | … (acme.sh DNS API plugin name)
    dns_api = Column(String, nullable=False, default="dns_cf")
    # letsencrypt | letsencrypt_test
    acme_ca = Column(String, nullable=False, default="letsencrypt")
    # Fernet ciphertext — Cloudflare API token (never plaintext)
    cf_token_encrypted = Column(Text, nullable=True)
    cf_account_id = Column(String, nullable=False, default="")
    cf_zone_id = Column(String, nullable=False, default="")
    # Last admin-triggered or sidecar-reported reconcile
    last_reconcile_at = Column(DateTime(timezone=True), nullable=True)
    last_reconcile_status = Column(String, nullable=True)  # ok | error | pending
    last_reconcile_message = Column(Text, nullable=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)
    updated_by = Column(String, nullable=True)


class AdminNotificationDismissal(Base):
    """Per-admin dismissed notification keys (reappear if fingerprint changes)."""

    __tablename__ = "admin_notification_dismissals"
    __table_args__ = (
        UniqueConstraint(
            "user_email",
            "item_id",
            name="uq_admin_notif_dismissal_user_item",
        ),
    )

    id = Column(Integer, primary_key=True)
    user_email = Column(String, nullable=False, index=True)
    item_id = Column(String, nullable=False, index=True)
    # Opaque state at dismiss time — if feed fingerprint differs, show again.
    fingerprint = Column(String, nullable=False, default="")
    dismissed_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)


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


class PendingHost(Base):
    """Unknown Host discovered by bastion-nginx (awaiting admin approval)."""

    __tablename__ = "pending_hosts"

    id = Column(Integer, primary_key=True)
    hostname = Column(String, unique=True, nullable=False, index=True)
    first_seen_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    last_seen_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    hit_count = Column(Integer, nullable=False, default=1)
    last_client_ip = Column(String, nullable=True)
    last_user_agent = Column(String, nullable=True)
    last_uri = Column(String, nullable=True)
    # pending | approved | rejected
    status = Column(String, nullable=False, default="pending", index=True)
    approved_app_slug = Column(String, nullable=True)
    notes = Column(Text, nullable=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)


ACCESS_REQUEST_STATUSES: tuple[str, ...] = ("pending", "approved", "rejected")


class AccessRequest(Base):
    """Public self-registration request from the login page — awaits admin approval.

    Distinct from PendingUser (first SSO sighting of an already-existing IdP
    account). Approving an AccessRequest runs the bastion account creation
    pipeline into the chosen realm.
    """

    __tablename__ = "access_requests"

    id = Column(Integer, primary_key=True)
    realm_id = Column(
        Integer, ForeignKey("realm_configs.id"), nullable=False, index=True
    )
    username = Column(String, nullable=False)
    email = Column(String, nullable=False, index=True)
    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    organization = Column(String, nullable=True)
    message = Column(Text, nullable=True)
    client_ip = Column(String, nullable=True)
    # pending | approved | rejected
    status = Column(String, nullable=False, default="pending", index=True)
    bastion_account_id = Column(
        Integer, ForeignKey("bastion_accounts.id"), nullable=True
    )
    reviewed_by = Column(String, nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    review_notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    realm = relationship("RealmConfig", foreign_keys=[realm_id])
    bastion_account = relationship("BastionAccount", foreign_keys=[bastion_account_id])


class PendingUser(Base):
    """First SSO sighting of a user — admin review queue (does not block login)."""

    __tablename__ = "pending_users"

    id = Column(Integer, primary_key=True)
    user_email = Column(String, unique=True, nullable=False, index=True)
    username = Column(String, nullable=True)
    realm_slug = Column(String, nullable=False)
    first_seen_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    last_seen_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    hit_count = Column(Integer, nullable=False, default=1)
    last_client_ip = Column(String, nullable=True)
    # pending | approved | rejected
    status = Column(String, nullable=False, default="pending", index=True)
    notes = Column(Text, nullable=True)
    reviewed_by = Column(String, nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)


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
