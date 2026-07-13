"""SQLAlchemy models for the SSO portal catalogue and admin."""

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, String, Text
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
    access_mode = Column(String, default="sso")
    auth_mode = Column(String, default="oidc")
    robotic_driver = Column(String, nullable=True)
    healthcheck_url = Column(String, nullable=True)
    enabled = Column(Boolean, default=True)
    tile_icon = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    groups = relationship("AppGroup", back_populates="app", cascade="all, delete-orphan")
    credentials = relationship(
        "AppCredential", back_populates="app", cascade="all, delete-orphan"
    )


class RBACGroup(Base):
    """Keycloak RBAC group (e.g. admins, transfer-users)."""

    __tablename__ = "rbac_groups"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    realm_slug = Column(String, nullable=True)

    app_links = relationship("AppGroup", back_populates="group")


class AppGroup(Base):
    """Association App <-> RBACGroup (authorized access)."""

    __tablename__ = "app_groups"

    id = Column(Integer, primary_key=True)
    app_id = Column(Integer, ForeignKey("apps.id"), nullable=False)
    group_id = Column(Integer, ForeignKey("rbac_groups.id"), nullable=False)

    app = relationship("App", back_populates="groups")
    group = relationship("RBACGroup", back_populates="app_links")


class AppCredential(Base):
    """Encrypted application credential (Fernet) — portal vault."""

    __tablename__ = "app_credentials"

    id = Column(Integer, primary_key=True)
    app_id = Column(Integer, ForeignKey("apps.id"), nullable=False)
    username = Column(String, nullable=False)
    encrypted_password = Column(Text, nullable=False)
    label = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    app = relationship("App", back_populates="credentials")


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
