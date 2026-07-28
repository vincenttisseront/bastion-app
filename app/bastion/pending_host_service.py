"""Record / approve / reject unknown Hosts discovered by bastion-nginx."""

from __future__ import annotations

import re
from sqlalchemy.orm import Session

from app.access_modes import normalize_access_mode, validate_app_access_fields
from app.admin.export import export_app_catalogue_files
from app.audit import log_action
from app.bastion.nginx_known_hosts_export import normalize_hostname
from app.models import App, PendingHost, utcnow
from app.sso_settings import Settings

_SLUG_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$")


def suggest_slug(hostname: str) -> str:
    label = (hostname or "").split(".")[0].lower()
    label = re.sub(r"[^a-z0-9-]+", "-", label).strip("-")
    if not label:
        label = "app"
    if not _SLUG_RE.match(label):
        label = re.sub(r"^-+|-+$", "", label) or "app"
    return label[:64]


def record_unknown_host(
    db: Session,
    *,
    hostname: str,
    client_ip: str | None = None,
    user_agent: str | None = None,
    uri: str | None = None,
) -> PendingHost | None:
    """Upsert a pending (or update rejected) discovery row. Returns None if host invalid."""
    host = normalize_hostname(hostname)
    if not host or host in ("127.0.0.1", "localhost", "::1"):
        return None

    now = utcnow()
    row = db.query(PendingHost).filter_by(hostname=host).first()
    if row is None:
        row = PendingHost(
            hostname=host,
            first_seen_at=now,
            last_seen_at=now,
            hit_count=1,
            last_client_ip=client_ip,
            last_user_agent=(user_agent or "")[:512] or None,
            last_uri=(uri or "")[:1024] or None,
            status="pending",
        )
        db.add(row)
    else:
        row.last_seen_at = now
        row.hit_count = int(row.hit_count or 0) + 1
        row.last_client_ip = client_ip or row.last_client_ip
        if user_agent:
            row.last_user_agent = user_agent[:512]
        if uri:
            row.last_uri = uri[:1024]
        # approved hosts should already be in the known map; if still hitting
        # discovery, leave status as-is (ops can re-apply infra).
        if row.status == "approved":
            pass
        elif row.status == "rejected":
            pass  # stay rejected; still count hits
        else:
            row.status = "pending"
        row.updated_at = now
    db.commit()
    db.refresh(row)
    return row


def reject_pending_host(
    db: Session,
    *,
    host_id: int,
    actor: str,
    notes: str | None = None,
) -> PendingHost:
    row = db.query(PendingHost).filter_by(id=host_id).first()
    if row is None:
        raise ValueError("Hôte introuvable")
    row.status = "rejected"
    if notes is not None:
        row.notes = notes.strip() or None
    row.updated_at = utcnow()
    db.commit()
    log_action(
        db,
        actor=actor,
        action="pending_host.rejected",
        target=row.hostname,
        details={"id": row.id},
    )
    db.refresh(row)
    return row


def approve_pending_host(
    db: Session,
    settings: Settings,
    *,
    host_id: int,
    actor: str,
    upstream_url: str,
    slug: str | None = None,
    label: str | None = None,
) -> tuple[PendingHost, App]:
    """Create a public_proxy App from a pending host and refresh nginx exports."""
    row = db.query(PendingHost).filter_by(id=host_id).first()
    if row is None:
        raise ValueError("Hôte introuvable")
    if row.status == "approved" and row.approved_app_slug:
        app = db.query(App).filter_by(slug=row.approved_app_slug).first()
        if app:
            return row, app
        raise ValueError("App approuvée introuvable — créez-la manuellement")

    host = row.hostname
    app_slug = (slug or suggest_slug(host)).strip().lower()
    app_label = (label or host).strip() or host
    upstream = (upstream_url or "").strip()
    mode = "public_proxy"

    errors = validate_app_access_fields(mode, upstream, host)
    if not _SLUG_RE.match(app_slug):
        errors["slug"] = "Slug invalide (a-z, 0-9, tirets)."
    if db.query(App).filter_by(slug=app_slug).first():
        errors["slug"] = f"Le slug « {app_slug} » existe déjà."
    existing_fqdn = (
        db.query(App)
        .filter(App.public_fqdn.isnot(None))
        .filter(App.public_fqdn == host)
        .first()
    )
    if existing_fqdn:
        errors["public_fqdn"] = f"Le FQDN « {host} » est déjà utilisé par {existing_fqdn.slug}."
    if errors:
        raise ValueError("; ".join(f"{k}: {v}" for k, v in errors.items()))

    app = App(
        slug=app_slug,
        label=app_label,
        upstream_url=upstream,
        access_mode=mode,
        public_fqdn=host,
        enabled=True,
        auth_mode="sso",
    )
    db.add(app)
    row.status = "approved"
    row.approved_app_slug = app_slug
    row.updated_at = utcnow()
    db.commit()
    db.refresh(app)
    db.refresh(row)

    export_app_catalogue_files(db, settings)
    log_action(
        db,
        actor=actor,
        action="pending_host.approved",
        target=host,
        details={
            "id": row.id,
            "app_slug": app_slug,
            "access_mode": normalize_access_mode(mode),
            "upstream_url": upstream,
        },
    )
    log_action(db, actor=actor, action="app.created", target=app_slug)
    return row, app
