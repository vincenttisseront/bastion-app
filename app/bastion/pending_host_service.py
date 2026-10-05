"""Record / approve / reject unknown Hosts discovered by bastion-nginx."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app import re_safe
from app.access_modes import normalize_access_mode, validate_app_access_fields
from app.admin.export import export_app_catalogue_files
from app.audit import log_action
from app.bastion.nginx_known_hosts_export import normalize_hostname
from app.models import App, PendingHost, utcnow
from app.robotic.robotic_session_cookies import portal_sso_cookie_domain
from app.security.banning.engine import record_unknown_host_refusal
from app.sso_settings import Settings

_SLUG_RE = re_safe.compile(r"^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$")

# Ansible Traefik/nginx catch-all smoke (traefik_catchall.yml) fabricates
# Host: discovery-probe-<epoch>.<domain> + URI /probe-discovery — not real apps.
_INFRA_DISCOVERY_PROBE_HOST = re_safe.compile(
    r"^discovery-probe-\d+(\.|$)",
    re_safe.IGNORECASE,
)

_SORT_COLUMNS = frozenset({"hostname", "hits", "last_seen", "status", "ip"})

# Until the setup wizard sets a real portal FQDN, do not filter discovery
# (avoids hiding queues on fresh installs still on portal.example.com).
_PLACEHOLDER_PORTAL_DOMAINS = frozenset(
    {
        "",
        "localhost",
        "portal.example.com",
        "example.com",
    }
)


def is_placeholder_portal_domain(domain: str | None) -> bool:
    host = normalize_hostname(domain or "") or ""
    return host in _PLACEHOLDER_PORTAL_DOMAINS


def is_infra_discovery_probe(hostname: str | None) -> bool:
    """True for synthetic Host headers from deploy discovery smokes."""
    host = normalize_hostname(hostname or "") or ""
    return bool(_INFRA_DISCOVERY_PROBE_HOST.match(host))


def parse_managed_domain_suffixes(raw: str | None) -> list[str]:
    """Split admin-entered extras (newline / comma / space)."""
    text = (raw or "").strip()
    if not text:
        return []
    parts: list[str] = []
    for chunk in text.replace(",", "\n").replace(";", "\n").splitlines():
        for token in chunk.split():
            host = normalize_hostname(token)
            if host and host not in parts:
                parts.append(host)
    return parts


def format_managed_domain_suffixes(suffixes: list[str]) -> str:
    """Persist extras as one domain per line."""
    return "\n".join(parse_managed_domain_suffixes("\n".join(suffixes)))


def managed_domain_suffixes(
    *,
    portal_domain: str | None,
    extra_raw: str | None = None,
) -> list[str]:
    """Apex / parent domains the bastion manages for discovery.

    When the portal FQDN is still a placeholder, only admin extras apply (empty
    list = no filter). After a real portal domain is set, the parent apex
    (``portal.example.com`` → ``example.com``) and the portal FQDN are included.
    """
    out: list[str] = []
    portal = normalize_hostname(portal_domain or "") or ""
    if portal and portal not in _PLACEHOLDER_PORTAL_DOMAINS:
        parent = portal_sso_cookie_domain(portal)
        for candidate in (parent, portal):
            if candidate and candidate not in out:
                out.append(candidate)
    for extra in parse_managed_domain_suffixes(extra_raw):
        if extra not in out:
            out.append(extra)
    return out


def hostname_is_managed(hostname: str | None, suffixes: list[str]) -> bool:
    """True when host equals a managed suffix or is a subdomain of one."""
    host = normalize_hostname(hostname or "") or ""
    if not host or not suffixes:
        return False
    for suffix in suffixes:
        if host == suffix or host.endswith("." + suffix):
            return True
    return False


def purge_infra_discovery_probes(db: Session) -> int:
    """Delete Ansible discovery-probe rows already sitting in the queue."""
    rows = (
        db.query(PendingHost)
        .filter(PendingHost.hostname.like("discovery-probe-%"))
        .all()
    )
    deleted = 0
    for row in rows:
        if is_infra_discovery_probe(row.hostname):
            db.delete(row)
            deleted += 1
    if deleted:
        db.commit()
    return deleted


def purge_unmanaged_pending_hosts(
    db: Session,
    *,
    suffixes: list[str],
) -> int:
    """Delete pending rows whose hostname is outside managed suffixes."""
    if not suffixes:
        return 0
    rows = db.query(PendingHost).filter(PendingHost.status == "pending").all()
    deleted = 0
    for row in rows:
        if is_infra_discovery_probe(row.hostname):
            db.delete(row)
            deleted += 1
            continue
        if not hostname_is_managed(row.hostname, suffixes):
            db.delete(row)
            deleted += 1
    if deleted:
        db.commit()
    return deleted


def suggest_slug(hostname: str) -> str:
    label = (hostname or "").split(".")[0].lower()
    label = re_safe.sub(r"[^a-z0-9-]+", "-", label).strip("-")
    if not label:
        label = "app"
    if not _SLUG_RE.match(label):
        label = re_safe.sub(r"^-+|-+$", "", label) or "app"
    return label[:64]


def record_unknown_host(
    db: Session,
    *,
    hostname: str,
    client_ip: str | None = None,
    user_agent: str | None = None,
    uri: str | None = None,
    managed_suffixes: list[str] | None = None,
) -> PendingHost | None:
    """Upsert a pending discovery row. Returns None if host invalid / out of scope.

    When ``managed_suffixes`` is a non-empty list, hosts outside those apexes are
    ignored (no queue pollution from random Internet Host headers).
    """
    host = normalize_hostname(hostname)
    if not host or host in ("127.0.0.1", "localhost", "::1"):
        return None
    if is_infra_discovery_probe(host):
        return None
    if managed_suffixes is not None and not hostname_is_managed(host, managed_suffixes):
        return None

    now = utcnow()
    row = db.query(PendingHost).filter_by(hostname=host).first()
    is_new = row is None
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
        if row.status == "approved":
            pass
        elif row.status == "rejected":
            pass
        else:
            row.status = "pending"
        row.updated_at = now
    db.commit()
    db.refresh(row)

    hit = int(row.hit_count or 0)
    if is_new or hit <= 5 or hit % 10 == 0:
        log_action(
            db,
            actor="anonymous",
            action="access_denied_unknown_host",
            target=host,
            details={
                "reason": "unknown_host",
                "uri": (uri or row.last_uri or "/")[:1024],
                "hit_count": hit,
                "pending_status": row.status,
                "user_agent": (user_agent or row.last_user_agent or "")[:256] or None,
            },
            ip_address=client_ip or row.last_client_ip,
        )
    if client_ip:
        record_unknown_host_refusal(
            db,
            ip=client_ip,
            hostname=host,
            uri=uri or row.last_uri,
        )
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


def reject_pending_hosts_bulk(
    db: Session,
    *,
    host_ids: list[int],
    actor: str,
) -> list[PendingHost]:
    """Reject only pending hosts; skip missing / already decided rows."""
    rejected: list[PendingHost] = []
    seen: set[int] = set()
    for host_id in host_ids:
        if host_id in seen:
            continue
        seen.add(host_id)
        row = db.query(PendingHost).filter_by(id=host_id).first()
        if row is None or row.status != "pending":
            continue
        rejected.append(reject_pending_host(db, host_id=host_id, actor=actor))
    return rejected


def sort_pending_hosts(
    rows: list[PendingHost],
    *,
    sort: str = "last_seen",
    direction: str = "desc",
) -> list[PendingHost]:
    """Stable in-memory sort for the admin list (max 500 rows)."""
    key = (sort or "last_seen").strip().lower()
    if key not in _SORT_COLUMNS:
        key = "last_seen"
    asc = (direction or "desc").strip().lower() == "asc"

    def sort_key(row: PendingHost):
        if key == "hostname":
            return (row.hostname or "").lower()
        if key == "hits":
            return int(row.hit_count or 0)
        if key == "status":
            return (row.status or "").lower()
        if key == "ip":
            return (row.last_client_ip or "").lower()
        return row.last_seen_at or row.first_seen_at or utcnow()

    return sorted(rows, key=sort_key, reverse=not asc)


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
