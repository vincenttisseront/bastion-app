"""Public access-request queue — self-registration awaiting admin approval."""
from __future__ import annotations
import logging
import re
from sqlalchemy.orm import Session, joinedload
from app.audit import log_action
from app.mail.smtp_service import SmtpError, send_email, smtp_configured
from app.models import AccessRequest, BastionAccount, RealmConfig, utcnow
from app.rbac.account_service import (
    AccountCreationError,
    create_bastion_account,
    normalize_organization_name,
    realm_provisioning_ready,
    send_account_credentials_email,
)
from app.sso_settings import Settings
logger = logging.getLogger(__name__)
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{2,64}$")
_MAX_PENDING_PER_IP = 5
_MAX_MESSAGE_LEN = 1000
# Generic copy — do not reveal whether username/email already exists (enumeration).
_GENERIC_DUP_MSG = (
    "Impossible d'enregistrer cette demande. Vérifiez vos informations "
    "ou contactez un administrateur si vous avez déjà un compte."
)


class AccessRequestError(ValueError):
    """Validation / state error for public or admin access-request flows."""


def realms_advertising_access_requests(db: Session) -> list[RealmConfig]:
    """Realms that opted into the public form (login CTA). Provisioning optional.
    The login link / public form are shown when this list is non-empty.
    Account creation still requires a provisioning-ready realm at approve time.
    """
    return (
        db.query(RealmConfig)
        .filter_by(enabled=True, access_request_enabled=True)
        .order_by(RealmConfig.slug)
        .all()
    )


def realms_accepting_access_requests(db: Session) -> list[RealmConfig]:
    """Realms an admin can target on approve (opt-in + provisioning ready)."""
    return [r for r in realms_advertising_access_requests(db) if realm_provisioning_ready(r)]


def realms_for_access_request_approve(db: Session) -> list[RealmConfig]:
    """Enabled realms with provisioning ready — admin assigns one on approve."""
    rows = (
        db.query(RealmConfig)
        .filter_by(enabled=True)
        .order_by(RealmConfig.slug)
        .all()
    )
    return [r for r in rows if realm_provisioning_ready(r)]


def count_pending_access_requests(db: Session) -> int:
    return (
        db.query(AccessRequest).filter_by(status="pending").count()
    )


def count_pending_access_requests_for_ip(db: Session, client_ip: str | None) -> int:
    ip = (client_ip or "").strip()
    if not ip:
        return 0
    return (
        db.query(AccessRequest)
        .filter_by(status="pending", client_ip=ip)
        .count()
    )


def list_access_requests(
    db: Session, *, status: str = "pending", limit: int = 500
) -> list[AccessRequest]:
    q = db.query(AccessRequest).options(joinedload(AccessRequest.realm))
    status_n = (status or "pending").strip().lower()
    if status_n != "all":
        q = q.filter_by(status=status_n)
    return q.order_by(AccessRequest.created_at.desc()).limit(limit).all()


def submit_access_request(
    db: Session,
    settings: Settings,
    *,
    username: str,
    email: str,
    first_name: str | None = None,
    last_name: str | None = None,
    organization: str | None = None,
    message: str | None = None,
    client_ip: str | None = None,
) -> AccessRequest:
    """Public form submit — pending row without realm; admin assigns on approve."""
    if not realms_advertising_access_requests(db):
        raise AccessRequestError(
            "Les demandes d'accès ne sont pas ouvertes actuellement."
        )
    username = (username or "").strip()
    email = (email or "").strip().lower()
    first_name = (first_name or "").strip() or None
    last_name = (last_name or "").strip() or None
    organization = normalize_organization_name(organization) or None
    message = (message or "").strip() or None
    if message and len(message) > _MAX_MESSAGE_LEN:
        raise AccessRequestError(
            f"Motif trop long (max {_MAX_MESSAGE_LEN} caractères)."
        )
    if not username or not _USERNAME_RE.match(username):
        raise AccessRequestError(
            "Identifiant invalide (2–64 caractères : lettres, chiffres, . _ -)."
        )
    if not email or "@" not in email or len(email) > 254:
        raise AccessRequestError("Email invalide")
    if not organization:
        raise AccessRequestError("Société / organisation requise")
    if len(organization) > 200:
        raise AccessRequestError("Société / organisation trop longue")
    # Anti-spam: cap open requests from the same client IP.
    if count_pending_access_requests_for_ip(db, client_ip) >= _MAX_PENDING_PER_IP:
        raise AccessRequestError(
            "Trop de demandes en attente depuis cette adresse — réessayez plus tard "
            "ou contactez un administrateur."
        )
    existing_account = (
        db.query(BastionAccount)
        .filter(
            (BastionAccount.username == username) | (BastionAccount.email == email)
        )
        .first()
    )
    if existing_account:
        raise AccessRequestError(_GENERIC_DUP_MSG)
    pending_dup = (
        db.query(AccessRequest)
        .filter_by(status="pending")
        .filter(
            (AccessRequest.username == username) | (AccessRequest.email == email)
        )
        .first()
    )
    if pending_dup:
        raise AccessRequestError(_GENERIC_DUP_MSG)
    row = AccessRequest(
        realm_id=None,
        username=username,
        email=email,
        first_name=first_name,
        last_name=last_name,
        organization=organization,
        message=message,
        client_ip=client_ip,
        status="pending",
        created_at=utcnow(),
    )
    db.add(row)
    db.flush()
    log_action(
        db,
        actor=email,
        action="access_request.submitted",
        target=f"access_request:{row.id}",
        details={
            "username": username,
            "email": email,
            "organization": organization,
        },
        ip_address=client_ip,
    )
    db.commit()
    db.refresh(row)
    # Best-effort admin ping via first advertising realm that has SMTP.
    notify_realm = next(
        (r for r in realms_advertising_access_requests(db) if smtp_configured(r) and r.smtp_from_email),
        None,
    )
    if notify_realm is not None:
        try:
            send_email(
                notify_realm,
                settings,
                to_email=notify_realm.smtp_from_email,
                subject=f"[{notify_realm.name or notify_realm.slug}] Nouvelle demande d'accès — {username}",
                body_text=(
                    f"Nouvelle demande d'accès en attente.\n\n"
                    f"Identifiant : {username}\n"
                    f"Email : {email}\n"
                    f"Société : {organization}\n"
                    f"Message : {message or '—'}\n\n"
                    f"Assigner le realm à l'approbation : "
                    f"https://{(settings.portal_domain or '').strip()}/admin/access-requests\n"
                ),
            )
        except SmtpError:
            logger.info(
                "access_request admin notify skipped (smtp) realm=%s id=%s",
                notify_realm.slug,
                row.id,
            )
    return row


async def approve_access_request(
    db: Session,
    settings: Settings,
    *,
    request_id: int,
    actor: str,
    realm_id: int,
    ip_address: str | None = None,
    application_ids: list[int] | None = None,
    send_credentials: bool | None = None,
) -> tuple[AccessRequest, BastionAccount, list[str]]:
    """Approve → create_bastion_account in the admin-chosen realm."""
    row = (
        db.query(AccessRequest)
        .options(joinedload(AccessRequest.realm))
        .filter_by(id=request_id)
        .first()
    )
    if row is None:
        raise AccessRequestError("Demande introuvable")
    if row.status != "pending":
        raise AccessRequestError(f"Demande déjà {row.status}")
    realm = db.query(RealmConfig).filter_by(id=realm_id).first()
    if realm is None or not realm.enabled:
        raise AccessRequestError("Realm introuvable ou désactivé")
    if not realm_provisioning_ready(realm):
        raise AccessRequestError(
            f"Le realm « {realm.slug} » n'a pas le provisioning Keycloak prêt."
        )
    try:
        account, step_errors, temp_password = await create_bastion_account(
            db,
            settings,
            realm=realm,
            username=row.username,
            email=row.email,
            first_name=row.first_name,
            last_name=row.last_name,
            organization=row.organization,
            application_ids=application_ids or [],
            actor=actor,
            ip_address=ip_address,
        )
    except AccountCreationError as exc:
        raise AccessRequestError(str(exc)) from exc
    want_email = (
        bool(send_credentials)
        if send_credentials is not None
        else bool(getattr(realm, "send_credentials_email", False))
    )
    if want_email and temp_password and account.keycloak_user_id:
        try:
            send_account_credentials_email(
                settings,
                realm=realm,
                account=account,
                temporary_password=temp_password,
                kind="created",
            )
            log_action(
                db,
                actor=actor,
                action="account.credentials_emailed",
                target=f"realm:{realm.slug}/account:{account.username}",
                details={"kind": "created", "to": account.email, "via": "access_request"},
                ip_address=ip_address,
            )
        except Exception as exc:
            step_errors.append(f"Email credentials : {exc}")
            log_action(
                db,
                actor=actor,
                action="account.credentials_email_failed",
                target=f"realm:{realm.slug}/account:{account.username}",
                details={"kind": "created", "error": str(exc)},
                ip_address=ip_address,
            )
    temp_password = None  # noqa: F841
    row.realm_id = realm.id
    row.status = "approved"
    row.bastion_account_id = account.id
    row.reviewed_by = actor
    row.reviewed_at = utcnow()
    log_action(
        db,
        actor=actor,
        action="access_request.approved",
        target=f"realm:{realm.slug}/access_request:{row.id}",
        details={
            "bastion_account_id": account.id,
            "username": account.username,
            "account_status": account.status,
            "errors": step_errors,
        },
        ip_address=ip_address,
    )
    db.commit()
    db.refresh(row)
    return row, account, step_errors


def reject_access_request(
    db: Session,
    *,
    request_id: int,
    actor: str,
    notes: str | None = None,
    ip_address: str | None = None,
) -> AccessRequest:
    row = db.query(AccessRequest).filter_by(id=request_id).first()
    if row is None:
        raise AccessRequestError("Demande introuvable")
    if row.status != "pending":
        raise AccessRequestError(f"Demande déjà {row.status}")
    row.status = "rejected"
    row.reviewed_by = actor
    row.reviewed_at = utcnow()
    row.review_notes = (notes or "").strip() or None
    log_action(
        db,
        actor=actor,
        action="access_request.rejected",
        target=f"access_request:{row.id}",
        details={"username": row.username, "email": row.email, "notes": row.review_notes},
        ip_address=ip_address,
    )
    db.commit()
    db.refresh(row)
    return row
