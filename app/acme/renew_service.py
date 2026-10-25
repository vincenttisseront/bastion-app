"""Dispatch certificate renewals to DNS-01 sidecar or native HTTP-01 client."""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.acme.certificate_domain_service import (
    PROVIDER_DNS,
    PROVIDER_HTTP,
    get_certificate_domain,
    mark_failed,
    mark_valid_from_disk,
    sync_certificate_domains_from_manifest,
)
from app.acme.native_client import AcmeNativeError, issue_or_renew_http01
from app.acme.settings_service import get_acme_config, trigger_reconcile
from app.audit import log_action
from app.bastion.acme_domains_export import write_acme_domains_export
from app.sso_settings import Settings

logger = logging.getLogger(__name__)


def renew_domain(
    db: Session,
    settings: Settings,
    fqdn: str,
    *,
    actor: str,
) -> tuple[bool, str]:
    """Renew one FQDN via the correct provider worker."""
    sync_certificate_domains_from_manifest(db, settings)
    write_acme_domains_export(db, settings)
    row = get_certificate_domain(db, fqdn)
    if row is None:
        return False, f"Domaine inconnu: {fqdn}"

    provider = (row.provider_type or PROVIDER_DNS).strip()
    if provider == PROVIDER_DNS:
        ok, message = trigger_reconcile(db, settings, actor=actor)
        log_action(
            db,
            actor=actor,
            action="acme.renew_domain",
            target=row.domain,
            details={"provider": provider, "ok": ok},
        )
        return ok, message

    if provider != PROVIDER_HTTP:
        return False, f"provider inconnu: {provider}"

    cfg = get_acme_config(db)
    if not cfg.enabled:
        return False, "ACME est désactivé"

    portal = (settings.portal_domain or "").strip().lower()
    contact = f"acme@{portal}" if portal else None
    try:
        issue_or_renew_http01(
            settings,
            row.domain,
            acme_ca=cfg.acme_ca,
            contact_email=contact,
        )
    except AcmeNativeError as exc:
        mark_failed(db, row.domain, str(exc))
        log_action(
            db,
            actor=actor,
            action="acme.renew_domain",
            target=row.domain,
            details={"provider": provider, "ok": False, "error": str(exc)[:300]},
        )
        return False, str(exc)
    except Exception as exc:
        logger.exception("acme.native renew failed for %s", row.domain)
        mark_failed(db, row.domain, "native client unexpected error")
        log_action(
            db,
            actor=actor,
            action="acme.renew_domain",
            target=row.domain,
            details={"provider": provider, "ok": False},
        )
        return False, f"Échec HTTP-01: {exc.__class__.__name__}"

    mark_valid_from_disk(db, settings, row.domain)
    write_acme_domains_export(db, settings)
    msg = f"Certificat HTTP-01 émis/renouvelé pour {row.domain}"
    log_action(
        db,
        actor=actor,
        action="acme.renew_domain",
        target=row.domain,
        details={"provider": provider, "ok": True},
    )
    return True, msg


def renew_all_due(
    db: Session,
    settings: Settings,
    *,
    actor: str,
) -> tuple[bool, str]:
    """Bulk renew: sidecar for DNS domains + sequential HTTP-01 for native."""
    from app.acme.certificate_domain_service import domains_needing_attention

    sync_certificate_domains_from_manifest(db, settings)
    due = domains_needing_attention(db)
    dns_due = [r for r in due if r.provider_type == PROVIDER_DNS]
    http_due = [r for r in due if r.provider_type == PROVIDER_HTTP]

    messages: list[str] = []
    ok_all = True

    if dns_due:
        ok, msg = trigger_reconcile(db, settings, actor=actor)
        ok_all = ok_all and ok
        messages.append(msg)

    for row in http_due:
        ok, msg = renew_domain(db, settings, row.domain, actor=actor)
        ok_all = ok_all and ok
        messages.append(msg)

    if not due:
        return True, "Aucun certificat à renouveler (tous valides >30j)"

    return ok_all, " | ".join(messages)[:2000]
