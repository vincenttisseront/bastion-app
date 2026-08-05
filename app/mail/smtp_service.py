"""Global SMTP mailer — stdlib smtplib, no new dependency.

Config lives on PortalSettings (Admin → Général → Configuration).
Secrets stay Fernet-encrypted; plaintext password never logged.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any, Protocol

from sqlalchemy.orm import Session

from app.portal_settings_service import ensure_portal_settings
from app.secret_crypto import decrypt_secret
from app.sso_settings import Settings

logger = logging.getLogger(__name__)


class SmtpError(ValueError):
    """SMTP misconfiguration or delivery failure — never includes the password."""


class SmtpConfigLike(Protocol):
    smtp_enabled: bool
    smtp_host: str | None
    smtp_port: int | None
    smtp_use_tls: bool
    smtp_username: str | None
    smtp_password_encrypted: str | None
    smtp_from_email: str | None
    smtp_from_name: str | None


def smtp_configured(cfg: Any) -> bool:
    return bool(
        getattr(cfg, "smtp_enabled", False)
        and (getattr(cfg, "smtp_host", None) or "").strip()
        and (getattr(cfg, "smtp_from_email", None) or "").strip()
    )


def get_smtp_config(db: Session, settings: Settings) -> Any | None:
    """Return portal SMTP row when fully configured, else None."""
    row = ensure_portal_settings(db, settings)
    if smtp_configured(row):
        return row
    return None


def _from_header(cfg: SmtpConfigLike) -> str:
    email = (cfg.smtp_from_email or "").strip()
    name = (cfg.smtp_from_name or "").strip()
    if name:
        return f"{name} <{email}>"
    return email


def send_email(
    cfg: SmtpConfigLike,
    settings: Settings,
    *,
    to_email: str,
    subject: str,
    body_text: str,
    body_html: str | None = None,
) -> None:
    """Send one email via global SMTP settings. Raises SmtpError on failure."""
    if not smtp_configured(cfg):
        raise SmtpError(
            "SMTP non configuré — activez-le et renseignez hôte + expéditeur "
            "dans Admin → Général → Configuration."
        )
    to_addr = (to_email or "").strip()
    if not to_addr or "@" not in to_addr:
        raise SmtpError("Adresse destinataire invalide")

    host = (cfg.smtp_host or "").strip()
    port = int(cfg.smtp_port or 587)
    use_tls = bool(getattr(cfg, "smtp_use_tls", True))
    username = (cfg.smtp_username or "").strip() or None
    password = ""
    if cfg.smtp_password_encrypted:
        try:
            password = decrypt_secret(cfg.smtp_password_encrypted, settings)
        except ValueError as exc:
            raise SmtpError("Déchiffrement du mot de passe SMTP impossible") from exc

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = _from_header(cfg)
    msg["To"] = to_addr
    msg.set_content(body_text or "")
    if body_html:
        msg.add_alternative(body_html, subtype="html")

    try:
        _smtp_session(
            host,
            port,
            use_tls=use_tls,
            username=username,
            password=password,
            send_msg=msg,
        )
    finally:
        password = ""  # noqa: F841

    logger.info(
        "smtp sent to=%s subject=%s",
        to_addr,
        (subject or "")[:80],
    )


def _smtp_session(
    host: str,
    port: int,
    *,
    use_tls: bool,
    username: str | None,
    password: str,
    send_msg: EmailMessage | None = None,
) -> None:
    """Connect (and optionally STARTTLS / login / send). Raises SmtpError."""
    try:
        if use_tls:
            with smtplib.SMTP(host, port, timeout=20) as client:
                client.ehlo()
                context = ssl.create_default_context()
                client.starttls(context=context)
                client.ehlo()
                if username and password:
                    client.login(username, password)
                if send_msg is not None:
                    client.send_message(send_msg)
                else:
                    client.noop()
        else:
            with smtplib.SMTP(host, port, timeout=20) as client:
                if username and password:
                    client.login(username, password)
                if send_msg is not None:
                    client.send_message(send_msg)
                else:
                    client.noop()
    except smtplib.SMTPAuthenticationError as exc:
        raise SmtpError("Authentification SMTP refusée (identifiant / mot de passe)") from exc
    except smtplib.SMTPException as exc:
        raise SmtpError(f"Échec SMTP : {exc.__class__.__name__}") from exc
    except OSError as exc:
        raise SmtpError(f"SMTP injoignable ({host}:{port})") from exc


def test_smtp_connection(
    db: Session,
    settings: Settings,
    *,
    actor: str,
) -> tuple[bool, str]:
    """Verify saved SMTP settings (connect + auth). Does not send a message."""
    from app.audit import log_action

    row = ensure_portal_settings(db, settings)
    host = (row.smtp_host or "").strip()
    from_email = (row.smtp_from_email or "").strip()
    if not host:
        return False, "Hôte SMTP manquant — enregistrez la configuration d'abord"
    if not from_email:
        return False, "Expéditeur manquant — enregistrez la configuration d'abord"

    port = int(row.smtp_port or 587)
    use_tls = bool(getattr(row, "smtp_use_tls", True))
    username = (row.smtp_username or "").strip() or None
    password = ""
    if row.smtp_password_encrypted:
        try:
            password = decrypt_secret(row.smtp_password_encrypted, settings)
        except ValueError:
            return False, "Déchiffrement du mot de passe SMTP impossible"

    try:
        _smtp_session(
            host,
            port,
            use_tls=use_tls,
            username=username,
            password=password,
            send_msg=None,
        )
    except SmtpError as exc:
        log_action(
            db,
            actor=actor,
            action="smtp.connectivity.test",
            target="portal_settings",
            details={"ok": False, "host": host, "port": port, "error": str(exc)},
            forward_to_siem=False,
        )
        return False, str(exc)
    finally:
        password = ""  # noqa: F841

    log_action(
        db,
        actor=actor,
        action="smtp.connectivity.test",
        target="portal_settings",
        details={"ok": True, "host": host, "port": port, "use_tls": use_tls},
        forward_to_siem=False,
    )
    auth = "avec authentification" if username else "sans authentification"
    tls = "STARTTLS" if use_tls else "clair"
    return True, f"Connexion OK — {host}:{port} ({tls}, {auth})"


def credentials_email_bodies(
    *,
    portal_url: str,
    username: str,
    temporary_password: str,
    realm_name: str,
    kind: str = "created",
) -> tuple[str, str, str]:
    """Return (subject, text, html) — never log temporary_password."""
    if kind == "reset":
        subject = f"[{realm_name}] Nouveau mot de passe temporaire"
        lead = (
            f"Un administrateur a réinitialisé votre mot de passe sur le portail "
            f"« {realm_name} »."
        )
    else:
        subject = f"[{realm_name}] Vos identifiants de connexion"
        lead = (
            f"Un compte a été créé pour vous sur le portail "
            f"« {realm_name} »."
        )
    text = (
        f"{lead}\n\n"
        f"Portail : {portal_url}\n"
        f"Identifiant : {username}\n"
        f"Mot de passe temporaire : {temporary_password}\n\n"
        "Vous devrez changer ce mot de passe à la première connexion.\n"
        "Ne transmettez pas ce message — il contient un secret.\n"
    )
    html = (
        f"<p>{lead}</p>"
        f'<p>Portail : <a href="{portal_url}">{portal_url}</a><br>'
        f"Identifiant : <strong>{username}</strong><br>"
        f"Mot de passe temporaire : <code>{temporary_password}</code></p>"
        "<p>Vous devrez changer ce mot de passe à la première connexion.</p>"
        "<p><em>Ne transmettez pas ce message — il contient un secret.</em></p>"
    )
    return subject, text, html
