"""Per-realm SMTP mailer — stdlib smtplib, no new dependency.

Secrets stay Fernet-encrypted on RealmConfig; plaintext password never logged.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage

from app.models import RealmConfig
from app.secret_crypto import decrypt_secret
from app.sso_settings import Settings

logger = logging.getLogger(__name__)


class SmtpError(ValueError):
    """SMTP misconfiguration or delivery failure — never includes the password."""


def smtp_configured(realm: RealmConfig) -> bool:
    return bool(
        getattr(realm, "smtp_enabled", False)
        and (getattr(realm, "smtp_host", None) or "").strip()
        and (getattr(realm, "smtp_from_email", None) or "").strip()
    )


def _from_header(realm: RealmConfig) -> str:
    email = (realm.smtp_from_email or "").strip()
    name = (realm.smtp_from_name or "").strip()
    if name:
        return f"{name} <{email}>"
    return email


def send_email(
    realm: RealmConfig,
    settings: Settings,
    *,
    to_email: str,
    subject: str,
    body_text: str,
    body_html: str | None = None,
) -> None:
    """Send one email via the realm's SMTP settings. Raises SmtpError on failure."""
    if not smtp_configured(realm):
        raise SmtpError(
            f"SMTP non configuré pour le realm « {realm.slug} » — "
            "activez-le et renseignez hôte + expéditeur dans la fiche realm."
        )
    to_addr = (to_email or "").strip()
    if not to_addr or "@" not in to_addr:
        raise SmtpError("Adresse destinataire invalide")

    host = (realm.smtp_host or "").strip()
    port = int(realm.smtp_port or 587)
    use_tls = bool(getattr(realm, "smtp_use_tls", True))
    username = (realm.smtp_username or "").strip() or None
    password = ""
    if realm.smtp_password_encrypted:
        try:
            password = decrypt_secret(realm.smtp_password_encrypted, settings)
        except ValueError as exc:
            raise SmtpError("Déchiffrement du mot de passe SMTP impossible") from exc

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = _from_header(realm)
    msg["To"] = to_addr
    msg.set_content(body_text or "")
    if body_html:
        msg.add_alternative(body_html, subtype="html")

    try:
        if use_tls:
            with smtplib.SMTP(host, port, timeout=20) as client:
                client.ehlo()
                context = ssl.create_default_context()
                client.starttls(context=context)
                client.ehlo()
                if username and password:
                    client.login(username, password)
                client.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=20) as client:
                if username and password:
                    client.login(username, password)
                client.send_message(msg)
    except smtplib.SMTPAuthenticationError as exc:
        raise SmtpError("Authentification SMTP refusée (identifiant / mot de passe)") from exc
    except smtplib.SMTPException as exc:
        raise SmtpError(f"Échec envoi SMTP : {exc.__class__.__name__}") from exc
    except OSError as exc:
        raise SmtpError(f"SMTP injoignable ({host}:{port})") from exc
    finally:
        password = ""  # noqa: F841

    logger.info(
        "smtp sent realm=%s to=%s subject=%s",
        realm.slug,
        to_addr,
        (subject or "")[:80],
    )


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
