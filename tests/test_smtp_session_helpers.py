"""Unit coverage for SMTP session helpers extracted for Sonar S3776."""

from __future__ import annotations

import smtplib
from email.message import EmailMessage
from unittest.mock import MagicMock

import pytest

from app.mail.smtp_service import (
    SmtpError,
    _from_header,
    _msgid_domain,
    _raise_smtp_failure,
    _smtp_auth_and_send,
    _smtp_exc_detail,
    _smtp_typed_message,
    build_email_message,
    send_email,
    smtp_configured,
)


def test_smtp_auth_and_send_logs_in_and_noops():
    client = MagicMock()
    _smtp_auth_and_send(client, username="u", password="p", send_msg=None)
    client.login.assert_called_once_with("u", "p")
    client.noop.assert_called_once_with()
    client.send_message.assert_not_called()


def test_smtp_auth_and_send_sends_message_without_login():
    client = MagicMock()
    msg = EmailMessage()
    msg["From"] = "a@example.com"
    msg["To"] = "b@example.com"
    msg.set_content("hi")
    _smtp_auth_and_send(client, username=None, password="", send_msg=msg)
    client.login.assert_not_called()
    client.send_message.assert_called_once_with(msg)
    client.noop.assert_not_called()


def test_smtp_configured_and_from_header_helpers():
    row = MagicMock(
        smtp_enabled=True,
        smtp_host="smtp.example.com",
        smtp_from_email="noreply@example.com",
        smtp_from_name="Bastion",
    )
    assert smtp_configured(row) is True
    assert (
        smtp_configured(
            MagicMock(smtp_enabled=False, smtp_host="x", smtp_from_email="a@b.c")
        )
        is False
    )
    assert _from_header(row) == "Bastion <noreply@example.com>"
    bare = MagicMock(smtp_from_email="noreply@example.com", smtp_from_name="")
    assert _from_header(bare) == "noreply@example.com"
    assert _msgid_domain("Bastion <noreply@example.com>") == "example.com"
    assert _msgid_domain("no-at-sign") == "localhost"


def test_build_email_message_with_html_alternative():
    msg = build_email_message(
        from_header="Bastion <noreply@example.com>",
        to_email="user@example.com",
        subject="Hello",
        body_text="plain",
        body_html="<p>html</p>",
    )
    assert msg["To"] == "user@example.com"
    assert msg.get_body(preferencelist=("html",)) is not None


def test_smtp_exc_detail_handles_bytes_and_bad_code():
    exc = smtplib.SMTPException("boom")
    exc.smtp_code = "not-int"  # type: ignore[attr-defined]
    exc.smtp_error = b"relay denied"  # type: ignore[attr-defined]
    code, text = _smtp_exc_detail(exc)
    assert code is None
    assert "relay denied" in text

    exc2 = smtplib.SMTPException("plain")
    exc2.smtp_code = 550  # type: ignore[attr-defined]
    exc2.smtp_error = 12345  # type: ignore[attr-defined]
    code2, text2 = _smtp_exc_detail(exc2)
    assert code2 == 550
    assert "12345" in text2


def test_smtp_typed_messages_and_generic_raise():
    auth = smtplib.SMTPAuthenticationError(535, b"bad creds")
    msg = _smtp_typed_message(auth, code=535, detail="bad creds", loc="fr")
    assert msg is not None

    refused = smtplib.SMTPRecipientsRefused({"user@example.com": (550, b"no")})
    assert _smtp_typed_message(refused, code=550, detail="no", loc="fr")

    sender = smtplib.SMTPSenderRefused(550, b"no", "from@example.com")
    assert _smtp_typed_message(sender, code=550, detail="no", loc="fr")

    data = smtplib.SMTPDataError(554, b"spam")
    assert _smtp_typed_message(data, code=554, detail="spam", loc="fr")

    generic = smtplib.SMTPException("weird")
    generic.smtp_code = 421  # type: ignore[attr-defined]
    generic.smtp_error = b"try later"  # type: ignore[attr-defined]
    with pytest.raises(SmtpError) as ei:
        _raise_smtp_failure(generic, locale="fr")
    assert ei.value.smtp_code == 421


def test_send_email_rejects_unconfigured_and_bad_recipient():
    settings = MagicMock()
    bare = MagicMock(
        smtp_enabled=False,
        smtp_host="",
        smtp_from_email="",
    )
    with pytest.raises(SmtpError):
        send_email(
            bare,
            settings,
            to_email="user@example.com",
            subject="x",
            body_text="y",
        )
    cfg = MagicMock(
        smtp_enabled=True,
        smtp_host="smtp.example.com",
        smtp_from_email="noreply@example.com",
        smtp_from_name="",
        smtp_port=587,
        smtp_use_tls=True,
        smtp_username="",
        smtp_password_encrypted=None,
    )
    with pytest.raises(SmtpError, match="destinataire"):
        send_email(cfg, settings, to_email="nope", subject="x", body_text="y")
