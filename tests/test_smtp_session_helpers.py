"""Unit coverage for SMTP session helpers extracted for Sonar S3776."""

from __future__ import annotations

from email.message import EmailMessage
from unittest.mock import MagicMock

from app.mail.smtp_service import _smtp_auth_and_send


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
