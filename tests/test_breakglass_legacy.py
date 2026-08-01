"""Legacy break-glass settings migration tests."""

import json

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.breakglass_store import (
    LEGACY_BREAKGLASS_PASSWORD_HASH_KEY,
    LEGACY_BREAKGLASS_USERNAME,
    has_active_breakglass_account,
    set_breakglass_password,
    verify_breakglass_password,
)
from app.models import BreakGlassAccount


def _create_legacy_settings_table(db: Session) -> None:
    db.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value_json TEXT
            )
            """
        )
    )
    db.commit()


def test_legacy_breakglass_hash_migrates_and_verifies(db_session: Session):
    password = "legacy-password-12"
    set_breakglass_password(db_session, "tmp", password)
    account = db_session.execute(
        text("SELECT hashed_password FROM breakglass_accounts WHERE username='tmp'")
    ).fetchone()
    db_session.execute(text("DELETE FROM breakglass_accounts"))
    db_session.commit()

    _create_legacy_settings_table(db_session)
    db_session.execute(
        text("INSERT INTO settings (key, value_json) VALUES (:k, :v)"),
        {
            "k": LEGACY_BREAKGLASS_PASSWORD_HASH_KEY,
            "v": json.dumps(account[0]),
        },
    )
    db_session.commit()

    assert has_active_breakglass_account(db_session)
    assert verify_breakglass_password(db_session, LEGACY_BREAKGLASS_USERNAME, password)

    migrated = (
        db_session.query(BreakGlassAccount)
        .filter_by(username=LEGACY_BREAKGLASS_USERNAME, is_active=True)
        .first()
    )
    assert migrated is not None
    assert migrated.username == LEGACY_BREAKGLASS_USERNAME


def test_unknown_username_fails_without_500(client, db_session: Session):
    set_breakglass_password(db_session, "admin", "correct-password-12")

    response = client.post(
        "/auth/breakglass",
        data={"username": "vincent", "password": "any-password"},
        headers={"X-Real-IP": "10.0.0.8"},
    )

    assert response.status_code == 200
    assert "Identifiants invalides" in response.text
