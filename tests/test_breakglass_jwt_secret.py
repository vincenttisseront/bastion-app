"""Break-glass JWT secret separation + type claim + oauth2 cookie flags."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt

from app.breakglass import (
    create_breakglass_token,
    decode_breakglass_token,
    decode_breakglass_token_with_fallback,
    resolve_breakglass_signing_secret,
    validate_breakglass_cookie,
)
from app.sso_settings import Settings

NEW_SECRET = "dedicated-bg-jwt-secret-v2"
OLD_SECRET = "legacy-vault-portal-internal-token"
WRONG_SECRET = "totally-unrelated-hmac-key"


def _settings(**kwargs) -> Settings:
    base = dict(
        vault_portal_internal_token=OLD_SECRET,
        breakglass_jwt_secret=NEW_SECRET,
        breakglass_jwt_secret_fallback_enabled=True,
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
    )
    base.update(kwargs)
    return Settings(**base)


def test_breakglass_jwt_signed_with_new_secret_accepted():
    settings = _settings()
    token = create_breakglass_token("admin", resolve_breakglass_signing_secret(settings))
    assert validate_breakglass_cookie(token, settings=settings) is True
    payload, used_fb = decode_breakglass_token_with_fallback(token, settings)
    assert payload is not None
    assert used_fb is False


def test_breakglass_jwt_signed_with_legacy_secret_accepted_when_fallback_on():
    settings = _settings(breakglass_jwt_secret_fallback_enabled=True)
    token = create_breakglass_token("admin", OLD_SECRET)
    assert validate_breakglass_cookie(token, settings=settings) is True
    payload, used_fb = decode_breakglass_token_with_fallback(token, settings)
    assert payload is not None
    assert used_fb is True


def test_breakglass_jwt_signed_with_legacy_secret_rejected_when_fallback_off():
    settings = _settings(breakglass_jwt_secret_fallback_enabled=False)
    token = create_breakglass_token("admin", OLD_SECRET)
    assert validate_breakglass_cookie(token, settings=settings) is False
    payload, used_fb = decode_breakglass_token_with_fallback(token, settings)
    assert payload is None
    assert used_fb is False


def test_breakglass_jwt_signed_with_wrong_secret_rejected():
    settings = _settings()
    token = create_breakglass_token("admin", WRONG_SECRET)
    assert validate_breakglass_cookie(token, settings=settings) is False


def test_breakglass_rejects_wrong_type_claim():
    """Explicit proof that type != 'bg' is rejected (Tâche 2)."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "admin",
        "iat": now,
        "exp": now + timedelta(hours=1),
        "last": int(now.timestamp()),
        "type": "not-bg",
        "jti": "jti-wrong-type",
    }
    token = jwt.encode(payload, NEW_SECRET, algorithm="HS256")
    assert decode_breakglass_token(token, NEW_SECRET) is None
    assert validate_breakglass_cookie(token, NEW_SECRET) is False

    payload_missing = {
        "sub": "admin",
        "iat": now,
        "exp": now + timedelta(hours=1),
        "last": int(now.timestamp()),
        "jti": "jti-no-type",
    }
    token2 = jwt.encode(payload_missing, NEW_SECRET, algorithm="HS256")
    assert decode_breakglass_token(token2, NEW_SECRET) is None


def test_generate_oauth2_proxy_config_includes_samesite(db_session):
    from app.admin.export import generate_oauth2_proxy_config
    from app.models import RealmConfig
    from app.secret_crypto import encrypt_secret

    settings = Settings(
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
        oauth2_proxy_network_mode="docker",
    )
    realm = RealmConfig(
        slug="clients",
        name="CLIENTS",
        issuer_url="https://keycloak.example/realms/test",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", settings),
        redirect_uri="https://portal.example.test/oauth2/clients/callback",
        oauth2_proxy_port=4182,
        enabled=True,
        last_test_status="ok",
    )
    db_session.add(realm)
    db_session.commit()
    cfg = generate_oauth2_proxy_config(realm, settings)
    assert 'cookie_samesite = "lax"' in cfg
    assert "cookie_secure = true" in cfg
    assert "cookie_httponly = true" in cfg


def test_ansible_smoke_cookie_flags_grep_patterns():
    """Prove smoke grep patterns fail on incomplete cfg and pass on complete."""
    import re

    patterns = [
        r"cookie_secure\s*=\s*true",
        r"cookie_httponly\s*=\s*true",
        r'cookie_samesite\s*=\s*"lax"',
    ]
    incomplete = "cookie_secure = true\ncookie_httponly = true\n"
    complete = (
        "cookie_secure = true\n"
        "cookie_httponly = true\n"
        'cookie_samesite = "lax"\n'
    )
    for pat in patterns:
        assert re.search(pat, complete), pat
    assert re.search(patterns[0], incomplete)
    assert re.search(patterns[1], incomplete)
    assert not re.search(patterns[2], incomplete)


def test_cookie_flags_conform_helper():
    from app.admin.session_alignment import cookie_flags_conform, parse_oauth2_cookie_settings

    ok = parse_oauth2_cookie_settings(
        'cookie_secure = true\ncookie_httponly = true\ncookie_samesite = "lax"\n'
    )
    assert cookie_flags_conform(ok) is True
    bad = parse_oauth2_cookie_settings("cookie_secure = true\ncookie_httponly = true\n")
    assert cookie_flags_conform(bad) is False
