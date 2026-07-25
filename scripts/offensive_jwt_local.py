"""Local JWT break-glass forgery checks (no network)."""

from __future__ import annotations

import base64
import json

import jwt

from app.breakglass import decode_breakglass_token

SECRET = "unit-test-breakglass-secret-not-used-on-staging"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def main() -> None:
    none = _b64(b'{"alg":"none","typ":"JWT"}') + "." + _b64(b'{"sub":"a","exp":9999999999}') + "."
    empty_sig = (
        _b64(b'{"alg":"HS256","typ":"JWT"}')
        + "."
        + _b64(b'{"sub":"a","exp":9999999999}')
        + "."
        + _b64(b"")
    )
    weak = jwt.encode({"sub": "a", "exp": 9999999999}, "dev", algorithm="HS256")
    expired = jwt.encode({"sub": "a", "exp": 1}, SECRET, algorithm="HS256")
    valid_tok = jwt.encode(
        {
            "sub": "a",
            "exp": 9999999999,
            "iat": 1700000000,
            "last": 1700000000,
            "type": "bg",
            "jti": "unit-valid",
        },
        SECRET,
        algorithm="HS256",
    )
    out = {
        "alg_none": decode_breakglass_token(none, SECRET),
        "empty_sig": decode_breakglass_token(empty_sig, SECRET),
        "wrong_secret": decode_breakglass_token(weak, SECRET),
        "expired": decode_breakglass_token(expired, SECRET),
        "valid": decode_breakglass_token(valid_tok, SECRET) is not None,
    }
    print(json.dumps(out, indent=2))
    assert out["alg_none"] is None
    assert out["empty_sig"] is None
    assert out["wrong_secret"] is None
    assert out["expired"] is None
    assert out["valid"] is True
    print("OK")


if __name__ == "__main__":
    main()
