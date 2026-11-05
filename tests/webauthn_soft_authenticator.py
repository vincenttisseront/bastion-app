"""Minimal software WebAuthn authenticator (ES256, ``none`` attestation) for tests.

Produces the browser-side JSON (``PublicKeyCredential.toJSON()`` shape) with
real signatures, so py_webauthn verification runs unmocked.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from dataclasses import dataclass, field

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_BE = 0x08
FLAG_BS = 0x10
FLAG_AT = 0x40


def _b64(data: bytes) -> str:
    return bytes_to_base64url(data)


@dataclass
class SoftAuthenticator:
    rp_id: str
    origin: str
    user_verified: bool = True
    synced: bool = False
    sign_count: int = 0
    credential_id: bytes = field(default_factory=lambda: os.urandom(16))
    aaguid: bytes = b"\x00" * 16
    user_handle: bytes | None = None
    _key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )

    def _flags(self, *, attested: bool) -> int:
        flags = FLAG_UP
        if self.user_verified:
            flags |= FLAG_UV
        if self.synced:
            flags |= FLAG_BE | FLAG_BS
        if attested:
            flags |= FLAG_AT
        return flags

    def _cose_public_key(self) -> bytes:
        numbers = self._key.public_key().public_numbers()
        return cbor2.dumps(
            {
                1: 2,  # kty: EC2
                3: -7,  # alg: ES256
                -1: 1,  # crv: P-256
                -2: numbers.x.to_bytes(32, "big"),
                -3: numbers.y.to_bytes(32, "big"),
            }
        )

    def _client_data(self, kind: str, challenge: str, origin: str | None) -> bytes:
        return json.dumps(
            {
                "type": kind,
                "challenge": challenge,
                "origin": origin or self.origin,
                "crossOrigin": False,
            }
        ).encode()

    def register(self, options: dict, *, origin: str | None = None) -> dict:
        """Answer ``navigator.credentials.create`` options (JSON form)."""
        self.user_handle = base64url_to_bytes(options["user"]["id"])
        client_data = self._client_data("webauthn.create", options["challenge"], origin)
        attested = (
            self.aaguid
            + struct.pack(">H", len(self.credential_id))
            + self.credential_id
            + self._cose_public_key()
        )
        auth_data = (
            hashlib.sha256(self.rp_id.encode()).digest()
            + bytes([self._flags(attested=True)])
            + struct.pack(">I", self.sign_count)
            + attested
        )
        attestation_object = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "id": _b64(self.credential_id),
            "rawId": _b64(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": _b64(client_data),
                "attestationObject": _b64(attestation_object),
                "transports": ["internal", "hybrid"],
            },
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }

    def assert_(
        self,
        options: dict,
        *,
        origin: str | None = None,
        sign_count: int | None = None,
        user_handle: bytes | None = None,
    ) -> dict:
        """Answer ``navigator.credentials.get`` options (JSON form)."""
        if sign_count is not None:
            self.sign_count = sign_count
        elif self.sign_count:
            self.sign_count += 1
        client_data = self._client_data("webauthn.get", options["challenge"], origin)
        auth_data = (
            hashlib.sha256(self.rp_id.encode()).digest()
            + bytes([self._flags(attested=False)])
            + struct.pack(">I", self.sign_count)
        )
        signature = self._key.sign(
            auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
        )
        handle = user_handle if user_handle is not None else self.user_handle
        return {
            "id": _b64(self.credential_id),
            "rawId": _b64(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": _b64(client_data),
                "authenticatorData": _b64(auth_data),
                "signature": _b64(signature),
                "userHandle": _b64(handle) if handle else None,
            },
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }
