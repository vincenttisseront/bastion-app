"""Lightweight ACME HTTP-01 client (cryptography + httpx, no Certbot).

Writes challenge tokens under the nginx webroot and installs PEMs under the
same ``certs/<fqdn>/`` layout as acme.sh so sync-acme-tls.sh stays uniform.
Never logs private keys or certificate PEMs.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from app.acme.settings_service import certs_dir
from app.sso_settings import Settings

logger = logging.getLogger(__name__)

DIRECTORY_URLS = {
    "letsencrypt": "https://acme-v02.api.letsencrypt.org/directory",
    "letsencrypt_test": "https://acme-staging-v02.api.letsencrypt.org/directory",
}

DEFAULT_CHALLENGE_WEBROOT = "/var/www/acme-challenge"
_ACCOUNT_LOCK = threading.Lock()


class AcmeNativeError(RuntimeError):
    """ACME protocol or local I/O failure (message must not contain secrets)."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_json(obj: Any) -> str:
    return _b64url(
        json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )


def challenge_webroot(settings: Settings) -> Path:
    raw = (getattr(settings, "acme_challenge_webroot", None) or "").strip()
    return Path(raw or DEFAULT_CHALLENGE_WEBROOT)


def account_dir(settings: Settings) -> Path:
    return certs_dir(settings) / "_account"


def _load_or_create_account_key(settings: Settings) -> ec.EllipticCurvePrivateKey:
    path = account_dir(settings) / "account_key.pem"
    account_dir(settings).mkdir(parents=True, exist_ok=True)
    with _ACCOUNT_LOCK:
        if path.is_file():
            key = serialization.load_pem_private_key(
                path.read_bytes(), password=None
            )
            if not isinstance(key, ec.EllipticCurvePrivateKey):
                raise AcmeNativeError("account key must be ECDSA P-256")
            return key
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        tmp = path.with_suffix(".pem.tmp")
        tmp.write_bytes(pem)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        logger.info("acme.native: created account key under certs/_account/")
        return key


def _jwk_ec(public_key: ec.EllipticCurvePublicKey) -> dict[str, str]:
    numbers = public_key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(numbers.x.to_bytes(32, "big")),
        "y": _b64url(numbers.y.to_bytes(32, "big")),
    }


def _thumbprint(jwk: dict[str, str]) -> str:
    # RFC 7638 — only required members, sorted keys.
    payload = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _b64url(hashlib.sha256(payload).digest())


def _sign_es256(key: ec.EllipticCurvePrivateKey, signing_input: bytes) -> bytes:
    der = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    # Convert DER ECDSA to raw R||S (ACME / JOSE).
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _atomic_write_bytes(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(
        f".{path.name}.tmp.{os.getpid()}.{threading.get_ident()}"
    )
    try:
        tmp.write_bytes(data)
        try:
            os.chmod(tmp, mode)
        except OSError:
            pass
        os.replace(tmp, path)
    finally:
        if tmp.is_file():
            try:
                tmp.unlink()
            except OSError:
                pass


def _atomic_write_text(path: Path, text: str, *, mode: int = 0o644) -> None:
    _atomic_write_bytes(path, text.encode("utf-8"), mode=mode)


def write_http01_token(webroot: Path, token: str, key_authorization: str) -> Path:
    """Write ``webroot/.well-known/acme-challenge/<token>`` (nginx root layout).

    nginx config uses ``root /var/www/acme-challenge`` with location
    ``/.well-known/acme-challenge/``, so the file lives at
    ``{webroot}/.well-known/acme-challenge/<token>``.
    """
    safe = (token or "").strip()
    if not safe or "/" in safe or "\\" in safe or ".." in safe:
        raise AcmeNativeError("invalid ACME HTTP-01 token")
    dest = webroot / ".well-known" / "acme-challenge" / safe
    _atomic_write_text(dest, key_authorization, mode=0o644)
    return dest


def clear_http01_token(webroot: Path, token: str) -> None:
    safe = (token or "").strip()
    if not safe or "/" in safe or "\\" in safe:
        return
    path = webroot / ".well-known" / "acme-challenge" / safe
    try:
        if path.is_file():
            path.unlink()
    except OSError:
        pass


def install_domain_cert(
    settings: Settings,
    fqdn: str,
    *,
    fullchain_pem: bytes,
    privkey_pem: bytes,
) -> Path:
    """Write certs/<fqdn>/{fullchain,privkey}.pem atomically (sidecar layout)."""
    host = (fqdn or "").strip().lower()
    if not host or "/" in host or ".." in host:
        raise AcmeNativeError("invalid FQDN for cert install")
    dest = certs_dir(settings) / host
    _atomic_write_bytes(dest / "fullchain.pem", fullchain_pem, mode=0o644)
    _atomic_write_bytes(dest / "privkey.pem", privkey_pem, mode=0o600)
    # Signal nginx reload watcher (same sentinel as acme.sh install-cert).
    try:
        (certs_dir(settings) / ".reload_nginx").write_text(
            datetime.now(timezone.utc).isoformat(), encoding="utf-8"
        )
    except OSError as exc:
        logger.warning("acme.native: could not touch .reload_nginx: %s", exc)
    return dest


def _build_csr(fqdn: str, key: rsa.RSAPrivateKey) -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, fqdn)])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(name)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(fqdn)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.DER)


class AcmeNativeClient:
    """Synchronous ACME client for a single HTTP-01 issuance."""

    def __init__(
        self,
        settings: Settings,
        *,
        acme_ca: str = "letsencrypt",
        contact_email: str | None = None,
        http_client: httpx.Client | None = None,
        directory_url: str | None = None,
    ) -> None:
        self.settings = settings
        self.acme_ca = (acme_ca or "letsencrypt").strip()
        self.contact_email = (contact_email or "").strip() or None
        self._owns_client = http_client is None
        self._client = http_client or httpx.Client(timeout=30.0, follow_redirects=True)
        self._directory_url = directory_url or DIRECTORY_URLS.get(
            self.acme_ca, DIRECTORY_URLS["letsencrypt"]
        )
        self._directory: dict[str, Any] = {}
        self._nonce: str | None = None
        self._account_key = _load_or_create_account_key(settings)
        self._jwk = _jwk_ec(self._account_key.public_key())
        self._kid: str | None = None
        self._account_url_path = account_dir(settings) / "account_url.txt"

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> AcmeNativeClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _load_kid(self) -> None:
        if self._account_url_path.is_file():
            kid = self._account_url_path.read_text(encoding="utf-8").strip()
            if kid:
                self._kid = kid

    def _save_kid(self, kid: str) -> None:
        self._kid = kid
        _atomic_write_text(self._account_url_path, kid + "\n", mode=0o600)

    def _refresh_nonce(self) -> str:
        new_nonce = self._directory.get("newNonce")
        if not new_nonce:
            raise AcmeNativeError("ACME directory missing newNonce")
        resp = self._client.head(new_nonce)
        nonce = resp.headers.get("Replay-Nonce")
        if not nonce:
            raise AcmeNativeError("ACME server did not return Replay-Nonce")
        self._nonce = nonce
        return nonce

    def _ensure_directory(self) -> None:
        if self._directory:
            return
        resp = self._client.get(self._directory_url)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            raise AcmeNativeError("invalid ACME directory payload")
        self._directory = data
        self._refresh_nonce()

    def _signed_post(
        self, url: str, payload: dict[str, Any] | None
    ) -> httpx.Response:
        self._ensure_directory()
        assert self._nonce
        if self._kid:
            protected: dict[str, Any] = {
                "alg": "ES256",
                "kid": self._kid,
                "nonce": self._nonce,
                "url": url,
            }
        else:
            protected = {
                "alg": "ES256",
                "jwk": self._jwk,
                "nonce": self._nonce,
                "url": url,
            }
        protected_b64 = _b64url_json(protected)
        if payload is None:
            payload_b64 = ""
        else:
            payload_b64 = _b64url(
                json.dumps(payload, separators=(",", ":")).encode("utf-8")
            )
        signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
        signature = _b64url(_sign_es256(self._account_key, signing_input))
        body = {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": signature,
        }
        resp = self._client.post(
            url,
            content=json.dumps(body),
            headers={"Content-Type": "application/jose+json"},
        )
        new_nonce = resp.headers.get("Replay-Nonce")
        if new_nonce:
            self._nonce = new_nonce
        return resp

    def _ensure_account(self) -> None:
        self._ensure_directory()
        self._load_kid()
        if self._kid:
            return
        new_account = self._directory.get("newAccount")
        if not new_account:
            raise AcmeNativeError("ACME directory missing newAccount")
        payload: dict[str, Any] = {"termsOfServiceAgreed": True}
        if self.contact_email:
            payload["contact"] = [f"mailto:{self.contact_email}"]
        resp = self._signed_post(new_account, payload)
        if resp.status_code not in (200, 201):
            # Retry without contact if CA rejects email shape.
            if self.contact_email and resp.status_code in (400, 403):
                resp = self._signed_post(
                    new_account, {"termsOfServiceAgreed": True}
                )
        if resp.status_code not in (200, 201):
            raise AcmeNativeError(
                f"ACME newAccount failed HTTP {resp.status_code}"
            )
        kid = resp.headers.get("Location")
        if not kid:
            raise AcmeNativeError("ACME newAccount missing Location (kid)")
        self._save_kid(kid)
        logger.info("acme.native: account ready")

    def _poll(
        self,
        url: str,
        *,
        ready: Callable[[dict[str, Any]], bool],
        timeout_sec: float = 90.0,
        interval_sec: float = 2.0,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_sec
        last: dict[str, Any] = {}
        while time.monotonic() < deadline:
            resp = self._signed_post(url, None)
            if resp.status_code not in (200, 202):
                raise AcmeNativeError(
                    f"ACME poll failed HTTP {resp.status_code}"
                )
            last = resp.json()
            if not isinstance(last, dict):
                raise AcmeNativeError("ACME poll returned non-object")
            status = str(last.get("status") or "")
            if status == "invalid":
                raise AcmeNativeError(_safe_acme_error(last))
            if ready(last):
                return last
            time.sleep(interval_sec)
        raise AcmeNativeError("ACME poll timed out")

    def issue_or_renew(self, fqdn: str) -> Path:
        """Run HTTP-01 for ``fqdn`` and install PEMs under certs/<fqdn>/."""
        host = (fqdn or "").strip().lower()
        if not host or host.startswith("*."):
            raise AcmeNativeError("HTTP-01 cannot issue wildcards")

        self._ensure_account()
        new_order = self._directory.get("newOrder")
        if not new_order:
            raise AcmeNativeError("ACME directory missing newOrder")

        resp = self._signed_post(
            new_order,
            {"identifiers": [{"type": "dns", "value": host}]},
        )
        if resp.status_code not in (201,):
            raise AcmeNativeError(f"ACME newOrder failed HTTP {resp.status_code}")
        order = resp.json()
        order_url = resp.headers.get("Location")
        if not isinstance(order, dict) or not order_url:
            raise AcmeNativeError("ACME newOrder missing body/Location")

        authz_urls = order.get("authorizations") or []
        if not authz_urls:
            raise AcmeNativeError("ACME order has no authorizations")

        webroot = challenge_webroot(self.settings)
        tokens_written: list[str] = []
        try:
            for authz_url in authz_urls:
                authz_resp = self._signed_post(str(authz_url), None)
                if authz_resp.status_code != 200:
                    raise AcmeNativeError(
                        f"ACME authz failed HTTP {authz_resp.status_code}"
                    )
                authz = authz_resp.json()
                if not isinstance(authz, dict):
                    raise AcmeNativeError("invalid authz payload")
                if str(authz.get("status") or "") == "valid":
                    continue
                challenge = _pick_http01(authz)
                token = str(challenge.get("token") or "")
                key_auth = f"{token}.{_thumbprint(self._jwk)}"
                write_http01_token(webroot, token, key_auth)
                tokens_written.append(token)
                chall_url = str(challenge.get("url") or "")
                trig = self._signed_post(chall_url, {})
                if trig.status_code not in (200, 202):
                    raise AcmeNativeError(
                        f"ACME challenge trigger failed HTTP {trig.status_code}"
                    )
                self._poll(
                    str(authz_url),
                    ready=lambda d: str(d.get("status") or "") == "valid",
                )

            order = self._poll(
                order_url,
                ready=lambda d: str(d.get("status") or "") == "ready",
            )
            finalize = str(order.get("finalize") or "")
            if not finalize:
                raise AcmeNativeError("ACME order missing finalize URL")

            domain_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            csr_der = _build_csr(host, domain_key)
            fin_resp = self._signed_post(
                finalize, {"csr": _b64url(csr_der)}
            )
            if fin_resp.status_code not in (200, 202):
                raise AcmeNativeError(
                    f"ACME finalize failed HTTP {fin_resp.status_code}"
                )

            order = self._poll(
                order_url,
                ready=lambda d: str(d.get("status") or "") == "valid",
            )
            cert_url = str(order.get("certificate") or "")
            if not cert_url:
                raise AcmeNativeError("ACME order missing certificate URL")
            cert_resp = self._signed_post(cert_url, None)
            if cert_resp.status_code != 200:
                raise AcmeNativeError(
                    f"ACME certificate download failed HTTP {cert_resp.status_code}"
                )
            fullchain = cert_resp.content
            if b"BEGIN CERTIFICATE" not in fullchain:
                raise AcmeNativeError("ACME certificate payload not PEM")
            privkey = domain_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
            dest = install_domain_cert(
                self.settings,
                host,
                fullchain_pem=fullchain,
                privkey_pem=privkey,
            )
            logger.info("acme.native: issued certificate for %s", host)
            return dest
        finally:
            for token in tokens_written:
                clear_http01_token(webroot, token)


def _pick_http01(authz: dict[str, Any]) -> dict[str, Any]:
    for chall in authz.get("challenges") or []:
        if isinstance(chall, dict) and chall.get("type") == "http-01":
            return chall
    raise AcmeNativeError("no http-01 challenge offered by CA")


def _safe_acme_error(payload: dict[str, Any]) -> str:
    err = payload.get("error")
    if isinstance(err, dict):
        detail = str(err.get("detail") or err.get("type") or "invalid")
        return f"ACME authorization invalid: {detail[:300]}"
    for chall in payload.get("challenges") or []:
        if isinstance(chall, dict) and isinstance(chall.get("error"), dict):
            detail = str(
                chall["error"].get("detail")
                or chall["error"].get("type")
                or "invalid"
            )
            return f"ACME challenge invalid: {detail[:300]}"
    return "ACME authorization invalid"


def issue_or_renew_http01(
    settings: Settings,
    fqdn: str,
    *,
    acme_ca: str = "letsencrypt",
    contact_email: str | None = None,
    http_client: httpx.Client | None = None,
    directory_url: str | None = None,
) -> Path:
    """Convenience wrapper used by Admin renew dispatch."""
    with AcmeNativeClient(
        settings,
        acme_ca=acme_ca,
        contact_email=contact_email,
        http_client=http_client,
        directory_url=directory_url,
    ) as client:
        return client.issue_or_renew(fqdn)
