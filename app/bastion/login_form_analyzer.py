"""Analyze remote HTML login forms to pre-fill vault generic_form fields."""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup, Tag

logger = logging.getLogger(__name__)

USER_AGENT = "BastionPro-LoginFormAnalyzer/1.0"
TIMEOUT_SECONDS = 10.0
MAX_REDIRECTS = 5
MAX_BODY_BYTES = 2 * 1024 * 1024  # 2 MiB

_USERNAME_TOKENS = ("user", "login", "email", "identifiant")
_USERNAME_TOKEN_RE = re.compile("|".join(_USERNAME_TOKENS), re.IGNORECASE)

# Explicit cloud metadata / link-local ranges beyond ipaddress.is_* helpers.
_BLOCKED_NETWORKS = (
    ipaddress.ip_network("169.254.0.0/16"),  # IPv4 link-local / cloud metadata
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
)


class AnalyzeLoginFormError(Exception):
    """Structured analysis failure suitable for JSON API responses."""

    def __init__(self, error: str, message: str, *, status_code: int = 502) -> None:
        super().__init__(message)
        self.error = error
        self.message = message
        self.status_code = status_code


def is_likely_dynamic(value: str) -> bool:
    """Heuristic: long token-like values are probably CSRF / session tokens."""
    text = value or ""
    if len(text) <= 20:
        return False
    has_digit = any(c.isdigit() for c in text)
    has_alpha = any(c.isalpha() for c in text)
    has_upper = any(c.isupper() for c in text)
    has_lower = any(c.islower() for c in text)
    if has_digit and has_alpha and has_upper and has_lower:
        return True
    if has_digit and has_alpha and re.fullmatch(r"[A-Za-z0-9+/=_\-.]+", text):
        return True
    if len(text) > 20 and all(c in "0123456789abcdefABCDEF" for c in text):
        return True
    return False


def _attr(el: Tag, name: str) -> str:
    raw = el.get(name)
    if raw is None:
        return ""
    if isinstance(raw, list):
        return " ".join(str(x) for x in raw).strip()
    return str(raw).strip()


def _input_type(el: Tag) -> str:
    return (_attr(el, "type") or "text").lower()


def _looks_like_username(el: Tag) -> bool:
    blob = " ".join(
        [
            _attr(el, "name"),
            _attr(el, "id"),
            _attr(el, "autocomplete"),
        ]
    )
    return bool(_USERNAME_TOKEN_RE.search(blob))


def _pick_username_field(form: Tag, password_el: Tag) -> dict[str, Any] | None:
    inputs = [
        el
        for el in form.find_all("input")
        if isinstance(el, Tag) and _input_type(el) not in ("hidden", "submit", "button", "image", "reset", "checkbox", "radio", "file")
    ]
    # 1. email
    for el in inputs:
        if _input_type(el) == "email" and _attr(el, "name"):
            return {"name": _attr(el, "name"), "confidence": "high"}
    # 2. text/email-like with username tokens
    for el in inputs:
        if _input_type(el) in ("text", "email", "tel", "search") and _looks_like_username(el):
            name = _attr(el, "name")
            if name:
                return {"name": name, "confidence": "high"}
    # 3. first text input before password in DOM order
    for el in inputs:
        if el is password_el:
            break
        if _input_type(el) == "text" and _attr(el, "name"):
            return {"name": _attr(el, "name"), "confidence": "medium"}
    return None


def _hidden_fields(form: Tag) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for el in form.find_all("input"):
        if not isinstance(el, Tag) or _input_type(el) != "hidden":
            continue
        name = _attr(el, "name")
        if not name:
            continue
        value = _attr(el, "value")
        out.append(
            {
                "name": name,
                "value": value,
                "likely_dynamic": is_likely_dynamic(value),
            }
        )
    return out


def analyze_html(html: str, page_url: str) -> list[dict[str, Any]]:
    """Parse HTML and return candidate login forms (those with a password input)."""
    soup = BeautifulSoup(html or "", "html.parser")
    forms: list[dict[str, Any]] = []
    for form in soup.find_all("form"):
        if not isinstance(form, Tag):
            continue
        password_el = None
        for el in form.find_all("input"):
            if isinstance(el, Tag) and _input_type(el) == "password" and _attr(el, "name"):
                password_el = el
                break
        if password_el is None:
            continue

        action_raw = _attr(form, "action")
        action = urljoin(page_url, action_raw) if action_raw else page_url

        method_attr = _attr(form, "method")
        method_explicit = bool(method_attr)
        if method_explicit:
            method = method_attr.upper()
            if method not in ("GET", "POST"):
                method = "POST"
        else:
            # HTML default is GET; vault admin default is POST — signal convention.
            method = "POST"

        username = _pick_username_field(form, password_el)
        field_count = len(
            [
                el
                for el in form.find_all("input")
                if isinstance(el, Tag) and _attr(el, "name")
            ]
        )
        forms.append(
            {
                "action": action,
                "method": method,
                "method_explicit": method_explicit,
                "username_field": username,
                "password_field": {
                    "name": _attr(password_el, "name"),
                    "confidence": "high",
                },
                "hidden_fields": _hidden_fields(form),
                "field_count": field_count,
            }
        )
    return forms


def is_blocked_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True for private, loopback, link-local, multicast, reserved, or metadata ranges."""
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    ):
        return True
    return any(addr in net for net in _BLOCKED_NETWORKS)


def resolve_hostname_ips(hostname: str) -> list[str]:
    """Resolve hostname to IP strings. Raises AnalyzeLoginFormError on failure."""
    host = (hostname or "").strip().strip("[]")
    if not host:
        raise AnalyzeLoginFormError(
            "invalid_url",
            "URL invalide — hôte manquant.",
            status_code=400,
        )
    try:
        # Literal IP — no DNS needed.
        addr = ipaddress.ip_address(host)
        return [str(addr)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise AnalyzeLoginFormError(
            "dns_failed",
            f"Impossible de résoudre l'hôte « {host} ».",
            status_code=400,
        ) from exc
    ips: list[str] = []
    seen: set[str] = set()
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)
    if not ips:
        raise AnalyzeLoginFormError(
            "dns_failed",
            f"Aucune adresse IP pour « {host} ».",
            status_code=400,
        )
    return ips


def assert_url_host_allowed(url: str) -> None:
    """Resolve URL host and reject blocked IP ranges (SSRF guard)."""
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise AnalyzeLoginFormError(
            "invalid_url",
            "URL invalide — hôte manquant.",
            status_code=400,
        )
    for ip_str in resolve_hostname_ips(host):
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError as exc:
            raise AnalyzeLoginFormError(
                "invalid_url",
                f"Adresse IP invalide résolue pour « {host} ».",
                status_code=400,
            ) from exc
        if is_blocked_ip(addr):
            raise AnalyzeLoginFormError(
                "url_blocked",
                "Cette URL pointe vers une adresse non autorisée (réseau interne ou réservé).",
                status_code=400,
            )


def validate_analyze_url(url: str) -> str:
    cleaned = (url or "").strip()
    if not cleaned:
        raise AnalyzeLoginFormError(
            "invalid_url",
            "URL manquante.",
            status_code=400,
        )
    parsed = urlparse(cleaned)
    if parsed.scheme not in ("http", "https"):
        raise AnalyzeLoginFormError(
            "invalid_url",
            "L'URL doit commencer par http:// ou https://.",
            status_code=400,
        )
    if not parsed.netloc:
        raise AnalyzeLoginFormError(
            "invalid_url",
            "URL invalide — hôte manquant.",
            status_code=400,
        )
    assert_url_host_allowed(cleaned)
    return cleaned


async def _read_body_limited(response: httpx.Response) -> str:
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > MAX_BODY_BYTES:
            raise AnalyzeLoginFormError(
                "response_too_large",
                "La page dépasse la taille maximale autorisée (2 Mo).",
                status_code=502,
            )
        chunks.append(chunk)
    raw = b"".join(chunks)
    charset = response.charset_encoding or "utf-8"
    try:
        return raw.decode(charset, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


async def fetch_login_page(url: str) -> tuple[str, str]:
    """GET the page with manual redirects + per-hop SSRF checks."""
    current = validate_analyze_url(url)
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*"}
    try:
        async with httpx.AsyncClient(
            timeout=TIMEOUT_SECONDS,
            follow_redirects=False,
            headers=headers,
        ) as client:
            for _ in range(MAX_REDIRECTS + 1):
                assert_url_host_allowed(current)
                async with client.stream("GET", current) as response:
                    if response.is_redirect:
                        location = response.headers.get("location")
                        if not location:
                            raise AnalyzeLoginFormError(
                                "fetch_failed",
                                "Redirection sans en-tête Location.",
                                status_code=502,
                            )
                        next_url = urljoin(str(response.url), location)
                        # Drain / close before next hop.
                        await response.aread()
                        current = next_url
                        # Re-validate scheme + host before following (DNS rebinding).
                        if urlparse(current).scheme not in ("http", "https"):
                            raise AnalyzeLoginFormError(
                                "url_blocked",
                                "Redirection vers un schéma non autorisé.",
                                status_code=400,
                            )
                        assert_url_host_allowed(current)
                        continue

                    if response.status_code >= 400:
                        raise AnalyzeLoginFormError(
                            "fetch_failed",
                            f"La page a répondu HTTP {response.status_code}.",
                            status_code=502,
                        )
                    text = await _read_body_limited(response)
                    final_url = str(response.url)
                    return final_url, text

            raise AnalyzeLoginFormError(
                "fetch_failed",
                "Trop de redirections (maximum 5).",
                status_code=502,
            )
    except AnalyzeLoginFormError:
        raise
    except httpx.TimeoutException as exc:
        raise AnalyzeLoginFormError(
            "timeout",
            "Délai dépassé en récupérant la page (10 s).",
            status_code=504,
        ) from exc
    except httpx.HTTPError as exc:
        raise AnalyzeLoginFormError(
            "fetch_failed",
            f"Impossible de récupérer la page : {exc.__class__.__name__}.",
            status_code=502,
        ) from exc


async def analyze_login_form_url(url: str) -> dict[str, Any]:
    """Fetch and analyze a login page URL. Returns the §3 JSON payload."""
    final_url, html = await fetch_login_page(url)
    forms = analyze_html(html, final_url)
    if not forms:
        raise AnalyzeLoginFormError(
            "no_form_found",
            (
                "Aucun champ mot de passe détecté sur cette page — vérifiez l'URL, "
                "ou remplissez les champs manuellement si le formulaire est généré "
                "dynamiquement en JavaScript et non présent dans le HTML brut."
            ),
            status_code=400,
        )
    return {
        "forms_found": len(forms),
        "forms": forms,
        "fetched_url": final_url,
    }
