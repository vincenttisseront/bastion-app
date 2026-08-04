"""CrushFTP robotic SSO driver — login via WebInterface function API."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from urllib.parse import quote, urljoin

import httpx

from app.bastion.drivers.base import RoboticDriver, RoboticLoginError

logger = logging.getLogger(__name__)

_TIMEOUT = 5.0
_SUCCESS_RE = re.compile(r"<response>\s*success\s*</response>", re.IGNORECASE)
_RESPONSE_OK_RE = re.compile(r"<response>\s*OK\s*</response>", re.IGNORECASE)
_RESPONSE_STATUS_OK_RE = re.compile(
    r"<response_status>\s*OK\s*</response_status>", re.IGNORECASE
)
_FAILURE_RE = re.compile(r"<response>\s*(failure|error)\s*</response>", re.IGNORECASE)
_USERNAME_RE = re.compile(
    r"<username>\s*(?:<!\[CDATA\[)?\s*([^<\]]+?)\s*(?:\]\]>)?\s*</username>",
    re.IGNORECASE,
)
_LISTING_SUBITEM_RE = re.compile(
    r"<listing_subitem[^>]*>(.*?)</listing_subitem>",
    re.IGNORECASE | re.DOTALL,
)
_LISTING_NAME_RE = re.compile(
    r"<name>\s*(?:<!\[CDATA\[)?\s*([^<\]]+?)\s*(?:\]\]>)?\s*</name>",
    re.IGNORECASE,
)
_LISTING_TYPE_RE = re.compile(
    r"<type>\s*(?:<!\[CDATA\[)?\s*([^<\]]+?)\s*(?:\]\]>)?\s*</type>",
    re.IGNORECASE,
)
_SKIP_FOLDER_NAMES = frozenset({".", "..", ""})


@dataclass(frozen=True)
class CrushFTPSession:
    """Structured CrushFTP session cookies (not a framework cookie jar)."""

    cookies: dict[str, str]
    base_url: str
    tls_verify: bool = False
    # Host/Origin/Referer when login hits upstream IP but browser uses public_fqdn.
    request_headers: dict[str, str] | None = None


def _normalize_base_url(base_url: str) -> str:
    return base_url.rstrip("/") + "/"


def _merge_request_headers(
    base: dict[str, str] | None,
    extra: dict[str, str] | None,
) -> dict[str, str]:
    out: dict[str, str] = {}
    if base:
        out.update(base)
    if extra:
        out.update(extra)
    return out


def _login_reject_hint(text: str, status: int) -> str:
    """Secret-free hint for WebInterface login failures."""
    body = (text or "").strip()
    if not body:
        return f"réponse vide (HTTP {status})"
    lowered = body.lower()
    if "ip is banned" in lowered or "hammering" in lowered:
        # CrushFTP DENIAL: "---Your IP is banned, no further requests will be
        # processed from this IP---:<ip>:<since>:hammering http". The banned IP
        # is the docker host NAT — it carries the robotic login AND every
        # proxied browser user, so the whole platform is locked out at once.
        return (
            f"IP bastion bannie par CrushFTP (protection anti-hammering, "
            f"HTTP {status}) — débannir dans l'admin CrushFTP "
            "(Server Admin → IP restrictions / ban list) puis chercher la "
            "cause de la rafale (ex. boucle de redirections login.html)"
        )
    if "max simultaneous" in lowered or "user limit" in lowered:
        return (
            f"limite de sessions simultanées CrushFTP atteinte (HTTP {status}) "
            "— augmentez « Max logins » du compte robotique ou attendez "
            "l'expiration des sessions orphelines"
        )
    if _FAILURE_RE.search(body):
        return (
            f"CrushFTP a renvoyé failure (HTTP {status}) — "
            "mot de passe vault incorrect ou compte désactivé ; "
            "ré-enregistrez le credential pour le re-pousser"
        )
    if "<html" in lowered or "<!doctype" in lowered:
        return (
            f"réponse HTML (HTTP {status}) — l’URL pointe vers un portail SSO "
            "ou une page web, pas l’API WebInterface CrushFTP"
        )
    if "oauth" in lowered or "keycloak" in lowered or "sso" in lowered:
        return f"réponse type SSO (HTTP {status}) — utilisez l’URL Admin API interne"
    return f"pas de <response>success</response> (HTTP {status}, {len(body)} octets)"


def _body_excerpt(text: str, limit: int = 200) -> str:
    """Whitespace-collapsed body excerpt for WARNING logs (login responses only —
    they never echo credentials; at worst the username)."""
    collapsed = re.sub(r"\s+", " ", (text or "").strip())
    return collapsed[:limit] + ("…" if len(collapsed) > limit else "")


def _extract_session_cookies(response: httpx.Response) -> dict[str, str]:
    out: dict[str, str] = {}
    crush_auth = response.cookies.get("CrushAuth")
    current_auth = response.cookies.get("currentAuth")
    if crush_auth:
        out["CrushAuth"] = crush_auth
    if current_auth:
        out["currentAuth"] = current_auth
    # Some CrushFTP builds only set CrushAuth; derive currentAuth as last 4 chars.
    if "CrushAuth" in out and "currentAuth" not in out and len(out["CrushAuth"]) >= 4:
        out["currentAuth"] = out["CrushAuth"][-4:]
    return out


def _c2f(cookies: dict[str, str]) -> str | None:
    if "currentAuth" in cookies:
        return cookies["currentAuth"]
    crush = cookies.get("CrushAuth")
    if crush and len(crush) >= 4:
        return crush[-4:]
    return None


class CrushFTPDriver(RoboticDriver):
    """Robotic login against CrushFTP `/WebInterface/function/`."""

    async def login(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        tls_verify: bool = False,
        extra_headers: dict[str, str] | None = None,
    ) -> CrushFTPSession:
        base = _normalize_base_url(base_url)
        url = urljoin(base, "WebInterface/function/")
        # encoded=true: CrushFTP URI-decodes username/password after form parse.
        # Pre-encode so characters like '+' '/' survive the form round-trip.
        data = {
            "command": "login",
            "username": quote(username or "", safe=""),
            "password": quote(password or "", safe=""),
            "encoded": "true",
            "language": "en",
        }
        headers = _merge_request_headers(None, extra_headers)
        try:
            async with httpx.AsyncClient(
                timeout=_TIMEOUT,
                follow_redirects=False,
                verify=tls_verify,
            ) as client:
                response = await client.post(
                    url, data=data, headers=headers or None
                )
        except httpx.TimeoutException as exc:
            raise RoboticLoginError("CrushFTP login timed out") from exc
        except httpx.RequestError as exc:
            raise RoboticLoginError("CrushFTP login network error") from exc

        if response.status_code in (301, 302, 303, 307, 308):
            loc = response.headers.get("location") or ""
            raise RoboticLoginError(
                "CrushFTP login redirected (HTTP "
                f"{response.status_code}) — URL probablement SSO/publique "
                f"(tentée: {base}). Utilisez l’URL API Admin CrushFTP interne "
                f"(ex. https://172.x.x.x:8080/), pas le FQDN public. "
                f"Location: {loc[:120] if loc else '—'}"
            )

        body = response.text or ""
        if not _SUCCESS_RE.search(body):
            hint = _login_reject_hint(body, response.status_code)
            # Mirror CrushFTP.log diagnostics (DENIAL ban, session limit, …) in
            # bastion logs — the response body is the only place CrushFTP says why.
            logger.warning(
                "CrushFTP login rejected: %s | url=%s user=%s http=%s body=%r",
                hint,
                url,
                username,
                response.status_code,
                _body_excerpt(body),
            )
            raise RoboticLoginError(f"CrushFTP login rejected — {hint}")

        cookies = _extract_session_cookies(response)
        if "CrushAuth" not in cookies:
            raise RoboticLoginError("CrushFTP login missing CrushAuth cookie")

        return CrushFTPSession(
            cookies=cookies,
            base_url=base,
            tls_verify=tls_verify,
            request_headers=dict(extra_headers) if extra_headers else None,
        )

    async def get_username(self, session: CrushFTPSession) -> str:
        url = urljoin(session.base_url, "WebInterface/function/")
        c2f = _c2f(session.cookies)
        if not c2f:
            raise RoboticLoginError("CrushFTP session missing auth token")
        data = {"command": "getUsername", "c2f": c2f}
        headers = _merge_request_headers(
            {"Cookie": "; ".join(f"{k}={v}" for k, v in session.cookies.items())},
            session.request_headers,
        )
        try:
            async with httpx.AsyncClient(
                timeout=_TIMEOUT,
                follow_redirects=False,
                verify=bool(session.tls_verify),
            ) as client:
                response = await client.post(url, data=data, headers=headers)
        except httpx.TimeoutException as exc:
            raise RoboticLoginError("CrushFTP getUsername timed out") from exc
        except httpx.RequestError as exc:
            raise RoboticLoginError("CrushFTP getUsername network error") from exc

        text = response.text or ""
        if not _SUCCESS_RE.search(text):
            logger.warning(
                "CrushFTP getUsername rejected: %s | url=%s http=%s body=%r",
                _login_reject_hint(text, response.status_code),
                url,
                response.status_code,
                _body_excerpt(text),
            )
            raise RoboticLoginError("CrushFTP getUsername rejected")
        match = _USERNAME_RE.search(text)
        if not match:
            raise RoboticLoginError(
                "CrushFTP getUsername missing username despite success"
            )
        username = match.group(1).strip()
        if not username or username.lower() in ("failure", "error", "anonymous"):
            raise RoboticLoginError("CrushFTP getUsername identity check failed")
        return username

    async def logout(self, session: CrushFTPSession) -> None:
        """
        Best-effort session close.

        CrushFTP enforces a max simultaneous sessions limit per account. Orphaned
        CrushAuth sessions (login succeeded, later step failed without logout)
        accumulate until idle timeout and surface as
        "421 — Max simultaneous user limit reached". Never raise from here.
        """
        url = urljoin(session.base_url, "WebInterface/function/")
        c2f = _c2f(session.cookies)
        data: dict[str, str] = {"command": "logout"}
        if c2f:
            data["c2f"] = c2f
        headers = _merge_request_headers(
            {"Cookie": "; ".join(f"{k}={v}" for k, v in session.cookies.items())},
            session.request_headers,
        )
        try:
            async with httpx.AsyncClient(
                timeout=_TIMEOUT,
                follow_redirects=False,
                verify=bool(session.tls_verify),
            ) as client:
                await client.post(url, data=data, headers=headers)
        except httpx.RequestError:
            pass

    async def fingerprint(self, base_url: str, *, tls_verify: bool = False) -> bool:
        base = _normalize_base_url(base_url)
        url = urljoin(base, "WebInterface/login.html")
        try:
            async with httpx.AsyncClient(
                timeout=_TIMEOUT,
                follow_redirects=True,
                verify=tls_verify,
            ) as client:
                response = await client.get(url)
        except httpx.RequestError:
            return False
        body = (response.text or "").lower()
        return "crushftp" in body or "webinterface" in response.url.path.lower()


# ---------------------------------------------------------------------------
# Account provisioning (bastion accounts → CrushFTP local users)
# ---------------------------------------------------------------------------
#
# Official CrushFTP Admin API uses HTTP Basic Auth per request (curl -u admin:pass),
# NOT the browser-session flow (CrushAuth/c2f) used by robotic impersonation above.
# See creation-comptes §13 — keep those two auth modes strictly separate.

from xml.sax.saxutils import escape as _xml_escape

from app.bastion.drivers.base_provisioning import (
    PROVISIONING_FAILED,
    PROVISIONING_SUCCESS,
    GeneratedCredential,
    ProvisioningResult,
)

# Never create FILE://users/<username>/ or any per-user home on disk.
_CRUSHFTP_USER_XML_TEMPLATE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<user type="properties">'
    "<username>{username}</username>"
    "<password>{password}</password>"
    "<version>1.0</version>"
    "<root_dir>/</root_dir>"
    "<userVersion>6</userVersion>"
    "<max_logins>0</max_logins>"
    "<create_home_folder>false</create_home_folder>"
    "</user>"
)

_DEFAULT_SERVER_GROUP = "MainUsers"


def crushftp_company_folder_name(organization: str | None) -> str:
    """Filesystem / VFS folder for a société — alphanumeric (+ - _), no spaces."""
    raw = (organization or "").strip()
    cleaned = "".join(ch for ch in raw if ch.isalnum() or ch in "-_")
    return cleaned or ""


def crushftp_company_file_url(base_path: str, company_folder: str) -> str:
    """Build FILE:// URL under the app VFS root (CrushFTP physical path)."""
    base = (base_path or "").strip().replace("\\", "/").strip("/")
    folder = (company_folder or "").strip().strip("/")
    if not base or not folder:
        raise ValueError("crushftp_vfs_base_path et dossier société sont requis")
    return f"FILE://{base}/{folder}/"


def normalize_crushftp_listing_path(vfs_base: str) -> str:
    """Absolute directory path for getXMLListing (leading + trailing slash)."""
    path = (vfs_base or "").strip().replace("\\", "/")
    if not path:
        return ""
    if not path.startswith("/"):
        path = "/" + path
    if not path.endswith("/"):
        path = path + "/"
    return path


def parse_crushftp_directory_names(body: str) -> list[str]:
    """Extract immediate subdirectory names from getXMLListing (jsonobj or XML)."""
    text = (body or "").strip()
    if not text:
        return []
    names: list[str] = []

    # Prefer JSON (format=jsonobj / json).
    if text.startswith("{") or text.startswith("["):
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = None
        if payload is not None:
            items: list = []
            if isinstance(payload, list):
                items = payload
            elif isinstance(payload, dict):
                for key in ("listing", "listings", "files", "rows"):
                    val = payload.get(key)
                    if isinstance(val, list):
                        items = val
                        break
                if not items and isinstance(payload.get("data"), list):
                    items = payload["data"]
            for item in items:
                if not isinstance(item, dict):
                    continue
                name = str(
                    item.get("name")
                    or item.get("href_path")
                    or item.get("path")
                    or ""
                ).strip().rstrip("/")
                if "/" in name:
                    name = name.rsplit("/", 1)[-1]
                typ = str(item.get("type") or item.get("dir") or "").strip().upper()
                is_dir = typ in ("DIR", "DIRECTORY", "FOLDER", "TRUE", "1") or item.get(
                    "dir"
                ) is True
                # CrushFTP jsonobj often uses type DIR; some builds omit type for dirs.
                if not is_dir and typ in ("FILE", "FILELINK"):
                    continue
                if not is_dir and typ and typ not in ("DIR", "DIRECTORY", "FOLDER"):
                    continue
                if not name or name in _SKIP_FOLDER_NAMES:
                    continue
                if not is_dir and not typ:
                    # No type: keep only société-like folder names (alnum/_/-).
                    cleaned = crushftp_company_folder_name(name)
                    if cleaned != name:
                        continue
                names.append(name)
            return _dedupe_preserve(names)

    # XML listing_subitem blocks.
    for block in _LISTING_SUBITEM_RE.findall(text):
        name_m = _LISTING_NAME_RE.search(block)
        type_m = _LISTING_TYPE_RE.search(block)
        if not name_m:
            continue
        name = name_m.group(1).strip().rstrip("/")
        if "/" in name:
            name = name.rsplit("/", 1)[-1]
        typ = (type_m.group(1).strip().upper() if type_m else "")
        if typ in ("FILE", "FILELINK"):
            continue
        if not name or name in _SKIP_FOLDER_NAMES:
            continue
        if typ and typ not in ("DIR", "DIRECTORY", "FOLDER"):
            continue
        names.append(name)
    return _dedupe_preserve(names)


def _dedupe_preserve(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        key = v.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append(v)
    return out


def _crushftp_user_xml(credential: GeneratedCredential) -> str:
    """Minimal CrushFTP user XML for setUserItem — values XML-escaped."""
    return _CRUSHFTP_USER_XML_TEMPLATE.format(
        username=_xml_escape(credential.username),
        password=_xml_escape(credential.password),
    )


def _crushftp_vfs_items_xml(*, company_folder: str, file_url: str) -> str:
    """Mount company folder only — never FILE://users/<username>/ personal homes."""
    name = _xml_escape((company_folder or "").strip())
    url = _xml_escape((file_url or "").strip())
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<vfs_items type="vector">'
        '<vfs_items_subitem type="properties">'
        f"<name>{name}</name>"
        "<path>/</path>"
        '<vfs_item type="vector">'
        '<vfs_item_subitem type="properties">'
        f"<url>{url}</url>"
        "</vfs_item_subitem>"
        "</vfs_item>"
        "</vfs_items_subitem>"
        "</vfs_items>"
    )


def _crushftp_permissions_xml(company_folder: str) -> str:
    """Default VFS permissions: read-only (no upload/write/delete/mkdir/rename)."""
    folder = _xml_escape((company_folder or "").strip())
    read_only = "(read)(view)(resume)"
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<VFS type="properties">'
        f'<item name="/{folder}/">{read_only}</item>'
        f'<item name="/">{read_only}</item>'
        "</VFS>"
    )


def _admin_response_ok(text: str) -> bool:
    """Accept CrushFTP success shapes (login + admin API variants)."""
    body = text or ""
    return bool(
        _SUCCESS_RE.search(body)
        or _RESPONSE_OK_RE.search(body)
        or _RESPONSE_STATUS_OK_RE.search(body)
    )


def _admin_reject_hint(text: str, status: int) -> str:
    """Human-readable failure without echoing body (may contain secrets)."""
    body = (text or "").strip()
    if not body:
        return f"réponse vide (HTTP {status})"
    lowered = body.lower()
    if _FAILURE_RE.search(body):
        return f"CrushFTP a renvoyé failure (HTTP {status})"
    if "<html" in lowered or "<!doctype" in lowered:
        return (
            f"réponse HTML (HTTP {status}) — URL API Admin incorrecte "
            "(listener CrushFTP racine, pas UserManager / SSO)"
        )
    if "access denied" in lowered or "permission" in lowered or "not authorized" in lowered:
        return f"accès refusé / droits admin insuffisants (HTTP {status})"
    if "already" in lowered or "exist" in lowered:
        return f"conflit username (déjà existant) (HTTP {status})"
    return (
        f"réponse non-success (HTTP {status}, {len(body)} octets) — "
        "vérifiez data_action/VFS ou les droits du compte admin CrushFTP"
    )


def _admin_api_url(base_url: str) -> str:
    """POST target for admin commands (doc: host:port root; WebInterface also OK)."""
    raw = (base_url or "").strip()
    if not raw:
        return ""
    if "WebInterface" in raw:
        return raw if raw.endswith("/") else raw + "/"
    return raw.rstrip("/") + "/"


def _server_group(app) -> str:
    value = (getattr(app, "crushftp_admin_server_group", None) or "").strip()
    return value or _DEFAULT_SERVER_GROUP


class CrushFTPProvisioningDriver:
    """CrushFTP Admin API via HTTP Basic Auth (setUserItem user + groups)."""

    driver_name = "crushftp"

    async def create_account(
        self,
        *,
        db,
        settings,
        app,
        account,
        credential,
        group_names: list[str] | None = None,
    ) -> ProvisioningResult:
        """Create/update user with company VFS, then optional CrushFTP groups."""
        admin = self._resolve_admin(app, settings)
        if isinstance(admin, ProvisioningResult):
            return admin
        username, password, base_url, server_group, tls_verify = admin

        company = crushftp_company_folder_name(getattr(account, "organization", None))
        vfs_base = (getattr(app, "crushftp_vfs_base_path", None) or "").strip()
        if not company:
            return ProvisioningResult(
                status=PROVISIONING_FAILED,
                detail=(
                    "Société / organization manquante sur le compte bastion — "
                    "requis pour monter le dossier CrushFTP."
                ),
            )
        if not vfs_base:
            return ProvisioningResult(
                status=PROVISIONING_FAILED,
                detail=(
                    "Racine VFS sociétés non configurée sur l'application "
                    "(champ crushftp_vfs_base_path, ex. /crush_data/AR-SYSTEMS)."
                ),
            )
        try:
            file_url = crushftp_company_file_url(vfs_base, company)
        except ValueError as exc:
            return ProvisioningResult(status=PROVISIONING_FAILED, detail=str(exc))

        try:
            existing = await self._verify_user_exists(
                base_url=base_url,
                admin_username=username,
                admin_password=password,
                server_group=server_group,
                tls_verify=tls_verify,
                username=credential.username,
            )
            folder_note = await self._ensure_company_folder(
                base_url=base_url,
                admin_username=username,
                admin_password=password,
                tls_verify=tls_verify,
                vfs_base=vfs_base,
                company_folder=company,
            )

            user_result = await self._set_user_item(
                base_url=base_url,
                admin_username=username,
                admin_password=password,
                server_group=server_group,
                tls_verify=tls_verify,
                credential=credential,
                company_folder=company,
                file_url=file_url,
                account_existed=existing,
            )
            if user_result.status != PROVISIONING_SUCCESS:
                return user_result

            detail_bits = [user_result.detail, folder_note]
            names = [n.strip() for n in (group_names or []) if (n or "").strip()]
            # Always try the company CrushFTP group (same name as folder) when not listed.
            if company not in names:
                names = [company, *names]

            if names:
                group_parts: list[str] = []
                group_errors: list[str] = []
                for name in names:
                    ok, msg = await self._set_group_membership(
                        base_url=base_url,
                        admin_username=username,
                        admin_password=password,
                        server_group=server_group,
                        tls_verify=tls_verify,
                        username=credential.username,
                        group_name=name,
                        data_action="add",
                    )
                    if ok:
                        group_parts.append(f"{name}=ok")
                    else:
                        group_parts.append(f"{name}=échec ({msg})")
                        group_errors.append(f"{name}: {msg}")
                detail_bits.append("Groupes: " + "; ".join(group_parts))
                return ProvisioningResult(
                    status=PROVISIONING_SUCCESS,
                    detail=". ".join(p for p in detail_bits if p),
                    credential_pushed=True,
                    group_errors=tuple(group_errors),
                )

            return ProvisioningResult(
                status=PROVISIONING_SUCCESS,
                detail=". ".join(p for p in detail_bits if p),
                credential_pushed=True,
            )
        finally:
            password = ""  # noqa: F841

    async def _ensure_company_folder(
        self,
        *,
        base_url: str,
        admin_username: str,
        admin_password: str,
        tls_verify: bool,
        vfs_base: str,
        company_folder: str,
    ) -> str:
        """Best-effort: ensure the *company* directory exists (never a per-user home).

        Personal paths like /users/<username>/ are intentionally never created.
        """
        base = vfs_base.strip().replace("\\", "/")
        if not base.startswith("/"):
            base = "/" + base
        path = f"{base.rstrip('/')}/{company_folder}"
        ok, msg, _status = await self._admin_post(
            base_url=base_url,
            admin_username=admin_username,
            admin_password=admin_password,
            tls_verify=tls_verify,
            data={
                "command": "makedir",
                "path": path,
            },
        )
        if ok:
            return f"Dossier société {path} créé ou déjà présent"
        lowered = (msg or "").lower()
        if "exist" in lowered or "already" in lowered or "failure" in lowered:
            return f"Dossier société {path} (makedir: {msg})"
        return f"Dossier société {path} — makedir non confirmé ({msg})"

    async def add_user_to_group(
        self,
        *,
        db,
        settings,
        app,
        username: str,
        group_name: str,
        session=None,  # unused — kept for call-site compat; Basic Auth is per-request
    ) -> ProvisioningResult:
        return await self._group_op(
            db=db,
            settings=settings,
            app=app,
            username=username,
            group_name=group_name,
            data_action="add",
        )

    async def remove_user_from_group(
        self,
        *,
        db,
        settings,
        app,
        username: str,
        group_name: str,
        session=None,
    ) -> ProvisioningResult:
        return await self._group_op(
            db=db,
            settings=settings,
            app=app,
            username=username,
            group_name=group_name,
            data_action="delete",
        )

    async def _group_op(
        self,
        *,
        db,
        settings,
        app,
        username: str,
        group_name: str,
        data_action: str,
    ) -> ProvisioningResult:
        admin = self._resolve_admin(app, settings)
        if isinstance(admin, ProvisioningResult):
            return admin
        admin_user, admin_pass, base_url, server_group, tls_verify = admin
        try:
            ok, msg = await self._set_group_membership(
                base_url=base_url,
                admin_username=admin_user,
                admin_password=admin_pass,
                server_group=server_group,
                tls_verify=tls_verify,
                username=username,
                group_name=group_name,
                data_action=data_action,
            )
        finally:
            admin_pass = ""  # noqa: F841
        if ok:
            verb = "ajouté au" if data_action == "add" else "retiré du"
            return ProvisioningResult(
                status=PROVISIONING_SUCCESS,
                detail=f"Utilisateur {verb} groupe CrushFTP « {group_name} »",
            )
        return ProvisioningResult(status=PROVISIONING_FAILED, detail=msg)

    def _resolve_admin(
        self, app, settings
    ) -> tuple[str, str, str, str, bool] | ProvisioningResult:
        """Return (username, password, api_url, server_group, tls_verify) or error."""
        from app.bastion.upstream_tls import resolve_upstream_tls_verify
        from app.secret_crypto import decrypt_secret

        base_url = _admin_api_url(getattr(app, "crushftp_admin_base_url", None) or "")
        username = (getattr(app, "crushftp_admin_username", None) or "").strip()
        encrypted = getattr(app, "crushftp_admin_password_encrypted", None) or ""
        if not base_url or not username or not encrypted:
            return ProvisioningResult(
                status=PROVISIONING_FAILED,
                detail=(
                    "API Admin CrushFTP non configurée — renseignez l'URL, le "
                    "compte admin et le mot de passe dans la section « API Admin "
                    "CrushFTP » de la fiche application (distincte du vault individuel)."
                ),
            )
        try:
            password = decrypt_secret(encrypted, settings)
        except ValueError:
            return ProvisioningResult(
                status=PROVISIONING_FAILED,
                detail="Déchiffrement du mot de passe admin CrushFTP impossible",
            )
        return (
            username,
            password,
            base_url,
            _server_group(app),
            resolve_upstream_tls_verify(app),
        )

    async def _admin_post(
        self,
        *,
        base_url: str,
        admin_username: str,
        admin_password: str,
        tls_verify: bool,
        data: dict[str, str],
    ) -> tuple[bool, str, int]:
        """POST admin command with HTTP Basic Auth. Never logs auth headers or body."""
        ok, msg, status, _body = await self._admin_post_body(
            base_url=base_url,
            admin_username=admin_username,
            admin_password=admin_password,
            tls_verify=tls_verify,
            data=data,
            require_success_marker=True,
        )
        return ok, msg, status

    async def _admin_post_body(
        self,
        *,
        base_url: str,
        admin_username: str,
        admin_password: str,
        tls_verify: bool,
        data: dict[str, str],
        require_success_marker: bool = True,
    ) -> tuple[bool, str, int, str]:
        """POST admin command; optionally accept listing bodies without <response>success."""
        try:
            async with httpx.AsyncClient(
                timeout=_TIMEOUT,
                follow_redirects=False,
                verify=tls_verify,
                # httpx auth= never appears in our log lines (we do not log headers).
                auth=(admin_username, admin_password),
            ) as client:
                response = await client.post(base_url, data=data)
        except httpx.TimeoutException:
            return False, "Timeout CrushFTP", 0, ""
        except httpx.RequestError:
            return False, "Erreur réseau CrushFTP", 0, ""
        body = response.text or ""
        if response.status_code in (401, 403):
            return (
                False,
                "Authentification admin CrushFTP refusée (Basic Auth)",
                response.status_code,
                "",
            )
        if response.status_code in (301, 302, 303, 307, 308):
            return (
                False,
                (
                    f"Redirection HTTP {response.status_code} — l'URL API Admin pointe "
                    "probablement vers le bastion/SSO (URL publique) au lieu du "
                    "listener CrushFTP direct (IP:port interne)."
                ),
                response.status_code,
                "",
            )
        if require_success_marker and not _admin_response_ok(body):
            return (
                False,
                _admin_reject_hint(body, response.status_code),
                response.status_code,
                "",
            )
        if response.status_code >= 400:
            return (
                False,
                _admin_reject_hint(body, response.status_code),
                response.status_code,
                "",
            )
        if _FAILURE_RE.search(body):
            return (
                False,
                _admin_reject_hint(body, response.status_code),
                response.status_code,
                "",
            )
        return True, "ok", response.status_code, body

    async def list_company_folders(
        self,
        *,
        app,
        settings,
    ) -> tuple[list[str], str | None]:
        """List immediate subfolders under app.crushftp_vfs_base_path via getXMLListing."""
        admin = self._resolve_admin(app, settings)
        if isinstance(admin, ProvisioningResult):
            return [], admin.detail
        username, password, base_url, _server_group, tls_verify = admin
        vfs_base = (getattr(app, "crushftp_vfs_base_path", None) or "").strip()
        path = normalize_crushftp_listing_path(vfs_base)
        if not path:
            return [], (
                "Racine VFS sociétés non configurée "
                "(champ crushftp_vfs_base_path, ex. /crush_data/AR-SYSTEMS)."
            )

        ok, msg, _status, body = await self._admin_post_body(
            base_url=base_url,
            admin_username=username,
            admin_password=password,
            tls_verify=tls_verify,
            data={
                "command": "getXMLListing",
                "path": path,
                "format": "jsonobj",
            },
            require_success_marker=False,
        )
        if not ok:
            return [], f"Lecture dossiers CrushFTP échouée : {msg}"

        folders = parse_crushftp_directory_names(body)
        cleaned: list[str] = []
        for name in folders:
            folder = crushftp_company_folder_name(name)
            if folder:
                cleaned.append(folder)
        return _dedupe_preserve(cleaned), None

    async def _set_user_item(
        self,
        *,
        base_url: str,
        admin_username: str,
        admin_password: str,
        server_group: str,
        tls_verify: bool,
        credential: GeneratedCredential,
        company_folder: str,
        file_url: str,
        account_existed: bool = False,
    ) -> ProvisioningResult:
        # CrushFTP wiki: replace + vfs_items (company FILE://) + VFS permissions RO.
        ok, msg, status = await self._admin_post(
            base_url=base_url,
            admin_username=admin_username,
            admin_password=admin_password,
            tls_verify=tls_verify,
            data={
                "command": "setUserItem",
                "data_action": "replace",
                "serverGroup": server_group,
                "username": credential.username,
                "user": _crushftp_user_xml(credential),
                "xmlItem": "user",
                "vfs_items": _crushftp_vfs_items_xml(
                    company_folder=company_folder, file_url=file_url
                ),
                "permissions": _crushftp_permissions_xml(company_folder),
            },
        )
        if not ok:
            if "Authentification admin" in msg:
                detail = msg
            elif "Redirection HTTP" in msg:
                detail = msg
            elif msg.startswith("Timeout"):
                detail = "Timeout CrushFTP lors de la création du compte (setUserItem)"
            elif msg.startswith("Erreur réseau"):
                detail = "Erreur réseau CrushFTP lors de la création du compte"
            else:
                detail = f"Création compte CrushFTP échouée : {msg}"
            return ProvisioningResult(status=PROVISIONING_FAILED, detail=detail)

        verified = await self._verify_user_exists(
            base_url=base_url,
            admin_username=admin_username,
            admin_password=admin_password,
            server_group=server_group,
            tls_verify=tls_verify,
            username=credential.username,
        )
        if not verified:
            return ProvisioningResult(
                status=PROVISIONING_FAILED,
                detail=(
                    f"CrushFTP a répondu succès à setUserItem mais getUser ne trouve "
                    f"pas « {credential.username} » dans {server_group} — vérifiez "
                    "l'URL API Admin (même instance que User Manager) et le compte admin."
                ),
            )

        action = "mis à jour" if account_existed else "créé"
        return ProvisioningResult(
            status=PROVISIONING_SUCCESS,
            detail=(
                f"Compte CrushFTP {action} (username={credential.username}, "
                f"serverGroup={server_group}, VFS={file_url}, lecture seule)"
            ),
            credential_pushed=True,
        )

    async def _verify_user_exists(
        self,
        *,
        base_url: str,
        admin_username: str,
        admin_password: str,
        server_group: str,
        tls_verify: bool,
        username: str,
    ) -> bool:
        """Confirm the user is readable via admin getUser (avoids false setUserItem OK)."""
        try:
            async with httpx.AsyncClient(
                timeout=_TIMEOUT,
                follow_redirects=False,
                verify=tls_verify,
                auth=(admin_username, admin_password),
            ) as client:
                response = await client.post(
                    base_url,
                    data={
                        "command": "getUser",
                        "serverGroup": server_group,
                        "username": username,
                    },
                )
        except (httpx.TimeoutException, httpx.RequestError):
            return False
        text = response.text or ""
        if response.status_code != 200:
            return False
        if response.status_code in (301, 302, 303, 307, 308):
            return False
        if _FAILURE_RE.search(text):
            return False
        lowered = text.lower()
        if "<html" in lowered or "<!doctype" in lowered:
            return False
        # getUser returns user properties XML — not always <response>success.
        if username.lower() in lowered and (
            "<user" in lowered or "password" in lowered or "root_dir" in lowered
        ):
            return True
        return False

    async def _set_group_membership(
        self,
        *,
        base_url: str,
        admin_username: str,
        admin_password: str,
        server_group: str,
        tls_verify: bool,
        username: str,
        group_name: str,
        data_action: str,
    ) -> tuple[bool, str]:
        """xmlItem=groups — creates the group implicitly on first add (CrushFTP docs)."""
        ok, msg, status = await self._admin_post(
            base_url=base_url,
            admin_username=admin_username,
            admin_password=admin_password,
            tls_verify=tls_verify,
            data={
                "command": "setUserItem",
                "xmlItem": "groups",
                "data_action": data_action,
                "serverGroup": server_group,
                "group_name": group_name,
                "usernames": username,
            },
        )
        if ok:
            return True, "ok"
        if "Authentification admin" in msg:
            return False, msg
        if status:
            return False, f"HTTP {status}"
        return False, msg

    async def disable_account(self, *, db, settings, app, account) -> ProvisioningResult:
        return ProvisioningResult(
            status=PROVISIONING_FAILED,
            detail=(
                "Désactivation automatique hors périmètre V1 — action manuelle "
                "dans CrushFTP (cf. spec §5.3)."
            ),
        )

    async def delete_account(self, *, db, settings, app, account) -> ProvisioningResult:
        """Delete the CrushFTP local user (setUserItem data_action=delete).

        Idempotent: an already-absent user is a success ("déjà absent"), so the
        bastion-side cleanup can be retried safely. The outcome is always
        verified with getUser — never trust the setUserItem response alone.
        """
        admin = self._resolve_admin(app, settings)
        if isinstance(admin, ProvisioningResult):
            return admin
        admin_username, admin_password, base_url, server_group, tls_verify = admin
        target = (account.username or "").strip()
        if not target:
            return ProvisioningResult(
                status=PROVISIONING_FAILED,
                detail="Username bastion manquant — suppression CrushFTP impossible",
            )
        try:
            exists = await self._verify_user_exists(
                base_url=base_url,
                admin_username=admin_username,
                admin_password=admin_password,
                server_group=server_group,
                tls_verify=tls_verify,
                username=target,
            )
            if not exists:
                return ProvisioningResult(
                    status=PROVISIONING_SUCCESS,
                    detail=(
                        f"Compte CrushFTP « {target} » déjà absent "
                        f"(serverGroup={server_group})"
                    ),
                )

            ok, msg, _status = await self._admin_post(
                base_url=base_url,
                admin_username=admin_username,
                admin_password=admin_password,
                tls_verify=tls_verify,
                data={
                    "command": "setUserItem",
                    "data_action": "delete",
                    "xmlItem": "user",
                    "serverGroup": server_group,
                    "username": target,
                },
            )

            still_there = await self._verify_user_exists(
                base_url=base_url,
                admin_username=admin_username,
                admin_password=admin_password,
                server_group=server_group,
                tls_verify=tls_verify,
                username=target,
            )
            if not still_there:
                return ProvisioningResult(
                    status=PROVISIONING_SUCCESS,
                    detail=(
                        f"Compte CrushFTP « {target} » supprimé "
                        f"(serverGroup={server_group})"
                    ),
                )
            if ok:
                detail = (
                    f"CrushFTP a répondu succès à la suppression mais getUser "
                    f"trouve toujours « {target} » dans {server_group}"
                )
            else:
                detail = f"Suppression compte CrushFTP échouée : {msg}"
            return ProvisioningResult(status=PROVISIONING_FAILED, detail=detail)
        finally:
            admin_password = ""  # noqa: F841
