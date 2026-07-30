"""CrushFTP robotic SSO driver — login via WebInterface function API."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from urllib.parse import urljoin

import httpx

from app.bastion.drivers.base import RoboticDriver, RoboticLoginError

logger = logging.getLogger(__name__)

_TIMEOUT = 5.0
_SUCCESS_RE = re.compile(r"<response>\s*success\s*</response>", re.IGNORECASE)
_USERNAME_RE = re.compile(
    r"<username>\s*(?:<!\[CDATA\[)?\s*([^<\]]+?)\s*(?:\]\]>)?\s*</username>",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CrushFTPSession:
    """Structured CrushFTP session cookies (not a framework cookie jar)."""

    cookies: dict[str, str]
    base_url: str
    tls_verify: bool = False


def _normalize_base_url(base_url: str) -> str:
    return base_url.rstrip("/") + "/"


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
    ) -> CrushFTPSession:
        base = _normalize_base_url(base_url)
        url = urljoin(base, "WebInterface/function/")
        data = {
            "command": "login",
            "username": username,
            "password": password,
            "encoded": "true",
            "language": "en",
        }
        try:
            async with httpx.AsyncClient(
                timeout=_TIMEOUT,
                follow_redirects=False,
                verify=tls_verify,
            ) as client:
                response = await client.post(url, data=data)
        except httpx.TimeoutException as exc:
            raise RoboticLoginError("CrushFTP login timed out") from exc
        except httpx.RequestError as exc:
            raise RoboticLoginError("CrushFTP login network error") from exc

        if not _SUCCESS_RE.search(response.text or ""):
            raise RoboticLoginError("CrushFTP login rejected")

        cookies = _extract_session_cookies(response)
        if "CrushAuth" not in cookies:
            raise RoboticLoginError("CrushFTP login missing CrushAuth cookie")

        return CrushFTPSession(cookies=cookies, base_url=base, tls_verify=tls_verify)

    async def get_username(self, session: CrushFTPSession) -> str:
        url = urljoin(session.base_url, "WebInterface/function/")
        c2f = _c2f(session.cookies)
        if not c2f:
            raise RoboticLoginError("CrushFTP session missing auth token")
        data = {"command": "getUsername", "c2f": c2f}
        headers = {"Cookie": "; ".join(f"{k}={v}" for k, v in session.cookies.items())}
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
        headers = {"Cookie": "; ".join(f"{k}={v}" for k, v in session.cookies.items())}
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

_CRUSHFTP_USER_XML_TEMPLATE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<user type="properties">'
    "<username>{username}</username>"
    "<password>{password}</password>"
    "<root_dir>/</root_dir>"
    "<extra_vfs_linked_details></extra_vfs_linked_details>"
    "</user>"
)

_DEFAULT_SERVER_GROUP = "MainUsers"


def _crushftp_user_xml(credential: GeneratedCredential) -> str:
    """Minimal CrushFTP user XML for setUserItem — values XML-escaped."""
    return _CRUSHFTP_USER_XML_TEMPLATE.format(
        username=_xml_escape(credential.username),
        password=_xml_escape(credential.password),
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
        """Create user then optionally add to CrushFTP groups — Basic Auth per call."""
        admin = self._resolve_admin(app, settings)
        if isinstance(admin, ProvisioningResult):
            return admin
        username, password, base_url, server_group, tls_verify = admin

        try:
            user_result = await self._set_user_item(
                base_url=base_url,
                admin_username=username,
                admin_password=password,
                server_group=server_group,
                tls_verify=tls_verify,
                credential=credential,
            )
            if user_result.status != PROVISIONING_SUCCESS:
                return user_result

            names = [n.strip() for n in (group_names or []) if (n or "").strip()]
            if not names:
                return user_result

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

            detail = f"{user_result.detail}. Groupes: {'; '.join(group_parts)}"
            return ProvisioningResult(
                status=PROVISIONING_SUCCESS,
                detail=detail,
                credential_pushed=True,
                group_errors=tuple(group_errors),
            )
        finally:
            password = ""  # noqa: F841

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
            return False, "Timeout CrushFTP (setUserItem)", 0
        except httpx.RequestError:
            return False, "Erreur réseau CrushFTP (setUserItem)", 0
        # Never echo response.text — may contain user XML / passwords.
        if response.status_code in (401, 403):
            return (
                False,
                "Authentification admin CrushFTP refusée (Basic Auth)",
                response.status_code,
            )
        if not _SUCCESS_RE.search(response.text or ""):
            return (
                False,
                f"CrushFTP a rejeté setUserItem (HTTP {response.status_code})",
                response.status_code,
            )
        return True, "ok", response.status_code

    async def _set_user_item(
        self,
        *,
        base_url: str,
        admin_username: str,
        admin_password: str,
        server_group: str,
        tls_verify: bool,
        credential: GeneratedCredential,
    ) -> ProvisioningResult:
        ok, msg, status = await self._admin_post(
            base_url=base_url,
            admin_username=admin_username,
            admin_password=admin_password,
            tls_verify=tls_verify,
            data={
                "command": "setUserItem",
                "data_action": "new",
                "serverGroup": server_group,
                "username": credential.username,
                "user": _crushftp_user_xml(credential),
                "xmlItem": "user",
                "vfs_items": "",
            },
        )
        if not ok:
            if "Authentification admin" in msg:
                detail = msg
            elif msg.startswith("Timeout"):
                detail = "Timeout CrushFTP lors de la création du compte (setUserItem)"
            elif msg.startswith("Erreur réseau"):
                detail = "Erreur réseau CrushFTP lors de la création du compte"
            elif status:
                detail = (
                    "CrushFTP a rejeté la création du compte (setUserItem "
                    f"HTTP {status}) — compte déjà existant ou droits admin "
                    "insuffisants."
                )
            else:
                detail = msg
            return ProvisioningResult(status=PROVISIONING_FAILED, detail=detail)
        return ProvisioningResult(
            status=PROVISIONING_SUCCESS,
            detail="Compte CrushFTP créé (setUserItem)",
            credential_pushed=True,
        )

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
