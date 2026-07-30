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
# The robotic driver above logs in AS the target user (impersonation). User
# management (`setUserItem`) requires an ADMIN session instead. The session
# mechanics (command=login → CrushAuth cookie → c2f token) are identical — only
# the credentials differ: the shared vault AppCredential of the CrushFTP app
# MUST be an admin account for provisioning to work (audit §2.3).

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


def _crushftp_user_xml(credential: GeneratedCredential) -> str:
    """Minimal CrushFTP user XML for setUserItem — values XML-escaped."""
    return _CRUSHFTP_USER_XML_TEMPLATE.format(
        username=_xml_escape(credential.username),
        password=_xml_escape(credential.password),
    )


class CrushFTPProvisioningDriver:
    """Create CrushFTP local users / manage group membership via admin API."""

    driver_name = "crushftp"
    server_group = "MainUsers"

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
        """Create user then optionally add to CrushFTP groups — one admin session."""
        opened = await self._open_admin_session(db=db, settings=settings, app=app)
        if isinstance(opened, ProvisioningResult):
            return opened
        session, robotic = opened
        try:
            user_result = await self._set_user_item(session, credential)
            if user_result.status != PROVISIONING_SUCCESS:
                return user_result

            names = [n.strip() for n in (group_names or []) if (n or "").strip()]
            if not names:
                return user_result

            group_parts: list[str] = []
            group_errors: list[str] = []
            for name in names:
                ok, msg = await self._set_group_membership(
                    session,
                    username=credential.username,
                    group_name=name,
                    data_action="add",
                )
                if ok:
                    group_parts.append(f"{name}=ok")
                else:
                    group_parts.append(f"{name}=échec ({msg})")
                    group_errors.append(f"{name}: {msg}")

            # User create stays "success" even if a group call fails — both
            # outcomes stay visible in detail (spec Étape 1.1).
            detail = f"{user_result.detail}. Groupes: {'; '.join(group_parts)}"
            return ProvisioningResult(
                status=PROVISIONING_SUCCESS,
                detail=detail,
                credential_pushed=True,
                group_errors=tuple(group_errors),
            )
        finally:
            await robotic.logout(session)

    async def add_user_to_group(
        self,
        *,
        db,
        settings,
        app,
        username: str,
        group_name: str,
        session: CrushFTPSession | None = None,
    ) -> ProvisioningResult:
        """Add username to a CrushFTP group (creates the group if missing)."""
        return await self._group_op(
            db=db,
            settings=settings,
            app=app,
            username=username,
            group_name=group_name,
            data_action="add",
            session=session,
        )

    async def remove_user_from_group(
        self,
        *,
        db,
        settings,
        app,
        username: str,
        group_name: str,
        session: CrushFTPSession | None = None,
    ) -> ProvisioningResult:
        """Remove username from a CrushFTP group."""
        return await self._group_op(
            db=db,
            settings=settings,
            app=app,
            username=username,
            group_name=group_name,
            data_action="delete",
            session=session,
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
        session: CrushFTPSession | None,
    ) -> ProvisioningResult:
        owned_session = False
        robotic: CrushFTPDriver | None = None
        if session is None:
            opened = await self._open_admin_session(db=db, settings=settings, app=app)
            if isinstance(opened, ProvisioningResult):
                return opened
            session, robotic = opened
            owned_session = True
        try:
            ok, msg = await self._set_group_membership(
                session,
                username=username,
                group_name=group_name,
                data_action=data_action,
            )
            if ok:
                verb = "ajouté au" if data_action == "add" else "retiré du"
                return ProvisioningResult(
                    status=PROVISIONING_SUCCESS,
                    detail=f"Utilisateur {verb} groupe CrushFTP « {group_name} »",
                )
            return ProvisioningResult(status=PROVISIONING_FAILED, detail=msg)
        finally:
            if owned_session and robotic is not None:
                await robotic.logout(session)

    async def _open_admin_session(
        self, *, db, settings, app
    ) -> tuple[CrushFTPSession, CrushFTPDriver] | ProvisioningResult:
        from app.bastion.upstream_tls import resolve_upstream_tls_verify
        from app.secret_crypto import decrypt_secret
        from app.vault.app_credential_service import get_app_credential

        admin_cred = get_app_credential(db, app.slug)
        if admin_cred is None or not admin_cred.is_active:
            return ProvisioningResult(
                status=PROVISIONING_FAILED,
                detail=(
                    "Credential admin CrushFTP absent du vault partagé de "
                    "l'application — configurez un compte admin CrushFTP dans le "
                    "vault avant de provisionner."
                ),
            )
        try:
            admin_password = decrypt_secret(admin_cred.encrypted_password, settings)
        except ValueError:
            return ProvisioningResult(
                status=PROVISIONING_FAILED,
                detail="Déchiffrement du credential admin CrushFTP impossible",
            )

        base_url = (app.upstream_url or "").strip()
        if not base_url:
            return ProvisioningResult(
                status=PROVISIONING_FAILED,
                detail="upstream_url non configurée pour cette application",
            )

        robotic = CrushFTPDriver()
        tls_verify = resolve_upstream_tls_verify(app)
        try:
            session = await robotic.login(
                base_url,
                admin_cred.robotic_username,
                admin_password,
                tls_verify=tls_verify,
            )
        except RoboticLoginError:
            return ProvisioningResult(
                status=PROVISIONING_FAILED,
                detail=(
                    "Authentification admin CrushFTP refusée — vérifiez le "
                    "credential admin du vault partagé."
                ),
            )
        finally:
            admin_password = ""  # noqa: F841
        return session, robotic

    async def _admin_function_post(
        self, session: CrushFTPSession, data: dict[str, str]
    ) -> tuple[bool, str, int]:
        """POST /WebInterface/function/ with session cookies. Never returns body."""
        url = urljoin(session.base_url, "WebInterface/function/")
        c2f = _c2f(session.cookies)
        if not c2f:
            return False, "Session admin CrushFTP sans token c2f", 0
        payload = {**data, "c2f": c2f}
        headers = {"Cookie": "; ".join(f"{k}={v}" for k, v in session.cookies.items())}
        try:
            async with httpx.AsyncClient(
                timeout=_TIMEOUT,
                follow_redirects=False,
                verify=bool(session.tls_verify),
            ) as client:
                response = await client.post(url, data=payload, headers=headers)
        except httpx.TimeoutException:
            return False, "Timeout CrushFTP (setUserItem)", 0
        except httpx.RequestError:
            return False, "Erreur réseau CrushFTP (setUserItem)", 0
        # Never echo response.text — may contain user XML / passwords.
        if not _SUCCESS_RE.search(response.text or ""):
            return (
                False,
                f"CrushFTP a rejeté setUserItem (HTTP {response.status_code})",
                response.status_code,
            )
        return True, "ok", response.status_code

    async def _set_user_item(
        self, session: CrushFTPSession, credential: GeneratedCredential
    ) -> ProvisioningResult:
        ok, msg, status = await self._admin_function_post(
            session,
            {
                "command": "setUserItem",
                "data_action": "new",
                "serverGroup": self.server_group,
                "username": credential.username,
                "user": _crushftp_user_xml(credential),
                "xmlItem": "user",
                "vfs_items": "",
            },
        )
        if not ok:
            detail = (
                "Timeout CrushFTP lors de la création du compte (setUserItem)"
                if msg.startswith("Timeout")
                else "Erreur réseau CrushFTP lors de la création du compte"
                if msg.startswith("Erreur réseau")
                else (
                    "CrushFTP a rejeté la création du compte (setUserItem "
                    f"HTTP {status}) — compte déjà existant ou droits admin "
                    "insuffisants."
                    if status
                    else msg
                )
            )
            return ProvisioningResult(status=PROVISIONING_FAILED, detail=detail)
        return ProvisioningResult(
            status=PROVISIONING_SUCCESS,
            detail="Compte CrushFTP créé (setUserItem)",
            credential_pushed=True,
        )

    async def _set_group_membership(
        self,
        session: CrushFTPSession,
        *,
        username: str,
        group_name: str,
        data_action: str,
    ) -> tuple[bool, str]:
        """xmlItem=groups — creates the group implicitly on first add (CrushFTP docs)."""
        ok, msg, status = await self._admin_function_post(
            session,
            {
                "command": "setUserItem",
                "xmlItem": "groups",
                "data_action": data_action,
                "serverGroup": self.server_group,
                "group_name": group_name,
                "usernames": username,
            },
        )
        if ok:
            return True, "ok"
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
