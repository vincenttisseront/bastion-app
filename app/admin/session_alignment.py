"""SSO session alignment — oauth2-proxy cookie TTL vs Keycloak ssoSession* timeouts.

Target (bastion portal, 2026-07): cookie_expire=12h, cookie_refresh=1h,
Keycloak ssoSessionMaxLifespan ≤ 12h (43200s) so cookie_refresh cannot extend
the SSO session past the documented hard wall.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.admin.export import (
    core_static_realm_slugs,
    generate_oauth2_proxy_config,
)
from app.models import RealmConfig
from app.rbac.keycloak_admin import _admin_get, _issuer_parts
from app.sso_settings import Settings

# Must stay in sync with generate_oauth2_proxy_config().
TARGET_COOKIE_EXPIRE = "12h"
TARGET_COOKIE_REFRESH = "1h"
TARGET_COOKIE_EXPIRE_SECONDS = 12 * 3600


@dataclass
class RealmSessionAlignment:
    realm_slug: str
    realm_name: str
    enabled: bool
    cookie_expire_export: str | None
    cookie_refresh_export: str | None
    cookie_expire_generator: str
    cookie_refresh_generator: str
    export_path: str | None
    export_matches_generator: bool | None
    sso_session_max_lifespan_s: int | None
    sso_session_idle_timeout_s: int | None
    client_session_max_lifespan_s: int | None
    keycloak_error: str | None
    coherent: bool
    notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_COOKIE_RE = re.compile(
    r'^\s*cookie_(expire|refresh)\s*=\s*"([^"]+)"\s*$',
    re.MULTILINE,
)


def parse_oauth2_cookie_settings(cfg_text: str) -> dict[str, str | None]:
    found: dict[str, str | None] = {"cookie_expire": None, "cookie_refresh": None}
    for match in _COOKIE_RE.finditer(cfg_text or ""):
        found[f"cookie_{match.group(1)}"] = match.group(2)
    return found


def _duration_to_seconds(value: str | None) -> int | None:
    if not value:
        return None
    text = value.strip().lower()
    m = re.fullmatch(r"(\d+)\s*([smhd])?", text)
    if not m:
        return None
    n = int(m.group(1))
    unit = m.group(2) or "s"
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    return n * mult


def resolve_oauth2_export_path(realm: RealmConfig, settings: Settings) -> Path | None:
    exports = Path(settings.exports_dir)
    candidates = [
        exports / "oauth2" / realm.slug / "oauth2-proxy.cfg",
        exports / f"oauth2-proxy-{realm.slug}.conf",
    ]
    if realm.slug in core_static_realm_slugs(settings):
        # apply-infra-docker mirrors core export → docker/oauth2-core/oauth2-proxy.cfg
        candidates.extend(
            [
                Path("/tools/portal/docker/oauth2-core/oauth2-proxy.cfg"),
                Path("/var/lib/sso-portal/docker/oauth2-core/oauth2-proxy.cfg"),
            ]
        )
    for path in candidates:
        if path.is_file():
            return path
    return None


def _as_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


async def fetch_realm_session_timeouts(
    realm: RealmConfig, settings: Settings
) -> dict[str, Any]:
    """Read SSO session timeouts from Keycloak Admin API (realm representation)."""
    if not realm.keycloak_admin_client_id or not realm.keycloak_admin_client_secret_encrypted:
        raise ValueError(
            "Compte de service Keycloak non configuré — impossible de lire ssoSessionMaxLifespan"
        )
    _, realm_name = _issuer_parts(realm.issuer_url)
    # GET /admin/realms/{realm} — empty path suffix.
    resp = await _admin_get(realm, settings, "")
    if resp.status_code == 403:
        raise ValueError(
            "Le compte de service n'a pas le droit de lire la config du realm "
            "(realm-management:view-realm ou realm-admin requis)."
        )
    if resp.status_code >= 400:
        raise ValueError(f"Échec lecture realm Keycloak (HTTP {resp.status_code})")
    data = resp.json()
    if not isinstance(data, dict):
        raise ValueError("Réponse realm Keycloak invalide")
    return {
        "realm": data.get("realm") or realm_name,
        "ssoSessionMaxLifespan": data.get("ssoSessionMaxLifespan"),
        "ssoSessionIdleTimeout": data.get("ssoSessionIdleTimeout"),
        "clientSessionMaxLifespan": data.get("clientSessionMaxLifespan"),
        "clientSessionIdleTimeout": data.get("clientSessionIdleTimeout"),
        "accessTokenLifespan": data.get("accessTokenLifespan"),
    }


def _evaluate_coherent(
    *,
    cookie_expire: str | None,
    cookie_refresh: str | None,
    max_lifespan_s: int | None,
    export_matches: bool | None,
    keycloak_error: str | None,
) -> tuple[bool, list[str]]:
    notes: list[str] = []
    ok = True
    expire_s = _duration_to_seconds(cookie_expire)
    if cookie_expire != TARGET_COOKIE_EXPIRE:
        ok = False
        notes.append(f"cookie_expire={cookie_expire!r} (cible {TARGET_COOKIE_EXPIRE})")
    if cookie_refresh != TARGET_COOKIE_REFRESH:
        ok = False
        notes.append(f"cookie_refresh={cookie_refresh!r} (cible {TARGET_COOKIE_REFRESH})")
    if export_matches is False:
        ok = False
        notes.append("fichier export ≠ générateur actuel — relancer apply infra")
    if export_matches is None:
        notes.append(
            "fichier export introuvable — apply infra non fait ou chemin hors exports/"
        )
        ok = False
    if keycloak_error:
        ok = False
        notes.append(keycloak_error)
    elif max_lifespan_s is None:
        ok = False
        notes.append("ssoSessionMaxLifespan absent de la réponse Keycloak")
    elif max_lifespan_s > TARGET_COOKIE_EXPIRE_SECONDS:
        ok = False
        notes.append(
            f"ssoSessionMaxLifespan={max_lifespan_s}s > {TARGET_COOKIE_EXPIRE_SECONDS}s "
            f"— cookie_refresh peut prolonger la session au-delà de {TARGET_COOKIE_EXPIRE}"
        )
    elif expire_s is not None and max_lifespan_s < expire_s:
        notes.append(
            f"ssoSessionMaxLifespan={max_lifespan_s}s < cookie_expire "
            "— coupure Keycloak possible avant Max-Age cookie (acceptable si voulu)"
        )
    if ok and not notes:
        notes.append("conforme (cookie 12h/1h + Keycloak max ≤ 12h)")
    return ok, notes


async def build_session_alignment_report(
    db: Session, settings: Settings
) -> list[RealmSessionAlignment]:
    realms = (
        db.query(RealmConfig)
        .filter_by(enabled=True)
        .order_by(RealmConfig.slug)
        .all()
    )
    rows: list[RealmSessionAlignment] = []
    for realm in realms:
        gen_cfg = generate_oauth2_proxy_config(realm, settings)
        gen = parse_oauth2_cookie_settings(gen_cfg)
        export_path = resolve_oauth2_export_path(realm, settings)
        export_expire = export_refresh = None
        export_matches: bool | None = None
        if export_path is not None:
            exported = parse_oauth2_cookie_settings(
                export_path.read_text(encoding="utf-8")
            )
            export_expire = exported.get("cookie_expire")
            export_refresh = exported.get("cookie_refresh")
            export_matches = (
                export_expire == gen.get("cookie_expire")
                and export_refresh == gen.get("cookie_refresh")
            )

        max_ls = idle = client_max = None
        kc_error: str | None = None
        try:
            timeouts = await fetch_realm_session_timeouts(realm, settings)
            max_ls = _as_int(timeouts.get("ssoSessionMaxLifespan"))
            idle = _as_int(timeouts.get("ssoSessionIdleTimeout"))
            client_max = _as_int(timeouts.get("clientSessionMaxLifespan"))
        except ValueError as exc:
            kc_error = str(exc)
        except Exception as exc:
            kc_error = f"Keycloak injoignable: {exc}"

        cookie_for_eval = export_expire or gen.get("cookie_expire")
        refresh_for_eval = export_refresh or gen.get("cookie_refresh")
        coherent, notes = _evaluate_coherent(
            cookie_expire=cookie_for_eval,
            cookie_refresh=refresh_for_eval,
            max_lifespan_s=max_ls,
            export_matches=export_matches,
            keycloak_error=kc_error,
        )
        rows.append(
            RealmSessionAlignment(
                realm_slug=realm.slug,
                realm_name=realm.name or realm.slug,
                enabled=bool(realm.enabled),
                cookie_expire_export=export_expire,
                cookie_refresh_export=export_refresh,
                cookie_expire_generator=gen.get("cookie_expire") or TARGET_COOKIE_EXPIRE,
                cookie_refresh_generator=gen.get("cookie_refresh") or TARGET_COOKIE_REFRESH,
                export_path=str(export_path) if export_path else None,
                export_matches_generator=export_matches,
                sso_session_max_lifespan_s=max_ls,
                sso_session_idle_timeout_s=idle,
                client_session_max_lifespan_s=client_max,
                keycloak_error=kc_error,
                coherent=coherent,
                notes=notes,
            )
        )
    return rows
