"""Central allow-list and helpers for systematic route access coverage.

New routes must either inherit a recognized security dependency
(``require_admin``, ``require_user``, ``require_user_enriched``,
``require_internal_token``) via their router / endpoint, or be added here
with an explicit justification.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute, APIRouter
from starlette.routing import Mount

# Callables recognized as an access-control gate (by __name__).
SECURITY_DEPENDENCY_NAMES: frozenset[str] = frozenset(
    {
        "require_admin",
        "require_user",
        "require_user_enriched",
        "require_internal_token",
        "require_nginx_internal_token",
    }
)

# Intentionally public (or self-authenticating) routes. Keep short + justified.
# Keys are FastAPI path templates (as on APIRoute.path).
PUBLIC_ROUTES_ALLOWLIST: dict[str, str] = {
    "/": "root redirect to /apps",
    "/auth/login": "authentication entry — cannot require a session",
    "/auth/setup": "initial break-glass setup before any session exists",
    "/auth/sso-start": "OIDC start redirect — unauthenticated by design",
    "/breakglass": "break-glass login page (same family as /auth/login)",
    "/logout": "clears break-glass cookie; safe without session",
    "/health": "liveness probe, non-sensitive",
    "/api/health": "monitoring probe, non-sensitive",
    "/errors/403": "static error page",
    "/errors/404": "static error page",
    "/errors/500": "static error page",
    "/api/admin/breakglass/login": (
        "emergency access — public by design; password + jti anti-replay"
    ),
    "/api/admin/breakglass/logout": (
        "clears/revokes current break-glass cookie; usable without portal session"
    ),
    "/internal/oauth2-auth": (
        "nginx auth_request — validates session itself (portal, no AccessGrant)"
    ),
    "/internal/subdomain-auth": (
        "nginx auth_request — validates session + AccessGrant itself"
    ),
    "/internal/portal-rfc1918-bypass-auth": (
        "LAN recovery auth_request helper; validates client IP itself"
    ),
    "/.bastion/session-cookies": (
        "Target session cookie hop — HMAC cookie self-authenticates; host-only on app FQDN"
    ),
    "/api/internal/session-cookie-hop": (
        "alias of /.bastion/session-cookies for direct bastion calls / tests"
    ),
    "/.bastion/crush-session": (
        "legacy alias of session-cookies hop (CrushFTP-era path)"
    ),
    "/api/internal/crush-cookie-hop": (
        "legacy alias of session-cookie-hop"
    ),
    "/media/app-logos/{filename}": (
        "app tile logos — non-sensitive; path traversal already blocked"
    ),
}

# Mount prefixes treated as public static assets.
PUBLIC_MOUNT_PREFIXES: frozenset[str] = frozenset({"/static"})


def _walk_dependant(dependant: Dependant) -> Iterable[Callable[..., Any]]:
    if dependant.call is not None:
        yield dependant.call
    for child in dependant.dependencies:
        yield from _walk_dependant(child)


def _depends_callable(dep: Any) -> Callable[..., Any] | None:
    """Extract the callable from a ``Depends(...)`` or params.Depends object."""
    if callable(dep) and not hasattr(dep, "dependency"):
        return dep  # type: ignore[return-value]
    call = getattr(dep, "dependency", None)
    if call is None:
        call = getattr(dep, "call", None)
    return call if callable(call) else None


def security_names_from_depends(depends: Iterable[Any]) -> set[str]:
    names: set[str] = set()
    for dep in depends:
        call = _depends_callable(dep)
        if call is None:
            continue
        name = getattr(call, "__name__", None)
        if name in SECURITY_DEPENDENCY_NAMES:
            names.add(name)
    return names


def security_dependency_names(
    route: APIRoute, *, extra_depends: Iterable[Any] = ()
) -> set[str]:
    """Return ``__name__`` of security callables on the route (+ include extras)."""
    names: set[str] = set()
    for call in _walk_dependant(route.dependant):
        name = getattr(call, "__name__", None)
        if name in SECURITY_DEPENDENCY_NAMES:
            names.add(name)
    names |= security_names_from_depends(extra_depends)
    return names


def route_is_protected(
    route: APIRoute, *, extra_depends: Iterable[Any] = ()
) -> bool:
    return bool(security_dependency_names(route, extra_depends=extra_depends))


def _iter_router_api_routes(
    router: APIRouter, *, inherited_depends: list[Any]
) -> Iterable[tuple[APIRoute, list[Any]]]:
    router_depends = list(getattr(router, "dependencies", None) or [])
    combined = inherited_depends + router_depends
    for route in router.routes:
        if isinstance(route, APIRoute):
            yield route, combined
        elif isinstance(route, APIRouter):
            yield from _iter_router_api_routes(route, inherited_depends=combined)


def iter_api_routes(app: Any) -> list[tuple[APIRoute, list[Any]]]:
    """Yield ``(APIRoute, extra_Depends)`` including ``include_router`` deps.

    FastAPI 0.128+ stores included routers as ``_IncludedRouter`` wrappers
    rather than flattening ``APIRoute`` onto ``app.routes``.
    """
    out: list[tuple[APIRoute, list[Any]]] = []
    for entry in app.routes:
        if isinstance(entry, APIRoute):
            out.append((entry, []))
            continue
        if isinstance(entry, Mount):
            continue
        if type(entry).__name__ == "_IncludedRouter":
            ctx = entry.include_context
            inherited = list(getattr(ctx, "dependencies", None) or [])
            out.extend(
                _iter_router_api_routes(
                    entry.original_router, inherited_depends=inherited
                )
            )
            continue
        # Fallback: nested APIRouter directly on app.routes (older Starlette).
        if isinstance(entry, APIRouter):
            out.extend(_iter_router_api_routes(entry, inherited_depends=[]))
    return out
