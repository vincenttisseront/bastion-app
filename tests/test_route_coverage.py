"""Exhaustive route access-control coverage — fails CI on unprotected routes."""

from __future__ import annotations

from fastapi import Depends
from fastapi.routing import APIRoute

from app.main import app
from app.security.route_access import (
    PUBLIC_MOUNT_PREFIXES,
    PUBLIC_ROUTES_ALLOWLIST,
    SECURITY_DEPENDENCY_NAMES,
    iter_api_routes,
    route_is_protected,
    security_dependency_names,
)
from app.web.user_context import require_admin
from starlette.routing import Mount


def test_every_api_route_is_protected_or_allowlisted():
    uncovered: list[str] = []
    for route, extra in iter_api_routes(app):
        path = route.path
        if path in PUBLIC_ROUTES_ALLOWLIST:
            continue
        if route_is_protected(route, extra_depends=extra):
            continue
        methods = ",".join(sorted(m for m in (route.methods or []) if m != "HEAD"))
        uncovered.append(f"{methods} {path}")

    assert not uncovered, (
        "Routes without a recognized security dependency and not on the "
        "public allow-list (add a router/endpoint guard or justify in "
        f"PUBLIC_ROUTES_ALLOWLIST):\n  - " + "\n  - ".join(sorted(uncovered))
    )


def test_public_allowlist_entries_exist_as_routes():
    """Prevent stale allow-list entries that no longer match any route."""
    paths = {r.path for r, _ in iter_api_routes(app)}
    missing = sorted(set(PUBLIC_ROUTES_ALLOWLIST) - paths)
    assert not missing, f"Allow-list paths not found on app.routes: {missing}"


def test_static_mount_is_present_and_allowlisted():
    mounts = [r for r in app.routes if isinstance(r, Mount)]
    static = [m for m in mounts if m.path.rstrip("/") == "/static"]
    assert static, "expected /static mount"
    assert "/static" in PUBLIC_MOUNT_PREFIXES


def test_coverage_detects_missing_guard():
    """Meta-test: an unprotected route must fail the coverage check."""

    async def _orphan():
        return {"ok": True}

    orphan = APIRoute(path="/__coverage_orphan__", endpoint=_orphan, methods=["GET"])
    assert not route_is_protected(orphan)
    assert security_dependency_names(orphan) == set()

    async def _guarded(_admin=Depends(require_admin)):
        return {"ok": True}

    guarded = APIRoute(path="/__coverage_guarded__", endpoint=_guarded, methods=["GET"])
    assert "require_admin" in security_dependency_names(guarded)
    assert SECURITY_DEPENDENCY_NAMES
