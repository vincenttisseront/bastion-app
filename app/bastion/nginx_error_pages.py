"""nginx ``error_page`` lines for generated vhosts (subdomain_proxy, public_proxy, …).

Pages live in the bastion-nginx image (``/var/www/nginx-errors``, generated from
``app/web/static_error_pages.py``) so nginx can serve them while bastion-app or
the app upstream is down.

Generated exports inline everything (no ``include`` of a new snippet): an export
written by a newer bastion-app must still pass ``nginx -t`` on an older
bastion-nginx image. Missing files there only degrade to nginx's default page.

Only nginx-generated errors are affected — every location keeps
``proxy_intercept_errors off``, so the app's own error pages (and the
``WWW-Authenticate`` of an upstream 401) reach the client untouched.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Literal

ErrorPageFormat = Literal["html", "json", "txt"]

ERROR_PAGES_URI_PREFIX = "/__bastion_errors/"
NGINX_ERRORS_ROOT = "/var/www/nginx-errors/"

# Served under their own status: one error_page line with ``$status``.
_STATUS_CODES: tuple[int, ...] = (400, 401, 403, 404, 405, 408, 413, 414, 429, 500, 502, 503, 504)
# nginx rewrites these to 400 before the URI is evaluated ($status would be 400).
_BAD_REQUEST_ALIASES: tuple[int, ...] = (494, 495, 496)

ERROR_PAGE_CODES: tuple[int, ...] = _STATUS_CODES + _BAD_REQUEST_ALIASES


def error_page_lines(
    fmt: ErrorPageFormat,
    *,
    indent: str = "    ",
    exclude: Iterable[int] = (),
) -> list[str]:
    """``error_page`` directives → static ``<code>.<fmt>`` pages.

    ``exclude``: codes the location already maps elsewhere (e.g. 401 → portal
    redirect). A location that declares any ``error_page`` stops inheriting the
    server{} list, so each such location needs its own copy.
    """
    skip = set(exclude)
    codes = [c for c in _STATUS_CODES if c not in skip]
    lines: list[str] = []
    if codes:
        joined = " ".join(str(c) for c in codes)
        lines.append(f"{indent}error_page {joined} {ERROR_PAGES_URI_PREFIX}$status.{fmt};")
    for code in _BAD_REQUEST_ALIASES:
        if code not in skip:
            lines.append(f"{indent}error_page {code} {ERROR_PAGES_URI_PREFIX}{code}.{fmt};")
    return lines


def error_pages_location_lines(
    *, indent: str = "    ", auth_request_off: bool = True
) -> list[str]:
    """Internal location serving the static pages (one per server{}).

    ``auth_request_off``: only for vhosts that use auth_request at all — the
    page must stay reachable even if one is ever set at server{} level.
    """
    inner = indent + "    "
    return [
        f"{indent}# Static branded error pages (bastion-nginx image) — no bastion-app needed.",
        f"{indent}location ^~ {ERROR_PAGES_URI_PREFIX} {{",
        f"{inner}internal;",
        f"{inner}alias {NGINX_ERRORS_ROOT};",
        *([f"{inner}auth_request off;"] if auth_request_off else []),
        f"{inner}modsecurity off;",
        f"{inner}recursive_error_pages off;",
        f"{inner}charset utf-8;",
        f"{inner}charset_types text/html text/plain application/json;",
        f'{inner}add_header Cache-Control "no-store" always;',
        f"{indent}}}",
    ]


def server_error_pages_lines(
    *, indent: str = "    ", auth_request_off: bool = True
) -> list[str]:
    """server{}-level HTML pages for nginx-generated errors + the serving location."""
    return [
        f"{indent}# Branded pages for errors raised by nginx itself (upstream down,",
        f"{indent}# body / header too large, auth backend failure). Upstream answers pass",
        f"{indent}# through untouched (proxy_intercept_errors off).",
        f"{indent}proxy_intercept_errors off;",
        *error_page_lines("html", indent=indent),
        *error_pages_location_lines(indent=indent, auth_request_off=auth_request_off),
    ]
