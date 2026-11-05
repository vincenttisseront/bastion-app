"""RFC 6266 / RFC 5987 ``Content-Disposition`` for user-supplied file names (S8)."""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import quote

_UNSAFE_ASCII = re.compile(r'[^A-Za-z0-9._ ()\[\]+,@-]')
_FALLBACK_NAME = "download.bin"


def _ascii_fallback(filename: str) -> str:
    """Latin-safe ``filename=`` value: no quote, backslash, ``;`` or control char."""
    folded = unicodedata.normalize("NFKD", filename).encode("ascii", "ignore").decode()
    cleaned = _UNSAFE_ASCII.sub("_", folded).strip(" .")
    return cleaned[:150] or _FALLBACK_NAME


def attachment_disposition(filename: str | None) -> str:
    """``attachment; filename="<ascii>"; filename*=UTF-8''<percent-encoded>``.

    The header stays pure ASCII (Starlette encodes headers latin-1: a ``€`` or
    CJK name raised UnicodeEncodeError → 500) and a ``"`` in the stored name can
    no longer inject extra parameters.
    """
    name = (filename or "").replace("\r", "").replace("\n", "").strip() or _FALLBACK_NAME
    name = name.replace("/", "_").replace("\\", "_")
    return (
        f'attachment; filename="{_ascii_fallback(name)}"; '
        f"filename*=UTF-8''{quote(name, safe='')}"
    )
