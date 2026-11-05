"""Upload size bound enforced by the app (A2) — not only by nginx."""

from __future__ import annotations

from fastapi import HTTPException, UploadFile

# Same ceiling as the portal vhost (``client_max_body_size 32M``).
MAX_UPLOAD_BYTES = 32 * 1024 * 1024


async def read_upload_bounded(
    upload: UploadFile, max_bytes: int = MAX_UPLOAD_BYTES
) -> bytes:
    """Read at most ``max_bytes`` (+1 to detect overflow) — 413 beyond."""
    data = await upload.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise HTTPException(status_code=413, detail="Fichier trop volumineux")
    return data
