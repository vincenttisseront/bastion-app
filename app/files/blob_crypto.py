"""Chunked Fernet encryption for catalogue file blobs at rest."""

from __future__ import annotations

import struct
from collections.abc import Iterator
from pathlib import Path

from app.secret_crypto import get_fernet
from app.sso_settings import Settings, get_settings

DEFAULT_CHUNK_SIZE = 1 * 1024 * 1024  # 1 MiB plaintext per Fernet block


def _fernet(settings: Settings | None = None):
    settings = settings or get_settings()
    return get_fernet(settings)


def chunk_size(settings: Settings | None = None) -> int:
    settings = settings or get_settings()
    raw = getattr(settings, "file_encryption_chunk_size", None)
    try:
        value = int(raw) if raw is not None else DEFAULT_CHUNK_SIZE
    except (TypeError, ValueError):
        value = DEFAULT_CHUNK_SIZE
    return max(64 * 1024, value)


def write_encrypted_blob(
    path: Path,
    data: bytes,
    *,
    settings: Settings | None = None,
) -> None:
    """Write plaintext bytes as length-prefixed Fernet chunks."""
    settings = settings or get_settings()
    f = _fernet(settings)
    size = chunk_size(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as out:
        offset = 0
        while offset < len(data):
            block = data[offset : offset + size]
            token = f.encrypt(block)
            out.write(struct.pack(">I", len(token)))
            out.write(token)
            offset += size


def iter_decrypted_chunks(
    path: Path,
    *,
    settings: Settings | None = None,
) -> Iterator[bytes]:
    """Yield plaintext chunks from an encrypted on-disk blob."""
    settings = settings or get_settings()
    f = _fernet(settings)
    with path.open("rb") as fh:
        while True:
            header = fh.read(4)
            if not header:
                break
            if len(header) < 4:
                raise ValueError("Truncated encrypted blob header")
            (token_len,) = struct.unpack(">I", header)
            token = fh.read(token_len)
            if len(token) < token_len:
                raise ValueError("Truncated encrypted blob token")
            yield f.decrypt(token)


def write_plaintext_blob(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
