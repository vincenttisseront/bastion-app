#!/usr/bin/env python3
"""Re-encrypt legacy plaintext FileVersion blobs (idempotent).

Usage:
  python -m scripts.reencrypt_file_blobs
  # or: python scripts/reencrypt_file_blobs.py
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

# Allow `python scripts/reencrypt_file_blobs.py` from repo root.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.files.blob_crypto import write_encrypted_blob
from app.files.service import resolve_storage_path
from app.models import FileVersion
from app.sso_settings import get_settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("reencrypt_file_blobs")


def reencrypt_versions(db: Session) -> int:
    settings = get_settings()
    count = 0
    rows = db.query(FileVersion).filter(FileVersion.encrypted.is_(False)).all()
    for version in rows:
        path = resolve_storage_path(version.storage_path, settings)
        if not path.is_file():
            logger.warning("missing blob version=%s path=%s", version.id, path)
            continue
        plaintext = path.read_bytes()
        tmp = path.with_suffix(path.suffix + ".reencrypting")
        write_encrypted_blob(tmp, plaintext, settings=settings)
        tmp.replace(path)
        version.encrypted = True
        count += 1
        logger.info("re-encrypted version=%s label=%s", version.id, version.version_label)
    db.commit()
    return count


def main() -> int:
    db = SessionLocal()
    try:
        n = reencrypt_versions(db)
        logger.info("done count=%s", n)
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
