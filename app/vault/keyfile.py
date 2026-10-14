"""Secret file helpers shared by the Fernet key store and SQLCipher."""

from __future__ import annotations

import os
from pathlib import Path


def ensure_private_dir(path: Path) -> None:
    """Create ``path`` as 0700. Raises OSError when it cannot be created."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass  # Windows / some bind mounts: permissions are managed outside the app.


def write_secret_file(path: Path, content: str) -> None:
    """Atomically write ``content`` to ``path``, never readable by others.

    The file is created 0600 (no window where the umask applies) and swapped in
    with ``os.replace`` so a crash cannot leave a truncated key behind.
    """
    tmp = path.with_name(path.name + ".tmp")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(content.strip() + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
