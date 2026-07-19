"""App catalogue logos — validate, resize, store under static/uploads/app-logos/."""

from __future__ import annotations

import hashlib
import io
from pathlib import Path

from PIL import Image, UnidentifiedImageError

from app.models import App

STATIC_DIR = Path(__file__).resolve().parents[1] / "static"
LOGO_SUBDIR = Path("uploads") / "app-logos"
LOGO_DIR = STATIC_DIR / LOGO_SUBDIR
MAX_LOGO_BYTES = 512 * 1024
LOGO_SIZE = (128, 128)

# Content-sniffed formats only — SVG deliberately excluded (XSS risk).
_FORMAT_EXT = {
    "PNG": "png",
    "JPEG": "jpg",
    "WEBP": "webp",
}


class LogoValidationError(ValueError):
    """Raised when uploaded bytes are not an accepted image."""


def ensure_logo_dir() -> Path:
    LOGO_DIR.mkdir(parents=True, exist_ok=True)
    return LOGO_DIR


def _sniff_format(data: bytes) -> str:
    """Detect image format from magic bytes + Pillow; never trust the filename."""
    if len(data) < 12:
        raise LogoValidationError("Fichier trop court ou vide.")
    # Reject obvious SVG / XML before Pillow (which may not open SVG anyway).
    head = data.lstrip()[:256].lower()
    if head.startswith(b"<") or b"<svg" in head[:64]:
        raise LogoValidationError("Le format SVG n'est pas accepté.")

    try:
        with Image.open(io.BytesIO(data)) as img:
            fmt = (img.format or "").upper()
            img.verify()
    except UnidentifiedImageError as exc:
        raise LogoValidationError("Type de fichier non reconnu.") from exc
    except OSError as exc:
        raise LogoValidationError("Image illisible ou corrompue.") from exc

    if fmt not in _FORMAT_EXT:
        raise LogoValidationError(
            "Formats acceptés : PNG, JPG/JPEG, WEBP (pas de SVG)."
        )
    # Re-open after verify() (Pillow requires a fresh handle).
    try:
        with Image.open(io.BytesIO(data)) as img:
            if img.format and img.format.upper() != fmt:
                raise LogoValidationError("Type de fichier incohérent.")
    except UnidentifiedImageError as exc:
        raise LogoValidationError("Type de fichier non reconnu.") from exc
    return fmt


def process_logo_bytes(data: bytes) -> tuple[bytes, str]:
    """Validate content, resize to 128×128, return (encoded_bytes, extension)."""
    if len(data) > MAX_LOGO_BYTES:
        raise LogoValidationError("Le logo dépasse 512 Ko.")
    fmt = _sniff_format(data)
    ext = _FORMAT_EXT[fmt]
    try:
        with Image.open(io.BytesIO(data)) as img:
            img = img.convert("RGBA" if fmt in ("PNG", "WEBP") else "RGB")
            img = img.resize(LOGO_SIZE, Image.Resampling.LANCZOS)
            out = io.BytesIO()
            save_kw: dict = {"format": fmt}
            if fmt == "JPEG":
                save_kw["quality"] = 90
                save_kw["optimize"] = True
            elif fmt == "WEBP":
                save_kw["quality"] = 90
            img.save(out, **save_kw)
            return out.getvalue(), ext
    except OSError as exc:
        raise LogoValidationError("Impossible de traiter l'image.") from exc


def _disk_path(logo_path: str) -> Path | None:
    """Resolve a stored relative logo_path; reject traversal / escape."""
    if not logo_path:
        return None
    rel = Path(logo_path)
    if rel.is_absolute() or ".." in rel.parts:
        return None
    full = (STATIC_DIR / rel).resolve()
    try:
        full.relative_to(LOGO_DIR.resolve())
    except ValueError:
        return None
    return full


def logo_public_url(app: App) -> str | None:
    """Return /static/... URL if logo_path points to an existing file; else None."""
    path = _disk_path(app.logo_path or "")
    if path is None or not path.is_file():
        return None
    return f"/static/{Path(app.logo_path).as_posix()}"


def delete_logo_file(app: App) -> None:
    path = _disk_path(app.logo_path or "")
    if path is not None and path.is_file():
        path.unlink()


def save_app_logo(app: App, raw: bytes) -> str:
    """Write resized logo to disk, replace previous file, return new logo_path."""
    encoded, ext = process_logo_bytes(raw)
    ensure_logo_dir()
    digest = hashlib.sha256(encoded).hexdigest()[:8]
    filename = f"{app.slug}-{digest}.{ext}"
    rel = (LOGO_SUBDIR / filename).as_posix()
    dest = LOGO_DIR / filename

    old_path = app.logo_path
    dest.write_bytes(encoded)
    app.logo_path = rel

    if old_path and old_path != rel:
        previous = _disk_path(old_path)
        if previous is not None and previous.is_file() and previous != dest:
            previous.unlink()
    return rel


def clear_app_logo(app: App) -> None:
    delete_logo_file(app)
    app.logo_path = None
