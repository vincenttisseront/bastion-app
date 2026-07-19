"""App catalogue logos — store under PORTAL_DATA_DIR/uploads/app-logos/ (persistent volume)."""

from __future__ import annotations

import hashlib
import io
import logging
import re
from pathlib import Path

from PIL import Image, UnidentifiedImageError

from app.models import App
from app.sso_settings import Settings, get_settings

logger = logging.getLogger(__name__)

LOGO_SUBDIR = Path("uploads") / "app-logos"
MEDIA_URL_PREFIX = "/media/app-logos"
MAX_LOGO_BYTES = 512 * 1024
LOGO_SIZE = (128, 128)
_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9._-]+$")

# Content-sniffed formats only — SVG deliberately excluded (XSS risk).
_FORMAT_EXT = {
    "PNG": "png",
    "JPEG": "jpg",
    "WEBP": "webp",
}
_EXT_MEDIA_TYPE = {
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "webp": "image/webp",
}


class LogoValidationError(ValueError):
    """Raised when uploaded bytes are not an accepted image."""


def get_portal_data_dir(settings: Settings | None = None) -> Path:
    settings = settings or get_settings()
    return Path(settings.portal_data_dir)


def get_logo_dir(settings: Settings | None = None) -> Path:
    return get_portal_data_dir(settings) / LOGO_SUBDIR


def ensure_logo_dir(settings: Settings | None = None) -> Path:
    """Create logo directory and verify it is writable. Call at app startup."""
    settings = settings or get_settings()
    logo_dir = get_logo_dir(settings)
    try:
        logo_dir.mkdir(parents=True, exist_ok=True)
        probe = logo_dir / ".write_probe"
        probe.write_bytes(b"")
        probe.unlink(missing_ok=True)
    except OSError as exc:
        raise RuntimeError(
            f"Logo directory not writable: {logo_dir} "
            f"(set PORTAL_DATA_DIR to a persistent volume, e.g. /var/lib/sso-portal)"
        ) from exc
    logger.info("App logo storage ready: %s", logo_dir)
    return logo_dir


def _sniff_format(data: bytes) -> str:
    """Detect image format from magic bytes + Pillow; never trust the filename."""
    if len(data) < 12:
        raise LogoValidationError("Fichier trop court ou vide.")
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


def logo_filename(logo_path: str | None) -> str | None:
    """Extract safe filename from stored logo_path (supports legacy uploads/… paths)."""
    if not logo_path:
        return None
    name = Path(logo_path).name
    if not name or name in (".", "..") or not _SAFE_FILENAME.match(name):
        return None
    return name


def resolve_logo_file(
    logo_path: str | None, settings: Settings | None = None
) -> Path | None:
    """Absolute path on disk if the logo file exists; else None (tile_icon fallback)."""
    name = logo_filename(logo_path)
    if not name:
        return None
    full = (get_logo_dir(settings) / name).resolve()
    try:
        full.relative_to(get_logo_dir(settings).resolve())
    except ValueError:
        return None
    if not full.is_file():
        return None
    return full


def logo_public_url(app: App, settings: Settings | None = None) -> str | None:
    """Return /media/app-logos/{filename} if file exists; else None."""
    name = logo_filename(app.logo_path)
    if not name:
        return None
    if resolve_logo_file(app.logo_path, settings) is None:
        return None
    return f"{MEDIA_URL_PREFIX}/{name}"


def media_type_for_filename(filename: str) -> str:
    ext = Path(filename).suffix.lstrip(".").lower()
    return _EXT_MEDIA_TYPE.get(ext, "application/octet-stream")


def delete_logo_file(app: App, settings: Settings | None = None) -> None:
    path = resolve_logo_file(app.logo_path, settings)
    if path is not None and path.is_file():
        path.unlink()


def save_app_logo(app: App, raw: bytes, settings: Settings | None = None) -> str:
    """Write resized logo to data volume, replace previous file, return new logo_path."""
    settings = settings or get_settings()
    encoded, ext = process_logo_bytes(raw)
    logo_dir = ensure_logo_dir(settings)
    digest = hashlib.sha256(encoded).hexdigest()[:8]
    filename = f"{app.slug}-{digest}.{ext}"
    dest = logo_dir / filename

    old_path = app.logo_path
    dest.write_bytes(encoded)
    # Store filename only (served via /media/app-logos/{filename}).
    app.logo_path = filename

    if old_path and logo_filename(old_path) != filename:
        previous = resolve_logo_file(old_path, settings)
        if previous is not None and previous.is_file() and previous != dest:
            previous.unlink()
    return filename


def clear_app_logo(app: App, settings: Settings | None = None) -> None:
    delete_logo_file(app, settings)
    app.logo_path = None
