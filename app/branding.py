"""Public portal branding — singleton BrandingSettings (id=1)."""

from __future__ import annotations

import hashlib
import io
import logging
import re
from pathlib import Path
from typing import Any

from PIL import Image, UnidentifiedImageError
from sqlalchemy.orm import Session

from app.audit import log_action
from app.models import BrandingSettings, utcnow
from app.sso_settings import Settings, get_settings
from app.web.app_logos import LogoValidationError, get_portal_data_dir, process_logo_bytes

logger = logging.getLogger(__name__)

BRANDING_SETTINGS_ID = 1
BRANDING_SUBDIR = Path("uploads") / "branding"
MEDIA_URL_PREFIX = "/media/branding"
MAX_FAVICON_BYTES = 256 * 1024
_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9._-]+$")
_HEX_COLOR = re.compile(r"^#[0-9A-Fa-f]{6}$")

DEFAULTS: dict[str, Any] = {
    "company_name": "Portail sécurisé",
    "page_title": "Connexion",
    "accent_color": "#10b981",
    "default_theme": "dark",
    "welcome_text": None,
    "footer_text": None,
    "support_contact": None,
    "show_product_branding": False,
    "logo_path": None,
    "favicon_path": None,
}


def get_branding_dir(settings: Settings | None = None) -> Path:
    return get_portal_data_dir(settings) / BRANDING_SUBDIR


def ensure_branding_dir(settings: Settings | None = None) -> Path:
    branding_dir = get_branding_dir(settings)
    branding_dir.mkdir(parents=True, exist_ok=True)
    return branding_dir


def get_branding_settings_row(db: Session) -> BrandingSettings | None:
    return db.query(BrandingSettings).filter_by(id=BRANDING_SETTINGS_ID).first()


def ensure_branding_settings(db: Session) -> BrandingSettings:
    row = get_branding_settings_row(db)
    if row is not None:
        return row
    row = BrandingSettings(
        id=BRANDING_SETTINGS_ID,
        company_name=DEFAULTS["company_name"],
        page_title=DEFAULTS["page_title"],
        accent_color=DEFAULTS["accent_color"],
        default_theme=DEFAULTS["default_theme"],
        show_product_branding=False,
        updated_at=utcnow(),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def get_branding_settings(db: Session | None) -> dict[str, Any]:
    """Return a template-friendly branding dict (never falls back to « Bastion Pro »)."""
    if db is None:
        return _dict_from_defaults()
    try:
        row = ensure_branding_settings(db)
    except Exception:
        logger.exception("branding_settings unavailable — using neutral defaults")
        return _dict_from_defaults()
    return branding_to_dict(row)


def branding_to_dict(row: BrandingSettings) -> dict[str, Any]:
    theme = (row.default_theme or "dark").strip().lower()
    if theme not in {"dark", "light"}:
        theme = "dark"
    accent = (row.accent_color or DEFAULTS["accent_color"]).strip()
    if not _HEX_COLOR.match(accent):
        accent = DEFAULTS["accent_color"]
    logo = (row.logo_path or "").strip() or None
    favicon = (row.favicon_path or "").strip() or None
    return {
        "company_name": (row.company_name or DEFAULTS["company_name"]).strip()
        or DEFAULTS["company_name"],
        "page_title": (row.page_title or DEFAULTS["page_title"]).strip()
        or DEFAULTS["page_title"],
        "accent_color": accent,
        "default_theme": theme,
        "welcome_text": (row.welcome_text or "").strip() or None,
        "footer_text": (row.footer_text or "").strip() or None,
        "support_contact": (row.support_contact or "").strip() or None,
        "show_product_branding": bool(row.show_product_branding),
        "logo_path": logo,
        "favicon_path": favicon,
        "logo_url": f"{MEDIA_URL_PREFIX}/{logo}" if logo else None,
        "favicon_url": (
            f"{MEDIA_URL_PREFIX}/{favicon}"
            if favicon
            else "/static/img/generic-shield.svg"
        ),
    }


def _dict_from_defaults() -> dict[str, Any]:
    return {
        **DEFAULTS,
        "logo_url": None,
        "favicon_url": "/static/img/generic-shield.svg",
    }


def update_branding_settings(
    db: Session,
    *,
    actor: str,
    ip_address: str | None = None,
    company_name: str | None = None,
    page_title: str | None = None,
    accent_color: str | None = None,
    default_theme: str | None = None,
    welcome_text: str | None = None,
    footer_text: str | None = None,
    support_contact: str | None = None,
    show_product_branding: bool | None = None,
) -> BrandingSettings:
    row = ensure_branding_settings(db)
    before = branding_to_dict(row)
    changed: dict[str, Any] = {}

    def _set(field: str, value: Any) -> None:
        old = getattr(row, field)
        if old != value:
            setattr(row, field, value)
            changed[field] = {"previous": old, "new": value}

    if company_name is not None:
        name = company_name.strip() or DEFAULTS["company_name"]
        _set("company_name", name[:120])
    if page_title is not None:
        title = page_title.strip() or DEFAULTS["page_title"]
        _set("page_title", title[:120])
    if accent_color is not None:
        color = accent_color.strip()
        if not _HEX_COLOR.match(color):
            raise ValueError("Couleur d'accent invalide (attendu #RRGGBB)")
        _set("accent_color", color.lower())
    if default_theme is not None:
        theme = default_theme.strip().lower()
        if theme not in {"dark", "light"}:
            raise ValueError("Thème invalide (dark|light)")
        _set("default_theme", theme)
    if welcome_text is not None:
        text = welcome_text.strip() or None
        if text and len(text) > 500:
            raise ValueError("Texte de bienvenue trop long (500 car. max)")
        _set("welcome_text", text)
    if footer_text is not None:
        text = footer_text.strip() or None
        if text and len(text) > 2000:
            raise ValueError("Pied de page trop long (2000 car. max)")
        _set("footer_text", text)
    if support_contact is not None:
        contact = support_contact.strip() or None
        if contact and len(contact) > 200:
            raise ValueError("Contact support trop long")
        _set("support_contact", contact)
    if show_product_branding is not None:
        _set("show_product_branding", bool(show_product_branding))

    if not changed:
        return row

    row.updated_at = utcnow()
    row.updated_by = actor
    db.commit()
    db.refresh(row)
    log_action(
        db,
        actor=actor,
        action="branding_settings.updated",
        target="branding_settings",
        details={"fields": changed, "before_company": before.get("company_name")},
        ip_address=ip_address,
    )
    return row


def _safe_branding_filename(name: str | None) -> str | None:
    if not name or not _SAFE_FILENAME.match(name):
        return None
    if ".." in name or "/" in name or "\\" in name:
        return None
    return name


def resolve_branding_file(filename: str, settings: Settings | None = None) -> Path | None:
    safe = _safe_branding_filename(filename)
    if safe is None:
        return None
    path = (get_branding_dir(settings) / safe).resolve()
    root = get_branding_dir(settings).resolve()
    if not str(path).startswith(str(root)) or not path.is_file():
        return None
    return path


def media_type_for_branding_filename(filename: str) -> str:
    ext = filename.rsplit(".", 1)[-1].lower()
    return {
        "png": "image/png",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "webp": "image/webp",
        "ico": "image/x-icon",
    }.get(ext, "application/octet-stream")


def save_branding_logo(
    db: Session,
    data: bytes,
    *,
    actor: str,
    ip_address: str | None = None,
    settings: Settings | None = None,
) -> BrandingSettings:
    settings = settings or get_settings()
    encoded, ext = process_logo_bytes(data)
    digest = hashlib.sha256(encoded).hexdigest()[:16]
    filename = f"logo-{digest}.{ext}"
    ensure_branding_dir(settings)
    path = get_branding_dir(settings) / filename
    path.write_bytes(encoded)

    row = ensure_branding_settings(db)
    previous = row.logo_path
    if previous and previous != filename:
        old = resolve_branding_file(previous, settings)
        if old is not None:
            old.unlink(missing_ok=True)
    row.logo_path = filename
    row.updated_at = utcnow()
    row.updated_by = actor
    db.commit()
    db.refresh(row)
    log_action(
        db,
        actor=actor,
        action="branding_settings.logo_changed",
        target="branding_settings",
        details={"previous": previous, "new": filename},
        ip_address=ip_address,
    )
    return row


def process_favicon_bytes(data: bytes) -> tuple[bytes, str]:
    """Validate favicon: ICO or PNG, max 256 KiB, no SVG."""
    if len(data) > MAX_FAVICON_BYTES:
        raise LogoValidationError("Le favicon dépasse 256 Ko.")
    if len(data) < 4:
        raise LogoValidationError("Fichier trop court ou vide.")
    head = data.lstrip()[:256].lower()
    if head.startswith(b"<") or b"<svg" in head[:64]:
        raise LogoValidationError("Le format SVG n'est pas accepté.")

    # ICO magic: 00 00 01 00
    if data[:4] == b"\x00\x00\x01\x00":
        return data, "ico"

    try:
        with Image.open(io.BytesIO(data)) as img:
            fmt = (img.format or "").upper()
            img.verify()
    except UnidentifiedImageError as exc:
        raise LogoValidationError("Formats acceptés : PNG ou ICO.") from exc
    except OSError as exc:
        raise LogoValidationError("Image illisible ou corrompue.") from exc

    if fmt != "PNG":
        raise LogoValidationError("Formats acceptés : PNG ou ICO.")
    try:
        with Image.open(io.BytesIO(data)) as img:
            img = img.convert("RGBA")
            # Keep reasonably small for favicons
            if max(img.size) > 256:
                img.thumbnail((64, 64), Image.Resampling.LANCZOS)
            out = io.BytesIO()
            img.save(out, format="PNG", optimize=True)
            return out.getvalue(), "png"
    except OSError as exc:
        raise LogoValidationError("Impossible de traiter le favicon.") from exc


def save_branding_favicon(
    db: Session,
    data: bytes,
    *,
    actor: str,
    ip_address: str | None = None,
    settings: Settings | None = None,
) -> BrandingSettings:
    settings = settings or get_settings()
    encoded, ext = process_favicon_bytes(data)
    digest = hashlib.sha256(encoded).hexdigest()[:16]
    filename = f"favicon-{digest}.{ext}"
    ensure_branding_dir(settings)
    path = get_branding_dir(settings) / filename
    path.write_bytes(encoded)

    row = ensure_branding_settings(db)
    previous = row.favicon_path
    if previous and previous != filename:
        old = resolve_branding_file(previous, settings)
        if old is not None:
            old.unlink(missing_ok=True)
    row.favicon_path = filename
    row.updated_at = utcnow()
    row.updated_by = actor
    db.commit()
    db.refresh(row)
    log_action(
        db,
        actor=actor,
        action="branding_settings.favicon_changed",
        target="branding_settings",
        details={"previous": previous, "new": filename},
        ip_address=ip_address,
    )
    return row


def clear_branding_asset(
    db: Session,
    *,
    kind: str,
    actor: str,
    ip_address: str | None = None,
    settings: Settings | None = None,
) -> BrandingSettings:
    if kind not in {"logo", "favicon"}:
        raise ValueError("kind must be logo or favicon")
    settings = settings or get_settings()
    row = ensure_branding_settings(db)
    field = "logo_path" if kind == "logo" else "favicon_path"
    previous = getattr(row, field)
    if previous:
        old = resolve_branding_file(previous, settings)
        if old is not None:
            old.unlink(missing_ok=True)
    setattr(row, field, None)
    row.updated_at = utcnow()
    row.updated_by = actor
    db.commit()
    db.refresh(row)
    log_action(
        db,
        actor=actor,
        action=f"branding_settings.{kind}_cleared",
        target="branding_settings",
        details={"previous": previous},
        ip_address=ip_address,
    )
    return row
