"""Username derivation and display formatting for new Bastion accounts."""

from __future__ import annotations

import re
import unicodedata

_USERNAME_PART_RE = re.compile(r"[^a-z0-9-]+")
_USERNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")


def _fold_ascii(value: str) -> str:
    norm = unicodedata.normalize("NFKD", value or "")
    return "".join(c for c in norm if not unicodedata.combining(c))


def _username_part(raw: str) -> str:
    folded = _fold_ascii((raw or "").strip()).casefold()
    cleaned = _USERNAME_PART_RE.sub("", folded.replace(" ", "-"))
    return cleaned.strip("-")


def format_identity_first_name(raw: str) -> str:
    """Title-case per segment (spaces and hyphens): ``jean-pierre`` → ``Jean-Pierre``."""
    text = (raw or "").strip()
    if not text:
        return ""

    def _cap_segment(seg: str) -> str:
        seg = seg.strip()
        if not seg:
            return seg
        return seg[0].upper() + seg[1:].lower()

    out: list[str] = []
    for token in re.split(r"(\s+|-)", text):
        if token in {"", " ", "-"} or token.isspace():
            out.append(token if token != "" else " ")
            continue
        if token == "-":
            out.append("-")
            continue
        out.append(_cap_segment(token))
    return "".join(out).strip()


def format_identity_last_name(raw: str) -> str:
    return _fold_ascii((raw or "").strip()).upper()


def derive_username_from_names(first_name: str, last_name: str) -> str:
    """Build ``prenom.nom`` login id from identity fields (ASCII, lowercase)."""
    first = _username_part(first_name)
    last = _username_part(last_name)
    if not first or not last:
        raise ValueError("Prénom et nom sont requis pour générer l'identifiant.")
    username = f"{first}.{last}"
    if not is_valid_derived_username(username):
        raise ValueError(
            "Impossible de générer un identifiant valide — vérifiez prénom et nom "
            "(caractères autorisés : lettres, chiffres, tirets)."
        )
    return username


def is_valid_derived_username(username: str) -> bool:
    return bool(_USERNAME_RE.match((username or "").strip()))


def parse_identity_from_username(username: str) -> tuple[str, str] | None:
    """Best-effort prénom/nom from a ``prenom.nom`` login (portal display fallback)."""
    text = (username or "").strip()
    if not is_valid_derived_username(text):
        return None
    first_raw, last_raw = text.split(".", 1)
    return format_identity_first_name(first_raw), format_identity_last_name(last_raw)
