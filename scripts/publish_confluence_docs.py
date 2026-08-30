#!/usr/bin/env python3
"""Publish docs/wikijs Markdown pages to Confluence space DL (Bastion Pro).

Credentials: .secrets/atlassian.env (gitignored) — never commit the token.

  python scripts/publish_confluence_docs.py
  python scripts/publish_confluence_docs.py --dry-run
  python scripts/publish_confluence_docs.py --attachments-only

Pièces jointes : docs/wikijs/confluence-attachments.json
(configs externes nginx, Wazuh, ModSecurity, oauth2-proxy, ACME…).
"""

from __future__ import annotations

import argparse
import base64
import html
import json
import mimetypes
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs" / "wikijs"
SECRETS = ROOT / ".secrets" / "atlassian.env"
MAP_PATH = ROOT / "docs" / "wikijs" / "confluence-page-map.json"
ATTACHMENTS_PATH = ROOT / "docs" / "wikijs" / "confluence-attachments.json"

# Audience-oriented Confluence tree under space DL.
TREE: list[tuple[str, str | None, Path | None]] = [
    ("Bastion Pro", None, None),
    ("Bastion Pro — Accueil", "Bastion Pro", DOCS / "00-accueil.md"),
    ("Utilisateurs", "Bastion Pro", None),
    ("Utilisateurs — Accueil", "Utilisateurs", DOCS / "01-utilisateur" / "00-accueil.md"),
    ("Connexion", "Utilisateurs", DOCS / "01-utilisateur" / "01-01-connexion.md"),
    ("Mes applications", "Utilisateurs", DOCS / "01-utilisateur" / "01-02-mes-applications.md"),
    ("Lancer une application", "Utilisateurs", DOCS / "01-utilisateur" / "01-03-lancer-une-application.md"),
    ("Fichiers", "Utilisateurs", DOCS / "01-utilisateur" / "01-04-fichiers.md"),
    ("Administrateurs", "Bastion Pro", None),
    ("Parcours administrateur", "Administrateurs", DOCS / "04-administrateur" / "04-01-parcours-admin.md"),
    ("Apps, domaines et Apply", "Administrateurs", DOCS / "04-administrateur" / "04-02-apps-domaines-apply.md"),
    ("Sessions et logs", "Administrateurs", DOCS / "04-administrateur" / "04-03-sessions-logs.md"),
    ("ACME et certificats", "Administrateurs", DOCS / "04-administrateur" / "04-04-acme-certificats.md"),
    ("WAF ModSecurity", "Administrateurs", DOCS / "04-administrateur" / "04-05-waf-modsecurity.md"),
    ("SIEM — niveaux de criticité et CEF", "Administrateurs", DOCS / "04-administrateur" / "04-06-siem-niveaux-criticite.md"),
    ("Modes d’accès", "Administrateurs", DOCS / "02-fonctionnel" / "02-01-modes-acces.md"),
    ("Modes d’auth et vault", "Administrateurs", DOCS / "02-fonctionnel" / "02-02-modes-auth-vault.md"),
    ("Realms OIDC", "Administrateurs", DOCS / "02-fonctionnel" / "02-03-realms-oidc.md"),
    ("RBAC et grants", "Administrateurs", DOCS / "02-fonctionnel" / "02-04-rbac-grants.md"),
    ("Comptes et provisioning", "Administrateurs", DOCS / "02-fonctionnel" / "02-05-comptes-provisioning.md"),
    ("Break-glass", "Administrateurs", DOCS / "02-fonctionnel" / "02-06-break-glass.md"),
    ("Développeurs", "Bastion Pro", None),
    ("Architecture — vue d’ensemble", "Développeurs", DOCS / "03-architecture" / "03-01-vue-ensemble.md"),
    ("Chaîne d’authentification", "Développeurs", DOCS / "03-architecture" / "03-02-chaine-auth.md"),
    ("Routage nginx", "Développeurs", DOCS / "03-architecture" / "03-03-routage-nginx.md"),
    ("Données, vault et hot store", "Développeurs", DOCS / "03-architecture" / "03-04-donnees-vault-hotstore.md"),
    ("Environnement et secrets", "Développeurs", DOCS / "05-configuration" / "05-01-environnement-secrets.md"),
    ("Realms — source de vérité OIDC", "Développeurs", DOCS / "05-configuration" / "05-02-realms-oidc-source-verite.md"),
    ("Déploiement Docker", "Développeurs", DOCS / "05-configuration" / "05-03-deploiement-docker.md"),
    ("IP client et dépannage", "Développeurs", DOCS / "05-configuration" / "05-04-ip-client-troubleshooting.md"),
    ("Annexes techniques", "Développeurs", DOCS / "06-annexes" / "00-index.md"),
    ("Glossaire", "Bastion Pro", DOCS / "99-glossaire.md"),
]

ANNEX_GLOB = sorted((DOCS / "06-annexes").glob("06-*.md"))


def load_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    text = path.read_text(encoding="utf-8-sig")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip()
    return out


def md_to_storage(md: str) -> str:
    """Minimal Markdown → Confluence storage XHTML (good enough for product docs)."""
    lines = md.replace("\r\n", "\n").split("\n")
    out: list[str] = []
    i = 0
    in_code = False
    code_lang = ""
    code_buf: list[str] = []
    in_ul = False
    in_ol = False
    in_table = False
    table_rows: list[list[str]] = []

    def close_lists() -> None:
        nonlocal in_ul, in_ol
        if in_ul:
            out.append("</ul>")
            in_ul = False
        if in_ol:
            out.append("</ol>")
            in_ol = False

    def close_table() -> None:
        nonlocal in_table, table_rows
        if not in_table:
            return
        if table_rows:
            body = ["<table>"]
            header = table_rows[0]
            body.append(
                "<tr>" + "".join(f"<th>{inline(c.strip())}</th>" for c in header) + "</tr>"
            )
            start = 1
            if len(table_rows) > 1 and all(
                re.match(r"^:?-+:?$", (c.strip() or "-")) for c in table_rows[1]
            ):
                start = 2
            for row in table_rows[start:]:
                body.append(
                    "<tr>" + "".join(f"<td>{inline(c.strip())}</td>" for c in row) + "</tr>"
                )
            body.append("</table>")
            out.extend(body)
        in_table = False
        table_rows = []

    def inline(text: str) -> str:
        text = html.escape(text)
        text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
        text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
        text = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<em>\1</em>", text)
        text = re.sub(
            r"\[([^\]]+)\]\(([^)]+)\)",
            r'<a href="\2">\1</a>',
            text,
        )
        return text

    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            if not in_code:
                close_lists()
                close_table()
                in_code = True
                code_lang = line[3:].strip()
                code_buf = []
            else:
                code = html.escape("\n".join(code_buf))
                lang_attr = f' class="language-{html.escape(code_lang)}"' if code_lang else ""
                out.append(f"<ac:structured-macro ac:name=\"code\">")
                if code_lang:
                    out.append(
                        f'<ac:parameter ac:name="language">{html.escape(code_lang)}</ac:parameter>'
                    )
                out.append(f"<ac:plain-text-body><![CDATA[{chr(10).join(code_buf)}]]></ac:plain-text-body>")
                out.append("</ac:structured-macro>")
                in_code = False
            i += 1
            continue
        if in_code:
            code_buf.append(line)
            i += 1
            continue

        if "|" in line and line.strip().startswith("|"):
            close_lists()
            if not in_table:
                in_table = True
                table_rows = []
            cells = [c for c in line.strip().strip("|").split("|")]
            table_rows.append(cells)
            i += 1
            continue
        else:
            close_table()

        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        if m:
            close_lists()
            level = len(m.group(1))
            out.append(f"<h{level}>{inline(m.group(2))}</h{level}>")
            i += 1
            continue

        if re.match(r"^[-*]\s+", line):
            close_table()
            if in_ol:
                out.append("</ol>")
                in_ol = False
            if not in_ul:
                out.append("<ul>")
                in_ul = True
            out.append(f"<li>{inline(re.sub(r'^[-*]\s+', '', line))}</li>")
            i += 1
            continue

        if re.match(r"^\d+\.\s+", line):
            close_table()
            if in_ul:
                out.append("</ul>")
                in_ul = False
            if not in_ol:
                out.append("<ol>")
                in_ol = True
            out.append(f"<li>{inline(re.sub(r'^\d+\.\s+', '', line))}</li>")
            i += 1
            continue

        if not line.strip():
            close_lists()
            i += 1
            continue

        close_lists()
        out.append(f"<p>{inline(line)}</p>")
        i += 1

    close_lists()
    close_table()
    footer = (
        "<hr/><p><em>Source : dépôt bastion-app — "
        f"<code>docs/wikijs/</code> — publiée automatiquement.</em></p>"
    )
    return "\n".join(out) + footer


def attachments_storage_html(files: list[Path]) -> str:
    """Visible download links + attachments macro (Cloud hides PJ hors corps de page)."""
    items: list[str] = []
    for path in files:
        if not path.is_file():
            continue
        name = html.escape(path.name)
        rel = html.escape(str(path.relative_to(ROOT)).replace("\\", "/"))
        items.append(
            "<li>"
            f'<ac:link><ri:attachment ri:filename="{name}" /></ac:link>'
            f" — <code>{rel}</code>"
            "</li>"
        )
    if not items:
        return ""
    return (
        "<h2>Pièces jointes (configs dépôt)</h2>"
        "<p>Télécharger les fichiers de configuration versionnés liés à cette page :</p>"
        f"<ul>{''.join(items)}</ul>"
        '<ac:structured-macro ac:name="attachments">'
        '<ac:parameter ac:name="upload">false</ac:parameter>'
        '<ac:parameter ac:name="old">false</ac:parameter>'
        '<ac:parameter ac:name="patterns">*</ac:parameter>'
        "</ac:structured-macro>"
    )


def inject_attachments_section(storage: str, files: list[Path]) -> str:
    block = attachments_storage_html(files)
    if not block:
        return storage
    marker = "<hr/><p><em>Source :"
    if marker in storage:
        return storage.replace(marker, block + marker, 1)
    return storage + block


_MOJIBAKE_MARKERS = (
    "Ã©",
    "Ã¨",
    "Ã ",
    "Ã´",
    "Ã®",
    "Ã§",
    "â€",
    "Ã‰",
    "Ã€",
    "â€™",
    "â†",
    "Â«",
    "Â»",
)


def has_mojibake(text: str) -> bool:
    return any(m in text for m in _MOJIBAKE_MARKERS)


def read_md(path: Path) -> str:
    """Read Markdown as UTF-8 (BOM-safe). Refuse double-encoded content."""
    text = path.read_text(encoding="utf-8-sig")
    if has_mojibake(text):
        raise SystemExit(
            f"Mojibake UTF-8 détecté dans {path} — corriger le fichier avant publication "
            "(souvent copie double-encodée ; restaurer depuis la source docs/)."
        )
    return text


class Confluence:
    def __init__(self, site: str, email: str, token: str, space_key: str):
        self.base = site.rstrip("/") + "/wiki"
        self.space_key = space_key
        raw = f"{email}:{token}".encode()
        self.auth = "Basic " + base64.b64encode(raw).decode()

    def _req(self, method: str, path: str, body: dict | None = None) -> dict:
        url = self.base + path
        data = None
        headers = {
            "Authorization": self.auth,
            "Accept": "application/json",
        }
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json; charset=utf-8"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            err = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"{method} {path} → {e.code}: {err[:800]}") from e

    def get_page(self, page_id: str) -> dict:
        return self._req(
            "GET",
            f"/rest/api/content/{page_id}?expand=version,ancestors",
        )

    def find_page(self, title: str) -> dict | None:
        q = urllib.parse.urlencode(
            {"title": title, "spaceKey": self.space_key, "expand": "version,ancestors"}
        )
        data = self._req("GET", f"/rest/api/content?{q}")
        results = data.get("results") or []
        return results[0] if results else None

    def create_page(self, title: str, storage: str, parent_id: str | None) -> dict:
        body: dict = {
            "type": "page",
            "title": title,
            "space": {"key": self.space_key},
            "body": {"storage": {"value": storage, "representation": "storage"}},
        }
        if parent_id:
            body["ancestors"] = [{"id": parent_id}]
        return self._req("POST", "/rest/api/content", body)

    def update_page(self, page_id: str, title: str, storage: str, version: int) -> dict:
        body = {
            "id": page_id,
            "type": "page",
            "title": title,
            "space": {"key": self.space_key},
            "body": {"storage": {"value": storage, "representation": "storage"}},
            "version": {"number": version + 1, "message": "docs/wikijs sync (utf-8)"},
        }
        return self._req("PUT", f"/rest/api/content/{page_id}", body)

    def delete_page(self, page_id: str) -> None:
        self._req("DELETE", f"/rest/api/content/{page_id}")

    def list_attachments(self, page_id: str, filename: str | None = None) -> list[dict]:
        q: dict[str, str] = {"limit": "50", "expand": "version"}
        if filename:
            q["filename"] = filename
        data = self._req(
            "GET",
            f"/rest/api/content/{page_id}/child/attachment?{urllib.parse.urlencode(q)}",
        )
        return list(data.get("results") or [])

    def _multipart_post(
        self,
        path: str,
        *,
        file_path: Path,
        fields: dict[str, str] | None = None,
    ) -> dict:
        """POST multipart/form-data (Confluence attachment upload)."""
        boundary = f"----BastionBoundary{uuid4().hex}"
        filename = file_path.name
        ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        payload = file_path.read_bytes()
        chunks: list[bytes] = []
        for key, value in (fields or {}).items():
            chunks.append(f"--{boundary}\r\n".encode())
            chunks.append(
                f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode()
            )
            chunks.append(value.encode("utf-8"))
            chunks.append(b"\r\n")
        chunks.append(f"--{boundary}\r\n".encode())
        chunks.append(
            (
                f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                f"Content-Type: {ctype}\r\n\r\n"
            ).encode()
        )
        chunks.append(payload)
        chunks.append(b"\r\n")
        chunks.append(f"--{boundary}--\r\n".encode())
        body = b"".join(chunks)
        url = self.base + path
        headers = {
            "Authorization": self.auth,
            "Accept": "application/json",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "X-Atlassian-Token": "nocheck",
        }
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            err = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"POST {path} → {e.code}: {err[:800]}") from e

    def upload_attachment(
        self,
        page_id: str,
        file_path: Path,
        *,
        comment: str = "",
    ) -> dict:
        """Create or replace an attachment (same filename → new version)."""
        existing = self.list_attachments(page_id, filename=file_path.name)
        fields = {"minorEdit": "true"}
        if comment:
            fields["comment"] = comment
        if existing:
            att_id = str(existing[0]["id"])
            return self._multipart_post(
                f"/rest/api/content/{page_id}/child/attachment/{att_id}/data",
                file_path=file_path,
                fields=fields,
            )
        return self._multipart_post(
            f"/rest/api/content/{page_id}/child/attachment",
            file_path=file_path,
            fields=fields,
        )

    def upsert(
        self,
        title: str,
        storage: str,
        parent_id: str | None,
        *,
        known_id: str | None = None,
    ) -> dict:
        if known_id:
            try:
                existing = self.get_page(known_id)
                return self.update_page(
                    known_id,
                    title,
                    storage,
                    int(existing["version"]["number"]),
                )
            except RuntimeError as exc:
                if "404" not in str(exc):
                    raise
        existing = self.find_page(title)
        if existing:
            return self.update_page(
                existing["id"],
                title,
                storage,
                int(existing["version"]["number"]),
            )
        return self.create_page(title, storage, parent_id)


def stub_html(title: str, blurb: str) -> str:
    return (
        f"<h1>{html.escape(title)}</h1>"
        f"<p>{html.escape(blurb)}</p>"
        "<p><em>Section Bastion Pro — documentation produit.</em></p>"
    )


def build_tree() -> list[tuple[str, str | None, Path | None]]:
    items = list(TREE)
    # Insert annex pages under Annexes techniques
    annex_parent = "Annexes techniques"
    for path in ANNEX_GLOB:
        title = path.stem.replace("-", " ")
        text = read_md(path)
        m = re.search(r"^#\s+(.+)$", text, re.M)
        page_title = f"Annexe — {m.group(1).strip()}" if m else f"Annexe — {title}"
        items.append((page_title, annex_parent, path))
    return items


def _index_map_by_source(page_ids: dict) -> dict[str, str]:
    """source relative path → confluence page id."""
    by_src: dict[str, str] = {}
    for _title, meta in page_ids.items():
        if not isinstance(meta, dict):
            continue
        src = meta.get("source")
        pid = meta.get("id")
        if src and pid:
            by_src[str(src).replace("\\", "/")] = str(pid)
    return by_src


def load_attachments_map() -> dict[str, list[Path]]:
    """Markdown source path → list of absolute file paths to attach."""
    if not ATTACHMENTS_PATH.is_file():
        return {}
    raw = json.loads(ATTACHMENTS_PATH.read_text(encoding="utf-8"))
    out: dict[str, list[Path]] = {}
    for src, files in raw.items():
        if src.startswith("_") or not isinstance(files, list):
            continue
        key = str(src).replace("\\", "/")
        paths: list[Path] = []
        for rel in files:
            p = ROOT / str(rel).replace("\\", "/")
            paths.append(p)
        out[key] = paths
    return out


def sync_attachments(
    cf: Confluence,
    page_id: str,
    files: list[Path],
    *,
    dry_run: bool = False,
) -> int:
    """Upload/replace attachments; return count of successful uploads."""
    ok = 0
    for path in files:
        if not path.is_file():
            print(f"  ATTACH SKIP missing {path.relative_to(ROOT)}")
            continue
        rel = str(path.relative_to(ROOT)).replace("\\", "/")
        print(f"  {'DRY ' if dry_run else ''}ATTACH {path.name} <- {rel}")
        if dry_run:
            ok += 1
            continue
        cf.upload_attachment(
            page_id,
            path,
            comment=f"bastion-app sync: {rel}",
        )
        ok += 1
        time.sleep(0.25)
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument(
        "--attachments-only",
        action="store_true",
        help="Ne republier que les pièces jointes (utilise confluence-page-map.json).",
    )
    args = ap.parse_args()

    if not SECRETS.is_file():
        print(f"Missing {SECRETS}", file=sys.stderr)
        return 1
    env = load_env(SECRETS)
    site = env["ATLASSIAN_SITE"]
    email = env["ATLASSIAN_EMAIL"]
    token = env["ATLASSIAN_API_TOKEN"]
    space = env.get("CONFLUENCE_SPACE_KEY", "DL")

    cf = Confluence(site, email, token, space)
    page_ids: dict = {}
    if MAP_PATH.is_file():
        page_ids = json.loads(MAP_PATH.read_text(encoding="utf-8"))
    by_source = _index_map_by_source(page_ids)
    attachments_by_source = load_attachments_map()

    if args.attachments_only:
        attached = 0
        for src, files in attachments_by_source.items():
            pid = by_source.get(src)
            if not pid:
                print(f"ATTACH SKIP no page id for {src}")
                continue
            print(f"{'DRY ' if args.dry_run else ''}ATTACHMENTS {src} → page {pid}")
            attached += sync_attachments(cf, pid, files, dry_run=args.dry_run)
            md_path = ROOT / src
            if md_path.is_file() and not args.dry_run:
                page = cf.get_page(pid)
                storage = inject_attachments_section(md_to_storage(read_md(md_path)), files)
                cf.update_page(
                    pid,
                    page["title"],
                    storage,
                    int(page["version"]["number"]),
                )
                print(f"  EMBED links on page {pid}")
                time.sleep(0.25)
        print(f"\nAttachments synced: {attached}")
        return 0

    title_to_id: dict[str, str] = {}
    # Keep known section ids from previous map (title exact match, no mojibake keys)
    for title, meta in page_ids.items():
        if isinstance(meta, dict) and meta.get("id") and not has_mojibake(title):
            title_to_id[title] = str(meta["id"])

    published: list[str] = []
    new_map: dict = {}
    attached_total = 0

    for title, parent_title, path in build_tree():
        src_rel = None
        if path is not None and not path.is_file():
            print(f"SKIP missing {path}")
            continue
        if has_mojibake(title):
            raise SystemExit(f"Titre mojibake refusé: {title!r}")
        if path is None:
            storage = stub_html(
                title,
                {
                    "Bastion Pro": "Documentation produit Bastion Pro (utilisateurs, administrateurs, développeurs).",
                    "Utilisateurs": "Guides pour les utilisateurs du portail SSO.",
                    "Administrateurs": "Exploitation, RBAC, apps, WAF, realms.",
                    "Développeurs": "Architecture, déploiement, configuration et annexes techniques.",
                }.get(title, "Section documentation Bastion Pro."),
            )
            src_rel = None
            known_id = title_to_id.get(title)
        else:
            md = read_md(path)
            storage = md_to_storage(md)
            src_rel = str(path.relative_to(ROOT)).replace("\\", "/")
            known_id = by_source.get(src_rel) or title_to_id.get(title)
            if src_rel and src_rel in attachments_by_source:
                storage = inject_attachments_section(
                    storage, attachments_by_source[src_rel]
                )

        parent_id = title_to_id.get(parent_title) if parent_title else None
        if parent_title and not parent_id and not args.dry_run:
            print(f"ERROR: parent missing for {title!r}: {parent_title!r}", file=sys.stderr)
            return 1

        print(f"{'DRY ' if args.dry_run else ''}UPSERT {title}" + (f" <- {path.name}" if path else ""))
        if args.dry_run:
            title_to_id[title] = known_id or f"dry-{len(title_to_id)}"
            if src_rel and src_rel in attachments_by_source:
                sync_attachments(
                    cf,
                    title_to_id[title],
                    attachments_by_source[src_rel],
                    dry_run=True,
                )
            continue

        # Upload attachments first so ri:attachment links resolve in the body.
        if (
            known_id
            and src_rel
            and src_rel in attachments_by_source
        ):
            attached_total += sync_attachments(
                cf, known_id, attachments_by_source[src_rel], dry_run=False
            )

        page = cf.upsert(title, storage, parent_id, known_id=known_id)
        pid = str(page["id"])
        title_to_id[title] = pid
        webui = page.get("_links", {}).get("webui", f"/spaces/{space}/pages/{pid}")
        new_map[title] = {
            "id": pid,
            "url": site.rstrip("/") + "/wiki" + webui,
            "source": src_rel,
        }
        published.append(title)
        if (
            src_rel
            and src_rel in attachments_by_source
            and (not known_id or known_id != pid)
        ):
            # New page: attach after create, then refresh body with links.
            attached_total += sync_attachments(
                cf, pid, attachments_by_source[src_rel], dry_run=False
            )
            page = cf.upsert(
                title,
                storage,
                parent_id,
                known_id=pid,
            )
        time.sleep(0.35)

    if not args.dry_run:
        MAP_PATH.write_text(
            json.dumps(new_map, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(f"\nWrote {MAP_PATH} ({len(published)} pages, {attached_total} attachments)")
        root = new_map.get("Bastion Pro") or {}
        if isinstance(root, dict) and root.get("url"):
            print(f"Root: {root['url']}")
        else:
            print(f"Space: {site}/wiki/spaces/{space}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
