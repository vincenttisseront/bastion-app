"""Idea 9 — dependency update review and draft PR.

Works only from the existing inventory (``DependencySnapshot``: declared /
installed / latest versions, runtime vs dev, direct vs transitive). The
inventory holds no vulnerability data, so the model is told not to cite CVE
identifiers; exposure comes from where a package sits (request path,
crypto/auth, build-only). Fallback: the raw list on /admin/dependencies.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.llm.insights import STATUS_INFO, generate_insight
from app.models import DependencySnapshot, utcnow
from app.sso_settings import Settings

# Packages on the request / auth / crypto path of the portal (exposure hint).
EXPOSED = frozenset({
    "fastapi", "starlette", "uvicorn", "httpx", "httpcore", "h11", "jinja2", "markupsafe",
    "pydantic", "pydantic-core", "python-multipart", "pyjwt", "cryptography", "webauthn",
    "pyotp", "bcrypt", "sqlalchemy", "psycopg", "sqlcipher3", "altcha", "pillow",
    "beautifulsoup4", "pyyaml", "email-validator", "google-re2", "reportlab",
})

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string", "maxLength": 1000},
        "priorities": {
            "type": "array",
            "maxItems": 20,
            "items": {
                "type": "object",
                "properties": {
                    "ecosystem": {"type": "string", "enum": ["python", "npm"]},
                    "name": {"type": "string", "maxLength": 120},
                    "from_version": {"type": "string", "maxLength": 40},
                    "to_version": {"type": "string", "maxLength": 40},
                    "priority": {"type": "string", "enum": ["haute", "moyenne", "basse"]},
                    "reason": {"type": "string", "maxLength": 300},
                },
                "required": ["ecosystem", "name", "from_version", "to_version", "priority", "reason"],
                "additionalProperties": False,
            },
        },
        "pr_title": {"type": "string", "maxLength": 120},
        "pr_body": {"type": "string", "maxLength": 4000},
    },
    "required": ["summary", "priorities", "pr_title", "pr_body"],
    "additionalProperties": False,
}

INSTRUCTIONS = (
    "Priorise les mises à jour de dépendances du portail Bastion (FastAPI, "
    "exposé sur Internet derrière nginx). Haute priorité : paquets exposés "
    "(chemin des requêtes, authentification, cryptographie) avec retard majeur ou "
    "mineur ; basse : outils de dev/build et transitifs. Les données ne "
    "contiennent AUCUNE information de vulnérabilité : ne cite aucun identifiant "
    "CVE et n'affirme pas qu'une version est vulnérable. Rédige ensuite un "
    "brouillon de pull request (titre + corps Markdown : liste des montées de "
    "version groupées, risques de rupture pour les versions majeures, tests à lancer)."
)


def _rows(db: Session) -> list[dict[str, Any]]:
    rows = (
        db.query(DependencySnapshot)
        .filter(DependencySnapshot.status.like("outdated_%"))
        .order_by(DependencySnapshot.ecosystem, DependencySnapshot.name)
        .all()
    )
    return [
        {
            "ecosystem": r.ecosystem,
            "name": r.name,
            "declared": r.declared_version,
            "current": r.current_version,
            "latest": r.latest_version,
            "retard": (r.status or "").replace("outdated_", ""),
            "type": r.dep_type,
            "direct": bool(r.is_direct),
            "expose": r.ecosystem == "python" and r.name.lower() in EXPOSED,
        }
        for r in rows
    ]


async def review_dependencies(
    db: Session, settings: Settings, *, requested_by: str | None = None
) -> Any:
    outdated = _rows(db)
    if not outdated:
        return None
    # Direct + exposed first so the cap never drops the important ones.
    outdated.sort(key=lambda d: (not d["expose"], not d["direct"], d["type"] != "runtime"))
    insight = await generate_insight(
        db,
        kind="dependency_review",
        subject_type="inventory",
        subject_id=utcnow().strftime("%Y-%m-%d"),
        instructions=INSTRUCTIONS,
        data={"paquets_en_retard": outdated[:120], "total_en_retard": len(outdated)},
        schema=SCHEMA,
        status=STATUS_INFO,
        requested_by=requested_by,
        settings=settings,
        think=True,
    )
    if insight is not None:
        known = {(d["ecosystem"], d["name"]) for d in outdated}
        payload = dict(insight.payload)
        payload["priorities"] = [
            p for p in payload.get("priorities") or [] if (p.get("ecosystem"), p.get("name")) in known
        ]
        insight.payload = payload
        db.commit()
    return insight
