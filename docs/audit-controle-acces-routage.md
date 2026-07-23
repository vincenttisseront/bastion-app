# Audit — Contrôle d'accès systématique sur toutes les routes (suivi)

> Audit du 2026-07-23 (`audit-controle-acces-routage`), complété par vérification code
> réelle. Correctif livré le même jour : gaps §2 + refactor routeurs + test de couverture.

## Décisions retenues

| # | Point | Décision |
|---|---|---|
| 1 | `/dashboard` | **Admin only** (`require_admin`) — le portail générique est `/apps` |
| 2 | `GET /api/apps*` | Authentifié (`require_user_enriched`), pas public |
| 3 | `GET /audit`, `GET /api/metrics` | **Admin only** |
| 4 | Mécanisme | Dependencies au niveau `APIRouter` + allow-list publique courte |
| 5 | Middleware global | Écarté — matching fragile vs routing FastAPI natif |

## Gaps confirmés avant correctif

| Route | Avant | Après |
|---|---|---|
| `GET /api/apps`, `GET /api/apps/{slug}` | Aucune auth | `require_user_enriched` (router) |
| `GET /audit` | `require_user` | `require_admin` (router) |
| `GET /api/metrics` | `require_user` | `require_admin` (router) |

---

## Clôture — implémentation réelle (2026-07-23)

| Élément | Emplacement |
|---------|-------------|
| Allow-list + helpers | `app/security/route_access.py` |
| Test exhaustif CI | `tests/test_route_coverage.py` |
| Tests des 3 gaps | `tests/test_route_access_gaps.py` |
| Routeurs groupés | `pages` (public / user / admin), `portal`, `sessions`, `services` (read/write), `breakglass` (public / admin), vault/realms/infra (`require_internal_token`), modules admin homogènes |
| Breakglass admin | `admin_router` + `include_router(..., dependencies=[Depends(require_admin)])` (évite import circulaire) |
| Commentaire `/dashboard` | `app/auth.py` — précise `/apps` vs `/dashboard` admin |

**Comportement** :

1. Toute nouvelle route sur un routeur gardé hérite de la dependency.
2. Toute route hors allow-list sans `require_admin` / `require_user` / `require_user_enriched` / `require_internal_token` **fait échouer la CI**.
3. Seuls changements de comportement utilisateur : les 3 gaps du tableau ci-dessus (+ redirect 403→`/apps` déjà en place pour pages HTML admin).

**Prod** :

- [ ] Déployer ; vérifier qu’un user non-admin ne lit plus `/api/apps` ni `/audit` / `/api/metrics`
- [ ] Confirmer que le catalogue UI `/apps` et les mutations token interne restent OK
