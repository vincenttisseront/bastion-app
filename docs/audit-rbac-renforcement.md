# Audit RBAC — Renforcement (priorité haute)

> Date initiale d’audit documentaire : 2026-07-23  
> Correctif priorité haute livré : **2026-07-23**  
> Périmètre de cette itération : items §2.1, §2.2, §2.4 uniquement.  
> Hors scope : grants à durée limitée, revue périodique, rôles au-delà de
> `portal_admin`, liste par défaut des utilisateurs.

---

## 1. Synthèse

| # | Écart | Statut | Décision |
|---|--------|--------|----------|
| 1 | Break-glass vs `AccessGrant` | **corrigé** | Accès total sans grant (secours IdP) |
| 2 | Legacy `AppGroup` | **corrigé** (fusion livrée) | Supprimé — bascule directe vers `AccessGrant` |
| 4 | Auto-retrait `portal_admin` | **corrigé** | Auto-retrait bloqué + audit dédié |

---

## 2. Items

### 2.1 Break-glass vs AccessGrant — **corrigé** (2026-07-23)

**Constat code (état avant / après ce correctif) :**  
`/internal/subdomain-auth` (`app/subdomain/subdomain_auth.py`) traitait déjà le cookie
break-glass **après** la branche OIDC et renvoyait 200 **sans** appeler
`user_can_launch_application` / `get_effective_apps_for_user`.  
`/internal/oauth2-auth` (portail) n’applique volontairement **aucun** AccessGrant
applicatif (launcher `/apps` pour tout utilisateur authentifié).

**Décision explicite (Vincent, 2026-07-23) :** le compte break-glass conserve un
**accès total** à toutes les applications du catalogue / vhosts subdomain, sans
dépendre d’`AccessGrant`. Justification : mécanisme de secours quand Keycloak/SSO
est indisponible — des grants explicites seraient inutilisables au moment où le
break-glass sert.

**Implémentation :** comportement rendu **explicite** dans le docstring + commentaires
du flux décisionnel de `subdomain_auth` (pas un contournement implicite non documenté).  
Test : `test_breakglass_access_grant_without_grant_returns_200`
(`tests/test_subdomain_auth_access_grant.py`).

### 2.2 Table legacy `AppGroup` — **corrigé** (fusion livrée, 2026-07-23)

**Décision Vincent (2026-07-23) :** fusion en **bascule directe** (pas de double-run).

**Livré :**

1. Backfill idempotent `AppGroup` → `AccessGrant` (`subject_type=group`,
   `resource_type=application`, `access_level=launch` par défaut,
   `granted_by=migration_appgroup_2026-07-23`). Conflits : niveau le plus élevé conservé
   (`view` → upgrade `launch` ; `manage` conservé).
   Code : `app/rbac/migrate_appgroup.py` + Alembic `026_migrate_appgroup_to_accessgrant`.
2. Runtime unique via `get_effective_apps_for_user()` /
   `user_can_launch_application()` :
   - `/catalogue` (`pages.py`)
   - robotic `_check_app_rbac` (`client_open_action.py`)
3. CRUD `/{slug}/groups` et encart UI legacy supprimés.
4. Modèle `AppGroup` + table `app_groups` supprimés.

**Tests :** `test_access_grant_migration_*`, `test_check_app_rbac_*`.

---

### 2.4 Anti-auto-élévation `portal_admin` — **corrigé** (2026-07-23)

**Implémentation :**

- `DELETE` / `POST …/delete` sur `/admin/rbac/grants/{id}` : si le grant est
  `system_role=portal_admin` **et** `subject_type=user` **et**
  `keycloak_user_id` = l’acteur courant → **400** avec
  « Vous ne pouvez pas retirer votre propre rôle admin » (grant inchangé).
- Retrait du `portal_admin` d’**un autre** compte : autorisé.
- Attribution : non bloquée (hors scope 2FA) ; audit renforcé.
- Actions d’audit dédiées (en plus des `rbac.grant.*` génériques) :
  - `portal_admin_grant_created`
  - `portal_admin_grant_revoked`

Code : `app/admin/rbac_access.py`, helpers
`is_portal_admin_system_grant` / `is_self_portal_admin_grant` dans
`app/rbac/grants_service.py`.  
Tests : `tests/test_portal_admin_self_revoke.py`.

---

## 3. Priorités (rappel)

| Priorité | Items | Statut itération |
|----------|-------|------------------|
| Haute | 1, 2, 4 | **Traité** |
| Moyenne / basse | grants TTL, revue périodique, rôles étendus, annuaire users | Hors scope |

---

## 4. Confirmation des 3 comportements (prête à coller)

1. **Break-glass** : accès total aux apps subdomain **sans** `AccessGrant` — explicite dans
   `subdomain_auth.py`, testé par `test_breakglass_access_grant_without_grant_returns_200`.
2. **AppGroup** : **supprimé** — fusion bascule directe vers `AccessGrant` (backfill
   `migration_appgroup_2026-07-23`, runtime unique `get_effective_apps_for_user` /
   `user_can_launch_application`, table droppée en Alembic 026).
3. **portal_admin** : auto-retrait de son propre grant **bloqué** ; retrait/attribution
   sur un autre compte OK avec audits `portal_admin_grant_*`.
