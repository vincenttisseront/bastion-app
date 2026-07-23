# RBAC — Audit de l'enforcement runtime (§6)

> Date : 2026-07-15  
> Périmètre : application réelle des droits au login / catalogue / admin  
> **Hors scope de la tâche AccessGrant** : ce document constate l'écart, sans implémenter l'enforcement.

---

## 1. Groupes dans le token OIDC

| Question | État constaté |
|----------|-------------|
| Le mapper Keycloak `groups` est-il actif sur le client portail ? | **Non vérifié automatiquement** — à confirmer dans la console Keycloak (client `sso-portal-ar-systems`, mappers / client scopes). |
| oauth2-proxy transmet-il les groupes à Nginx ? | **Partiellement prévu** : `set_xauthrequest = true` dans la config oauth2-proxy exportée ; Nginx lit `$upstream_http_x_auth_request_groups` dans le vhost portail. |
| FastAPI reçoit-il `X-Groups` ? | **Oui, si Nginx les transmet** — `user_context.py` parse `X-Groups` depuis les headers injectés par Nginx. |
| `/internal/oauth2-auth` relaie-t-il les headers oauth2-proxy ? | **Oui (corrigé 2026-07-15)** — forward whitelist `X-Auth-Request-*` depuis oauth2-proxy. Voir tests `oauth2_auth_header_forward`. |

**Conclusion :** même si Keycloak émet les groupes, la chaîne Nginx → FastAPI est **incomplète** tant que `/internal/oauth2-auth` ne mappe pas les headers oauth2-proxy vers la réponse auth_request.

---

## 2. Contrôle d'accès catalogue (applications)

| Mécanisme | Fichier | Comportement |
|-----------|---------|--------------|
| **Legacy `AppGroup`** | `app/web/pages.py` (`catalogue_page`) | Si l'utilisateur n'est pas admin **et** `user.groups` non vide : filtre les apps dont l'`app_id` est lié à un `RBACGroup.name` présent dans `X-Groups`. Si `user.groups` est **vide** : **aucun filtrage** → catalogue complet pour tout utilisateur authentifié. |
| **`AccessGrant`** | `access_grants` (nouveau) | **Non utilisé** au runtime catalogue. |

---

## 3. Contrôle d'accès admin

| Mécanisme | Comportement |
|-----------|--------------|
| `portal_admin_groups` (settings) | Intersection `X-Groups` avec la liste configurée (`portal-admins`, etc.) dans `user_context._is_admin_user`. |
| Break-glass | Admin implicite. |
| **`AccessGrant` `system_role=portal_admin`** | **Non utilisé** au runtime — l'admin reste basé sur les groupes Keycloak / break-glass. |

---

## 4. Synthèse

| Composant | Statut |
|-----------|--------|
| CRUD admin `AccessGrant` | **Implémenté** (gestion déclarative) |
| Membres groupe / recherche user Keycloak | **Implémenté** (API à la demande) |
| Droits effectifs (calcul + provenance) | **Implémenté** (admin uniquement) |
| Enforcement catalogue via `AccessGrant` | **Absent** |
| Enforcement admin via `AccessGrant.system_role` | **Absent** |
| Propagation groupes token → FastAPI | **Incomplet** (`/internal/oauth2-auth`) |
| Legacy `AppGroup` | **Toujours actif** pour le catalogue (si groupes header présents) |

---

## 5. Points de suivi recommandés (tâche séparée)

1. ~~Corriger `/internal/oauth2-auth` pour renvoyer `X-Auth-Request-*`~~ (**fait** 2026-07-15). Suivi restant : relay `Set-Cookie` sur refresh de session via `auth_request_set` Nginx (non implémenté — risque doc. dans le correctif).
2. Valider le mapper Keycloak `groups` sur le client portail et documenter la config prod.
3. Brancher le catalogue (et éventuellement l'admin) sur `AccessGrant` + niveaux `view` / `launch` / `manage`.
4. Migrer l'enforcement runtime de `AppGroup` vers `AccessGrant` (chantier séparé, **ne pas supprimer** `AppGroup` avant).

---

## 6. Investigation `AppGroup` (2026-07-15) — **effet réel constaté**

| Emplacement | Effet |
|-------------|--------|
| `app/web/pages.py` (`catalogue_page`) | Filtre le catalogue pour les non-admins lorsque `X-Groups` est non vide |
| `app/subdomain/subdomain_service.py` (`get_app_allowed_groups` / `user_has_access`) | Legacy AppGroup (encore utilisé côté impersonate robotic) |
| `app/subdomain/subdomain_auth.py` (`/internal/subdomain-auth`) | **AccessGrant launch+** (corrigé 2026-07-23) — voir `docs/audit-gestion-sessions.md` |
| `app/services.py` | API interne CRUD `/{slug}/groups` (lien App ↔ Groupe) |
| Encart UI admin RBAC | Affichage legacy uniquement |

**Verdict :** `AppGroup` n'est **pas** un reliquat inerte. Suppression = risque de régression catalogue/subdomain.  
**Plan :** conserver jusqu'à migration explicite vers `AccessGrant` (hors scope de la vue croisée Application).

---

## 7. Compte de service Keycloak (sync + RBAC)

Le compte de service realm-management doit disposer **à minima** de :

- `query-groups` — import / liste des groupes
- `view-users` — membres de groupe, recherche utilisateur, groupes d'un utilisateur

Sans `view-users`, les endpoints membres / recherche renvoient HTTP 403 avec un message explicite côté bastion-app.
