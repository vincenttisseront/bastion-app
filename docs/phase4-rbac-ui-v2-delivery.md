# RBAC UI v2 — livrable (lots 1–4)

Alignement Utilisateurs / Groupes / Gouvernance sur les maquettes Stitch, avec modèle
`PermissionModule` / `RbacRole` / `RolePermission` orthogonal aux `AccessGrant` catalogue.

## Routes

| URL | Rôle |
|---|---|
| `/admin/rbac` | Cartes groupes + modale Permissions + panneaux distribution / alertes |
| `/admin/rbac/users` | Stats Keycloak live, filtres, table enrichie, anomalies, répartition |
| `/admin/rbac/matrix` | **Inchangée** — Applications × Groupes |
| `/admin/rbac/governance` | **Nouveau** — Modules internes × Rôle (4ᵉ onglet) |

## Enforcement câblé vs déclaratif

- **Câblé** : `DELETE /admin/apps/{slug}/users/{id}/credential` vérifie
  `secret_vault.can_delete` via `user_can_module_action` (les `portal_admin` legacy
  passent encore tant que les grants `rbac_role` ne sont pas le seul chemin).
- **Déclaratif pour l’instant** : READ/WRITE/EXECUTE des autres modules (Dashboard,
  Logs, Sessions, etc.) — pas de gate sur chaque action admin dans ce lot.

## Heuristiques V1 (volontairement simples)

| Zone | Implémenté | Limite |
|---|---|---|
| Anomalies de connexion | `session_hijack_suspected` + `breakglass.login_failed` | Pas de compteur SSO `login_failed` générique (absent du code) — pas d’instrumentation inventée |
| Alertes d’excès | write/delete sur `RolePermission` sans update depuis 90 j | Pas d’usage réel « last_used_at » |
| Contrôle d’intégrité | noms uniques + héritage ≤ 1 niveau | Pas d’analyse de conflits croisés |
| Stats tendances % | **Jamais inventées** | Badge « N Nouveaux » seulement si grants system_role < 7 j |
| Membres carte groupe | `fetch_group_members` Keycloak | Fallback avatar groupe si Keycloak indisponible |
| Filtre Groupe (users) | Query param présent | Liste = users avec grants directs ; membership Keycloak non rechargée pour le filtre |

## Tests

```text
pytest -k "rbac_permission_modules or rbac_users_stats or rbac_group_modal or rbac_governance_matrix or rbac_nav_tabs or rbac_portal_admin_parity or access_grant"
→ 37 passed
```

Migration Alembic : `027_rbac_governance_permissions`.
