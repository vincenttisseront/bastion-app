# Système de codes de logs — criticité normalisée

Format : `BST-<DOMAINE>-<NNNN>` (la tranche du numéro porte la criticité).

Source de vérité runtime : [`app/audit/event_catalog.py`](../app/audit/event_catalog.py).

## Tranches

| Tranche | Criticité |
|---------|-----------|
| 0000 | WARNING (non catalogué) |
| 0001–0999 | INFO |
| 1000–1999 | NOTICE |
| 2000–2999 | WARNING |
| 3000–3999 | ERROR |
| 4000–4999 | CRITICAL |

## Domaines

`AUTH`, `BGL`, `SESS`, `RBAC`, `VLT`, `FILE`, `WAF`, `PROXY`, `ADM`, `SIEM`, `PROV`, `SYS`.

## Inventaire (2026-08-12)

- **184** actions distinctes émises par `log_action` en production, toutes mappées (`legacy_action`).
- **20** codes réservés sans émetteur actuel (ex. `BST-BGL-4001`, `BST-SYS-3001`).
- **204** entrées au total dans le registre.

Corrections vs catalogue Pod initial :

| Hypothèse Pod | Réalité code |
|---------------|--------------|
| `auth.login` / `auth.logout` | `oidc_login_success`, `oidc_logout`, `portal_logout` |
| `grant.create` / `grant.delete` | `rbac.grant.created` / `rbac.grant.deleted` |
| `security.sso_login_failed` | conservé + `oidc_login_failed` |
| `key_rotation` | conservé (`BST-VLT-1010`) |

Export admin : `/admin/logs/catalogue` (CSV/JSON).

## Écriture

`log_action(..., code=None)` résout via `legacy_action` ; action inconnue → `BST-<domaine>-0000` / WARNING, sans exception.

Colonnes `audit_logs.event_code` et `audit_logs.severity` (nullable, pas de backfill historique).
