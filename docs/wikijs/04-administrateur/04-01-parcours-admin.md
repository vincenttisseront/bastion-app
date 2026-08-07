# 04.01 — Parcours administrateur

## Accès

Compte avec rôle **`portal_admin`** (grant ou groupe) **ou** session break-glass.

Entrée : `/dashboard` / menu **Admin**.

## Zones principales

| Zone | Usage |
|------|--------|
| Dashboard | Santé, métriques, alertes |
| Apps | CRUD applications, auth, logos, entrée portail |
| Realms | OIDC, test, secrets |
| RBAC | Users, groupes, matrice, grants |
| Sessions | Présence portail / apps, révocation |
| Logs | Audit, accès nginx apps, containers |
| Infrastructure | Apply / dry-run exports |
| Domaines | Hosts inconnus capturés |
| ACME | Domaines TLS, reconcile |
| WAF | Profil ModSecurity, exclusions |
| Sécurité | Allowlist, ban, hot store, branding… |
| Fichiers | Contenu versionné |
| Configuration | SIEM, logs Docker, etc. |

## Ordre de mise en service typique

1. Secrets `.env` + démarrage stack
2. Realm OIDC + Test + Apply
3. Créer apps (FQDN, upstream, realm, auth_mode)
4. Grants groupes → launch
5. ACME / DNS pour les FQDN
6. Vérifier tuiles `/apps` et un FQDN app

Suite : [04.02 Apps & Apply](./04-02-apps-domaines-apply.md)
