# 02.05 — Comptes bastion & provisioning

## Périmètre

Le bastion peut :

- référencer des **identités Keycloak** (lecture / fiche utilisateur) ;
- gérer des **comptes partagés** / credentials vault pour apps robotic ;
- participer au **provisioning** vers certaines apps (ex. CrushFTP) selon drivers.

## Fiche utilisateur

Depuis Admin → RBAC → Utilisateurs, ou directement :

- `/admin/rbac/users/view?account_id=…` (compte bastion)
- `/admin/rbac/users/view?realm_id=…&keycloak_user_id=…` (identité Keycloak)

Contenu : identité, groupes, droits effectifs, vault, provisioning, appareils ActiveSync.
La fiche n’affiche **pas** la barre d’onglets RBAC parente (Groupes / Matrice / Gouvernance).

Si l’URL est ouverte sans paramètres requis, le portail redirige vers la liste
Utilisateurs (onglet Recherche Keycloak) avec un message flash.

## Provisioning applicatif

Le provisioning (création de compte métier dans l’app cible) est **spécifique driver**.
CrushFTP est le cas le plus abouti. Wiki.js / Grafana : plutôt OIDC self-registration
côté app + grants bastion pour la porte.

## Séparation des responsabilités

| Couche | Responsable |
|--------|-------------|
| Identité (login MFA) | IdP (Keycloak) |
| Droit d’ouvrir l’app via bastion | AccessGrant |
| Compte / rôle dans l’app | App (OIDC groups, admin app, ou driver) |

Suite : [02.06 Break-glass](./02-06-break-glass.md)
