# 02.05 — Comptes bastion & provisioning

## Périmètre

Le bastion peut :

- référencer des **identités Keycloak** (lecture / fiche utilisateur) ;
- gérer des **comptes partagés** / credentials vault pour apps robotic ;
- participer au **provisioning** vers certaines apps (ex. CrushFTP) selon drivers.

## Fiche utilisateur

Depuis Admin → RBAC → Utilisateurs :

- identité, groupes, droits effectifs ;
- sessions / présence applicative ;
- actions de gouvernance (selon droits admin).

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
