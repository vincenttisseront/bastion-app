# 02.04 — RBAC & AccessGrant

## Modèle

Un **AccessGrant** lie :

- un **sujet** : utilisateur Keycloak (`sub`) ou **groupe** RBAC ;
- une **ressource** : application, rôle système (`portal_admin`), fichier/dossier, etc. ;
- un **niveau** : typiquement `view`, `launch`, … selon le type de ressource.

Les droits **effectifs** = union des grants directs et hérités des groupes.

## Applications

| Niveau | Effet |
|--------|-------|
| `view` | Visible dans le catalogue (selon UI) |
| `launch` | Autorisé à franchir `subdomain-auth` / lancer l’app |

Sans `launch`, un utilisateur authentifié sur un FQDN app est **refusé**
(`access_denied_no_grant`) et renvoyé vers le portail.

## Rôle `portal_admin`

Grant `system_role = portal_admin` (user ou groupe) → accès aux écrans `/admin`.
Ce rôle **ne remplace pas** les grants applicatifs pour les sous-domaines en session OIDC
(le break-glass, lui, peut bypasser les grants apps).

## Administration

UI typique : Vue d’ensemble, Utilisateurs, Groupes, Matrice, Gouvernance.
Préférer les **groupes** (ex. `ARSYSTEMS-Users`) aux grants individuels massifs.

## Synchronisation groupes

Les noms de groupes utilisés dans les grants doivent correspondre aux claims
groupes de la session OIDC (mapper IdP / fallback Admin API selon config BFF).

Suite : [02.05 Comptes](./02-05-comptes-provisioning.md)
