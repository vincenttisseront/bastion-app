> **Format :** Markdown (source Wiki.js).  
> **Fichier dépôt d'origine :** docs/rbac-information-architecture.md — garder les deux synchronisés (voir docs/wikijs/MAINTENANCE.md).

---
# Architecture d’information RBAC (Bastion Pro)

## Pourquoi cette organisation

Le module RBAC mélangeait trois notions distinctes :

1. **Qui est l’utilisateur** (création bastion vs import Keycloak)
2. **Quels droits** (individuels vs hérités de groupes)
3. **Quel compte Crush/robotic** (priorité / exclusions multi-groupes)

Les écrans précédents forçaient un parcours multi-clics (fiche user → groupes → fiche groupe → droits → comptes) et répétaient un mini-bloc « Groupes » sous chaque onglet Utilisateurs.

## Les 5 espaces

| Onglet | URL | Rôle |
|--------|-----|------|
| Vue d'ensemble | `/admin/rbac/overview` | KPI + alertes + liens croisés (point d’entrée pédagogique) |
| Utilisateurs | `/admin/rbac/users` | Listes (créés / droits indiv. / recherche KC) + recherche live |
| Groupes | `/admin/rbac` | Sync, membres, comptes partagés, droits de groupe |
| Matrice | `/admin/rbac/matrix` | Apps × groupes (grants de groupe) |
| Gouvernance | `/admin/rbac/governance` | Rôles / permissions système |

## Fiche utilisateur (hors onglets RBAC)

Page dédiée **sans** la barre d’onglets Groupes / Matrice / Gouvernance :

| URL | Paramètres requis |
|-----|-------------------|
| `/admin/rbac/users/view?account_id={id}` | Compte bastion existant |
| `/admin/rbac/users/view?realm_id={id}&keycloak_user_id={kc_id}` | Identité Keycloak |

Sections : identité, groupes, droits, vault, provisioning, appareils ActiveSync.

**URL incomplète** (après auth, bookmark, lien sans paramètres) : **redirect 302**
vers `/admin/rbac/users?list_tab=open` avec message flash — jamais de JSON brut.

L’endpoint JSON `/admin/rbac/users/{keycloak_user_id}?realm_id=…` reste réservé aux
appels `fetch` (recherche / modales), pas à la navigation HTML.

## Liens croisés (pas seulement la sidebar)

- Fiche **utilisateur** → onglet **Accès effectifs** : droits consolidés + comptes vault retenus + lien Matrice
- Fiche **groupe** → Membres (lien fiche user), Comptes (membres effectifs), Droits → Matrice
- Page **Utilisateurs** : bandeau résumé groupes → `/admin/rbac` (plus de table dupliquée)

## Comptes partagés

Voir l’aide repliable sur Groupe → Comptes. Règle : priorité max gagne ; exclusion sans override individuel = app bloquée.

## Layout

Les pages RBAC utilisent `.page-rbac` / `.rbac-layout` avec `width: 100%` et `min-width: 0` (fix du rendu « miniature » dû à un grid sans largeur forcée sur le conteneur page).
