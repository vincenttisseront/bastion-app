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

## Liens croisés (pas seulement la sidebar)

- Fiche **utilisateur** → onglet **Accès effectifs** : droits consolidés + comptes vault retenus + lien Matrice
- Fiche **groupe** → Membres (lien fiche user), Comptes (membres effectifs), Droits → Matrice
- Page **Utilisateurs** : bandeau résumé groupes → `/admin/rbac` (plus de table dupliquée)

## Comptes partagés

Voir l’aide repliable sur Groupe → Comptes. Règle : priorité max gagne ; exclusion sans override individuel = app bloquée.

## Layout

Les pages RBAC utilisent `.page-rbac` / `.rbac-layout` avec `width: 100%` et `min-width: 0` (fix du rendu « miniature » dû à un grid sans largeur forcée sur le conteneur page).
