> **Format :** Markdown (source Wiki.js).  
> **Fichier dépôt d’origine :** `docs/rbac-information-architecture.md` — garder les deux synchronisés (voir `docs/wikijs/MAINTENANCE.md`).

---
# Architecture dâ€™information RBAC (Bastion Pro)

## Pourquoi cette organisation

Le module RBAC mÃ©langeait trois notions distinctes :

1. **Qui est lâ€™utilisateur** (crÃ©ation bastion vs import Keycloak)
2. **Quels droits** (individuels vs hÃ©ritÃ©s de groupes)
3. **Quel compte Crush/robotic** (prioritÃ© / exclusions multi-groupes)

Les Ã©crans prÃ©cÃ©dents forÃ§aient un parcours multi-clics (fiche user â†’ groupes â†’ fiche groupe â†’ droits â†’ comptes) et rÃ©pÃ©taient un mini-bloc Â« Groupes Â» sous chaque onglet Utilisateurs.

## Les 5 espaces

| Onglet | URL | RÃ´le |
|--------|-----|------|
| Vue d'ensemble | `/admin/rbac/overview` | KPI + alertes + liens croisÃ©s (point dâ€™entrÃ©e pÃ©dagogique) |
| Utilisateurs | `/admin/rbac/users` | Listes (crÃ©Ã©s / droits indiv. / recherche KC) + recherche live |
| Groupes | `/admin/rbac` | Sync, membres, comptes partagÃ©s, droits de groupe |
| Matrice | `/admin/rbac/matrix` | Apps Ã— groupes (grants de groupe) |
| Gouvernance | `/admin/rbac/governance` | RÃ´les / permissions systÃ¨me |

## Liens croisÃ©s (pas seulement la sidebar)

- Fiche **utilisateur** â†’ onglet **AccÃ¨s effectifs** : droits consolidÃ©s + comptes vault retenus + lien Matrice
- Fiche **groupe** â†’ Membres (lien fiche user), Comptes (membres effectifs), Droits â†’ Matrice
- Page **Utilisateurs** : bandeau rÃ©sumÃ© groupes â†’ `/admin/rbac` (plus de table dupliquÃ©e)

## Comptes partagÃ©s

Voir lâ€™aide repliable sur Groupe â†’ Comptes. RÃ¨gle : prioritÃ© max gagne ; exclusion sans override individuel = app bloquÃ©e.

## Layout

Les pages RBAC utilisent `.page-rbac` / `.rbac-layout` avec `width: 100%` et `min-width: 0` (fix du rendu Â« miniature Â» dÃ» Ã  un grid sans largeur forcÃ©e sur le conteneur page).

