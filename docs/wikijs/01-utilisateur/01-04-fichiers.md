# 01.04 — Fichiers

## Objectif

Télécharger (et éventuellement déposer) des fichiers mis à disposition via le
module fichiers versionnés du bastion, selon vos droits.

## Accès

Selon la configuration du portail, l’espace fichiers est disponible pour les
utilisateurs authentifiés disposant d’un **AccessGrant** sur le fichier / dossier
(niveaux typiques : lecture / téléchargement).

## Canaux

Les fichiers peuvent exposer des canaux **stable** et **bêta**. Le canal utilisé
dépend de votre appartenance (bêta-testeurs) sans modifier vos grants.

## Chiffrement

Certains binaires sont stockés chiffrés côté serveur ; le téléchargement
déchiffre selon votre droit. Ne partagez pas les liens hors des personnes autorisées.

## Dépôt (si activé)

Les interfaces de dépôt (drag-and-drop) sont réservées aux profils autorisés.
Respecter les formats et tailles indiqués dans l’UI.

## En cas d’erreur

| Message / symptôme | Action |
|--------------------|--------|
| Accès refusé | Demander un grant fichier à un admin |
| Fichier manquant | Contacter l’éditeur / admin contenu |
| Canal bêta indisponible | Retombée sur stable automatique |

Retour : [01.02 Mes applications](./01-02-mes-applications.md)
