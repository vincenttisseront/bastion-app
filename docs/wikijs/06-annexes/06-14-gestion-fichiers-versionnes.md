> **Format :** Markdown (source Wiki.js).  
> **Fichier dépôt d'origine :** docs/gestion-fichiers-versionnes-bastion.md — garder les deux synchronisés (voir docs/wikijs/MAINTENANCE.md).

---
# Mise à disposition de fichiers depuis le bastion — droits d'association + versions bêta/stable

> Tâche : Mettre à disposition des fichiers depuis le bastion, avec des droits d'association
> similaires aux applications, et une gestion des versions (bêta-testeurs / releases stables).
>
> Repo `bastion-app`. Réutilise `AccessGrant` (`resource_type="file"`) + canal de diffusion
> (`beta` | `stable`) porté par chaque `FileVersion` et par `FileChannelAssignment` **par fichier**.

Voir le détail des sections 0–9 dans l'historique de tâche. Ce document est la copie de référence
sur disque pour éviter un nouvel écart de synchronisation.

## Décisions actées (2026-07-24)

| # | Point | Décision |
|---|---|---|
| 1 | Chiffrement des blobs au repos | **Oui** — Fernet par blocs (`FILE_ENCRYPTION_CHUNK_SIZE`) |
| 2 | Tri des versions | **SemVer strict** — validation à l'upload + tri applicatif |
| 3 | Quota / liste blanche d'extensions | **Non** — upload libre |
| 4 | Volume Docker dédié | **Oui** — `sso_portal_files_data` + `FILES_STORAGE_DIR` |

## Statut

- §1–7 cœur fonctionnel livré (2026-07-24), tests verts.
- §9 complément : chiffrement, SemVer, volume dédié, alignement modèle (canal par fichier).
