> **Format :** Markdown (source Wiki.js).  
> **Fichier dépôt d’origine :** `docs/gestion-fichiers-versionnes-bastion.md` — garder les deux synchronisés (voir `docs/wikijs/MAINTENANCE.md`).

---
# Mise Ã  disposition de fichiers depuis le bastion â€” droits d'association + versions bÃªta/stable

> TÃ¢che : Mettre Ã  disposition des fichiers depuis le bastion, avec des droits d'association
> similaires aux applications, et une gestion des versions (bÃªta-testeurs / releases stables).
>
> Repo `bastion-app`. RÃ©utilise `AccessGrant` (`resource_type="file"`) + canal de diffusion
> (`beta` | `stable`) portÃ© par chaque `FileVersion` et par `FileChannelAssignment` **par fichier**.

Voir le dÃ©tail des sections 0â€“9 dans l'historique de tÃ¢che. Ce document est la copie de rÃ©fÃ©rence
sur disque pour Ã©viter un nouvel Ã©cart de synchronisation.

## DÃ©cisions actÃ©es (2026-07-24)

| # | Point | DÃ©cision |
|---|---|---|
| 1 | Chiffrement des blobs au repos | **Oui** â€” Fernet par blocs (`FILE_ENCRYPTION_CHUNK_SIZE`) |
| 2 | Tri des versions | **SemVer strict** â€” validation Ã  l'upload + tri applicatif |
| 3 | Quota / liste blanche d'extensions | **Non** â€” upload libre |
| 4 | Volume Docker dÃ©diÃ© | **Oui** â€” `sso_portal_files_data` + `FILES_STORAGE_DIR` |

## Statut

- Â§1â€“7 cÅ“ur fonctionnel livrÃ© (2026-07-24), tests verts.
- Â§9 complÃ©ment : chiffrement, SemVer, volume dÃ©diÃ©, alignement modÃ¨le (canal par fichier).

