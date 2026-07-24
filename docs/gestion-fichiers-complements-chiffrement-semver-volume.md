# Compléments fichiers — chiffrement, SemVer, volume dédié

Suite de `gestion-fichiers-versionnes-bastion.md` (§9). Décisions 2026-07-24.

| Tâche | Statut |
|---|---|
| **T6** Chiffrement Fernet par blocs + `FileVersion.encrypted` + `scripts/reencrypt_file_blobs.py` | Livré |
| **T7** SemVer strict (`packaging.version`) + tri applicatif | Livré |
| **T8** `FILES_STORAGE_DIR` + bind/volume `sso_portal_files_data` + backup Ansible/preflight + smoke persistance | Livré |
| Quota / whitelist extensions | **Décliné** — aucune restriction ajoutée |

Réf. code : `app/files/blob_crypto.py`, `app/files/service.py`, `docker-compose.yml`,
`ansible/roles/bastion_app_docker/`, `tests/test_file_versioning.py`.
