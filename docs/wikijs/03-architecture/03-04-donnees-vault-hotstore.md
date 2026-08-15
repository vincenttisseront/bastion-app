# 03.04 — Données, vault & hot store

## SQLite (config)

Base principale du portail (souvent SQLCipher en prod) :

- Realms, Apps, AccessGrant, groupes RBAC
- Sessions break-glass / OIDC natives
- Audit log, préférences admin
- Paramètres ACME, WAF, SIEM, hot store (métadonnées)

Emplacement typique : sous `SSO_PORTAL_DATA_DIR`.

## Vault

- Clé de chiffrement : `PORTAL_SECRET_ENCRYPTION_KEY` / magasin de clé versionné
- Secrets realm (`client_secret`), credentials apps, mots de passe admin CrushFTP…
- Rotation de clé : procédures admin (UI / jobs)

## Hot store (optionnel)

PostgreSQL pour volumes élevés (sessions / audit / rate) tout en gardant la
**config** sur SQLite. Wizard Admin → Général → Configuration / Stockage chaud :

1. Paramètres connexion
2. Test
3. Préparer schéma
4. Migrer / activer

## Fichiers versionnés

Stockage dédié (volume) pour binaires, canaux β/stable, chiffrement optionnel.
Hors SQLite pour les blobs.

## Exports

`exports/` : artefacts **générés** (nginx, oauth2-proxy). Pas de secrets source ;
les secrets viennent de la base déchiffrée au moment de l’export.

Suite : [04.01 Admin](../04-administrateur/04-01-parcours-admin.md)
