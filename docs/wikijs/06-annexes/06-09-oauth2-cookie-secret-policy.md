> **Format :** Markdown (source Wiki.js).  
> **Fichier dépôt d’origine :** `docs/oauth2-cookie-secret-policy.md` — garder les deux synchronisés (voir `docs/wikijs/MAINTENANCE.md`).

---
# Politique â€” `cookie_secret` oauth2-proxy

> Source de vÃ©ritÃ© applicative : `RealmConfig.oauth2_cookie_secret_encrypted` (SQLite).
> Les fichiers sous `exports/oauth2/` et `docker/oauth2-core/oauth2-proxy.cfg` sont des
> **miroirs gÃ©nÃ©rÃ©s** aprÃ¨s `infrastructure apply` / `apply-infra-docker.sh` â€” ne pas les
> Ã©diter Ã  la main comme source de vÃ©ritÃ©.

## GÃ©nÃ©ration

- Fonction : `generate_cookie_secret()` dans `app/secret_crypto.py`
- Algorithme : `secrets.token_urlsafe(32)` (â‰ˆ 32 octets alÃ©atoires, encodage URL-safe base64)
- DÃ©clenchement : Ã  lâ€™export oauth2 (`_ensure_cookie_secret` dans `app/admin/export.py`)
  si le realm nâ€™a pas encore de secret chiffrÃ© en base
- Contrainte AES oauth2-proxy : longueur dÃ©codÃ©e **16 / 24 / 32 octets** (vÃ©rifiÃ©e aussi
  cÃ´tÃ© Ansible par `scripts/oauth2-cookie-secret.sh`)

## Stockage

| Ã‰tape | OÃ¹ |
|---|---|
| Clair (Ã©phÃ©mÃ¨re) | MÃ©moire au moment de lâ€™export uniquement |
| Persistant | Colonne `RealmConfig.oauth2_cookie_secret_encrypted` |
| Chiffrement | MÃªme famille Fernet que le vault applicatif (`PORTAL_SECRET_ENCRYPTION_KEY` /
| | store `VAULT_KEYS_DIR`, helpers `encrypt_secret` / `decrypt_secret`) |
| DÃ©ployÃ© | Ligne `cookie_secret = "â€¦"` dans le `.cfg` gÃ©nÃ©rÃ© pour chaque realm / core |

Rotation Fernet des colonnes chiffrÃ©es : `scripts/rotate_fernet_key.py` (compte
`realm_oauth2_cookie_secrets`) â€” **ne change pas** la valeur claire du `cookie_secret`,
seulement son enveloppe au repos.

## Rotation du `cookie_secret` lui-mÃªme

**Non automatisÃ©e** Ã  ce jour. Effet : **invalide toutes les sessions oauth2-proxy** du
realm concernÃ© (les cookies navigateur chiffrÃ©s avec lâ€™ancien secret deviennent
illisibles â†’ re-login SSO).

### ProcÃ©dure recommandÃ©e

1. Hors heures de pointe ; prÃ©venir les utilisateurs du realm.
2. Admin â†’ Realms â†’ (rÃ©)gÃ©nÃ©rer / vider le cookie secret du realm **ou** remplacer
   `oauth2_cookie_secret_encrypted` via un flux admin dÃ©diÃ© si disponible ; sinon
   supprimer la valeur en base (re-export rÃ©gÃ©nÃ¨re via `_ensure_cookie_secret`).
3. `python -m app.admin.infrastructure apply` (ou bouton/API apply) puis
   `scripts/apply-infra-docker.sh` pour synchroniser le `.cfg` et redÃ©marrer
   oauth2-proxy.
4. VÃ©rifier smoke Ansible (`cookie_expire` / flags) + page **Alignement sessions SSO**.

### FrÃ©quence

- **Annuelle** (hygiÃ¨ne), **ou** immÃ©diatement en cas de suspicion de fuite du
  `.cfg` / backup / extrait de logs contenant le secret en clair.
- Coordonner avec une Ã©ventuelle rotation Keycloak client secret si lâ€™incident est
  plus large.

## Liens

- GÃ©nÃ©rateur : `app/admin/export.py` â†’ `generate_oauth2_proxy_config()`
- Garde-fou longueur : `ansible/.../tasks/main.yml` + `scripts/oauth2-cookie-secret.sh`
- Flags cookie : `cookie_secure`, `cookie_httponly`, `cookie_samesite="lax"` (smoke Ã©tendu)

