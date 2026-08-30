> **Format :** Markdown (source Wiki.js).  
> **Fichier dépôt d'origine :** docs/oauth2-cookie-secret-policy.md — garder les deux synchronisés (voir docs/wikijs/MAINTENANCE.md).

---
# Politique — `cookie_secret` oauth2-proxy

> Source de vérité applicative : `RealmConfig.oauth2_cookie_secret_encrypted` (SQLite).
> Les fichiers sous `exports/oauth2/` et `docker/oauth2-core/oauth2-proxy.cfg` sont des
> **miroirs générés** après `infrastructure apply` / `apply-infra-docker.sh` — ne pas les
> éditer à la main comme source de vérité.

## Génération

- Fonction : `generate_cookie_secret()` dans `app/secret_crypto.py`
- Algorithme : `secrets.token_urlsafe(32)` (≈ 32 octets aléatoires, encodage URL-safe base64)
- Déclenchement : à l’export oauth2 (`_ensure_cookie_secret` dans `app/admin/export.py`)
  si le realm n’a pas encore de secret chiffré en base
- Contrainte AES oauth2-proxy : longueur décodée **16 / 24 / 32 octets** (vérifiée aussi
  côté Ansible par `scripts/oauth2-cookie-secret.sh`)

## Stockage

| Étape | Où |
|---|---|
| Clair (éphémère) | Mémoire au moment de l’export uniquement |
| Persistant | Colonne `RealmConfig.oauth2_cookie_secret_encrypted` |
| Chiffrement | Même famille Fernet que le vault applicatif (`PORTAL_SECRET_ENCRYPTION_KEY` /
| | store `VAULT_KEYS_DIR`, helpers `encrypt_secret` / `decrypt_secret`) |
| Déployé | Ligne `cookie_secret = "…"` dans le `.cfg` généré pour chaque realm / core |

Rotation Fernet des colonnes chiffrées : `scripts/rotate_fernet_key.py` (compte
`realm_oauth2_cookie_secrets`) — **ne change pas** la valeur claire du `cookie_secret`,
seulement son enveloppe au repos.

## Rotation du `cookie_secret` lui-même

**Non automatisée** à ce jour. Effet : **invalide toutes les sessions oauth2-proxy** du
realm concerné (les cookies navigateur chiffrés avec l’ancien secret deviennent
illisibles → re-login SSO).

### Procédure recommandée

1. Hors heures de pointe ; prévenir les utilisateurs du realm.
2. Admin → Realms → (ré)générer / vider le cookie secret du realm **ou** remplacer
   `oauth2_cookie_secret_encrypted` via un flux admin dédié si disponible ; sinon
   supprimer la valeur en base (re-export régénère via `_ensure_cookie_secret`).
3. `python -m app.admin.infrastructure apply` (ou bouton/API apply) puis
   `scripts/apply-infra-docker.sh` pour synchroniser le `.cfg` et redémarrer
   oauth2-proxy.
4. Vérifier smoke Ansible (`cookie_expire` / flags) + page **Alignement sessions SSO**.

### Fréquence

- **Annuelle** (hygiène), **ou** immédiatement en cas de suspicion de fuite du
  `.cfg` / backup / extrait de logs contenant le secret en clair.
- Coordonner avec une éventuelle rotation Keycloak client secret si l’incident est
  plus large.

## Liens

- Générateur : `app/admin/export.py` → `generate_oauth2_proxy_config()`
- Garde-fou longueur : `ansible/.../tasks/main.yml` + `scripts/oauth2-cookie-secret.sh`
- Flags cookie : `cookie_secure`, `cookie_httponly`, `cookie_samesite="lax"` (smoke étendu)
