# Connexion par passkey (clé d'accès) — plan de mise en place

> Objectif : permettre à tout utilisateur du portail de se connecter **sans mot de passe ni OTP**, avec une clé d'accès (Face ID, Windows Hello, empreinte, clé FIDO2, passkey synchronisée iCloud/Google/1Password), sur le modèle d'Amazon. Le mot de passe Keycloak reste disponible en secours.

## 1. Point de départ (existant)

| Élément | Où | Constat |
|---|---|---|
| Login natif | `app/auth/oidc_bff.py` (`POST /auth/login`) + `oidc_bff_client.py` | Login **headless** Keycloak (scraping du formulaire + PKCE), puis émission de notre JWT `bastion_session` via `issue_oidc_session()` + `set_oidc_session_cookie()`. |
| WebAuthn | `app/auth/webauthn_service.py`, `app/admin/mfa.py`, `app/static/js/bastion-webauthn-b64.js` | Uniquement en **2ᵉ facteur admin** : **une seule** clé par admin, `allowCredentials` explicite, `user_id = sha256(email)`, UV `preferred`. |
| Dépendance | `pyproject.toml` | `webauthn>=2.0` (py_webauthn) déjà présent. |
| API admin Keycloak | `app/rbac/keycloak_admin.py` | `fetch_keycloak_user()`, `fetch_user_groups()`, `logout_keycloak_user()`, etc., disponibles via le compte de service du realm. |
| Profil utilisateur | `app/web/portal.py` (`GET /profile`), `profile_security_service.py` | Déjà une section sécurité (mot de passe, sessions) où ajouter la gestion des passkeys. |

**Conséquence d'architecture :** les passkeys natives de Keycloak sont inutilisables ici. Le login headless ne passe jamais par le navigateur sur l'origine Keycloak, alors que WebAuthn exige que la cérémonie ait lieu sur l'origine du RP. Les passkeys doivent donc être **gérées par Bastion** (RP ID = `portal_domain`), et Bastion émet lui-même la `bastion_session` après vérification. Il récupère l'identité et les groupes à jour via l'API admin Keycloak.

## 2. Parcours utilisateur cible (façon Amazon)

1. **Page de login** : le champ « Identifiant » porte `autocomplete="username webauthn"`. Le navigateur propose directement les passkeys du site dans l'autocomplétion (*conditional UI*). On ajoute aussi un bouton « Se connecter avec une clé d'accès » (flux modal, utile pour les clés FIDO2 et le QR cross-device). Le formulaire mot de passe reste en dessous.
2. **Après un login par mot de passe**, si l'utilisateur n'a pas encore de passkey, on affiche un écran intermédiaire « Connectez-vous plus vite et plus sûrement avec une clé d'accès » avec deux boutons : [Créer une clé d'accès] et [Plus tard]. Un refus est mémorisé 30 jours (cookie signé).
3. **Profil → Clés d'accès** : liste (nom, appareil/fournisseur via AAGUID, synchronisée ou non, date de création, dernière utilisation), avec ajout, renommage et suppression. Ajouter ou supprimer une clé exige une **ré-authentification récente**, comme Amazon qui redemande le mot de passe : une session émise il y a moins de 10 min, sinon on redemande le mot de passe.
4. **Admin → Comptes** : voir les passkeys d'un utilisateur et les révoquer (toutes ou une par une). Les clés sont révoquées automatiquement quand le compte est désactivé.

## 3. Modèle de données (migration `096_user_passkeys.py`)

```text
user_passkeys
  id                PK
  realm_id          FK realm_configs        (index)
  keycloak_sub      str                     (index)  — identité stable, pas l'email
  username          str                     — affichage / audit
  credential_id     str  UNIQUE             — base64url
  public_key        text                    — COSE base64url
  sign_count        int
  transports        JSON
  aaguid            str  nullable           — pour afficher « iCloud Keychain », « Windows Hello »…
  backup_eligible   bool / backup_state bool — passkey synchronisée ou liée à l'appareil
  name              str                     — libellé utilisateur
  created_at, last_used_at, last_used_ip
  revoked_at, revoked_by                    (RevocationMixin)

user_webauthn_handles
  realm_id, keycloak_sub  UNIQUE
  user_handle       str  UNIQUE             — 32 octets aléatoires base64url (≠ sha256(email))

webauthn_challenges
  id (random, mis dans le cookie), purpose, subject (sub ou vide), challenge,
  expires_at, consumed_at                   — usage unique côté serveur
```

Pourquoi un `user_handle` aléatoire : le login sans identifiant (*discoverable*) renvoie le `userHandle` stocké dans l'authentificateur. `sha256(email)` est corrélable entre sites et casse dès que l'email change.

Pourquoi des challenges stockés en base : le cookie signé actuel de `webauthn_service.py` est rejouable pendant son TTL de 5 min. Pour un facteur primaire, on veut un challenge à **usage unique**, consommé de façon atomique (même principe que `OidcLoginAttempt`).

Flag par realm : `RealmConfig.passkey_login_enabled` (bool, défaut `False`), sur le modèle de `oidc_native_session_enabled`. La fonctionnalité n'est active que si la session native est elle aussi activée pour le realm.

## 4. Backend

### 4.1 Service `app/auth/passkey_service.py`
- On réutilise `rp_id_and_origin()` en l'extrayant dans un petit module commun avec le MFA admin.
- `build_login_options()` → `generate_authentication_options(allow_credentials=[], user_verification=REQUIRED)`.
- `verify_login(credential)` :
  1. Consommer le challenge (usage unique).
  2. Retrouver la ligne par `credential.id` (non révoquée) et vérifier que `userHandle` correspond au handle du titulaire.
  3. Appeler `verify_authentication_response(require_user_verification=True)`, avec origine et RP ID stricts.
  4. Contrôler le compteur de signatures : régression avec compteur ≠ 0 → refus + audit `passkey_clone_suspected`. Les passkeys synchronisées ont un compteur à 0, ce qui est toléré.
  5. Mettre à jour `sign_count`, `backup_state`, `last_used_*`.
- `build_registration_options(user)` → `resident_key=REQUIRED`, `user_verification=REQUIRED`, `attestation=NONE`, `exclude_credentials=` clés existantes, ES256 / EdDSA / RS256.
- `verify_and_store_registration()` stocke `aaguid`, `backup_*` et `transports`, et propose un nom par défaut tiré de l'AAGUID et de l'User-Agent (`user_agent_label.py`).

### 4.2 Factoriser la fin du login
On extrait de `_complete_login()` (`oidc_bff.py`) une fonction `finalize_native_login(...)` qui fait : touch `last_login_at`, `issue_oidc_session()`, nettoyage des compteurs d'échec (`clear_failed_login_counters`), audit, cookie et redirection via `redirect_via_subdomain_sso_mirror`. Elle sert aux deux chemins, mot de passe et passkey, pour éviter toute divergence (binding, audience, max_age).

### 4.3 Routes publiques (non soumises à auth_request, comme `/auth/login`)
| Route | Rôle |
|---|---|
| `POST /auth/passkey/options` | CSRF + throttle IP → options JSON + cookie `challenge_id` |
| `POST /auth/passkey/verify` | Vérification (§4.1), puis contrôles d'accès, puis `finalize_native_login` → `{redirect}` |

Contrôles d'accès avant d'émettre la session, en **fail closed** :
- Le realm est actif, avec `passkey_login_enabled` et la session native activés.
- `evaluate_login_attempt()` (bannissement IP/compte) et `record_failure()` sur échec.
- `fetch_keycloak_user(sub)` : l'utilisateur existe et `enabled`. On vérifie aussi `BastionAccount.disabled_at` s'il existe une ligne.
- `fetch_user_groups(sub)` : on récupère des groupes **frais** pour le JWT. Si l'API admin est indisponible → 503 « utilisez votre mot de passe », jamais de session avec des groupes vides ou périmés.
- Audit `oidc_login_passkey_success` / `_failure`, transmis au SIEM par le pipeline existant.

### 4.4 Routes profil (authentifiées, CSRF)
`GET /profile/passkeys`, `POST /profile/passkeys/register/options`, `POST /profile/passkeys/register/verify`, `POST /profile/passkeys/{id}/rename`, `POST /profile/passkeys/{id}/delete`, plus un garde de ré-authentification récente (`iat` du JWT < 10 min, sinon vérification du mot de passe via `verify_keycloak_password()`, qui existe déjà).

### 4.5 Admin
- Section passkeys dans `admin_rbac_account_detail` : liste et révocation.
- Toggle `passkey_login_enabled` dans Admin → Realms.
- Hook de désactivation de compte : révoquer les passkeys et appeler `revoke_oidc_sessions_for_identity()`.

## 5. Frontend
- `app/static/js/bastion-passkey.js`, qui s'appuie sur `bastion-webauthn-b64.js` (ou `PublicKeyCredential.parseRequestOptionsFromJSON` quand le navigateur le supporte) :
  - Au chargement de `/login` : si `isConditionalMediationAvailable()`, appeler `navigator.credentials.get({mediation: "conditional", signal})`.
  - Le bouton « clé d'accès » interrompt la requête conditionnelle (`AbortController`) puis relance en mode modal.
  - Erreurs (`NotAllowedError`, annulation) traitées en silence : on retombe sur le formulaire mot de passe.
- Templates : `auth/login.html` (bouton + `autocomplete`), écran intermédiaire `auth/passkey_nudge.html`, section dans le template de profil, et chaînes i18n FR/EN.
- Respect de la CSP actuelle : script externe, pas d'inline.

## 6. Sécurité — points d'attention
- **On contourne Keycloak au moment du login.** Les *required actions*, l'expiration de mot de passe, la protection brute-force et les événements Keycloak ne s'appliquent pas, et aucune session Keycloak n'est créée (`kc_sid=None`). En compensation : contrôle `enabled` à chaque login, révocation à la désactivation, et `max_age` de session inchangé. La logique d'alignement des sessions (`app/admin/session_alignment.py`) devra ignorer les sessions sans `kc_sid` plutôt que les révoquer : **à vérifier**.
- **RP ID = `portal_domain`.** Les sous-domaines d'apps ne peuvent pas utiliser ces passkeys, ce qui est voulu : le login se fait toujours sur le portail, puis passe par le miroir SSO existant. Changer `portal_domain` invalide toutes les passkeys ; à documenter dans le runbook.
- UV **obligatoire**, ce qui fait de la passkey un facteur fort à elle seule. Elle remplace donc mot de passe + OTP.
- Pas d'énumération de comptes : le flux *discoverable* ne demande pas d'identifiant.
- Throttle sur `options` et `verify` par IP, avec le même moteur que `/auth/login`.

## 7. Tests
- Unitaires : service (challenge à usage unique, rejeu, mauvais `userHandle`, clé révoquée, régression du compteur, UV absente, mauvaise origine), routes (CSRF, bannissement, utilisateur désactivé côté Keycloak avec `respx`, API admin en panne → 503).
- E2E Playwright : authentificateur virtuel via CDP (`WebAuthn.addVirtualAuthenticator`, `hasResidentKey`, `isUserVerified`). Scénarios : enrôlement depuis le profil → logout → login via le bouton passkey → arrivée sur `/apps` ; suppression de la clé → le login par passkey échoue.

## 8. Découpage proposé (une PR par lot)
1. **Socle** — *fait sur `feat/passkey-login`* : migration `096_user_passkeys`, modèles `UserPasskey` / `UserWebauthnHandle` / `WebauthnChallenge`, `app/auth/passkey_service.py`, `finalize_native_login` (`oidc_bff.py`), routes `POST /auth/passkey/options|verify` (`app/auth/passkey_login.py`), tests `tests/test_passkey_login.py` avec un authentificateur logiciel (`tests/webauthn_soft_authenticator.py`).
   Choix faits dans ce lot :
   - Activation : `RealmConfig.passkey_login_enabled` **ou** la variable d'environnement CSV `PASSKEY_LOGIN_ENABLED_REALMS` (même logique que `OIDC_NATIVE_SESSION_ENABLED_REALMS`, pour un pilote sans UI).
   - Refus aussi si Keycloak signale une *required action* (`UPDATE_PASSWORD`…) : l'utilisateur est renvoyé vers le mot de passe.
   - Événements d'audit catalogués : `BST-AUTH-0010` (succès) et `BST-AUTH-2010` (échec, raison dans `details.reason`).
   - Les deux routes sont ajoutées à `PUBLIC_ROUTES_ALLOWLIST` et aux chemins de login du moteur de bannissement (fail closed). Rien à changer côté nginx : `location ^~ /auth/` est déjà public et limité par `portal_login`.
   - Le MFA admin n'est **pas** encore satisfait par une connexion passkey (décision 2 ouverte) : un admin repasse par son 2ᵉ facteur, comme aujourd'hui.
2. **Profil** : enrôlement et gestion des clés, ré-auth récente, JS, templates.
3. **UX login** : conditional UI, bouton, écran intermédiaire après login par mot de passe.
4. **Admin et exploitation** : toggle realm, vue et révocation admin, révocation à la désactivation, E2E, runbook.

## 9. Décisions à valider
1. **Passkey = facteur unique** (comme Amazon, remplace mot de passe + OTP) **ou** passkey en complément d'un mot de passe ? *Recommandé : facteur unique avec UV obligatoire.*
2. **Admins** : une connexion par passkey satisfait-elle le MFA admin (cookie `mfa_ok` posé directement) ? *Recommandé : oui.* Faut-il ensuite migrer l'actuel `AdminMfaCredential.webauthn_*` vers `user_passkeys` ?
3. **Activation** : opt-in par realm (recommandé pour un pilote) ou activation globale ?
4. **Nudge** : proposer la création d'une passkey après chaque login par mot de passe, ou seulement depuis le profil ?
