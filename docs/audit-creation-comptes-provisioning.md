# Audit de l'existant — Création de comptes bastion → Keycloak → provisioning API par appli

> Étape 0 du chantier « creation-comptes-bastion-keycloak-provisioning-api ».
> Aucun fichier de production modifié — rapport d'état uniquement.
> Date : 2026-07-30.

**Note préalable** : les documents référencés par la spec
(`phase4-rbac-group-import-keycloak.md`, `phase4-rbac-access-grants.md`,
`securite-anti-bruteforce-banning-generique.md`) ne sont **pas dans ce repo** (docs Pod
externes). Les points d'accroche cités ci-dessous ont été vérifiés directement dans le code.

---

## 1. Compte de service Keycloak et `get_admin_token()`

**Fichier réel : `app/rbac/keycloak_admin.py`.**

### 1.1 ⚠️ Constat important : le compte "sync" fait DÉJÀ de l'écriture

La prémisse de la spec (« tout l'existant RBAC n'était que lecture ») est **inexacte** :

- `logout_keycloak_user()` appelle `POST /admin/realms/{realm}/users/{id}/logout`, qui
  exige le rôle `realm-management:manage-users` (le code contient même un message d'erreur
  dédié `_manage_users_error()` qui documente ce prérequis).
- Ce logout SSO utilise le **même** couple `keycloak_admin_client_id` /
  `keycloak_admin_client_secret_encrypted` que la sync des groupes.

Conséquence : soit le compte `bastion-admin-sync` en prod a **déjà** `manage-users`
(dérive par rapport au principe de moindre privilège acté), soit la fonctionnalité
« déconnexion SSO d'un utilisateur » est cassée en prod. **À vérifier côté Keycloak prod
avant l'implémentation** (impossible à confirmer depuis le repo). Le tableau du §4 de la
spec doit être corrigé en conséquence : le compte existant n'est pas « lecture seule ».

Cela ne remet pas en cause la décision d'un compte `bastion-admin-provision` séparé — au
contraire, cela plaide pour clarifier aussi le périmètre réel du compte existant.

### 1.2 `get_admin_token()` n'est PAS paramétrable tel quel

```274:300:app/rbac/keycloak_admin.py
async def get_admin_token(realm: RealmConfig, settings: Settings) -> str:
    if not realm.keycloak_admin_client_id or not realm.keycloak_admin_client_secret_encrypted:
        raise ValueError(
            "Compte de service non configuré pour ce realm. "
            "Renseignez le Client ID/Secret (admin) dans la fiche realm."
        )
    token_endpoint = f"{realm.issuer_url.rstrip('/')}/protocol/openid-connect/token"
    client_secret = decrypt_secret(realm.keycloak_admin_client_secret_encrypted, settings)
    # ... POST client_credentials, gestion invalid_client / access_token manquant
```

La fonction lit les colonnes `keycloak_admin_*` **en dur** sur `RealmConfig` : elle n'accepte
pas un couple client_id/secret en paramètre. Ajustement à prévoir (léger, pas de duplication) :

- extraire le cœur en `_client_credentials_token(issuer_url, client_id, secret_encrypted, settings)`,
- garder `get_admin_token(realm, settings)` comme wrapper (compat sync/logout),
- ajouter `get_provision_token(realm, settings)` lisant les nouveaux champs
  `keycloak_provision_client_id` / `keycloak_provision_client_secret_encrypted`.

La gestion d'erreurs différenciée existe bien et est réutilisable : client non configuré,
`invalid_client`, `access_token` manquant, 403 avec messages par rôle manquant, timeout
(`httpx.TimeoutException` / `RequestError` → `ValueError` explicite).

### 1.3 Helpers HTTP admin : extensions nécessaires

- `_admin_get()` et `_admin_post()` existent, mais `_admin_post()` **ne supporte pas de body
  JSON** (il ne sert qu'au logout, POST sans payload). La création d'utilisateur
  (`POST /users` + body JSON + lecture du header `Location` pour récupérer l'id créé) et le
  reset de mot de passe (`PUT /users/{id}/reset-password`) nécessitent :
  - un paramètre `json=` sur `_admin_post` (ou une variante),
  - un nouveau `_admin_put` (n'existe pas) pour `PUT /users/{id}/groups/{group_id}` et
    `reset-password`.
- Ces helpers prennent `realm` et appellent `get_admin_token` en dur → il faudra leur passer
  le token (ou une fonction de token) pour utiliser le compte provision, sinon toutes les
  écritures partiraient avec le compte sync.

### 1.4 Fonctions de lecture réutilisables telles quelles

- `search_keycloak_users(realm, query, settings)` — existe, **mais** utilise
  `GET /users?search=` (recherche substring/prefix). Pour le contrôle de doublon « exact
  match username + email » du §7 de la spec, prévoir un appel
  `GET /users?username=...&exact=true` (et idem `email`) — petite fonction à ajouter, le
  filtre côté client sur les résultats de `search` serait fragile.
- `fetch_keycloak_user(realm, kc_user_id, settings)` — existe (retourne `None` si 404),
  utile pour la fiche compte.
- `fetch_user_groups`, `fetch_group_members`, `count_keycloak_users` — existants.

---

## 2. Modèle driver existant (`app/bastion/drivers/`)

### 2.1 ⚠️ État réel : seuls `crushftp.py` et `generic.py` sont implémentés

| Fichier | État réel |
|---|---|
| `base.py` | ABC `RoboticDriver` : `login()`, `get_username()`, `fingerprint()` + dataclasses `DriverLoginResult`, `SetCookieSpec` + exceptions (`RoboticLoginError`…) |
| `crushftp.py` | Implémenté (login robotic via `/WebInterface/function/`, logout, fingerprint) |
| `generic.py` | Implémenté (form login, Basic Auth, X-WSSE — pas une classe `RoboticDriver`, des fonctions) |
| `grafana.py` | **Placeholder vide** (`"""Module placeholder — Phase 2."""`) |
| `wikijs.py` | **Placeholder vide** |
| `driver_effective_config.py` | **Placeholder vide** |

La spec (§2, §5.1) présente `grafana.py` et `wikijs.py` comme des drivers existants « déjà
utilisés pour le login robotic » : **c'est faux**, ils sont à écrire intégralement. Idem
`driver_effective_config.py` : la config effective des drivers vit en réalité dans
`bastion_fields.py` (constantes, `resolve_robotic_driver()`, validation des champs
`login_*`) + les colonnes du modèle `App` (`robotic_driver`, `auth_mode`, `login_form_url`,
`login_username_field`, `login_password_field`, `login_extra_fields`, `login_http_method`,
`credential_mode`, `identity_format`).

### 2.2 Pas de registre de drivers — dispatch en dur

Il n'existe **aucun registre nom→driver**. Le dispatch est codé en if/elif dans
`app/robotic/impersonate_service.py` (instancie `CrushFTPDriver()` directement, appelle
`generic_form_login()` etc.). Pour le provisioning, recommandation :

- créer `app/bastion/drivers/base_provisioning.py` avec le Protocol
  `AccountProvisioningDriver` (comme prévu §5.1) **+ un registre explicite**
  (`PROVISIONING_DRIVERS: dict[str, AccountProvisioningDriver]`) plutôt que de reproduire
  le if/elif — sans toucher au dispatch robotic existant ;
- **ne pas** étendre l'ABC `RoboticDriver` avec `create_account()` : cela forcerait des
  méthodes abstraites factices sur des drivers qui ne provisionnent pas, et le driver
  wikijs/grafana de provisioning n'aura pas de pendant robotic. Interface séparée = aucun
  risque de casser l'impersonation actuelle.

### 2.3 CrushFTP : pas d'authentification admin réutilisable telle quelle

Le driver CrushFTP actuel se connecte **en tant que l'utilisateur cible** avec les
credentials du vault (impersonation), pas en tant qu'admin. Il n'y a **aucun appel à l'API
d'administration CrushFTP** (`setUserItem` & co) dans le repo.

En revanche, la **mécanique de session** est réutilisable pour un compte admin : `login()`
(POST `command=login`, cookies `CrushAuth`/`currentAuth`, token `c2f`) fonctionne à
l'identique pour un compte admin CrushFTP. Le driver de provisioning devra :
- ajouter les appels de gestion utilisateur (`command=setUserItem`, XML utilisateur),
- s'authentifier avec un credential **admin** dédié — champs `crushftp_admin_*`
  sur `App` (Basic Auth, distinct du vault `AppCredential` individuel)
  existant `AppCredential` (credential « robotic » de l'appli), ce qui évite un nouveau
  stockage de secret.

Donc : « le driver CrushFTP n'a pas d'authentification admin réutilisable telle quelle,
mais son mécanisme de login/session est directement transposable ; l'API de gestion
utilisateurs est à écrire ».

### 2.4 `generic.py` comme no-op

RAS : un driver de provisioning `generic` retournant `not_applicable` est trivial et ne
touche pas aux fonctions de login existantes du module.

---

## 3. Vault applicatif (`user_app_credential_service.py`)

**Implémentation réelle : `app/vault/user_app_credential_service.py`**
(`app/user_app_credential_service.py` n'est qu'un shim de compatibilité `import *`).

Signature exacte du point d'entrée utile au provisioning :

```154:164:app/vault/user_app_credential_service.py
def set_user_credential(
    db: Session,
    app_slug: str,
    keycloak_user_id: str,
    robotic_username: str,
    plain_password: str,
    settings: Settings,
    *,
    actor: str = "system",
    ip_address: str | None = None,
) -> UserAppCredential:
```

- Chiffrement Fernet via `app.secret_crypto.encrypt_secret(plaintext, settings)` — **rien à
  dupliquer**, la fonction gère aussi l'upsert (rotation), `is_active`, et l'audit
  `credential.user.set`.
- Clé d'unicité : `(app_slug, keycloak_user_id)` (`uq_user_app_credential`). Le credential
  généré par un driver de provisioning ne peut donc être stocké **qu'après** la création
  Keycloak réussie (il faut le `keycloak_user_id`) — cohérent avec l'ordre du flux §1 de la
  spec.
- ⚠️ `set_user_credential` fait un `db.commit()` interne (comme `log_action`). Le pipeline
  de provisioning multi-étapes doit en tenir compte : pas de grosse transaction englobante,
  chaque étape persiste son état au fil de l'eau (ce qui colle au principe « chaque étape a
  son statut »).

---

## 4. AccessGrant — point d'accroche du hook post-création

**Endpoint réel : `POST /admin/rbac/grants` → `admin_rbac_grants_create()` dans
`app/admin/rbac_access.py`** (fonction `async`, donc les drivers httpx async s'y intègrent
sans peine). La logique métier est dans `app/rbac/grants_service.py::create_grant(db, data,
granted_by)` (add + flush, pas de commit).

Séquence actuelle dans l'endpoint : validation Pydantic (`AccessGrantCreate`) →
`create_grant()` → `db.commit()` → `_log_grant_mutation()` → réponse JSON ou redirect.

**Point d'accroche recommandé** : dans l'endpoint, après le `db.commit()` du grant
(le grant doit être persisté même si le provisioning échoue — pas de rollback du droit),
sous condition `data.resource_type == "application"` et appli avec `provisioning_driver`
configuré. Pas de duplication : appeler une fonction de service unique
(ex. `provision_for_grant(db, grant, settings, actor=...)`) partagée avec le flux de
création de compte.

Deux précisions que la spec §5.3 doit trancher :
- `subject_type` peut être `group` **ou** `user`. Un grant **groupe** ne référence pas un
  utilisateur unique — première itération : ne déclencher le hook que pour
  `subject_type == "user"` (sinon il faudrait provisionner tous les membres du groupe,
  périmètre bien plus large).
- Le grant porte un `keycloak_user_id` ; la corrélation se fait donc via
  `BastionAccount.keycloak_user_id`. Si aucun `BastionAccount` n'existe pour cet
  utilisateur (utilisateur créé directement dans Keycloak), le hook ne peut pas
  provisionner → statut/message explicite plutôt que silence.

À noter : la suppression (`DELETE /admin/rbac/grants/{grant_id}`) existe avec ses gardes
(anti auto-révocation portal_admin) — le choix spec « pas de déprovisioning au retrait »
n'exige aucun changement de ce côté.

---

## 5. Modèles et migrations — conventions à respecter

### 5.1 ⚠️ La table catalogue s'appelle `apps`, pas `applications`

Le modèle §3 de la spec écrit `ForeignKey("applications.id")` : **la table réelle est
`apps`** (modèle `App`, `__tablename__ = "apps"`). L'existant `AccessGrant` montre la
convention à suivre : attribut `application_id = Column(Integer, ForeignKey("apps.id"))`
(nom d'attribut lisible, FK vers `apps.id`).

### 5.2 Conventions du repo à appliquer au modèle proposé

- `DateTime(timezone=True)` partout (la spec écrit `Column(DateTime, ...)` — à corriger),
  défaut `utcnow` (fonction du module `app.models`).
- `UniqueConstraint` **nommées** : `uq_realm_kc_group`, `uq_user_app_credential`,
  `uq_role_module`… → prévoir `uq_bastion_account_realm_username` et
  `uq_bastion_account_provisioning_app`.
- Statuts en `String` libre + constantes/normalisation en Python (pas d'Enum SQL) — comme
  `credential_mode`, `access_mode`.
- `RealmConfig` a déjà le bloc à imiter : `keycloak_admin_client_id`,
  `keycloak_admin_client_secret_encrypted`, `groups_sync_enabled`,
  `last_groups_sync_{at,status,error}`. Les nouveaux champs `keycloak_provision_client_id`,
  `keycloak_provision_client_secret_encrypted`, `provisioning_enabled` s'y calquent.
  ⚠️ Différence voulue à expliciter : `groups_sync_enabled` est aujourd'hui **auto-dérivé**
  dans `app/admin/realms.py` (`bool(client_id and secret)`), alors que la spec exige que
  `provisioning_enabled` soit un opt-in **explicite** — ne pas copier ce comportement.
- Migrations Alembic : fichiers `NNN_slug.py` sous `migrations/versions/`, revision =
  nom du fichier, chaînage linéaire. **Tête actuelle : `044_security_rate_events`** → la
  nouvelle migration sera `045_bastion_accounts_provisioning` (tables + colonnes App/RealmConfig,
  pattern idempotent `inspect(bind).get_table_names()` comme la 044).

### 5.3 Point d'extension `provisioning_driver` sur `App`

Sans risque : `App` a déjà `robotic_driver = Column(String, nullable=True)` ; une colonne
sœur `provisioning_driver` (nullable, `None` = SSO seul) suit le même schéma.
`bastion_fields.py` accueille naturellement `PROVISIONING_DRIVERS` +
`normalize_provisioning_driver()` à côté de `ROBOTIC_DRIVERS` / `resolve_robotic_driver()`.
Rien dans `bastion_fields.py` ne casse : le module est purement additif (constantes +
fonctions pures, pas d'état).

Aucun symbole `BastionAccount`, `BastionAccountProvisioning` ou `provisioning_driver`
n'existe déjà dans le repo — pas de collision.

---

## 6. Audit — `log_action()`

Signature confirmée (`app/audit.py`) :

```56:65:app/audit.py
def log_action(
    db: Session,
    actor: str,
    action: str,
    target: str | None = None,
    details: dict[str, Any] | None = None,
    ip_address: str | None = None,
    *,
    forward_to_siem: bool = True,
) -> AuditLog | None:
```

- Ne lève jamais, commit interne, normalise l'acteur (UUID Keycloak → email/username via
  `normalize_audit_actor`), enchaîne le forwarding SIEM. Réutilisable tel quel.
- La sévérité est **dérivée du nom de l'action** (`derive_severity`) : `*failed*` → error,
  `*created*`/`*success*` → success. Les noms proposés au §7 de la spec
  (`account.keycloak_create_failed`, `account.provisioning.success`…) tombent
  automatiquement dans les bonnes sévérités — garder ces suffixes.
- Convention `target` observée : `app:{slug}/user:{kc_id}` (cf. `credential.user.set`) —
  à réutiliser, ex. `realm:{slug}/account:{username}`.

---

## 7. Divers vérifié en passant

- **Rate limiting** (§7 spec) : le module anti-brute-force réel
  (`app/security/banning/`) est un middleware de bans par IP piloté par des règles typées
  en base (`security_ban_rules` : `hammering_login`, `successful_login`…). Il n'existe
  **pas de rate limiter générique par route** à brancher sur `/admin/rbac/users/new` : soit
  ajouter un `rule_type` dédié (mécanique existante, seed en migration comme la 044), soit
  s'en tenir à l'audit renforcé en première itération. À trancher, mais ne pas inventer un
  second système.
- **UI** : `/admin/rbac/users` (annuaire), `/admin/rbac/users/search`,
  `/admin/rbac/users/{keycloak_user_id}` existent déjà dans `rbac_access.py` — la route
  spec `/admin/rbac/users/new` s'insère dans ce router sans conflit (attention à l'ordre
  de déclaration : `/users/new` doit être déclarée **avant** `/users/{keycloak_user_id}`).
  `realm_form.html` fournit bien le pattern formulaire + placeholder de secret masqué à
  répliquer pour les champs provision.
- **Realms** : la sélection « realms cibles » du formulaire devra filtrer
  `enabled == True` **et** `provisioning_enabled == True` (spec §4 — confirmé faisable,
  `RealmConfig.enabled` existe).

---

## 8. Synthèse des ajustements à faire sur la spec avant l'Étape 1

1. **§2/§5.1 — corriger l'inventaire des drivers** : `grafana.py`, `wikijs.py` et
   `driver_effective_config.py` sont des placeholders vides. Les drivers de provisioning
   Grafana/Wiki.js sont des créations complètes, pas des extensions. La config driver
   effective vit dans `bastion_fields.py` + colonnes `App`.
2. **§4 — corriger la prémisse « lecture seule »** : le compte admin existant sert déjà à
   une écriture (`POST /users/{id}/logout`, rôle `manage-users` requis pour le logout SSO).
   Vérifier les rôles réels de `bastion-admin-sync` en prod avant de figer le tableau des
   comptes de service.
3. **§4 — refactor `get_admin_token()`** : extraire le cœur client_credentials paramétré
   (issuer + client_id + secret chiffré) ; ajouter `_admin_post(json=...)` et `_admin_put`
   (n'existent pas) ; faire passer le choix du compte (sync vs provision) aux helpers.
4. **§7 — doublon exact** : `search_keycloak_users` est une recherche floue ; ajouter un
   appel `GET /users?username=...&exact=true` (+ email) pour le contrôle pré-création.
5. **§3 — modèle** : `ForeignKey("apps.id")` (pas `applications.id`),
   `DateTime(timezone=True)`, contraintes uniques nommées, migration `045_*` idempotente.
6. **§4 — `provisioning_enabled`** : opt-in explicite, ne pas copier l'auto-dérivation
   actuelle de `groups_sync_enabled` dans `realms.py`.
7. **§5.3 — hook grants** : limiter aux grants `subject_type == "user"` en première
   itération ; définir le comportement quand aucun `BastionAccount` ne correspond au
   `keycloak_user_id` du grant (message explicite, pas de silence).
8. **§5.1 — architecture drivers** : Protocol `AccountProvisioningDriver` séparé + registre
   nom→driver ; ne pas étendre l'ABC `RoboticDriver`.
9. **§5.4 / §13 — credential admin CrushFTP** : bloc dédié `crushftp_admin_*`
   (Basic Auth), **pas** le vault `AppCredential` individuel
   existant pour le compte admin CrushFTP du driver de provisioning ; le credential
   *généré pour l'utilisateur* va dans `UserAppCredential` via `set_user_credential()`
   (réutilisable tel quel, commit interne à intégrer au design du pipeline).
10. **§7 — rate limiting** : pas de rate limiter générique par route existant ; choisir
    entre un `rule_type` dédié dans `security_ban_rules` ou audit seul en v1.

## 9. Tâche 0 (Étape 1) — vérification des rôles `bastion-admin-sync` en prod

> Ajouté le 2026-07-30 lors de l'implémentation Étape 1.

**Statut : vérification console Keycloak à faire par Vincent** — impossible depuis le repo
(aucun accès à la console Keycloak de prod depuis l'environnement de dev). À vérifier :
*Clients → bastion-admin-sync → Service account roles* : la présence ou non de
`realm-management:manage-users`.

**Mitigation appliquée côté code sans attendre la réponse** (couvre les deux hypothèses) :
`logout_keycloak_user()` utilise désormais le **compte provisioning dédié**
(`keycloak_provision_client_id`) dès qu'il est configuré pour le realm, et ne retombe sur le
compte sync historique que pour les realms sans compte provision (compat). Conséquences :

- si `bastion-admin-sync` a aujourd'hui `manage-users` (dérive) : une fois le compte
  `bastion-admin-provision` configuré sur le realm, le rôle `manage-users` peut être
  **retiré** du compte sync — le logout SSO passera par le compte d'écriture dédié ;
- si `bastion-admin-sync` n'a pas `manage-users` (logout SSO cassé) : la configuration du
  compte provision **répare** le logout SSO au passage.

### Impact sur les 3 points ouverts du §9 de la spec

- **Mot de passe initial** : Keycloak supporte `credentials[{temporary: true}]` +
  `requiredActions: ["UPDATE_PASSWORD"]` via le même `POST /users` — aucun obstacle
  technique côté code existant ; la recommandation « généré + UPDATE_PASSWORD » reste la
  plus simple à implémenter (pas d'affichage de secret à gérer).
- **Applis prioritaires** : seul CrushFTP a une base de code driver réelle à étendre ;
  Grafana/Wiki.js partent de zéro. Prioriser CrushFTP (+ `generic` no-op) en v1 est le
  choix le moins risqué.
- **Désactivation** : rien dans l'existant ne s'y oppose plus tard (le Protocol proposé
  prévoit `disable_account`) ; le choix « action manuelle uniquement en v1 » n'exige aucun
  changement des endpoints grants actuels.
