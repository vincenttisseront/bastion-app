# ActiveSync — inventaire des devices par utilisateur, blocage des inconnus + approbation self-service dans le portail

> Document de référence / prompt Cursor pour le repo `bastion-app`.
> Demande initiale (Vincent, tâche Pod 2026-08-14) : *« si active sync activé sur un domaine,
> mettre dans la fiche user la liste des devices autorisés, bloquer les nouveaux avec demande
> de validation dans le portail user »*.
> **Version 2 (2026-08-14) — révisée après l'audit factuel du repo** (§1). Trois prémisses de
> la v1 étaient fausses et sont corrigées ici : le registre des codes de logs est à jour, le
> flux ActiveSync est déjà exempté de l'anti-brute-force, et la fiche user HTML n'est pas la
> route que je supposais. Un problème non anticipé a été trouvé : le throttle de logs rend le
> backfill par parsing de logs structurellement incomplet (§6).
> **Version 3 (2026-08-15) — Lot 1 implémenté, vérifié et livré** (§9.bis).
> **Version 4 (2026-08-15) — Lot 1.5 livré** (§10.bis) : les appareils non identifiés portent
> désormais une `miss_reason`, et cette taxonomie a tranché le sort du fail-open (§3.1, §11).
> **Version 5 (2026-08-15) — Lot 1.6 livré** : la taxonomie `miss_family` vit dans le code
> (`decoder_failure` / `no_device_sent`), et **une erreur de rédaction du §10 est corrigée** :
> les exemptions ne sont pas de même nature (§3.1.bis).
> **Version 6 (2026-08-15) — Lot 1.7 livré** : `miss_family` est lisible depuis `/admin/logs`,
> le critère de bascule n°2 est donc réellement mesurable sans accès SQL (§11).
> **Version 7 (2026-08-15) — anomalie constatée en recette** : l'inventaire fonctionne (log
> `BST-AUTH-0007` enrichi, `device_status: pending`), mais **la section « Appareils
> ActiveSync » de la fiche user n'est pas visible**. Correctif Lot 1.8 au §13, et §4.1 révisé :
> **le rapprochement se fait sur l'email**, pas sur le `keycloak_user_id`.
> **Version 8 (2026-08-16) — modèle de menace explicite + détection de clone (§14)**, en
> réponse à la question « le numéro de série iPhone est-il spoofable ? ». Réponse : oui,
> trivialement. Ce que ça change est écrit au §14.1.
> **Version 9 (2026-08-16) — état réel du repo croisé avec la spec (§15)**. Constat majeur :
> `activesync_device_control=True` **ne refuse rien** aujourd'hui (seul `blocked_by_admin`
> coupe) — le gate est un interrupteur branché sur rien, l'activer donnerait une fausse
> assurance. Prochain lot décidé : **Lot 2**, libellé « Inventorié » replié dedans.
> **Version 10 (2026-08-16) — Lot 2 livré** (§15.4). L'enforcement, le portail utilisateur et
> l'écran de bascule existent. **Le gate reste `off` partout** : il ne reste plus que la
> décision d'activation, dont le runbook est au §16.
> **Version 11 (2026-08-16) — raffinements Lot 3 avant implémentation (§14.2.bis)** :
> DeviceType/UA défaut = alerter (403 seulement sur contradictions listées) ;
> multi-origine resserré sur simultanéité réelle ; vélocité à seuil haut post-bascule ;
> dérive modèle affiche ancien + nouveau modèle. Sync Pod ↔ `docs/` obligatoire (§15).
> Voisins directs : `docs/audit-anti-bruteforce-preexistant.md`,
> `systeme-codes-logs-criticite.md`, `decouverte-sous-domaines-approval-blacklist.md` (même
> patron pending / approved / blocked), `phase4-rbac-access-grants.md`,
> `phase4-portail-utilisateur-dashboard-part2.md`.

---


> **Copie dépôt :** `docs/activesync-devices-inventaire-approbation-user.md` (v11).
> La version Pod est celle où l'on itère ; **resynchroniser cette copie à chaque
> incrément de version** (§15). §5 = premier point de divergence (codes par lot).

## 0. État des lieux (audit repo livré le 2026-08-14)

### 0.1 Ce qui existe déjà

| Élément | Emplacement |
|---|---|
| Handler | `app/subdomain/activesync_auth.py:125-363` (`GET /internal/activesync-auth`), monté `app/main.py:338` |
| Sous-requête nginx | `docker/nginx/snippets/activesync_auth_common.conf:4-25`, incluse par `subdomain_auth_common.conf:40` |
| `location` clientes | générées par `app/bastion/nginx_subdomain_export.py:99-188` (`_activesync_locations()`), injectées **uniquement si** `allow_activesync=True` |
| Décision d'autorisation | `activesync_auth.py:168` |
| Émission `activesync.allowed` | **trois sites** : `:195` (basic), `:277` (oidc), `:321` (breakglass) |
| Flag | `App.allow_activesync` (`app/models.py:64-65`), migration `042_allow_activesync.py`, forcé `False` hors `access_mode == "subdomain_proxy"` (`app/services.py:210,248`) |
| Identité Basic | `_basic_username()` (`:58-70`) — décodage Base64, partie avant `:`, **pas** de validation du mot de passe (c'est grommunio qui valide) |
| Throttle de logs | `_should_log_allow()` (`:73-84`) — 1 log / 60 s par clé `(app_slug, client_ip, actor)` |
| Extracteur `DeviceId` | **uniquement post-hoc côté SIEM** : `app/siem/formatters.py:200-220` parse `DeviceId` depuis la chaîne `uri` du log. `DeviceType` n'est extrait nulle part. |
| Catalogue de codes | `app/audit/event_catalog.py` — criticité **dérivée du numéro** : `0001-0999` INFO, `1000-1999` NOTICE, `2000-2999` WARNING |
| CSRF | `verify_csrf_token` (`app/web/flash.py:95-110`) existe mais **n'est pas appliqué** sur les POST du portail |

Log de référence en production (`BST-AUTH-0007` / `ACTIVESYNC_ALLOWED`, domaine `AUTH`, INFO) :

```json
{
  "uri": "/Microsoft-Server-ActiveSync?User=vincent.tisseront@ar-systems.fr&DeviceId=FBJV9GQU3D7890K74K10V5IC5K&DeviceType=iPhone&Cmd=Ping",
  "host": "webmail.ar-systems.fr",
  "user_agent": "Apple-iPhone13C4/2307.71",
  "client_kind": "iphone",
  "activesync": true,
  "auth_source": "basic",
  "application_id": 2,
  "allow_activesync": true
}
```

### 0.2 Bonnes nouvelles confirmées par l'audit

- ✅ **La query string est disponible dans le handler** : nginx transmet
  `X-Original-URI = $request_uri` (`activesync_auth_common.conf:14`). Aucune modification
  nginx nécessaire pour extraire `DeviceId`/`DeviceType`.
- ✅ **Aucune purge sur `audit_logs`** (seuls `siem_outbox` 24 h, `breakglass_sessions` 7 j,
  `sso_session_anchors` 30 j le sont) → la fenêtre d'historique est illimitée.
- ✅ **L'anti-brute-force est déjà exempté par construction** :
  `/internal/activesync-auth` n'est pas dans `_SENSITIVE_PREFIXES`
  (`app/security/banning/engine.py:108-130`), `SecurityBanMiddleware` sort immédiatement
  (`middleware.py:38-39`), aucun appel à `evaluate_login_attempt` /
  `record_sensitive_request` dans `activesync_auth.py`, pas de `limit_req`,
  `modsecurity off`. **Le risque de lockout que la v1 traitait comme principal n'existe
  pas** — il reste à protéger par un test de non-régression (§7), pas à corriger.
- ✅ **Le registre de codes est à jour** (`docs/systeme-codes-logs-criticite.md:22-43`,
  mis à jour le 2026-08-14, 14 codes AUTH : `0001`→`0008`, `2001`→`2005`, `4001`). La v1
  parlait d'une dette de doc `0004`→`0007` : **c'est faux, il n'y a rien à solder**.
  Prochains libres : **`BST-AUTH-0009`** (INFO), **`BST-AUTH-1001`** (NOTICE, tranche
  vierge), **`BST-AUTH-2006`** (WARNING).

### 0.3 Écarts / pièges révélés par l'audit — à traiter

| # | Constat | Conséquence sur la spec |
|---|---|---|
| A | **Throttle de logs sans le device** : `_should_log_allow` cadence sur `(app_slug, client_ip, actor)`. Deux téléphones du même utilisateur derrière la même IP **se masquent mutuellement**. | Le backfill par parsing de logs est **structurellement incomplet**. → correctif de clé + fenêtre d'observation (§6). |
| B | **Aucun `keycloak_user_id` sur ce chemin** : pas d'appel Keycloak, et `find_keycloak_user_exact` (`rbac/keycloak_admin.py:324`) est async — inutilisable dans un chemin frappé à chaque `Ping`. Le seul mapping local, `BastionAccount` (`models.py:656-669`), est incomplet par nature. | L'identifiant EAS normalisé devient **la** clé d'identité. Résolution Keycloak repoussée hors du chemin chaud (§2.1). |
| C | **`X-Original-Method` n'est pas transmis** par le snippet ActiveSync (il l'est ailleurs, `vhost_sso_portal.conf.template:72`), et la regex `location ~* ^/Microsoft-Server-ActiveSync` (`nginx_subdomain_export.py:121`) matche **toutes** les méthodes, sans `limit_except`. Autodiscover a sa propre location (`:153`) vers le même endpoint. | Le handler ne peut pas distinguer un `OPTIONS`. → ajout d'un header nginx + exemptions explicites (§3.1). |
| D | **Trois sites d'émission** de `activesync.allowed` (basic / oidc / breakglass). | L'enforcement doit être posé en **un seul point** en amont, pas dupliqué trois fois (§3). |
| E | **Fiche user HTML = `/admin/rbac/users/view`** (`app/admin/rbac_accounts.py:294`, template `admin/rbac/user_view.html`). `/admin/rbac/users/{keycloak_user_id}` est une **API JSON** (`rbac_access.py:956`). | Corriger la cible UI (§4.1). |
| F | **CSRF non appliqué sur les POST du portail** alors que `verify_csrf_token` existe. | Appel **explicite** obligatoire sur les nouvelles routes (§4.2) + dette à traiter à part (§8). |
| G | `securite-anti-bruteforce-banning-generique.md` n'existe pas dans le repo ; l'équivalent in-repo est `docs/audit-anti-bruteforce-preexistant.md`. | Référence corrigée partout. |

---

## 0.bis Décisions actées avec Vincent (2026-08-14)

1. **Qui valide un device inconnu** → **l'utilisateur lui-même**, depuis le portail.
   **L'admin garde la main** : il peut bloquer/révoquer un device suspect ou déclaré volé, et
   ce blocage **prime toujours** (un device `blocked` par un admin n'est **jamais**
   réactivable par l'utilisateur).
2. **Pas de mode apprentissage** (pas d'état intermédiaire à piloter, pas d'alerte sans
   blocage) : à l'activation, les devices connus sont approuvés en masse et tout inconnu est
   bloqué immédiatement.
3. **Mais bascule différée après une fenêtre d'observation**, imposée par le constat A :
   - **Lot 1** — extraction du device, inventaire, correctif du throttle, visibilité admin.
     **Zéro blocage, comportement actuel strictement inchangé.**
   - **Fenêtre d'observation** de quelques jours (un client EAS `Ping` en permanence : 48-72 h
     suffisent, hors téléphone éteint / congés).
   - **Lot 2** — enforcement 403, approbation dans le portail, écran de bascule + backfill.
   Ce n'est **pas** un mode apprentissage : c'est un délai entre deux livraisons, sans état
   intermédiaire à administrer.

---

## 1. Audit préalable — ✅ livré

Le rapport d'audit (fichier/ligne) est intégré au §0. **Ne pas relancer d'audit** ; il reste
seulement deux vérifications ponctuelles à faire au moment d'implémenter :

1. **Comment `/admin/rbac/users/view` est-elle clé** (paramètre `user_id`, `email`, `realm_id` ?)
   → détermine le join avec `activesync_devices` (§4.1).
2. **Existe-t-il un mécanisme d'envoi d'email réutilisable** (le récapitulatif quotidien
   `BST-ADM-3001` / `portal_settings.daily_re…` suggère que oui) → détermine si la
   notification email du §3.3 entre dans le périmètre ou est différée. **Ne pas construire un
   nouveau système d'envoi** : si rien n'est réutilisable en l'état, la notification reste
   portail-only et l'email est reporté.

---

## 2. Modèle de données

### 2.1 Table `activesync_devices`

```python
class ActiveSyncDeviceStatus(str, Enum):  # pattern constantes string du projet, pas d'enum SQL
    PENDING  = "pending"    # vu, en attente de validation par l'utilisateur
    APPROVED = "approved"   # autorisé (utilisateur, admin, ou backfill)
    REJECTED = "rejected"   # refusé par l'utilisateur (réversible par lui)
    BLOCKED  = "blocked"    # bloqué par un admin — NON réversible par l'utilisateur

class ActiveSyncDevice(Base):
    __tablename__ = "activesync_devices"

    id: Mapped[int] = mapped_column(primary_key=True)
    application_id: Mapped[int] = mapped_column(ForeignKey("apps.id"), index=True)  # nom réel à confirmer

    # --- Identité (cf. constat B) ---
    user_key: Mapped[str] = mapped_column(String, index=True)  # identifiant Basic normalisé (lowercase) = LA clé
    keycloak_user_id: Mapped[Optional[str]] = mapped_column(nullable=True, index=True)  # best-effort, hors chemin chaud
    realm_id: Mapped[Optional[int]] = mapped_column(nullable=True, index=True)

    device_id: Mapped[str] = mapped_column(String, index=True)  # DeviceId EAS, casse PRÉSERVÉE
    device_type: Mapped[Optional[str]] = mapped_column(nullable=True)   # iPhone, Android, WindowsOutlook15...
    friendly_name: Mapped[Optional[str]] = mapped_column(nullable=True) # libellé posé par l'utilisateur
    user_agent: Mapped[Optional[str]] = mapped_column(nullable=True)    # dernier UA vu
    client_kind: Mapped[Optional[str]] = mapped_column(nullable=True)   # réutilise la valeur déjà calculée

    status: Mapped[str] = mapped_column(String, default="pending", index=True)
    source: Mapped[str] = mapped_column(String)   # "observed" | "backfill" | "user" | "admin"

    first_seen_at: Mapped[datetime]
    last_seen_at: Mapped[datetime]
    request_count: Mapped[int] = mapped_column(default=1)
    last_ip: Mapped[Optional[str]] = mapped_column(nullable=True)
    sample_source_ips: Mapped[list[str]] = mapped_column(JSON, default=list)  # capé à 10 IP distinctes

    decided_by: Mapped[Optional[str]] = mapped_column(nullable=True)  # email user OU admin
    decided_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    decision_note: Mapped[Optional[str]] = mapped_column(nullable=True)  # ex. "téléphone volé"
    blocked_by_admin: Mapped[bool] = mapped_column(default=False)     # verrou : l'utilisateur ne peut pas lever
```

Unicité : `UNIQUE (application_id, user_key, device_id)` → upsert
`INSERT ... ON CONFLICT DO UPDATE` en **une seule requête** (obligatoire vu la fréquence des
`Cmd=Ping`).

⚠️ **Identité (constat B)** : `user_key` est la seule clé fiable dans le chemin chaud — aucun
appel Keycloak, aucun `await` d'annuaire à chaque `Ping`. `keycloak_user_id` est renseignée
**hors chemin chaud** et de façon best-effort (job/résolution paresseuse au moment de
l'affichage admin, ou join sur `BastionAccount`), uniquement pour l'affichage et le
rapprochement avec la fiche user. **Un échec de résolution ne doit jamais bloquer un device**
ni empêcher l'affichage : c'est un problème d'annuaire, pas une décision de sécurité.

⚠️ **Ne pas normaliser le `device_id`** (pas de lowercase) : identifiant opaque sensible à la
casse ; le normaliser créerait des doublons ou des collisions.

### 2.2 Interrupteur par application

```python
activesync_device_control: Mapped[bool] = mapped_column(default=False)
activesync_device_control_enabled_at: Mapped[Optional[datetime]]
```

- `False` (défaut) : comportement actuel **strictement inchangé**, seul l'inventaire est alimenté.
- `True` : seuls les devices `approved` passent (§3).

Garde de cohérence, sur le modèle de ce qui existe déjà pour `allow_activesync`
(`app/services.py:210,248` le force à `False` hors `subdomain_proxy`) : interdire
`activesync_device_control=True` si `allow_activesync=False`, et le forcer à `False` dans les
mêmes conditions que `allow_activesync`.

Migration Alembic dédiée (numéro suivant le `042_allow_activesync` existant).

---

## 3. Extraction + enforcement dans `activesync_auth.py`

**Point d'insertion unique** (constat D) : en amont, dans le corps commun de
`activesync_auth()`, après la résolution de l'app et le contrôle `allow_activesync`
(`:168`) et après la détermination de `auth_source`/`actor`, mais **avant** les trois branches
qui émettent `activesync.allowed` (`:195` / `:277` / `:321`). Ne pas dupliquer la logique
dans les trois branches.

```python
device_id, device_type = extract_eas_device(original_uri)      # §3.1

if is_exempt_request(original_uri, original_method):           # OPTIONS, Autodiscover
    return allow_as_today(...)

if not device_id:                                              # non identifiable → jamais bloquant
    log_unidentified(...)                                      # BST-AUTH-2009 (throttlé)
    return allow_as_today(...)

device = upsert_activesync_device(...)                          # best-effort, try/except

if not app.activesync_device_control:                           # Lot 1 / contrôle off
    return allow_as_today(...)                                  # comportement actuel inchangé

if auth_source == "breakglass":                                 # échappatoire préservée
    return allow_as_today(...)                                  # + mention dans le détail du log

if device.status == "approved":
    return allow_as_today(...)                                  # log 0007 enrichi (§5)
return deny_activesync_device(device)                           # 403, §3.2
```

**Réutiliser l'extracteur, ne pas le dupliquer** : `app/siem/formatters.py:200-220` parse déjà
`DeviceId` depuis l'`uri`. Factoriser une fonction partagée (`extract_eas_device`) et faire
pointer le formatter SIEM dessus, en ajoutant `DeviceType` qui n'est extrait nulle part.

### 3.1 Pièges du protocole

1. **Query string classique** (forme observée en prod) :
   `?User=...&DeviceId=...&DeviceType=iPhone&Cmd=Ping` → parsing des paramètres. La query est
   disponible via `X-Original-URI` (`activesync_auth_common.conf:14`), déjà transmis.
2. **Query string encodée en base64** (EAS 14.x, fréquent sur Android/Outlook) :
   `?jAAJBBCgAAAA...` — blob binaire base64url (MS-ASHTTP : en-tête à taille fixe + champs
   `DeviceID`/`DeviceType` préfixés par leur longueur), **pas** de paramètres nommés.
   Décoder si possible.
   **Politique d'échec d'identification — révisée le 2026-08-15 :**
   - **Lot 1 (contrôle inactif) : fail-open.** Toute requête sans `device_id` extractible passe,
     avec un log `ACTIVESYNC_DEVICE_UNIDENTIFIED` portant sa `miss_reason` (§10.bis).
   - **Lot 2 (contrôle actif) : fail-closed — 403, comme un appareil inconnu.** C'est le seul
     contournement résiduel du contrôle : sans cela, quiconque détient le mot de passe franchit
     la porte du bastion en omettant simplement le `DeviceId`. Portée réelle limitée (grommunio
     exige lui-même un `DeviceId` pour synchroniser), mais un contrôle d'accès non étanche par
     construction n'est pas un contrôle d'accès.
   - Les cas légitimes **sans** `DeviceId` sont exemptés — mais **pas de la même façon**, voir
     §3.1.bis : c'est ce qui rend le fail-closed sûr, et c'est aussi ce qui doit être formulé
     avec précision dans les tests.
   - **Condition de bascule** : la fenêtre d'observation doit montrer qu'aucun client réel ne
     tombe dans les `miss_reason` de la famille « pas de device envoyé » (§11, critère 2).
3. **`OPTIONS /Microsoft-Server-ActiveSync`** (négociation de protocole, souvent sans DeviceId)
   → toujours autorisé. **Prérequis nginx (constat C)** : ajouter
   `proxy_set_header X-Original-Method $request_method;` dans
   `docker/nginx/snippets/activesync_auth_common.conf` (le pattern existe déjà dans
   `vhost_sso_portal.conf.template:72`), sinon le handler ne peut pas distinguer la méthode.
4. **`/Autodiscover/Autodiscover.xml`** (location dédiée `nginx_subdomain_export.py:153`) :
   exempté du contrôle device — pas de DeviceId, et le bloquer casserait la configuration
   initiale du compte.
5. **`auth_source == "breakglass"`** : exempté, pour ne pas fermer l'échappatoire
   d'administration. Tracé explicitement dans le détail du log.

### 3.1.bis Deux natures d'exemption — à ne pas confondre (correction du 2026-08-15)

Le §10 (prompt Lot 2) demandait initialement de vérifier que « les trois cas exemptés
n'atteignent jamais le point d'évaluation ». **C'est faux pour le break-glass**, et un test
écrit selon cette lettre échouerait sur un comportement correct — ou pousserait à retirer le
break-glass de l'inventaire, ce qui serait une régression.

| Cas | Mécanisme réel | Assertion de test correcte |
|---|---|---|
| `OPTIONS` | sort **en amont**, avant toute écriture d'inventaire | « n'atteint jamais le point d'évaluation » |
| `/Autodiscover/Autodiscover.xml` | sort **en amont**, avant toute écriture d'inventaire | « n'atteint jamais le point d'évaluation » |
| `auth_source=breakglass` | **traverse** `_evaluate_device()` avec `enforce=False` | « **jamais refusé** » (et **bien inventorié**) |

Le break-glass est inventorié **volontairement** (§9.bis) : c'est l'appareil qui vient
débloquer, il doit apparaître dans l'inventaire tout en restant hors de portée du refus.

### 3.2 Réponse de refus : **403, jamais 401**

- **`403 Forbidden`** + `X-Auth-Error: activesync-device-not-approved` : le client remonte une
  erreur de synchronisation et arrête de boucler agressivement.
- **Jamais 401** : un 401 déclenche sur iOS/Android une boucle de re-saisie de mot de passe et
  fait croire à l'utilisateur que son compte est cassé.
- **Anti-brute-force** : déjà exempté par construction (§0.2) — **rien à corriger**, mais
  ajouter un **test de non-régression** verrouillant ce fait (§7), car une future
  généralisation de `_SENSITIVE_PREFIXES` transformerait un téléphone non approuvé en cause de
  lockout pour son propriétaire.
- **Anti-flood de logs** : refus journalisé à la première occurrence puis agrégé (au plus
  1 événement / device / heure, avec `request_count`), sinon un seul device en boucle noie la
  table d'audit.
- **Best-effort strict** : si l'écriture d'inventaire échoue (DB indisponible), **ne jamais
  couper** un device déjà approuvé. Le refus ne doit venir que d'une décision explicite en
  base, jamais d'une panne de télémétrie (`try/except` autour de l'upsert).

### 3.3 Correctif d'observabilité — clé du throttle (constat A)

`_should_log_allow()` (`:73-84`) : ajouter le `device_id` à la clé
`(app_slug, client_ip, actor)` → `(app_slug, client_ip, actor, device_id)`.

Sans ce correctif, deux téléphones d'un même utilisateur derrière la même IP se masquent
mutuellement dans les logs : on ne peut ni auditer le parc, ni faire un backfill fiable.
**Ce correctif est dans le Lot 1 et vaut par lui-même**, indépendamment de l'enforcement.

### 3.4 Notification à l'utilisateur

Un device bloqué ne peut afficher aucune page web → canal hors bande. À la **première** mise
en `pending` seulement :
- portail : badge + bandeau (§4.2) ;
- email au titulaire **si et seulement si** un mécanisme d'envoi réutilisable existe (§1,
  vérification 2). L'email pointe vers le portail et ne contient **aucun lien d'approbation en
  un clic** : l'approbation exige une session SSO (un lien magique dans un mail serait une
  surface d'attaque).

---

## 4. Interfaces

### 4.1 Fiche user admin — `/admin/rbac/users/view` (constat E)

Section **« Appareils ActiveSync »** dans `templates/admin/rbac/user_view.html`, affichée
**uniquement** s'il existe au moins une app avec `allow_activesync=True` (sinon masquée, pas
vide). Design system existant (`.data-table`, `.badge-*`, `.btn`), pas de CSS nouveau.

| Appareil | Type | Application / domaine | Statut | 1ʳᵉ vue | Dernière sync | IP | Actions |
|---|---|---|---|---|---|---|---|
| `FBJV9GQU…IC5K` (iPhone de Vincent) | iPhone | grommunio / webmail.ar-systems.fr | ✅ Approuvé (utilisateur) | 12/06 | il y a 2 min | 82.x.x.x | Bloquer |
| `A1B2C3…` | Android | grommunio / webmail.ar-systems.fr | ⏳ En attente | il y a 20 min | il y a 1 min | 91.x.x.x | Approuver · Bloquer |

- `device_id` tronqué (8 premiers + 4 derniers) avec copie au clic ; `friendly_name` prioritaire.
- Badge de provenance : `utilisateur` / `admin` / `hérité (backfill)` / `observé`.
- ⚠️ **Libellé du statut tant que `activesync_device_control=False`** : ne pas afficher
  « En attente », qui laisse croire qu'une action est requise et qu'un utilisateur est bloqué.
  Tant que le contrôle est inactif, `pending` signifie « inventorié, non décidé » et **rien
  n'est bloqué** — l'afficher comme tel (ex. badge neutre « Inventorié »), et ne basculer sur
  « En attente de validation » qu'une fois le contrôle actif sur l'application.
- Actions admin : `Approuver` (dépannage), `Bloquer` (**raison obligatoire**, pose
  `status=blocked` + `blocked_by_admin=True`), `Débloquer` (réservé admin). Un device
  `blocked_by_admin` affiche « bloqué par un administrateur — l'utilisateur ne peut pas le
  réactiver ».
- **Join — révisé le 2026-08-15 (décision Vincent)** : **l'email est le pivot du
  rapprochement**, parce que c'est l'élément central de la gestion des utilisateurs dans le
  bastion. La requête doit donc partir de l'**email du compte affiché**, comparé à `user_key`
  (normalisation lowercase des deux côtés). Le `keycloak_user_id` n'est qu'un **complément
  opportuniste** : il peut affiner, il ne doit **jamais** conditionner l'affichage. Une section
  vide parce que `keycloak_user_id` est nul est un bug, pas un cas limite.
  Afficher les devices dont le rattachement est incertain avec un avertissement explicite,
  plutôt que de les faire disparaître silencieusement.
- L'API JSON `/admin/rbac/users/{keycloak_user_id}` (`rbac_access.py:956`) peut exposer les
  mêmes données, mais **la demande porte sur la fiche HTML**.

Côté fiche application : badge « N appareils · M en attente » calculé par `COUNT` (jamais par
chargement complet de la liste).

### 4.2 Portail utilisateur — `/profile`

- Bandeau d'alerte sur `/profile` **et** `/apps` si au moins un device `pending` :
  *« Un nouvel appareil (iPhone) tente d'accéder à votre messagerie depuis le 14/08 15:02 —
  Vérifier »*.
- Liste de **ses** devices uniquement : filtrage systématique sur l'identité de session,
  jamais sur un paramètre d'URL.
- Actions : `C'est mon appareil` → `approved` (`source=user`), `Ce n'est pas moi` →
  `rejected`, et **révocation** d'un device déjà approuvé.
- Détails affichés pour une décision éclairée : type, modèle/UA, IP, date/heure de première
  apparition, application concernée. Champ libre optionnel `friendly_name`.
- Un device `blocked_by_admin` est visible mais **non actionnable** (« bloqué par votre
  administrateur — contactez le support »).
- **Sécurité du parcours** : garde `require_user_enriched` (comme `/apps` et `/profile`,
  cf. `fix-controle-acces-routage.md`) ; **appel explicite de `verify_csrf_token`
  (`app/web/flash.py:95-110`) sur chaque nouvelle route POST** — il n'est pas appliqué
  automatiquement sur les POST du portail aujourd'hui (constat F) ; **jamais de `GET` qui
  modifie un statut** (un préchargement de lien approuverait un device).
- **Refus utilisateur = signal de sécurité fort** : « ce n'est pas moi » signifie
  potentiellement un mot de passe volé en cours d'exploitation → événement WARNING dédié (§5),
  visible côté admin/SIEM, pas seulement une ligne modifiée en base.

---

## 5. Audit — codes de logs

Source de vérité : **`app/audit/event_catalog.py`** (criticité dérivée du numéro). Le registre
`docs/systeme-codes-logs-criticite.md` est à jour — il s'agit d'**y ajouter** les nouveaux codes.

**Allocation réelle** (⚠️ le plan v2 sous-estimait le Lot 1 : les actions admin d'approbation
et de déblocage existent **dès** le Lot 1, elles auraient journalisé sous le code sentinelle
`BST-AUTH-0000`) :

| Code | Criticité (dérivée) | Label | Action | Lot | Statut |
|---|---|---|---|---|---|
| `BST-AUTH-0009` | INFO | `ACTIVESYNC_DEVICE_DISCOVERED` | `activesync.device_discovered` | 1 | ✅ livré |
| `BST-AUTH-1001` | NOTICE | `ACTIVESYNC_DEVICE_APPROVED` | `activesync.device_approved` | 1 | ✅ livré (`by=user\|admin\|backfill`) |
| `BST-AUTH-1004` | NOTICE | `ACTIVESYNC_DEVICE_UNBLOCKED` | `activesync.device_unblocked` | 1 | ✅ livré (déblocage admin) |
| `BST-AUTH-2008` | WARNING | `ACTIVESYNC_DEVICE_BLOCKED_BY_ADMIN` | `activesync.device_blocked` | 1 | ✅ livré (raison obligatoire) |
| `BST-AUTH-2009` | WARNING | `ACTIVESYNC_DEVICE_UNIDENTIFIED` | `activesync.device_unidentified` | 1 | ✅ livré (mesure du trou base64) |
| `BST-AUTH-1002` | NOTICE | `ACTIVESYNC_DEVICE_REVOKED` | `activesync.device_revoked` | 2 | ✅ livré (Lot 2 / PR #146) |
| `BST-AUTH-1003` | NOTICE | `ACTIVESYNC_DEVICE_CONTROL_ENABLED` | `activesync.device_control_enabled` | 2 | ✅ livré (Lot 2 / PR #146) |
| `BST-AUTH-2006` | WARNING | `ACTIVESYNC_DEVICE_DENIED` | `activesync.device_denied` | 2 | ✅ livré (Lot 2 / PR #146) |
| `BST-AUTH-2007` | WARNING | `ACTIVESYNC_DEVICE_REJECTED_BY_USER` | `activesync.device_rejected` | 2 | ✅ livré (Lot 2 / PR #146) |

**Mise à jour du 2026-08-16** : les quatre codes du Lot 2 sont **livrés** (PR #146), la mention
« réservé » est retirée du registre. Restent à créer au Lot 3 : `2010` à `2013` (§14.3).

Enrichir aussi `BST-AUTH-0007` : ajouter `device_id`, `device_type`, `device_status` (et
l'exemption `breakglass` le cas échéant) dans le JSON de détail — les valeurs sont déjà
disponibles, elles ne sont aujourd'hui lisibles qu'en parsant l'`uri` à la main.

**Piste SIEM** (cohérente avec `preparation-integration-siem.md` /
`prompt-cursor-detection-anomalies-logs-securite.md`) : plusieurs `device_discovered` pour un
même compte en peu de temps, ou un `device_rejected` suivi de nouvelles tentatives, doivent
pouvoir alimenter un `risk_flag=activesync_device_anomaly`.

---

## 6. Bascule sur un domaine — inventaire d'abord, puis backfill

Décision actée (§0.bis) : **deux livraisons séparées par une fenêtre d'observation**, parce
que le backfill par parsing de logs seul est incomplet (constat A).

**Lot 1 — inventaire, zéro blocage**
Extraction du device, table `activesync_devices` alimentée en continu (`source=observed`),
correctif de la clé du throttle (§3.3), header nginx `X-Original-Method`, section « Appareils
ActiveSync » de la fiche user admin (lecture + blocage admin possible dès maintenant, utile
pour un téléphone volé). `activesync_device_control` reste `False` partout.

**Fenêtre d'observation** : quelques jours (48-72 h suffisent en pratique). L'écran de
pré-visualisation affiche « inventaire alimenté depuis X jours ».

**Lot 2 — enforcement + portail + bascule**
1. **Écran de pré-visualisation** (`/admin/apps/{slug}/activesync/devices/preview`) : le bouton
   « Activer le contrôle des appareils » n'active **rien** ; il affiche ce que produirait le
   backfill, en distinguant les deux sources :
   - devices **observés** par l'inventaire (fiables, complets sur la fenêtre) ;
   - devices retrouvés **uniquement dans les logs antérieurs** (`activesync.allowed`, parsing
     de l'`uri`) — signalés comme *possiblement incomplets* à cause du throttle historique.
   Ex. *« 7 appareils pour 4 utilisateurs (6 observés, 1 uniquement dans les logs) — ils seront
   approuvés. Tout autre appareil sera bloqué immédiatement. »*
   Avertissement explicite : un device qui n'a pas synchronisé pendant la fenêtre
   d'observation et qui était masqué par le throttle **sera coupé** et devra être approuvé par
   son propriétaire dans le portail.
2. **Confirmation** → une seule transaction : création/mise à jour des devices en
   `status=approved`, `source=backfill`, `decided_by="backfill:<admin>"`, puis
   `activesync_device_control=True`, `activesync_device_control_enabled_at=now()`, et log
   `ACTIVESYNC_DEVICE_CONTROL_ENABLED` avec le décompte importé par source.

Backfill **idempotent** (rejouable sans doublon ni écrasement d'une décision existante) et
disponible aussi en commande CLI one-shot.

**Désactivation** (`activesync_device_control=False`) : ne supprime rien, suspend seulement
l'enforcement ; inventaire et décisions sont conservés.

---

## 7. Tests à ajouter (`pytest -k activesync`)

- Device connu `approved`, contrôle actif → 200, comportement identique à aujourd'hui.
- Device inconnu, contrôle actif → **403** + `X-Auth-Error: activesync-device-not-approved`,
  ligne `pending` créée, **aucun 401 émis**.
- Device inconnu, contrôle **inactif** (état du Lot 1) → 200, comportement actuel strictement
  inchangé, mais ligne d'inventaire créée.
- **Non-régression anti-brute-force** : `/internal/activesync-auth` reste hors de
  `_SENSITIVE_PREFIXES`, aucun appel à `evaluate_login_attempt` /
  `record_sensitive_request`, aucun lockout après N refus consécutifs (verrouille l'acquis
  du §0.2).
- 500 `Cmd=Ping` du même device → **une seule** ligne en base, `request_count` incrémenté,
  `sample_source_ips` plafonné à 10, et **pas** 500 logs de refus.
- **Throttle** : deux devices distincts, même utilisateur, même IP → **deux** événements
  distincts journalisés (test qui échoue avec la clé actuelle, constat A).
- `OPTIONS /Microsoft-Server-ActiveSync` (via `X-Original-Method`) et
  `/Autodiscover/Autodiscover.xml` → toujours autorisés, contrôle actif ou non.
- `auth_source=breakglass` → jamais bloqué, contrôle actif.
- Base64 : device identifié si décodage OK ; si décodage KO → autorisé + log
  `ACTIVESYNC_DEVICE_UNIDENTIFIED` (jamais de blocage silencieux).
- `device_id` avec casse mixte → une seule ligne, casse préservée, pas de collision.
- Résolution `keycloak_user_id` impossible → device quand même inventorié, affiché, et
  jamais bloqué pour ce motif.
- Portail : l'utilisateur A ne peut pas approuver/révoquer un device de l'utilisateur B
  (`device_id` forgé dans le POST → 403/404) ; POST sans jeton CSRF valide → refusé ; aucune
  route `GET` ne modifie un statut.
- Device `blocked_by_admin=True` : approbation utilisateur impossible, device reste bloqué
  (cas « téléphone volé » — le point le plus sensible du modèle).
- Révocation d'un device approuvé → la sync suivante renvoie 403.
- Backfill idempotent : deux exécutions → même nombre de devices, aucune décision écrasée.
- Garde de cohérence : `activesync_device_control=True` impossible si `allow_activesync=False`,
  et forcé à `False` hors `access_mode="subdomain_proxy"` (aligné sur `services.py:210,248`).
- Fiche user admin : section masquée si aucune app ActiveSync ; accès refusé pour un non-admin.
- Panne d'écriture d'inventaire (DB en erreur) → un device approuvé n'est pas coupé.

---

## 8. Hors scope de ce commit

- **CSRF sur les POST du portail existants** (constat F) : la nouvelle surface appelle
  `verify_csrf_token` explicitement, mais la dette sur les routes déjà en place mérite une
  **tâche dédiée** — ne pas l'élargir ici.
- **Remote wipe / effacement à distance** (commande EAS `Wipe`) : le bastion bloque l'accès, il
  ne pilote pas le terminal. Sujet grommunio/MDM.
- **Politiques de conformité EAS** (PIN imposé, chiffrement du terminal, version d'OS minimale)
  : sujet MDM, pas bastion.
- Contrôle par device sur d'autres protocoles (IMAP/SMTP/EWS/MAPI) : pas d'identifiant de
  device équivalent.
- Quota de devices par utilisateur, expiration des devices inactifs, géolocalisation d'IP : à
  évaluer une fois l'inventaire réel observé.
- Validation par push / TOTP : le canal de validation reste le portail web.

---

## 9. Prompt Cursor — Lot 1 (inventaire, zéro blocage) — ✅ **livré le 2026-08-15**, conservé pour historique

```
# Contexte

Repo bastion-app. L'audit d'état des lieux est déjà fait, ne le refais pas : handler
app/subdomain/activesync_auth.py:125-363, snippet docker/nginx/snippets/activesync_auth_common.conf,
locations générées par app/bastion/nginx_subdomain_export.py:99-188, flag App.allow_activesync
(app/models.py:64-65), trois sites d'émission de activesync.allowed (:195 basic, :277 oidc,
:321 breakglass), throttle _should_log_allow (:73-84) sur (app_slug, client_ip, actor),
extracteur DeviceId post-hoc côté SIEM app/siem/formatters.py:200-220, catalogue de codes
app/audit/event_catalog.py (criticité dérivée du numéro).

Objectif du Lot 1 : identifier et inventorier les appareils ActiveSync par utilisateur, les
afficher dans la fiche user admin, corriger le throttle de logs qui masque les appareils.
AUCUN blocage dans ce lot : le comportement observable du flux ActiveSync doit rester
strictement identique. L'enforcement et le portail utilisateur sont le Lot 2.

Spec complète : activesync-devices-inventaire-approbation-user.md (Pod "bastion applicatif").

# Tâche 1 — Extracteur de device partagé

extract_eas_device(uri) -> (device_id, device_type) :
- query string classique (?User=...&DeviceId=...&DeviceType=...) ;
- query string base64 MS-ASHTTP (?jAAJBBCg...) : décoder si possible ;
- si rien n'est extractible : retourner (None, None), JAMAIS d'exception.
Réutiliser/factoriser avec le parsing existant de app/siem/formatters.py:200-220 (ne pas
dupliquer) et ajouter DeviceType, qui n'est extrait nulle part aujourd'hui.
Ne PAS normaliser la casse du device_id.

# Tâche 2 — Modèle + migration

Table activesync_devices selon §2.1 de la spec : UNIQUE (application_id, user_key, device_id),
upsert en une seule requête INSERT ... ON CONFLICT DO UPDATE, sample_source_ips capé à 10.
user_key = identifiant Basic normalisé (lowercase) et c'est LA clé d'identité : aucun appel
Keycloak dans ce chemin (find_keycloak_user_exact est async et le chemin est frappé à chaque
Ping). keycloak_user_id/realm_id nullables, renseignés best-effort HORS chemin chaud
(join BastionAccount ou résolution paresseuse à l'affichage) et jamais bloquants.
Ajouter aussi les colonnes activesync_device_control (default False) et
activesync_device_control_enabled_at sur le modèle App, avec la même garde que
allow_activesync (cf. app/services.py:210,248 : forcé False hors access_mode=subdomain_proxy,
et interdit si allow_activesync=False). Migration Alembic dédiée.

# Tâche 3 — Inventaire dans le handler

Point d'insertion UNIQUE en amont des trois branches basic/oidc/breakglass (ne pas dupliquer
la logique trois fois), après le contrôle allow_activesync (:168). Lire la query via
X-Original-URI (déjà transmis par le snippet, conf:14). Upsert best-effort : try/except, une
panne d'écriture ne doit jamais changer la réponse HTTP. source="observed".
Exempter explicitement OPTIONS et /Autodiscover/Autodiscover.xml de toute future logique de
contrôle, et pour cela ajouter dans docker/nginx/snippets/activesync_auth_common.conf :
proxy_set_header X-Original-Method $request_method;
(pattern déjà présent dans docker/nginx/templates/vhost_sso_portal.conf.template:72).
Enrichir le log BST-AUTH-0007 existant avec device_id, device_type, device_status.
Si aucun device_id n'est extractible : log ACTIVESYNC_DEVICE_UNIDENTIFIED (throttlé), et on
laisse passer.

# Tâche 4 — Correctif du throttle de logs

_should_log_allow (:73-84) : ajouter device_id à la clé, qui devient
(app_slug, client_ip, actor, device_id). Sans ça, deux téléphones du même utilisateur derrière
la même IP se masquent mutuellement et le parc est inauditable. Test explicite : deux devices
distincts, même user, même IP => deux événements journalisés.

# Tâche 5 — Fiche user admin

Section "Appareils ActiveSync" dans templates/admin/rbac/user_view.html, servie par
app/admin/rbac_accounts.py:294 (/admin/rbac/users/view — c'est bien la vue HTML, pas l'API
JSON /admin/rbac/users/{keycloak_user_id} de rbac_access.py:956). Masquée s'il n'existe aucune
app avec allow_activesync=True. Colonnes et actions selon §4.1 : device_id tronqué + copie au
clic, friendly_name prioritaire, badge de provenance, statut, dates, IP.
Actions admin utiles DÈS ce lot : Bloquer (raison obligatoire, pose status=blocked +
blocked_by_admin=True) et Débloquer — un blocage admin doit être effectif même si
activesync_device_control est encore False (cas téléphone volé). Approuver/Débloquer réservés
admin. Réutiliser .data-table / .badge-* / .btn, aucun CSS nouveau.
Join sur user_key (email normalisé) ET keycloak_user_id quand renseigné ; ne jamais masquer
silencieusement un device dont le rattachement est incertain.

# Tâche 6 — Codes de logs

Ajouter dans app/audit/event_catalog.py, en revérifiant les numéros libres avant d'écrire
(les valeurs ci-dessous sont celles constatées à l'audit) :
BST-AUTH-0009 ACTIVESYNC_DEVICE_DISCOVERED (INFO)
BST-AUTH-2008 ACTIVESYNC_DEVICE_BLOCKED_BY_ADMIN (WARNING)
BST-AUTH-2009 ACTIVESYNC_DEVICE_UNIDENTIFIED (WARNING)
Puis mettre à jour docs/systeme-codes-logs-criticite.md (le registre est à jour, il s'agit
juste d'y ajouter les nouveaux codes). Les codes du Lot 2 (1001/1002/1003/2006/2007) sont déjà livrés (PR #146) — ne pas les recréer.

# Tests (pytest -k activesync)

- Comportement observable du flux ActiveSync strictement inchangé (200 comme avant), y compris
  device inconnu, contrôle inactif.
- Inventaire : 500 Ping du même device = 1 ligne, request_count incrémenté, IP plafonnées à 10.
- Throttle : deux devices distincts, même user, même IP => deux événements.
- device_id en casse mixte : une seule ligne, casse préservée.
- Base64 non décodable => autorisé + ACTIVESYNC_DEVICE_UNIDENTIFIED.
- OPTIONS et Autodiscover : autorisés, X-Original-Method bien reçu par le handler.
- Panne d'écriture d'inventaire (DB en erreur) => réponse HTTP inchangée.
- Non-régression anti-brute-force : /internal/activesync-auth reste hors _SENSITIVE_PREFIXES,
  aucun appel evaluate_login_attempt / record_sensitive_request.
- Garde : activesync_device_control=True impossible si allow_activesync=False.

# Livrable attendu

- Diff des fichiers créés/modifiés + migration Alembic
- Sortie de pytest -k activesync
- Capture de la section "Appareils ActiveSync" de la fiche user, avec les devices réels
  observés (ton iPhone + ceux d'Hervé)
- Confirmation explicite que le flux ActiveSync est inchangé pour les clients existants
- Décompte des devices distincts inventoriés après quelques heures de fonctionnement
  (sert de base à la fenêtre d'observation avant le Lot 2)
```

## 10. Prompt Cursor — Lot 2 (enforcement + portail), après la fenêtre d'observation

```
# Contexte

Suite du Lot 1 (inventaire activesync_devices en place, throttle corrigé, fiche user admin
affichant les appareils). L'inventaire tourne depuis plusieurs jours et est considéré complet.
Objectif : bloquer tout appareil non approuvé et permettre à l'UTILISATEUR de valider ses
appareils depuis le portail, l'admin gardant la main.

Spec complète : activesync-devices-inventaire-approbation-user.md (Pod "bastion applicatif"),
§3.2, §4.2, §5, §6.

# Tâche 1 — Enforcement

Au point d'insertion unique du Lot 1, si app.activesync_device_control est True :
status=approved => comportement actuel ; sinon 403 + X-Auth-Error:
activesync-device-not-approved. JAMAIS 401 (boucle de re-saisie de mot de passe côté
iOS/Android). Exempter auth_source=breakglass, OPTIONS et Autodiscover.
CHANGEMENT DE POLITIQUE (décidé le 2026-08-15) : quand le contrôle est actif, une requête sans
device_id extractible n'est PLUS laissée passer — elle est refusée en 403 comme un appareil
inconnu (X-Auth-Error: activesync-device-unidentified pour la distinguer en exploitation), et
l'événement ACTIVESYNC_DEVICE_UNIDENTIFIED continue d'être émis avec sa miss_reason. Le
fail-open du Lot 1 était le seul contournement résiduel du contrôle.
ATTENTION à la formulation des tests d'exemption (cf. §3.1.bis, corrigé le 2026-08-15) : les
trois cas ne sont PAS exemptés de la même façon. OPTIONS et Autodiscover sortent en amont, donc
l'assertion est "n'atteint jamais le point d'évaluation". Le break-glass, lui, TRAVERSE
_evaluate_device() avec enforce=False : l'assertion correcte est "jamais refusé" ET "bien
inventorié". Ne pas écrire "n'atteint jamais le point" pour le break-glass, ce test échouerait
sur un comportement correct ou pousserait à le retirer de l'inventaire.
Le point d'insertion est déjà prêt : _evaluate_device() reçoit le drapeau enforce, sort en amont
sur exempt, et app.activesync_device_control est disponible sur place — poser le refus ici ne
demande aucune restructuration. Journaliser le refus à
la première occurrence puis de façon agrégée (max 1/appareil/heure). Une panne d'écriture
d'inventaire ne doit jamais couper un appareil déjà approuvé.

# Tâche 2 — Portail utilisateur

Section "Mes appareils mobiles" sur /profile + bandeau d'alerte sur /profile et /apps s'il
existe un appareil en attente. Actions : "C'est mon appareil" / "Ce n'est pas moi" / révoquer.
Garde require_user_enriched. POST uniquement, avec appel EXPLICITE de verify_csrf_token
(app/web/flash.py:95-110) : il n'est pas appliqué automatiquement sur les POST du portail.
Aucune route GET ne doit modifier un statut. Filtrage systématique sur l'identité de session :
un utilisateur ne doit jamais pouvoir agir sur l'appareil d'un autre, même en forgeant le
device_id dans le POST. Un appareil blocked_by_admin=True est visible mais non actionnable.

# Tâche 3 — Écran de bascule + backfill

/admin/apps/{slug}/activesync/devices/preview : le bouton "Activer le contrôle des appareils"
n'active RIEN, il affiche le résultat simulé du backfill en distinguant deux sources :
appareils observés par l'inventaire (fiables) et appareils retrouvés uniquement dans les logs
antérieurs (parsing de DeviceId dans l'uri des events activesync.allowed — possiblement
incomplets à cause du throttle historique). Afficher depuis combien de jours l'inventaire
tourne, et avertir explicitement qu'un appareil absent des deux sources sera coupé.
Confirmation => une seule transaction : appareils en approved/source=backfill,
decided_by="backfill:<admin>", puis activesync_device_control=True +
activesync_device_control_enabled_at, et log ACTIVESYNC_DEVICE_CONTROL_ENABLED avec le
décompte par source. Backfill idempotent (rejouable, aucune décision existante écrasée),
disponible aussi en commande CLI one-shot. La désactivation du contrôle ne supprime rien.

# Tâche 4 — Notification utilisateur

À la PREMIÈRE mise en pending d'un appareil seulement : bandeau portail, et email au titulaire
UNIQUEMENT si un mécanisme d'envoi réutilisable existe déjà (vérifier ce que fait le
récapitulatif quotidien BST-ADM-3001 / portal_settings.daily_recap). NE PAS construire un
nouveau système d'envoi : si rien n'est réutilisable, s'en tenir au portail et le signaler.
L'email ne doit contenir aucun lien d'approbation en un clic (l'approbation exige une session
SSO).

# Tâche 5 — Codes de logs

BST-AUTH-0009, 1001 (approbation), 1004 (déblocage), 2008, 2009 existent déjà depuis le
Lot 1 : les RÉUTILISER, ne pas en créer de nouveaux pour l'approbation.
Ajouter uniquement les quatre codes réservés dans app/audit/event_catalog.py :
BST-AUTH-1002 ACTIVESYNC_DEVICE_REVOKED (NOTICE)
BST-AUTH-1003 ACTIVESYNC_DEVICE_CONTROL_ENABLED (NOTICE)
BST-AUTH-2006 ACTIVESYNC_DEVICE_DENIED (WARNING)
BST-AUTH-2007 ACTIVESYNC_DEVICE_REJECTED_BY_USER (WARNING)
L'approbation par l'utilisateur passe par BST-AUTH-1001 avec by=user.
Mettre à jour docs/systeme-codes-logs-criticite.md et retirer la mention "réservé".

# Tests (pytest -k activesync)

Tous les cas du §7 de la spec, en particulier :
- appareil inconnu bloqué en 403 et JAMAIS en 401 ;
- requête sans device_id extractible, contrôle actif => 403 (fail-closed) ; contrôle inactif
  => 200 (fail-open du Lot 1 préservé), dans les deux cas avec miss_reason journalisée ;
- OPTIONS et Autodiscover n'atteignent jamais le point d'évaluation ; le break-glass le
  traverse avec enforce=False et n'est jamais refusé, tout en restant inventorié (§3.1.bis) ;
- refus répété : aucun lockout, aucun ban (non-régression) ;
- breakglass, OPTIONS, Autodiscover jamais bloqués ;
- un utilisateur ne peut pas agir sur l'appareil d'un autre ; POST sans CSRF refusé ;
- un appareil bloqué par un admin ne peut pas être réactivé par l'utilisateur ;
- révocation d'un appareil approuvé => 403 à la sync suivante ;
- backfill idempotent ;
- contrôle désactivé => comportement du Lot 1 inchangé.

# Livrable attendu

- Diff + migration éventuelle
- Sortie de pytest -k activesync
- Captures : écran de pré-visualisation du backfill, section "Mes appareils mobiles" avec un
  appareil en attente, fiche user admin après approbation
- Validation réelle de bout en bout : ajouter un compte ActiveSync sur un téléphone non
  inventorié => sync en erreur, demande visible dans le portail, approbation => sync OK
```

---

## 9.bis Lot 1 — livré et vérifié (2026-08-15)

| Élément | Réalisation |
|---|---|
| Extracteur | `app/subdomain/eas_device.py` — query nommée + base64 MS-ASHTTP, casse préservée, ne lève jamais |
| Dé-duplication | le SIEM (`_device_id_from_detail`) pointe sur l'extracteur au lieu de reparser |
| Modèle / migration | `ActiveSyncDevice` + `activesync_device_control` / `_enabled_at` sur `App`, migration `070_activesync_devices` (up / down / up sur base neuve) |
| Invariant | `activesync_flags_for()` dans `app/access_modes.py` — **un seul endroit**, appelé par l'API catalogue et les trois sites d'affectation du formulaire admin |
| Chemin chaud | `record_sighting()` : statut **lu à chaque requête**, écriture **1 fois / minute / appareil**, hits accumulés en mémoire (121 pings → 121 comptés, sans perte) |
| Point d'évaluation | unique, appelé depuis les trois branches (Basic / OIDC / break-glass), enveloppé : panne d'inventaire ⇒ réponse HTTP inchangée |
| Break-glass | inventorié, **jamais bloqué** — c'est le chemin qui permet de venir débloquer un appareil |
| Throttle de logs | clé corrigée ; test qui échoue avec l'ancienne clé (2 téléphones, même user, même IP ⇒ 2 événements) |
| Refus | **403**, jamais 401 (confirmé conforme au §3.2) |
| Codes | `0009`, `1001`–`1004`, `2006`–`2009` livrés (§5) ; Lot 3 = `2010`–`2013` à venir |
| Vérification | 1126 tests passants (vs 1103 sur `master`), **14 échecs identiques avec et sans les changements** ⇒ aucune régression introduite ; +23 tests |

**Dette constatée au passage, hors périmètre** : les 14 échecs préexistants de la suite
complète en ordre déterministe. Ils ne sont pas causés par ce lot, mais ils masquent le signal
de non-régression pour les prochains — mériteraient une tâche dédiée.

---

## 10.bis Lot 1.5 — capture des blobs base64 + `miss_reason` — ✅ **livré le 2026-08-15**

Décidé le 2026-08-15. Le décodeur MS-ASHTTP n'est testé que sur une trame construite à la
main ; le compteur `ACTIVESYNC_DEVICE_UNIDENTIFIED` dira *combien* de requêtes échouent, pas
*pourquoi*. À livrer pendant la fenêtre d'observation, pas après :

- Sur `ACTIVESYNC_DEVICE_UNIDENTIFIED` **uniquement**, ajouter au détail JSON les **120
  premiers caractères** de la query brute (tronqués, marqueur `…` explicite) + le
  `user_agent`.
- **Throttlé fort** : au plus 1 échantillon / heure / `user_agent`, pour ne pas transformer un
  client bavard en générateur de logs.
- **Aucun secret exposé** : les identifiants EAS voyagent dans l'en-tête `Authorization`
  (jamais journalisé), pas dans la query. Le blob contient `DeviceId`/`DeviceType`/`User`,
  soit exactement ce que le log `BST-AUTH-0007` journalise déjà en clair pour la forme
  non encodée. Ne **jamais** étendre cette capture aux requêtes identifiées ni au corps de
  requête (le corps EAS contient le contenu des mails).
- Objectif : corriger le décodeur sur du réel **avant** d'activer l'enforcement.

### Ce qui a été livré (au-delà de la demande)

Le log `ACTIVESYNC_DEVICE_UNIDENTIFIED` enregistrait déjà l'`uri` **complète jusqu'à 1024
caractères** : la capture demandée existait en partie, en pire. Le lot a donc **resserré**
l'exposition au lieu de l'élargir.

Détail JSON de l'événement : `path`, `query_sample` (120 caractères, marqueur `…` explicite),
`query_len`, `miss_reason`, `user_agent`. Le champ `uri` non borné **disparaît** de cet
événement (le chemin est conservé séparément) → rien d'utile perdu, exposition bornée.

**`miss_reason`** — l'apport décisif, absent de ma spécification. Un compteur dit *combien*, un
échantillon brut demande un décodage manuel ; la raison nomme directement le chemin de parsing
qui a abandonné : `no_query`, `named_query_without_device_id`, `query_not_base64`,
`base64_undecodable`, `base64_truncated`, `base64_empty_device_id`, `parse_error`. Elle est
produite **par l'extracteur lui-même**, pas par une seconde analyse en parallèle : elle ne peut
pas diverger du comportement réel.

Throttle inchangé (1 échantillon / heure / `user_agent`, testé). Bug trouvé et corrigé au
passage : le discriminant prenait le `=` de padding base64 pour un `clé=valeur` et classait les
vrais blobs MS-ASHTTP en query nommée — attrapé par le test de trame.

Runbook du code `2009` complété. Vérification : 1132 tests passants (vs 1126), toujours les
mêmes 14 échecs préexistants avec et sans les changements, +6 tests. Un test affirme
explicitement l'absence de fuite d'identifiants, pour qu'un élargissement futur de la capture
ne passe pas inaperçu.

### Les deux familles de `miss_reason` (à exploiter au §11)

| Famille | `miss_reason` | Ce que ça veut dire | Décision |
|---|---|---|---|
| **Décodeur en défaut** | `base64_undecodable`, `base64_truncated`, `query_not_base64`, `parse_error` | notre parsing échoue sur une trame pourtant porteuse d'un device | **corriger le décodeur** avant la bascule |
| **Pas de device envoyé** | `no_query`, `named_query_without_device_id`, `base64_empty_device_id` | le client n'envoie pas de `DeviceId` — aucun correctif n'y changera rien | **fail-closed au Lot 2** (§3.1) après vérification qu'aucun client légitime n'est concerné |

**Lot 1.6 (livré le 2026-08-15) — la taxonomie est dans le code, plus seulement dans ce
document.** Chaque événement `ACTIVESYNC_DEVICE_UNIDENTIFIED` porte un champ **`miss_family`**
valant `decoder_failure` ou `no_device_sent`, produit par `app/subdomain/eas_device.py`. Le tri
se fait donc sur **une** valeur au lieu de mémoriser sept raisons et de refaire le classement
de tête à chaque relecture des logs.

La raison de fond n'est pas le confort de lecture : ces deux familles commandent des décisions
opposées et viennent de trancher le sort du fail-open (§3.1). Laisser la classification dans un
document pendant que le code émet sept valeurs plates, c'était accepter qu'elle dérive d'ici la
bascule. **Un test verrouille l'exhaustivité du mapping** : ajouter une `miss_reason` sans la
classer fait échouer la suite, au lieu de la laisser retomber silencieusement dans un défaut.

Runbook du code `2009` : nomme l'action à mener **pour chaque famille**. Le champ est documenté
dans `docs/systeme-codes-logs-criticite.md`. Vérification : 57 tests sur le périmètre
ActiveSync/SIEM, 17 sur le catalogue de codes, +2 tests.

---

## 11. Fenêtre d'observation — critères de bascule vers le Lot 2

Ne pas activer l'enforcement au calendrier, mais sur ces critères mesurés :

1. **Inventaire stable** : plus aucun nouvel appareil découvert depuis 48 h, et le nombre
   d'appareils distincts correspond au parc réel connu (toi + Hervé + tout client lourd
   éventuel). Un appareil oublié ici = un appareil coupé le jour de la bascule.
2. **`ACTIVESYNC_DEVICE_UNIDENTIFIED` expliqué, regroupé par `miss_family`** (et non plus
   « marginal ») — un `GROUP BY` sur un seul champ, `decoder_failure` vs `no_device_sent` :
   - famille **décodeur en défaut** (`decoder_failure`) → doit être retombée à zéro après
     correction ;
   - famille **pas de device envoyé** (`no_device_sent`) → doit être vide **sur un client
     légitime**. Si un client réel y figure, il faut l'identifier nommément et décider de son
     sort **avant** la bascule, puisque le Lot 2 le bloquera (§3.1, fail-closed).
   Les `query_sample` associés à `decoder_failure` fournissent la matière pour corriger le
   décodeur MS-ASHTTP sur du réel.

   **Comment le lire (Lot 1.7, livré le 2026-08-15) — aucun accès SQL requis** : dans
   `/admin/logs`, filtrer sur l'action `activesync.device_unidentified` et activer la colonne
   optionnelle **`miss_family`** (mécanisme générique déjà utilisé par `reason`, `peer`,
   `x_real_ip`). Les deux familles se lisent d'un coup d'œil. La recherche plein texte portant
   déjà sur le détail JSON, chercher `decoder_failure` ou `no_device_sent` fonctionne aussi
   sans toucher aux colonnes. Le champ est **opt-in** : aucune vue existante n'est modifiée.
   Un test verrouille le chemin de lecture **de bout en bout**, en partant d'un vrai événement
   `ACTIVESYNC_DEVICE_UNIDENTIFIED` et pas du seul mécanisme de colonnes.

   > Pourquoi ce lot existe : `miss_family` était dans le code depuis le Lot 1.6, mais enfoui
   > dans la colonne JSON `details` d'`audit_logs`, donc lisible seulement par requête SQL
   > directe sur une base SQLCipher. **Un critère de bascule qu'on ne peut pas mesurer depuis
   > une interface est un critère qu'on finit par sauter.**
   **Ne jamais activer l'enforcement avec un volume d'unidentified inexpliqué** : c'est le
   contournement le plus direct du contrôle, et au Lot 2 c'est aussi la première cause
   possible de coupure d'un client légitime.
3. **Couverture des utilisateurs** : chaque compte qui synchronise a au moins un appareil
   inventorié avec un `user_key` rattaché à un utilisateur identifiable dans la fiche admin.
4. **Un appareil de test disponible** : un téléphone (ou un profil EAS de test) volontairement
   **non** inventorié, pour valider de bout en bout le parcours du Lot 2 — sync en erreur,
   demande visible dans le portail, approbation, sync OK.

### Points de vérification du §11 — ✅ tranchés le 2026-08-15

- **Première apparition écrite immédiatement** → ✅ **garanti**. Le throttle d'écriture ne
  s'applique qu'aux **mises à jour** d'une ligne existante ; quand `record_sighting()` ne
  trouve rien, il insère et commit sur-le-champ puis vide le cache pour cette clé. La crainte
  était infondée, mais un **test dédié la verrouille** : il échouerait si la création passait
  un jour derrière la cadence. C'était le risque fonctionnel n°1 du Lot 2 (403 sans demande
  visible dans le portail) — il est fermé.
- **Multi-worker** → ✅ **sans objet aujourd'hui** : le conteneur et l'unité systemd Ansible
  lancent `uvicorn app.main:app` **sans `--workers`**. Process unique ⇒ cache mémoire global,
  `request_count` **exact**. Le raisonnement reste valable le jour d'un passage multi-worker,
  et sa conclusion ne change pas : seule la métrique de comptage deviendrait un minorant,
  **jamais** la décision de sécurité (le statut est relu en base à chaque requête).
- **Latence d'approbation** → ⚠️ **le seul point encore terrain**. Côté bastion : quelques
  millisecondes (un `SELECT` par requête, session neuve, aucun cache de statut). Le délai
  perçu sera **entièrement** celui du retry du client. À mesurer sur l'appareil de test au
  Lot 2 et, si iOS espace ses retries après une série de 403, **le dire dans le message de
  confirmation du portail** (« la synchronisation peut reprendre dans quelques minutes »)
  plutôt que de laisser l'utilisateur conclure à un échec.

---

## 12. Décisions de non-action (à ne pas refaire par réflexe)

Options évaluées et **écartées volontairement**, tracées ici pour éviter qu'elles reviennent
comme des évidences :

- **Vue système sauvegardée « ActiveSync non identifiés »** (le critère 2 en un clic) —
  écartée : le code ne gère aujourd'hui **qu'une seule** vue système (`is_system` est déduit
  d'une comparaison au nom de l'unique vue Sécurité). En ajouter une deuxième demande un petit
  refactor, pour un besoin qui **disparaît à la bascule**. Disproportionné. Le filtre + la
  colonne optionnelle suffisent (§11).
- **Écran de suivi de la fenêtre d'observation** (critères 1 et 3, restés manuels) — écarté :
  le Lot 2 prévoit déjà un écran de pré-visualisation qui affiche depuis combien de jours
  l'inventaire tourne et le décompte par source. Construire un tableau de bord séparé
  maintenant, c'est écrire deux fois la même chose dont une jetable. Sur un parc de cette
  taille, les critères 1 et 3 se vérifient en lisant la fiche user.
- **Implémenter le Lot 2 en avance** — écarté : ses critères de bascule sont des **mesures de
  trafic réel**, pas des choix de conception. L'activer sur un inventaire d'une journée
  produirait exactement la coupure de masse que le découpage en lots existe pour éviter.

---

## 13. Lot 1.8 — correctif : rendre les appareils visibles dans la fiche user

**Constat de recette (2026-08-15).** L'inventaire fonctionne de bout en bout : le log
`BST-AUTH-0007` est bien enrichi (`device_id`, `device_type`, `device_status: "pending"`,
`activesync_device_control: false`) pour un iPhone d'`herve.tisseront@ar-systems.fr` sur
l'application 2. **Mais aucune gestion des appareils n'est visible**, ni dans la fiche user
admin, ni côté portail.

Diagnostic de départ :
- **Portail user : normal.** La section « Mes appareils mobiles » est du Lot 2, non implémenté.
- **`device_status: pending` : normal.** Contrôle inactif ⇒ état d'inventaire, rien n'est
  bloqué (cf. libellé à corriger, §4.1).
- **Fiche user admin : anomalie.** La section « Appareils ActiveSync » était au périmètre du
  Lot 1 (Tâche 5) et sa capture n'a jamais été produite au rapport de livraison, alors que les
  codes `1001` / `1004` / `2008` ont bien été alloués **pour ses actions**.

### Prompt Cursor — Lot 1.8

```
# Contexte

Repo bastion-app. Les lots 1 à 1.7 (inventaire ActiveSync) sont livrés et l'inventaire
fonctionne : le log BST-AUTH-0007 est enrichi avec device_id, device_type, device_status et
activesync_device_control, et des appareils réels sont enregistrés (ex. un iPhone de
herve.tisseront@ar-systems.fr sur application_id=2).

Problème constaté en recette : aucune gestion des appareils n'est visible dans la fiche user
admin, alors que la Tâche 5 du Lot 1 la prévoyait et que les codes BST-AUTH-1001 (approbation),
1004 (déblocage) et 2008 (blocage admin) ont été alloués pour ses actions.

Spec : activesync-devices-inventaire-approbation-user.md (Pod "bastion applicatif"), §4.1 et
§13. Le portail utilisateur reste hors périmètre (Lot 2).

# Tâche 1 — Diagnostic (lecture seule, à livrer AVANT toute correction)

Répondre factuellement (fichier/ligne) :
1. La section "Appareils ActiveSync" existe-t-elle dans templates/admin/rbac/user_view.html ?
2. La route qui sert cette vue (app/admin/rbac_accounts.py:294) charge-t-elle les appareils,
   et avec quelle requête exactement ?
3. Sur quoi porte le filtre : keycloak_user_id, email/user_key, les deux ?
4. Sur les lignes réelles de activesync_devices en base : keycloak_user_id est-il renseigné,
   ou NULL ? Quelle valeur exacte a user_key ?
5. Les routes d'action admin (approuver / bloquer / débloquer) existent-elles, et sont-elles
   atteignables depuis une UI ou seulement en API ?
6. La condition d'affichage de la section (au moins une app avec allow_activesync=True) est-elle
   évaluée correctement pour ce compte ?

# Tâche 2 — Correction

DÉCISION STRUCTURANTE : l'email est le pivot du rapprochement, parce que c'est l'élément
central de la gestion des utilisateurs dans le bastion. La requête doit partir de l'EMAIL du
compte affiché, comparé à user_key (lowercase des deux côtés). keycloak_user_id n'est qu'un
complément opportuniste : il peut affiner le rapprochement, il ne doit JAMAIS conditionner
l'affichage. Une section vide parce que keycloak_user_id est NULL est un bug.

Livrer la section selon §4.1 : device_id tronqué (8 premiers + 4 derniers) avec copie au clic,
friendly_name prioritaire, type, application/domaine, statut, première vue, dernière sync, IP,
badge de provenance. Design system existant (.data-table, .badge-*, .btn), aucun CSS nouveau.

Actions admin opérationnelles depuis cette section dès maintenant : Bloquer (raison
obligatoire, pose status=blocked + blocked_by_admin=True, journalise BST-AUTH-2008), Débloquer
(BST-AUTH-1004), Approuver (BST-AUTH-1001, by=admin). Le blocage admin doit mordre même avec
activesync_device_control=False — c'est le cas "téléphone volé", déjà acquis au Lot 1 : le
vérifier, pas le réécrire.

# Tâche 3 — Libellé du statut

Tant que activesync_device_control est False sur l'application, ne PAS afficher "En attente" :
ce libellé laisse croire qu'une action est requise et qu'un utilisateur est bloqué, alors que
rien ne l'est. Afficher un badge neutre "Inventorié" (ou équivalent), et ne basculer sur
"En attente de validation" que lorsque le contrôle est actif sur l'application concernée.

# Tests

- Un appareil dont keycloak_user_id est NULL apparaît bien dans la fiche user du compte
  correspondant à son email (test de non-régression du bug constaté).
- Rapprochement insensible à la casse de l'email.
- Un appareil dont l'email ne correspond à aucun compte connu n'est jamais silencieusement
  masqué (il doit rester atteignable et signalé).
- Section masquée s'il n'existe aucune app avec allow_activesync=True.
- Blocage admin effectif avec activesync_device_control=False, et journalisé sous BST-AUTH-2008.
- Approbation et déblocage journalisés sous BST-AUTH-1001 / BST-AUTH-1004, jamais sous le code
  sentinelle BST-AUTH-0000.
- Le statut s'affiche "Inventorié" avec le contrôle inactif, "En attente de validation" avec le
  contrôle actif.
- Accès non-admin refusé.

# Livrable attendu

- Le rapport de diagnostic de la Tâche 1, avant toute correction
- Diff
- Sortie de pytest -k activesync
- LA CAPTURE de la section "Appareils ActiveSync" de la fiche user d'Hervé, montrant l'iPhone
  réellement inventorié — c'est le livrable qui manquait au Lot 1
```

---

## 14. Modèle de menace et détection de clone (Lot 3)

Décidé le 2026-08-16, en réponse à : *« comment s'assurer de la sécurité de notre filtrage
ActiveSync, notamment sur le spoof de numéro de série d'iPhone ? »*

### 14.1 Le `DeviceId` est une déclaration, pas une preuve

**À assumer et à ne jamais laisser oublier :** le `DeviceId` est fourni par le client dans la
query string, en clair, sans aucune liaison cryptographique. Ni Apple, ni grommunio, ni le
bastion ne le vérifient. Un `curl` muni d'identifiants valides et du `DeviceId` d'un appareil
approuvé **franchit le contrôle**. Aucune amélioration du filtrage EAS ne peut corriger cela :
le protocole ne prévoit pas d'authentification d'appareil.

Cas particulier du **numéro de série Apple** : certains clients iOS envoient `Appl<n° de
série>` (d'où le libellé lisible de la PR #144), d'autres un identifiant opaque — dans les logs
réels de production, les deux appareils envoient des chaînes opaques. Quand la forme `Appl…` est
utilisée, la situation est **pire** : le numéro de série est imprimé sur l'emballage, visible
dans les Réglages, présent sur la facture, connu du revendeur et de tout réparateur. Ce n'est
pas un secret, c'est une donnée administrative. **Le libellé lisible aide l'exploitation, il ne
prouve rien.**

| Le contrôle par appareil apporte | Le contrôle par appareil n'apporte **pas** |
|---|---|
| Blocage d'un attaquant qui a le mot de passe mais **ignore** un `DeviceId` approuvé (credential stuffing, phishing de masse) | Protection contre un attaquant ciblé qui a le mot de passe **et** a observé un `DeviceId` approuvé |
| Visibilité et attribution de toute nouvelle synchronisation | Authentification de l'appareil (seul mTLS le ferait, §14.6) |
| Révocation d'un appareil précis **sans** changer le mot de passe | Protection si une autre porte est ouverte sur grommunio (§14.6) |
| Désaveu par l'utilisateur lui-même | Compensation de l'absence de MFA sur l'auth Basic EAS |

C'est un contrôle d'**inventaire, de consentement et de détection**. Ce n'est **pas** un
contrôle d'authentification, et la documentation d'exploitation ne doit pas le présenter comme
tel.

### 14.2 Détection de clone — l'attaquant qui rejoue un `DeviceId` produit des incohérences

Le `DeviceId` est falsifiable, mais le **contexte** qui l'accompagne est difficile à falsifier
entièrement. Signaux à exploiter, tous calculables avec des données **déjà** en base :

| Signal | Détail | Faux positifs | Politique proposée |
|---|---|---|---|
| **Dérive du modèle** | couple (`device_id` → `user_agent`, `device_type`) **figé à l'approbation** ; le modèle change (`Apple-iPhone13C4` → autre) | quasi nuls **si** on ignore le numéro de build | repasse en `pending` + WARNING ⇒ l'utilisateur revalide |
| **`DeviceType` / UA** | contradictions **listées** vs couples inconnus (§14.2.bis) | Outlook/Android légitimes si matrice trop stricte | **403** seulement si contradiction connue ; sinon WARNING |
| **Multi-origine** | même `device_id`, deux `/24` **qui se chevauchent** (secondes), pas une fenêtre large (§14.2.bis) | CGNAT / 4G / WiFi si fenêtre trop large | **WARNING seul**, jamais de blocage |
| **Sessions `Ping` concurrentes** | deux boucles simultanées sur le même `device_id` depuis des IP différentes | faibles (EAS = un client par `DeviceId`) | WARNING, à réévaluer après observation |
| **Vélocité** | N nouveaux `device_id` pour un même compte en peu de temps | faibles | WARNING (indicateur de credential stuffing) |

⚠️ **Piège de la comparaison d'UA** : une mise à jour d'iOS change le **build**
(`Apple-iPhone13C4/2307.71` → `.../2401.x`) sans changer l'appareil. Comparer **uniquement la
partie modèle**, avant le `/`. Comparer l'UA complet produirait une alerte à chaque mise à jour
d'iOS, et le contrôle serait désactivé au bout de trois semaines.


### 14.2.bis Raffinements décidés le 2026-08-16 (avant implémentation du Lot 3)

**1. `DeviceType` / UA incohérents : la valeur par défaut doit être « alerter », pas
« bloquer ».** Un 403 sur incohérence n'est sûr que sur des contradictions **explicitement
connues** (`DeviceType=iPhone` + UA Android). Le parc actuel n'est composé que d'iPhones : une
matrice de cohérence stricte bloquerait le premier client Outlook Windows
(`DeviceType=WindowsOutlook15`, UA `Microsoft Office/16.x`) ou Android
(`DeviceType=Android`, UA `SAMSUNGSMG…`) comme « incohérent », alors qu'il est parfaitement
légitime. Règle à implémenter :
- couple **connu et cohérent** ⇒ rien ;
- **contradiction explicite** listée en dur ⇒ 403 + `BST-AUTH-2011` ;
- **couple inconnu** ⇒ **WARNING seulement**, jamais 403.
Le défaut d'un contrôle de sécurité doit être fail-closed quand il porte sur une décision
d'accès, mais fail-open quand il porte sur une **heuristique de cohérence** dont on ne connaît
pas encore l'espace des valeurs légitimes.

**2. Multi-origine `/24` : sera trop bruyant en l'état.** Un iPhone en 4G change de `/24`
constamment (CGNAT, changement de cellule, bascule 4G ↔ WiFi, roaming). La règle « deux
préfixes `/24` dans une fenêtre courte » se déclenchera en continu sur des appareils
parfaitement légitimes. Ce n'est pas dangereux (WARNING seul, aucun blocage) mais c'est **pire
qu'inutile** : un code qui crie tout le temps apprend à l'exploitant à l'ignorer, et le jour du
vrai clone personne ne regardera. À resserrer sur l'un de ces critères, dans cet ordre de
préférence :
- **simultanéité réelle** : deux requêtes qui se chevauchent à quelques secondes d'intervalle
  depuis deux `/24` différents (un téléphone ne synchronise pas depuis deux réseaux à la fois) ;
- **ASN différent**, si et seulement si l'information est déjà disponible côté SIEM ;
- à défaut, **seuil haut** sur le nombre de `/24` distincts par heure, calibré **après** la
  bascule sur le trafic réel — pas avant.

**3. Vélocité : ne pas figer de seuil avant d'avoir des données.** Sur un parc de trois
personnes, tout seuil écrit aujourd'hui est arbitraire. Démarrer volontairement **haut**, puis
resserrer sur ce qu'on observe une fois la gate active.

**4. Dérive de modèle : pourquoi `pending` est acceptable.** Un cas non adverse existe — le
remplacement de téléphone avec restauration de sauvegarde iCloud, qui peut conserver le compte
EAS. L'utilisateur légitime serait alors renvoyé en `pending`, donc coupé. C'est acceptable
**uniquement parce que le portail existe** (Lot 2) : il revalide lui-même en quelques secondes,
notification SMTP à l'appui. À condition que le log `BST-AUTH-2010` et l'écran de validation
affichent **l'ancien et le nouveau modèle** : sans ça, ni l'utilisateur ni l'admin ne peuvent
juger si c'est un nouveau téléphone ou un clone.

⚠️ **Ne pas introduire de dépendance GeoIP** pour ce lot : se limiter à ce qui est disponible
(comparaison d'IP, préfixe /24, ASN **seulement** s'il est déjà présent côté SIEM). Un signal
« pays différent » n'a pas besoin d'exister pour que la détection soit utile.

**Pourquoi la dérive de modèle est le meilleur contrôle** : elle oblige l'attaquant à connaître
le `DeviceId` **et** à reproduire exactement l'UA de l'appareil légitime. Le `DeviceId` fuit
relativement facilement (logs, UI, inventaire grommunio, numéro de série physique) ; le couple
`DeviceId` + UA exact au modèle près, beaucoup moins.

### 14.3 Codes de logs (Lot 3)

Numéros à revérifier dans `app/audit/event_catalog.py` avant écriture (`1002`, `1003`, `2006`,
`2007` sont déjà **livrés** au Lot 2 / PR #146) :

| Code proposé | Criticité | Label | Quand |
|---|---|---|---|
| `BST-AUTH-2010` | WARNING | `ACTIVESYNC_DEVICE_MODEL_DRIFT` | le modèle d'un appareil approuvé change ⇒ retour en `pending` |
| `BST-AUTH-2011` | WARNING | `ACTIVESYNC_DEVICE_TYPE_MISMATCH` | contradiction **listée** DeviceType/UA ⇒ 403 ; couple inconnu ⇒ WARNING seul (§14.2.bis) |
| `BST-AUTH-2012` | WARNING | `ACTIVESYNC_DEVICE_MULTI_ORIGIN` | même appareil, origines simultanées éloignées |
| `BST-AUTH-2013` | WARNING | `ACTIVESYNC_DEVICE_VELOCITY` | trop de nouveaux appareils sur un compte |

Ces événements doivent alimenter le `risk_flag=activesync_device_anomaly` déjà envisagé au §5
pour le SIEM.

### 14.4 ⚠️ Garde critique sur la fusion de doublons (PR #145)

La fusion des jumeaux `(application, DeviceId)` conserve **le statut le plus fort**
(`bloqué > approuvé > …`). C'est **le seul endroit du design où un appareil peut être promu sans
décision humaine**. Si une variante forgée était un jour fusionnée avec un appareil approuvé,
elle **hériterait de l'approbation**.

Invariants à verrouiller par test :
- la fusion porte **exclusivement** sur la variante d'identité utilisateur (`email` vs
  `domaine\email`), à **`DeviceId` strictement identique, casse comprise** ;
- **jamais** de fusion entre deux `DeviceId` différents, quelle que soit leur ressemblance
  (casse, espaces, encodage, homoglyphes) ;
- **jamais** de fusion inter-applications ;
- un test adverse explicite : forger une variante de casse/encodage d'un `DeviceId` approuvé
  et vérifier qu'elle reste une ligne distincte, non approuvée.

### 14.5 Suite de tests adverses — « un contrôle non attaqué en test est une hypothèse »

À écrire avec l'enforcement actif (Lot 2), et à faire vivre ensuite :

1. rejeu du `DeviceId` d'un appareil **approuvé** depuis une autre IP → détecté (WARNING).
2. rejeu du `DeviceId` d'un appareil **bloqué** → refusé, **y compris sous forme base64**.
3. `DeviceId` omis → refusé (fail-closed, §3.1).
4. **variantes de normalisation** : casse différente, `%20` / `+`, caractères de remplissage,
   longueur extrême, homoglyphes Unicode → aucune ne matche un appareil approuvé, aucune ne
   provoque de 500.
5. UA changé (modèle) sur un `DeviceId` approuvé → retour en `pending` + WARNING.
6. UA changé (**build seulement**, mise à jour iOS) → **aucune alerte**, appareil toujours
   approuvé.
7. contradiction **listée** DeviceType/UA → 403 ; couple inconnu (ex. Outlook Windows) → WARNING seul, pas de 403 (§14.2.bis).
8. fusion de doublons : impossible de promouvoir une variante forgée (§14.4).

### 14.6 Ce que ce lot ne traite pas — et qui domine le risque résiduel

Ces trois sujets pèsent **plus** que tout raffinement du filtrage par appareil. Ils sont hors
périmètre du Lot 3, mais doivent être tracés comme risques ouverts, pas oubliés :

1. **Étanchéité du périmètre grommunio.** Si IMAP, SMTP authentifié, EWS, MAPI/HTTP ou le
   webmail sont joignables hors bastion, quelqu'un qui a le mot de passe n'attaquera pas
   ActiveSync : il lira la boîte par une autre porte, sans appareil, sans log, sans gate. **Le
   contrôle par appareil ne vaut que l'étanchéité du périmètre autour de grommunio.**
   → à auditer.
2. **Mot de passe EAS = mot de passe SSO ?** Si oui, ActiveSync contourne en permanence tout ce
   que le bastion applique en amont (MFA, politique de session), puisque l'auth Basic EAS ne
   peut pas porter de MFA. Un **mot de passe applicatif dédié à la synchronisation** vaut plus,
   en sécurité réelle, que n'importe quel raffinement du gate — et il rend la révocation
   crédible (bloquer l'appareil **et** faire tourner le secret).
3. **mTLS = la seule vraie authentification d'appareil.** Un certificat client par appareil
   (EAS le supporte, nginx peut l'exiger sur les locations ActiveSync et mapper le CN vers
   l'inventaire) rend le spoofing structurellement impossible : le `DeviceId` redevient un
   simple libellé, l'identité repose sur une clé privée non extractible du keychain. Coût réel :
   PKI + provisionnement par profil de configuration (MDM ou Apple Configurator). C'est un
   chantier, pas un correctif — mais c'est la cible si le niveau d'exigence monte.

**Hygiène d'exposition** : le `DeviceId` n'est pas un secret, mais il n'y a aucune raison de le
diffuser. La troncature en UI est acquise ; ne pas le réintroduire en clair dans le récapitulatif
mail quotidien ni dans un export SIEM sortant.

### 14.7 Prompt Cursor — Lot 3 (détection de clone)

```
# Contexte

Repo bastion-app. L'inventaire ActiveSync par appareil est en place (PR #138, #143, #144, #145)
et l'enforcement per-app est livré (Lot 2 / PR #146) — gate encore off jusqu'au §16. Le DeviceId EAS est fourni par le client en clair,
sans liaison cryptographique : il est trivialement falsifiable, y compris quand il contient le
numéro de série Apple (donnée administrative, pas un secret). Le contrôle par appareil est donc
un contrôle d'inventaire, de consentement et de DÉTECTION — pas d'authentification.

Objectif du Lot 3 : détecter le rejeu d'un DeviceId, en exploitant les incohérences de contexte
qu'un attaquant ne peut pas toutes reproduire. Aucune dépendance externe, aucune GeoIP.

Spec : activesync-devices-inventaire-approbation-user.md (Pod "bastion applicatif"), §14.

# Tâche 1 — Figer l'empreinte à l'approbation

Au moment où un appareil passe en approved (par l'utilisateur, un admin ou le backfill),
enregistrer l'empreinte attendue : modèle extrait du user_agent (partie AVANT le "/", donc
"Apple-iPhone13C4" et PAS le build "2307.71") et device_type.
ATTENTION : comparer le user_agent complet produirait une alerte à chaque mise à jour d'iOS et
le contrôle serait désactivé en trois semaines. Comparer UNIQUEMENT la partie modèle.

# Tâche 2 — Signaux de détection (§14.2.bis)

1. Dérive de modèle sur un appareil approuvé => repasse en pending + BST-AUTH-2010
   (l'utilisateur revalide via le portail). Le log ET l'écran doivent afficher l'ANCIEN et le
   NOUVEAU modèle (sinon on ne distingue pas iCloud restore d'un clone). Comparer UNIQUEMENT
   la partie modèle avant "/".
2. DeviceType / UA : défaut = ALERTER, pas bloquer.
   - contradiction EXPLICITEMENT LISTÉE (ex. DeviceType=iPhone + UA Android) => 403 + 2011 ;
   - couple INCONNU (ex. WindowsOutlook15 + Microsoft Office) => WARNING seul, JAMAIS 403.
3. Multi-origine : WARNING SEUL (2012), JAMAIS de blocage. Ne PAS alerter sur « deux /24 dans
   une fenêtre large » (trop bruyant en 4G). Resserrer sur la simultanéité réelle : deux
   requêtes qui se chevauchent à quelques secondes depuis deux /24 différents. ASN seulement
   s'il est déjà côté SIEM. Sinon seuil /24/heure HAUTE, calibré APRÈS la bascule.
4. Vélocité (2013) : démarrer avec un seuil VOLONTAIREMENT HAUT ; resserrer sur le trafic
   observé une fois la gate active. Ne pas figer un chiffre arbitraire sur un parc de 3 personnes.
Ne PAS ajouter de dépendance GeoIP.
Ces événements doivent pouvoir alimenter risk_flag=activesync_device_anomaly.

# Tâche 3 — Garde sur la fusion de doublons (PR #145)

La fusion conserve "le statut le plus fort" : c'est le SEUL endroit du design où un appareil
peut être promu sans décision humaine. Verrouiller par tests que la fusion porte exclusivement
sur la variante d'identité utilisateur (email vs domaine\email), à DeviceId STRICTEMENT
identique casse comprise, jamais entre deux DeviceId différents, jamais inter-applications.

# Tâche 4 — Codes de logs

Ajouter BST-AUTH-2010 à 2013 (§14.3) dans app/audit/event_catalog.py après vérification des
numéros libres (1002, 1003, 2006, 2007 sont déjà livrés au Lot 2). Runbook + mise à jour de
docs/systeme-codes-logs-criticite.md, en indiquant pour chaque code l'action attendue de
l'exploitant.

# Tests adverses (le livrable qui compte)

Écrire la suite du §14.5 : rejeu d'un DeviceId approuvé depuis une autre IP ; rejeu d'un
DeviceId bloqué y compris en base64 ; DeviceId omis ; variantes de normalisation (casse, %20,
+, remplissage, longueur extrême, homoglyphes Unicode) qui ne doivent NI matcher un appareil
approuvé NI provoquer de 500 ; changement de modèle => pending ; changement de build seul =>
AUCUNE alerte ; contradiction listée DeviceType/UA => 403 ; couple inconnu => WARNING seul ;
impossibilité de promouvoir une variante forgée par la fusion ; dérive => pending avec
ancien+nouveau modèle visibles.

# Livrable attendu

- Diff + migration éventuelle
- Sortie de pytest -k activesync
- La suite de tests adverses, commentée cas par cas
- Une note explicite : ce lot améliore la DÉTECTION, il ne rend pas le DeviceId infalsifiable.
  Seul mTLS le ferait (§14.6).
```

---

## 15. État réel du repo au 2026-08-16 (croisement spec v8 / code)

> ⚠️ **Ce document est désormais dupliqué** : une copie vit dans le repo
> (`docs/activesync-devices-inventaire-approbation-user.md`, v11 + §14.2.bis ;
> checklist bascule : `docs/activesync-bascule-grommunio-checklist.md`).
> La version du Pod est celle où l'on itère ; **la copie repo doit être resynchronisée à chaque
> incrément de version**, sinon deux vérités coexisteront et c'est la mauvaise qui sera lue par
> celui qui code. Le §5 (codes de logs) est le premier endroit qui divergera.

| Périmètre | État |
|---|---|
| Socle EAS sur apps `subdomain_proxy` (ActiveSync + Autodiscover autorisés, proxy Ping/Sync durci : buffering, body, SSL ; parse des access logs nginx corrigé) | ✅ livré |
| Lots 1 → 1.7 : inventaire, sightings throttlés, fiche admin, identité lisible, `miss_family`, blocage admin | ✅ livré |
| PR #138 — table d'inventaire, onglet Appareils sur la fiche RBAC, actions Approuver/Bloquer, 403 (pas 401) si bloqué | ✅ livré |
| PR #143 — correctif 500 fiche user (`vault apps` dict → `.slug`) | ✅ livré |
| PR #144 — file `/admin/pending-devices`, sidebar, dashboard, cloche, récap mail quotidien, libellés humains (modèle, n° série `Appl…`), normalisation `DOMAIN\email` → email, match legacy `endswith(\email)` + repair à l'ouverture de la fiche | ✅ livré |
| PR #145 — fusion des jumeaux `(application, DeviceId)` (`email` vs `domaine\email`), statut le plus fort conservé, cumul des syncs ; rename Téléphones → Appareils ; liste pending densifiée + tiroir détail | ✅ livré (master) |
| **Lot 1.8** — section fiche user | ✅ soldé dans le Lot 2 (libellé « Inventorié » vs « En attente de validation ») |
| **Lot 2** — enforcement `pending`, portail user, écran preview/backfill | ✅ **livré le 2026-08-16** (§15.4) |
| **Lot 3** — détection de clone (§14) | ❌ absent |

### 15.1 Le constat qui a fait passer le Lot 2 en priorité — ⚠️ **périmé depuis le Lot 2**

> **Valable jusqu'au 2026-08-16 uniquement. Corrigé par le Lot 2 (§15.4, PR #146) : le gate
> refuse désormais `pending` / `rejected` / `blocked` en 403, et applique le fail-closed sur
> appareil non identifié.** Conservé ici parce qu'il explique l'ordonnancement.

État au 2026-08-16 avant le Lot 2 : `activesync_device_control=True` **ne refusait rien**. Seul
`blocked_by_admin` provoquait un 403. Le drapeau per-app existait et était journalisé
(`"activesync_device_control": false` dans le détail de `BST-AUTH-0007`), mais aucun refus
n'était branché sur l'état `pending`.

Activer le drapeau à ce moment-là **n'aurait rien protégé tout en donnant l'impression du
contraire** — c'est ce qui a rendu le Lot 2 nécessaire et non simplement souhaitable.

La vérification « le gate refuse-t-il réellement les `pending` ? » **reste dans le runbook**
(§16.2), mais elle a changé de nature : ce n'est plus la recherche d'un bug de code, c'est une
confirmation de configuration en production (bon drapeau, bonne application, nginx rechargé).

### 15.2 Décision d'ordonnancement (2026-08-16)

1. **Lot 2** — enforcement + portail user + bascule/backfill, **avec le libellé « Inventorié »
   du Lot 1.8 replié dedans** : le Lot 2 touche les mêmes templates, et il résout le libellé
   par le contexte (« Inventorié » si contrôle inactif, « En attente de validation » si actif).
   Un lot séparé rouvrirait deux fois les mêmes fichiers.
2. **Lot 3** ensuite. Détecter le rejeu d'un `DeviceId` sur un contrôle qui ne bloque personne
   n'aurait pas de sens.
3. **Audit du périmètre grommunio** (§14.6) en parallèle : c'est du réseau, pas du code, donc
   sans conflit.

### 15.4 Lot 2 — livré le 2026-08-16

| Périmètre | Réalisation |
|---|---|
| Enforcement | `activesync_device_control=True` ⇒ 403 sur `pending` / `rejected` / `blocked` (`activesync.device_denied`, `BST-AUTH-2006`) |
| Fail-closed | pas de `DeviceId` + contrôle actif ⇒ 403 `activesync-device-unidentified` (§3.1) |
| Non-régression | contrôle off ⇒ comportement Lot 1 inchangé ; `blocked_by_admin` coupe toujours |
| Portail | `/profile` → « Mes appareils mobiles » (approuver / refuser / révoquer, CSRF explicite) ; bandeaux `pending` sur `/profile` et `/apps` |
| Libellés | « Inventorié » (contrôle off) vs « En attente de validation » (contrôle on) — solde le Lot 1.8 |
| Notification | notif SMTP à l'utilisateur |
| Bascule | `/admin/apps/{slug}/activesync/devices/preview`, backfill inventaire + **liste figée** ; CLI `--preview` / `--enable --pending-id …` / `--disable` |
| Codes | `BST-AUTH-1002` / `1003` / `2006` / `2007` livrés (plus « réservés ») |
| Tests | 54 activesync + 25 catalog/pending/recap ✅ |

**Le gate reste `off` sur toutes les applications.** Il ne reste que la décision d'activation
(§16).

### 15.3 Amendements au prompt du §10, à appliquer avant de le lancer

**A. Le backfill part de l'inventaire, plus des logs.** Le §10 a été écrit quand l'inventaire
n'existait pas : il prévoyait un parsing des events `activesync.allowed` antérieurs, avec un
avertissement sur l'incomplétude due au throttle. **Cette précaution est périmée.** L'inventaire
tourne depuis le 2026-08-15 06:02 et porte `first_seen_at`, `last_seen_at` et le compteur de
hits par appareil. L'écran de pré-visualisation doit donc approuver les lignes **`pending`
réellement inventoriées** ; le parsing de logs antérieurs devient au mieux un complément
affiché à part, et n'est plus la source principale.

**B. Construire ≠ activer.** Le critère `miss_family` (§11) conditionne l'**activation** du
gate, pas le développement. Livrer le Lot 2 avec `activesync_device_control=False` partout, et
ne basculer Grommunio qu'après avoir regardé le regroupement : sinon le fail-closed sur
`no_device_sent` coupera un client dont on ne sait pas encore s'il existe.

**C. Parc observé au moment de la décision** (à confronter au parc réel, critère 1 du §11) :
`herve.tisseront` (iPhone `L0GIL6A9…HEB4`, 1236 hits), `brigitte.tisseront` (iPhone
`O1J17VR4…EBTS`, 132 hits), et l'appareil de `vincent.tisseront`. Tout téléphone éteint ou en
congés depuis le 2026-08-15 est **absent de l'inventaire** et sera bloqué à la bascule.

---

## 16. Runbook de bascule sur Grommunio

> Checklist opérationnelle (cases à cocher) : [docs/activesync-bascule-grommunio-checklist.md](./activesync-bascule-grommunio-checklist.md).

À exécuter dans cet ordre. Toute étape rouge ⇒ on n'active pas.

### 16.1 Pré-requis mesurés (critères §11)

1. **`miss_family`** — `/admin/logs`, action `activesync.device_unidentified`, colonne
   `miss_family` :
   - `decoder_failure` non vide ⇒ **stop**. Corriger le décodeur MS-ASHTTP avec les
     `query_sample` associés. Ces requêtes passeront en 403 à la bascule alors qu'elles portent
     peut-être un appareil légitime.
   - `no_device_sent` avec un client réel ⇒ **stop**. L'identifier nommément et décider de son
     sort : le fail-closed le coupera.
   - Les deux vides ⇒ ✅.
2. **Parc complet** — confronter l'inventaire au parc réel. Attention aux appareils **éteints,
   en congés, ou peu utilisés** depuis le 2026-08-15 : absents de l'inventaire, ils seront
   bloqués. Un second téléphone, une tablette, un client lourd comptent.
3. **Un appareil de test non inventorié** disponible pour valider le parcours complet.
4. **Le portail est en place** (Lot 2 ✅) : un utilisateur bloqué peut se dépanner seul. Ce
   n'était pas vrai avant le 2026-08-16.

### 16.2 Trois vérifications de code avant d'activer

- **Le backfill n'approuve que les `pending`.** Il ne doit **jamais** relever un `blocked`,
  `blocked_by_admin` ou `rejected` : un téléphone volé bloqué la veille ne doit pas être
  réhabilité par la bascule.
- **La confirmation approuve la liste explicitement affichée par la pré-visualisation**, pas le
  résultat d'une nouvelle requête au moment du clic. Sinon un appareil qui apparaît entre
  l'affichage et la confirmation est approuvé automatiquement, sans avoir jamais été vu par
  l'admin. Fenêtre étroite, mais c'est un contournement gratuit.
  ✅ **Corrigé (2026-08-16)** : le POST / CLI n'approuve que les `DeviceId` figés au preview ;
  un pending apparu après reste en attente (`left_pending`) et sera coupé par le gate.
- **Le gate refuse réellement les `pending`** — livré et testé au Lot 2 (PR #146). La
  vérification en prod ne cherche plus un bug de code mais une erreur de configuration : bon
  drapeau sur la bonne application, nginx rechargé, locations ActiveSync bien générées.

### 16.3 Bascule

1. `python -m app.admin.activesync_control_cli grommunio --preview` (ou l'écran
   `/admin/apps/{slug}/activesync/devices/preview`) → relire la liste **nom par nom**.
2. Confirmer avec la **liste figée** (formulaire UI, ou CLI
   `--enable --pending-id …`). Vérifier le log `BST-AUTH-1003`
   (`ACTIVESYNC_DEVICE_CONTROL_ENABLED`) et son décompte par source.
3. **Surveiller 30 minutes** : les appareils approuvés continuent de synchroniser (`hits` qui
   progressent), et **aucun** `BST-AUTH-2006` sur un utilisateur légitime.

### 16.4 Rollback

`python -m app.admin.activesync_control_cli grommunio --disable` — ne supprime rien, suspend
l'enforcement. Les décisions et l'inventaire sont conservés. À utiliser sans hésiter au premier
utilisateur légitime coupé : la protection peut attendre une heure, pas la messagerie de
l'entreprise.

> Activation CLI : `--enable` + `--pending-id` (issus du `--preview`). Sans `--enable` /
> `--preview` / `--disable`, la commande refuse (plus d'activation implicite).

### 16.5 Validation post-bascule (le test qui compte)

Ajouter un compte ActiveSync sur l'appareil de test non inventorié :
1. la synchronisation échoue ;
2. l'appareil apparaît dans `/admin/pending-devices` **et** dans le portail de son
   propriétaire, avec la notification SMTP ;
3. l'utilisateur approuve depuis `/profile` ;
4. la synchronisation reprend — **mesurer le délai** : il est côté client (retry iOS), pas côté
   bastion. S'il dépasse quelques minutes, l'écrire dans le message de confirmation du portail
   (§11) plutôt que de laisser l'utilisateur conclure à un échec.

---

## 17. Reste à faire après la bascule

1. **Lot 3 — détection de clone** (§14). Ce n'est qu'après la bascule qu'il prend son sens : le
   `DeviceId` est falsifiable, et c'est la détection d'incohérences qui compense.
2. **Audit du périmètre grommunio** (§14.6, point 1) : si IMAP, SMTP authentifié, EWS, MAPI/HTTP
   ou le webmail sont joignables hors bastion, le contrôle par appareil est contournable sans
   effort par quiconque a le mot de passe. **C'est le risque résiduel dominant**, et il ne se
   traite pas dans ce repo.
3. **Mot de passe applicatif dédié à la synchronisation** (§14.6, point 2) : tant que le mot de
   passe EAS est le mot de passe SSO, ActiveSync contourne le MFA en permanence.
4. **Dette hors périmètre** : les 14 échecs préexistants de la suite complète (§9.bis), et la
   CSRF absente sur les POST du portail **antérieurs** au Lot 2 (§8).