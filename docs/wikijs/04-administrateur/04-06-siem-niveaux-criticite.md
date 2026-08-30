# SIEM — niveaux de criticité et sévérité CEF

Documentation de référence pour les événements Bastion Pro envoyés au SIEM
(syslog TLS CEF ou webhook JSON). Source de vérité runtime :
`app/audit/event_catalog.py` et `app/siem/formatters.py`.

## Principe

Chaque événement d’audit porte un code `BST-<DOMAINE>-<NNNN>`. **La tranche
numérique du code fixe la criticité catalogue** ; cette criticité est ensuite
mappée vers :

1. le champ **sévérité CEF** (0–10) dans le message syslog ;
2. `event.severity` / `log.level` en JSON webhook (ECS-like) ;
3. la priorité syslog RFC5424 (facility/severity) du cadre transport.

Ces trois valeurs **ne sont pas** le `rule.level` Wazuh (voir plus bas).

## Tranches de code → criticité catalogue

| Tranche `NNNN` | Criticité catalogue | Exemples |
|----------------|---------------------|----------|
| `0000` | WARNING (non catalogué) | action inconnue → `BST-*-0000` |
| `0001`–`0999` | **INFO** | login OK, logout, app launch |
| `1000`–`1999` | **NOTICE** | config admin, allowlist, realm |
| `2000`–`2999` | **WARNING** | échec login, CRS déclenché, probing |
| `3000`–`3999` | **ERROR** | apply / infra en échec |
| `4000`–`4999` | **CRITICAL** | ban IP, intrusion, spoofing |

Domaines : `AUTH`, `BGL`, `SESS`, `RBAC`, `VLT`, `FILE`, `WAF`, `PROXY`, `ADM`,
`SIEM`, `PROV`, `SYS`.

Inventaire admin : **Admin → Logs → Catalogue** (`/admin/logs/catalogue`) — export
CSV/JSON.

## Mapping Bastion → SIEM (obligatoire)

| Criticité catalogue | **CEF severity** (dans `CEF:0|…|sev|`) | Syslog severity (RFC5424) | `log.level` webhook |
|---------------------|----------------------------------------|---------------------------|---------------------|
| INFO | **1** | 6 (info) | `info` |
| NOTICE | **3** | 5 (notice) | `notice` |
| WARNING | **5** | 4 (warning) | `warning` |
| ERROR | **7** | 3 (error) | `error` |
| CRITICAL | **10** | 2 (critical) | `critical` |

Exemple d’en-tête CEF (extrait) :

```text
CEF:0|Bastion|BastionPro-Sentinel|0.5.0|BST-SESS-2001|SESSION_BINDING_WEAK_MISMATCH|5|…
```

Le `5` final de l’en-tête = **WARNING**. Les infos (`…|1|`) et les détections WAF
critiques (`…|10|`) **n’ont jamais la même valeur CEF**.

Champs utiles côté collecteur / decoder :

| Champ | Signification |
|-------|----------------|
| CEF deviceEventClassId | code `BST-…` |
| CEF name | label catalogue (ex. `CRS_RULE_TRIGGERED`) |
| CEF severity | 1 / 3 / 5 / 7 / 10 (tableau ci-dessus) |
| `outcome` | `success` / `error` / `info` (résultat métier, **pas** la criticité) |
| `suser` / `src` | acteur + IP |
| `cs1` | détail JSON |

## Domaine WAF — niveaux exacts

Les événements **configuration** WAF (admin) sont NOTICE (CEF **3**).
Les **détections** sont WARNING (CEF **5**) ou CRITICAL (CEF **10**).

### NOTICE — CEF 3 (config / gouvernance)

| Code | Label |
|------|-------|
| BST-WAF-1001 | IP_BAN_LIFTED |
| BST-WAF-1002 | ALLOWLIST_ADDED |
| BST-WAF-1003 | ALLOWLIST_REMOVED |
| BST-WAF-1004 | BAN_RULES_UPDATED |
| BST-WAF-1005 | SECURITY_POLICY_UPDATED |
| BST-WAF-1006 | WAF_MODE_CHANGED |
| BST-WAF-1007 | WAF_THRESHOLD_CHANGED |
| BST-WAF-1008 | WAF_EXCLUSION_ADDED |
| BST-WAF-1009 | WAF_EXCLUSION_DISABLED |
| BST-WAF-1010 | WAF_CONFIG_APPLIED |
| BST-WAF-1011 | WAF_ENGINE_REACTIVATED |
| BST-WAF-1012 | WAF_ENGINE_DISARMED |
| BST-WAF-1013 | WAF_GEOLOC_TOGGLED |
| BST-WAF-1014 | WAF_SUBDOMAIN_REACTIVATED |

### WARNING — CEF 5 (détections / alertes)

| Code | Label |
|------|-------|
| BST-WAF-2001 | CRS_RULE_TRIGGERED (ModSecurity / CRS) |
| BST-WAF-2002 | BRUTE_FORCE_ATTEMPT |
| BST-WAF-2003 | SURFACE_PROBING |
| BST-WAF-2004 | SSRF_PROBING |
| BST-WAF-2005 | AUTHORIZED_REDTEAM_TEST |
| BST-WAF-2006 | RATE_LIMITED |
| BST-WAF-2007 | UNKNOWN_HOST_HAMMERING_DETECTED |
| BST-WAF-2013 | WAF_CONFIG_APPLY_ROLLBACK |

### CRITICAL — CEF 10 (réponse / intrusion)

| Code | Label |
|------|-------|
| BST-WAF-4001 | IP_BANNED |
| BST-WAF-4002 | HACK_ATTEMPT_DETECTED |
| BST-WAF-4003 | IP_SPOOFING_SUSPECTED |
| BST-WAF-4004 | SUCCESSFUL_LOGIN_HAMMERING |

## Wazuh : `rule.level` ≠ sévérité Bastion

Si toutes les alertes Wazuh affichent le même `rule.level` (ex. **3** pour la règle
catch-all `100500` « BastionPro: événement SIEM reçu »), c’est une **règle manager
Wazuh fixe**, pas un plat côté Bastion.

- Bastion envoie déjà des CEF différenciés (1 / 3 / 5 / 7 / 10).
- Exemple : `BST-WAF-4001` / `IP_BANNED` → CEF **10** dans `full_log` et
  `data.bastion.cef_severity`, mais `rule.level` reste **3** tant que seule
  `100500` matche.
- Les règles / décodeurs se déploient sur le **manager**
  (ex. `vmtools-wazuhdash01`), **pas** sur le forwarder
  (`vmtools-wazuhlogsfw01` = agent + rsyslog uniquement).

Fichiers prêts à déployer (également **pièces jointes** de cette page sur Confluence) :

- [`docs/ops/wazuh-bastionpro-rules.xml`](../../ops/wazuh-bastionpro-rules.xml)
  → `/var/ossec/etc/rules/bastionpro_rules.xml`
- [`docs/ops/wazuh-bastionpro-decoders.xml`](../../ops/wazuh-bastionpro-decoders.xml)
  → `/var/ossec/etc/decoders/bastionpro_decoders.xml`
- Runbook permissions / reload :
  [`docs/ops/wazuh-bastionpro-deploy.md`](../../ops/wazuh-bastionpro-deploy.md)

### Permissions (critique)

Les fichiers doivent être **`root:wazuh` `0660`**. Sinon `wazuh-analysisd` logue
`Could not open file 'etc/rules/bastionpro_rules.xml' … Permission denied`,
**continue de tourner**, mais **sans** charger les règles BastionPro → plus
d’alertes (incident 2026-08-30 après ~09:43).

```bash
sudo install -o root -g wazuh -m 0660 \
  wazuh-bastionpro-rules.xml \
  /var/ossec/etc/rules/bastionpro_rules.xml
sudo install -o root -g wazuh -m 0660 \
  wazuh-bastionpro-decoders.xml \
  /var/ossec/etc/decoders/bastionpro_decoders.xml

sudo xmllint --noout /var/ossec/etc/rules/bastionpro_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t   # code retour 0
sudo systemctl reload wazuh-manager
```

AWX / Ansible : `owner: root`, `group: wazuh`, `mode: "0660"` sur les deux
fichiers (détail dans le runbook).

Smoke `wazuh-logtest` (attendu `bastionpro-cef` + `rule.id` `100501`) :

```text
2026-08-30T13:45:00Z bastion BastionPro-Sentinel CEF:0|Bastion|BastionPro-Sentinel|0.5.0|BST-SIEM-0001|SIEM_CONNECTIVITY_TEST|1
```

| `data.bastion.cef_severity` | `rule.id` | `rule.level` | Exemple |
|-----------------------------|-----------|--------------|---------|
| 1 | 100520 | 3 | INFO / ActiveSync allowed |
| 3 | 100521 | 5 | NOTICE / config WAF |
| 5 | 100522 | 7 | WARNING / CRS, hammering |
| 7 | 100523 | 10 | ERROR |
| 10 | 100524 → **100530** | **12** | CRITICAL / **BST-WAF-4001** |

Règles manager : catch-all `100500`, SIEM/AUTH/PROXY `100501`–`100512`, mapping
CEF / WAF `100520`–`100532` (fichier dépôt ci-dessus).

### Chaîne forwarder (audit 2026-08-29)

| Étape | Hôte | Rôle |
|-------|------|------|
| Émission CEF TLS | `vmdmz-docker01` (bastion-app) | syslog TLS → `:6514` |
| Collecte fichier | `vmtools-wazuhlogsfw01` | rsyslog → `/var/log/remote/vmdmz-docker01.ar-systems.fr.log` |
| Agent | idem | `localfile` `/var/log/remote/*.log` |
| Decode + rules | **manager** | `bastionpro-cef` + règles `10050x` |

Bruit connu : ~90 % des lignes CEF = `BST-AUTH-0007` (ACTIVESYNC_ALLOWED, CEF 1).
Filtrer côté Bastion (Admin → SIEM) ou ignorer `100501` dans les dashboards
critique.

Sans ces règles enfants, INFO et ban IP apparaissent au même niveau dans Wazuh
alors que le CEF Bastion est correct.

## Filtrage à l’émission (Admin → Configuration → SIEM)

L’outbox SIEM n’envoie que si :

1. le forward SIEM est **activé** ;
2. l’événement passe le filtre (actions, codes `BST-…`, globs de domaine
   `BST-WAF-*`, ou seuil `severity>=WARNING`, etc.).

Un événement filtré n’apparaît **pas** dans le SIEM (même s’il est visible dans
`/admin/logs`).

## Volumes catalogue (indicatif)

Ordre de grandeur du registre runtime (tous domaines) :

| Criticité | CEF | Ordre de grandeur |
|-----------|-----|-------------------|
| INFO | 1 | ~25 |
| NOTICE | 3 | ~140 |
| WARNING | 5 | ~32 |
| ERROR | 7 | ~11 |
| CRITICAL | 10 | ~18 |

Les counts évoluent avec le catalogue — se fier à `/admin/logs/catalogue`.

## Références code

| Fichier | Rôle |
|---------|------|
| `app/audit/event_catalog.py` | codes, tranches, `CEF_SEVERITY`, `SYSLOG_SEVERITY` |
| `app/siem/formatters.py` | `cef_severity()`, `format_cef()`, `format_ecs()` |
| `app/siem/outbox.py` | enqueue + filtre |
| `docs/systeme-codes-logs-criticite.md` | note technique dépôt |
| `docs/ops/wazuh-bastionpro-deploy.md` | déploiement manager + permissions |

Suite admin : [Sessions et logs](./04-03-sessions-logs.md) · [WAF ModSecurity](./04-05-waf-modsecurity.md)
