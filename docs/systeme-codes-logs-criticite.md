# Système de codes de logs — criticité normalisée

Format : `BST-<DOMAINE>-<NNNN>` (la tranche du numéro porte la criticité).

Source de vérité runtime : [`app/audit/event_catalog.py`](../app/audit/event_catalog.py).

## Tranches

| Tranche | Criticité |
|---------|-----------|
| 0000 | WARNING (non catalogué) |
| 0001–0999 | INFO |
| 1000–1999 | NOTICE |
| 2000–2999 | WARNING |
| 3000–3999 | ERROR |
| 4000–4999 | CRITICAL |

## Domaines

`AUTH`, `BGL`, `SESS`, `RBAC`, `VLT`, `FILE`, `WAF`, `PROXY`, `ADM`, `SIEM`, `PROV`, `SYS`.

## Inventaire (2026-08-14)

- Source de vérité : `app/audit/event_catalog.py` (export admin : `/admin/logs/catalogue?export=json`).
- **206** entrées au registre (dont codes réservés sans émetteur).
- Domaine **AUTH** (extrait runtime) :

| Code | Label | Criticité | legacy_action |
|------|-------|-----------|---------------|
| BST-AUTH-0001 | SSO_LOGIN_SUCCEEDED | INFO | oidc_login_success |
| BST-AUTH-0002 | SSO_OTP_LOGIN_SUCCEEDED | INFO | oidc_login_otp_success |
| BST-AUTH-0003 | SSO_LOGOUT | INFO | oidc_logout |
| BST-AUTH-0004 | PORTAL_LOGOUT | INFO | portal_logout |
| BST-AUTH-0005 | SSO_OTP_REQUIRED | INFO | oidc_login_otp_required |
| BST-AUTH-0006 | SSO_TOTP_SETUP_REQUIRED | INFO | oidc_login_totp_setup_required |
| BST-AUTH-0007 | ACTIVESYNC_ALLOWED | INFO | activesync.allowed |
| BST-AUTH-0008 | APP_LAUNCH | INFO | app_launch |
| BST-AUTH-0009 | ACTIVESYNC_DEVICE_DISCOVERED | INFO | activesync.device_discovered |
| BST-AUTH-1001 | ACTIVESYNC_DEVICE_APPROVED | NOTICE | activesync.device_approved |
| BST-AUTH-1002 | ACTIVESYNC_DEVICE_REVOKED | NOTICE | activesync.device_revoked |
| BST-AUTH-1003 | ACTIVESYNC_DEVICE_CONTROL_ENABLED | NOTICE | activesync.device_control_enabled |
| BST-AUTH-1004 | ACTIVESYNC_DEVICE_UNBLOCKED | NOTICE | activesync.device_unblocked |
| BST-AUTH-2001 | SSO_LOGIN_FAILED | WARNING | oidc_login_failed |
| BST-AUTH-2002 | SSO_OTP_LOGIN_FAILED | WARNING | oidc_login_otp_failed |
| BST-AUTH-2003 | SSO_LOGIN_FAILED_PORTAL | WARNING | security.sso_login_failed |
| BST-AUTH-2004 | SSO_UNSUPPORTED_FLOW | WARNING | oidc_login_unsupported_flow |
| BST-AUTH-2005 | ACTIVESYNC_DENIED | WARNING | activesync.denied |
| BST-AUTH-2006 | ACTIVESYNC_DEVICE_DENIED | WARNING | activesync.device_denied |
| BST-AUTH-2007 | ACTIVESYNC_DEVICE_REJECTED_BY_USER | WARNING | activesync.device_rejected |
| BST-AUTH-2008 | ACTIVESYNC_DEVICE_BLOCKED_BY_ADMIN | WARNING | activesync.device_blocked |
| BST-AUTH-2009 | ACTIVESYNC_DEVICE_UNIDENTIFIED | WARNING | activesync.device_unidentified |
| BST-AUTH-4001 | AUTH_BYPASS_ATTEMPT | CRITICAL | *(réservé)* |

`BST-AUTH-2009` porte dans son détail JSON un champ `miss_family` qui regroupe les
`miss_reason` en deux familles décisionnelles : `decoder_failure` (notre parsing échoue sur
une trame porteuse d'un `DeviceId` — à corriger) et `no_device_sent` (le client n'envoie pas
de `DeviceId` — sera refusé dès l'activation du contrôle par appareil). Le critère de
bascule vers le lot 2 se lit par regroupement sur ce champ : `miss_family` est disponible
comme colonne optionnelle dans `/admin/logs`, et la recherche plein texte porte déjà sur le
détail JSON — aucun accès SQL direct n'est nécessaire.

Toute évolution du catalogue code doit être re-exportée ici (gouvernance : pas de drift §3 vs runtime).

Corrections vs catalogue Pod initial :

| Hypothèse Pod | Réalité code |
|---------------|--------------|
| `auth.login` / `auth.logout` | `oidc_login_success`, `oidc_logout`, `portal_logout` |
| `grant.create` / `grant.delete` | `rbac.grant.created` / `rbac.grant.deleted` |
| `security.sso_login_failed` | conservé + `oidc_login_failed` |
| `key_rotation` | conservé (`BST-VLT-1010`) |

Export admin : `/admin/logs/catalogue` (CSV/JSON).

## CEF (syslog TLS) — conformité multi-SIEM

- Extensions : `\` / `=` / `|` échappés (`Cmd\=Sync`). Obligatoire pour Splunk / QRadar / Sentinel (Wazuh custom decoder peut masquer le bug).
- `suser` = identité **canonique** (UUID Keycloak si présent, sinon email). Le display name va dans `cs3` (`cs3Label=displayName`), pas concaténé dans `suser`.
- `deviceExternalId` : promu depuis `DeviceId` ActiveSync (choix assumé, pas un effet de bord d’URI).
- Syslog RFC5424 : timestamp **sans** fraction de seconde (évite le tronquage hostname côté pré-décodeur Wazuh : `bastio` ← `bastion`).
- Transport produit : TLS + vérif certificat (`syslog_tls_verify`). Le hop DMZ → collecteur fichier (`/var/log/remote/…`) est hors code : à vérifier côté infra (TLS obligatoire jusqu’au collecteur).

## Écriture

`log_action(..., code=None)` résout via `legacy_action` ; action inconnue → `BST-<domaine>-0000` / WARNING, sans exception.

Colonnes `audit_logs.event_code` et `audit_logs.severity` (nullable, pas de backfill historique).
