"""Central Bastion audit event catalogue (BST-<DOMAIN>-<NNNN>)."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

DOMAINS: frozenset[str] = frozenset(
    {"AUTH", "BGL", "SESS", "RBAC", "VLT", "FILE", "WAF", "PROXY", "ADM", "SIEM", "PROV", "SYS"}
)

_CODE_RE = re.compile(r"^BST-([A-Z]{3,5})-(\d{4})$")


class Severity(str, Enum):
    INFO = "INFO"
    NOTICE = "NOTICE"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


def severity_from_number(num: int) -> Severity:
    if num == 0:
        return Severity.WARNING  # uncatalogued sentinel
    if 1 <= num <= 999:
        return Severity.INFO
    if 1000 <= num <= 1999:
        return Severity.NOTICE
    if 2000 <= num <= 2999:
        return Severity.WARNING
    if 3000 <= num <= 3999:
        return Severity.ERROR
    if 4000 <= num <= 4999:
        return Severity.CRITICAL
    raise ValueError(f"event number {num:04d} is outside allowed severity bands")


def parse_event_code(code: str) -> tuple[str, int]:
    m = _CODE_RE.match((code or "").strip().upper())
    if not m:
        raise ValueError(f"invalid event code: {code!r}")
    domain, num_s = m.group(1), m.group(2)
    if domain not in DOMAINS:
        raise ValueError(f"unknown event domain: {domain}")
    return domain, int(num_s)


@dataclass(frozen=True)
class EventDef:
    code: str
    label: str
    title_fr: str
    ecs_category: tuple[str, ...]
    legacy_action: str | None = None
    runbook: str | None = None
    deprecated: bool = False

    @property
    def domain(self) -> str:
        return parse_event_code(self.code)[0]

    @property
    def number(self) -> int:
        return parse_event_code(self.code)[1]

    @property
    def severity(self) -> Severity:
        return severity_from_number(self.number)


def _e(
    code: str,
    label: str,
    title_fr: str,
    ecs_category: tuple[str, ...] | list[str],
    *,
    legacy_action: str | None = None,
    runbook: str | None = None,
    deprecated: bool = False,
) -> EventDef:
    return EventDef(
        code=code,
        label=label,
        title_fr=title_fr,
        ecs_category=tuple(ecs_category),
        legacy_action=legacy_action,
        runbook=runbook,
        deprecated=deprecated,
    )


_RAW_EVENTS: tuple[EventDef, ...] = (
    _e('BST-ADM-0001', 'CONTAINER_LOGS_VIEWED', 'Logs de conteneur consultés', ('configuration',),
       legacy_action='admin.container_logs.viewed'),
    _e('BST-ADM-0002', 'APP_ACCESS_LOGS_VIEWED', "Logs d'accès applicatifs consultés", ('configuration',),
       legacy_action='admin.app_access_logs.viewed'),
    _e('BST-ADM-0003', 'PORTAL_FAVORITE_ADDED', 'Favori portail ajouté', ('configuration',),
       legacy_action='portal.favorite_add'),
    _e('BST-ADM-0004', 'PORTAL_FAVORITE_REMOVED', 'Favori portail retiré', ('configuration',),
       legacy_action='portal.favorite_remove'),
    _e('BST-ADM-0005', 'NOTIFICATION_DISMISSED', 'Notification masquée', ('configuration',),
       legacy_action='notification.dismissed'),
    _e('BST-ADM-0006', 'NOTIFICATIONS_DISMISSED_ALL', 'Toutes les notifications masquées', ('configuration',),
       legacy_action='notification.dismissed_all'),
    _e('BST-ADM-0007', 'SMTP_CONNECTIVITY_TEST', 'Test de connectivité SMTP', ('configuration',),
       legacy_action='smtp.connectivity.test'),
    _e('BST-ADM-1001', 'APP_CREATED', 'Application créée', ('configuration',),
       legacy_action='app.create'),
    _e('BST-ADM-1002', 'APP_CREATED_ALT', 'Application créée (flux alternatif)', ('configuration',),
       legacy_action='app.created'),
    _e('BST-ADM-1003', 'APP_UPDATED', 'Application modifiée', ('configuration',),
       legacy_action='app.update'),
    _e('BST-ADM-1004', 'APP_UPDATED_ALT', 'Application modifiée (flux alternatif)', ('configuration',),
       legacy_action='app.updated'),
    _e('BST-ADM-1005', 'APP_DELETED', 'Application supprimée', ('configuration',),
       legacy_action='app.delete'),
    _e('BST-ADM-1006', 'APP_LOGO_UPDATED', "Logo d'application mis à jour", ('configuration',),
       legacy_action='app.logo_updated'),
    _e('BST-ADM-1007', 'APP_LOGO_REMOVED', "Logo d'application retiré", ('configuration',),
       legacy_action='app.logo_removed'),
    _e('BST-ADM-1008', 'CRUSHFTP_COMPANIES_SYNCED', 'Sociétés CrushFTP synchronisées', ('configuration',),
       legacy_action='app.crushftp.companies_synced'),
    _e('BST-ADM-1009', 'REALM_CREATE', 'Realm créé (service)', ('configuration',),
       legacy_action='realm.create'),
    _e('BST-ADM-1010', 'REALM_CREATED', 'Realm créé', ('configuration',),
       legacy_action='realm.created'),
    _e('BST-ADM-1011', 'REALM_UPDATED', 'Realm modifié', ('configuration',),
       legacy_action='realm.updated'),
    _e('BST-ADM-1012', 'REALM_DELETE', 'Realm supprimé (service)', ('configuration',),
       legacy_action='realm.delete'),
    _e('BST-ADM-1013', 'REALM_DELETED', 'Realm supprimé', ('configuration',),
       legacy_action='realm.deleted'),
    _e('BST-ADM-1014', 'REALM_ENABLED', 'Realm activé', ('configuration',),
       legacy_action='realm.enabled'),
    _e('BST-ADM-1015', 'REALM_DISABLED', 'Realm désactivé', ('configuration',),
       legacy_action='realm.disabled'),
    _e('BST-ADM-1016', 'REALM_EXPORTED', 'Realm exporté', ('configuration',),
       legacy_action='realm.export'),
    _e('BST-ADM-1017', 'REALM_OIDC_TESTED', 'Test OIDC de realm', ('configuration', 'authentication',),
       legacy_action='realm.test'),
    _e('BST-ADM-1018', 'REALM_PORT_REALLOCATED', 'Port de realm réalloué', ('configuration',),
       legacy_action='realm.port_reallocated'),
    _e('BST-ADM-1019', 'REALM_OIDC_BFF_CONFIG_SET', 'Configuration OIDC BFF définie', ('configuration', 'authentication',),
       legacy_action='realm.oidc_bff_config_set'),
    _e('BST-ADM-1020', 'REALM_OIDC_NATIVE_SESSION_ENABLED', 'Session OIDC native activée', ('configuration', 'authentication',),
       legacy_action='realm.oidc_native_session_enabled'),
    _e('BST-ADM-1021', 'REALM_OIDC_NATIVE_SESSION_DISABLED', 'Session OIDC native désactivée', ('configuration', 'authentication',),
       legacy_action='realm.oidc_native_session_disabled'),
    _e('BST-ADM-1022', 'BRANDING_UPDATED', 'Personnalisation du portail modifiée', ('configuration',),
       legacy_action='branding_settings.updated'),
    _e('BST-ADM-1023', 'BRANDING_LOGO_CHANGED', 'Logo de marque modifié', ('configuration',),
       legacy_action='branding_settings.logo_changed'),
    _e('BST-ADM-1024', 'BRANDING_FAVICON_CHANGED', 'Favicon modifié', ('configuration',),
       legacy_action='branding_settings.favicon_changed'),
    _e('BST-ADM-1025', 'BRANDING_LOGO_CLEARED', 'Logo de marque effacé', ('configuration',),
       legacy_action='branding_settings.logo_cleared'),
    _e('BST-ADM-1026', 'BRANDING_FAVICON_CLEARED', 'Favicon effacé', ('configuration',),
       legacy_action='branding_settings.favicon_cleared'),
    _e('BST-ADM-1027', 'SMTP_SETTINGS_UPDATED', 'Paramètres SMTP mis à jour', ('configuration',),
       legacy_action='portal_settings.smtp_updated'),
    _e('BST-ADM-1028', 'SUBDOMAIN_SSO_TOGGLED', 'SSO sous-domaine modifié', ('configuration', 'authentication',),
       legacy_action='portal_settings.subdomain_sso_enabled'),
    _e('BST-ADM-1029', 'CONTAINER_LOGS_SETTINGS_UPDATED', 'Paramètres logs conteneurs mis à jour', ('configuration',),
       legacy_action='security.container_logs_settings.updated'),
    _e('BST-ADM-2001', 'LOGIN_FORM_ANALYZED', 'Analyse de formulaire de login', ('configuration',),
       legacy_action='app.login_form.analyzed'),
    _e('BST-ADM-4001', 'SECURITY_CONTROL_DISABLED', "Contrôle de sécurité désactivé depuis l'UI", ('configuration', 'iam',),
       runbook="Confirmer l'acteur, réactiver si non autorisé."),
    _e('BST-AUTH-0001', 'SSO_LOGIN_SUCCEEDED', 'Connexion SSO réussie', ('authentication',),
       legacy_action='oidc_login_success'),
    _e('BST-AUTH-0002', 'SSO_OTP_LOGIN_SUCCEEDED', 'Connexion SSO OTP réussie', ('authentication',),
       legacy_action='oidc_login_otp_success'),
    _e('BST-AUTH-0003', 'SSO_LOGOUT', 'Déconnexion SSO', ('authentication',),
       legacy_action='oidc_logout'),
    _e('BST-AUTH-0004', 'PORTAL_LOGOUT', 'Déconnexion portail', ('authentication',),
       legacy_action='portal_logout'),
    _e('BST-AUTH-0005', 'SSO_OTP_REQUIRED', 'OTP requis pour la connexion SSO', ('authentication',),
       legacy_action='oidc_login_otp_required'),
    _e('BST-AUTH-0006', 'SSO_TOTP_SETUP_REQUIRED', 'Configuration TOTP requise', ('authentication',),
       legacy_action='oidc_login_totp_setup_required'),
    _e('BST-AUTH-0007', 'ACTIVESYNC_ALLOWED', 'Accès ActiveSync autorisé', ('authentication',),
       legacy_action='activesync.allowed'),
    _e('BST-AUTH-0008', 'APP_LAUNCH', "Lancement d'application depuis le portail", ('authentication',),
       legacy_action='app_launch'),
    _e('BST-AUTH-2001', 'SSO_LOGIN_FAILED', "Échec d'authentification SSO", ('authentication',),
       legacy_action='oidc_login_failed'),
    _e('BST-AUTH-2002', 'SSO_OTP_LOGIN_FAILED', "Échec d'authentification SSO OTP", ('authentication',),
       legacy_action='oidc_login_otp_failed'),
    _e('BST-AUTH-2003', 'SSO_LOGIN_FAILED_PORTAL', 'Échec de connexion SSO (portail)', ('authentication',),
       legacy_action='security.sso_login_failed'),
    _e('BST-AUTH-2004', 'SSO_UNSUPPORTED_FLOW', "Flux d'authentification SSO non supporté", ('authentication',),
       legacy_action='oidc_login_unsupported_flow'),
    _e('BST-AUTH-2005', 'ACTIVESYNC_DENIED', 'Accès ActiveSync refusé', ('authentication',),
       legacy_action='activesync.denied'),
    _e('BST-AUTH-4001', 'AUTH_BYPASS_ATTEMPT', "Tentative de contournement de l'authentification", ('authentication', 'intrusion_detection',),
       runbook='Isoler la route, vérifier la chaîne oauth2-auth, auditer les accès récents.'),
    _e('BST-BGL-1001', 'BREAKGLASS_LOGIN_SUCCEEDED', 'Connexion break-glass réussie (LAN)', ('authentication',),
       legacy_action='breakglass.login'),
    _e('BST-BGL-1002', 'BREAKGLASS_LOGOUT', 'Déconnexion break-glass', ('authentication',),
       legacy_action='breakglass.logout'),
    _e('BST-BGL-1003', 'BREAKGLASS_SESSION_REVOKED', 'Session break-glass révoquée', ('authentication', 'session',),
       legacy_action='breakglass_session_revoked', runbook='Confirmer la légitimité de la révocation.'),
    _e('BST-BGL-1004', 'BREAKGLASS_SECRET_GENERATED', 'Secret JWT break-glass généré', ('authentication', 'configuration',),
       legacy_action='breakglass_secret_generated_from_ui'),
    _e('BST-BGL-1005', 'BREAKGLASS_SECRET_ROTATED', 'Secret JWT break-glass tourné', ('authentication', 'configuration',),
       legacy_action='breakglass_secret_rotated_from_ui'),
    _e('BST-BGL-1006', 'BREAKGLASS_SETUP', 'Compte break-glass configuré', ('authentication', 'configuration',),
       legacy_action='breakglass.setup'),
    _e('BST-BGL-1007', 'BREAKGLASS_COOKIE_GRACE_REUSE', 'Réutilisation gracieuse du cookie break-glass', ('authentication', 'session',),
       legacy_action='breakglass_cookie_grace_reuse'),
    _e('BST-BGL-2001', 'BREAKGLASS_LOGIN_FAILED', 'Échec de connexion break-glass', ('authentication',),
       legacy_action='breakglass.login_failed'),
    _e('BST-BGL-2002', 'BREAKGLASS_LOGIN_DENIED_NON_LAN', 'Connexion break-glass refusée : IP hors RFC1918', ('authentication',),
       legacy_action='breakglass.login_denied_non_lan', runbook="Vérifier l'origine de l'IP."),
    _e('BST-BGL-3001', 'BREAKGLASS_SECRET_MISSING', 'Secret break-glass absent : fail-closed', ('authentication',),
       runbook="Régénérer le secret depuis l'admin, vérifier le vault runtime."),
    _e('BST-BGL-4001', 'BREAKGLASS_LOGIN_FROM_NON_LAN', 'Connexion break-glass réussie depuis une IP hors LAN', ('authentication', 'intrusion_detection',),
       runbook="Vérifier l'origine de l'IP, confirmer avec le porteur, révoquer le jti si non légitime."),
    _e('BST-BGL-4002', 'BREAKGLASS_REVOKED_TOKEN_REPLAYED', "Réutilisation d'un jeton break-glass révoqué", ('authentication', 'intrusion_detection',),
       runbook='Révoquer toutes les sessions break-glass, tourner le secret JWT.'),
    _e('BST-BGL-4003', 'BREAKGLASS_COOKIE_REPLAY_DETECTED', 'Rejeu de cookie break-glass détecté', ('authentication', 'intrusion_detection',),
       legacy_action='breakglass_cookie_replay_detected', runbook="Révoquer la session, analyser l'IP source."),
    _e('BST-FILE-0001', 'FILE_DOWNLOADED', 'Fichier téléchargé', ('file',),
       legacy_action='file.downloaded'),
    _e('BST-FILE-1001', 'FILE_CREATED', 'Fichier créé', ('file',),
       legacy_action='file.created'),
    _e('BST-FILE-1002', 'FILE_FOLDER_CREATED', 'Dossier créé', ('file',),
       legacy_action='file.folder.created'),
    _e('BST-FILE-1003', 'FILE_UPDATED', 'Fichier modifié', ('file',),
       legacy_action='file.updated'),
    _e('BST-FILE-1004', 'FILE_RENAMED', 'Fichier renommé', ('file',),
       legacy_action='file.renamed'),
    _e('BST-FILE-1005', 'FILE_DELETED', 'Fichier supprimé', ('file',),
       legacy_action='file.deleted'),
    _e('BST-FILE-1006', 'FILE_ARCHIVED', 'Fichier archivé', ('file',),
       legacy_action='file.archived'),
    _e('BST-FILE-1007', 'FILE_VERSION_PUBLISHED', 'Version de fichier publiée', ('file',),
       legacy_action='file.version.published'),
    _e('BST-FILE-1008', 'FILE_VERSION_UPDATED', 'Version de fichier mise à jour', ('file',),
       legacy_action='file.version.updated'),
    _e('BST-FILE-1009', 'FILE_VERSION_PROMOTED', 'Version de fichier promue', ('file',),
       legacy_action='file.version.promoted'),
    _e('BST-FILE-1010', 'FILE_VERSION_ARCHIVED', 'Version de fichier archivée', ('file',),
       legacy_action='file.version.archived'),
    _e('BST-FILE-1011', 'FILE_VERSION_CHANNEL_CHANGED', 'Canal de version modifié', ('file',),
       legacy_action='file.version.channel_changed'),
    _e('BST-FILE-1012', 'FILE_CHANNEL_ASSIGNMENT_CREATED', 'Affectation de canal créée', ('file',),
       legacy_action='file.channel_assignment.created'),
    _e('BST-FILE-1013', 'FILE_CHANNEL_ASSIGNMENT_REMOVED', 'Affectation de canal retirée', ('file',),
       legacy_action='file.channel_assignment.removed'),
    _e('BST-FILE-4001', 'MALICIOUS_FILE_DETECTED', 'Fichier malveillant détecté au dépôt', ('file', 'malware',),
       runbook="Quarantaine, analyser l'acteur et le canal."),
    _e('BST-PROV-1001', 'ACCOUNT_CREATED', 'Compte créé', ('iam',),
       legacy_action='account.created'),
    _e('BST-PROV-1002', 'ACCOUNT_DELETED', 'Compte supprimé', ('iam',),
       legacy_action='account.deleted'),
    _e('BST-PROV-1003', 'KEYCLOAK_ACCOUNT_CREATED', 'Compte Keycloak créé', ('iam',),
       legacy_action='account.keycloak_created'),
    _e('BST-PROV-1004', 'KEYCLOAK_ACCOUNT_DELETED', 'Compte Keycloak supprimé', ('iam',),
       legacy_action='account.keycloak_deleted'),
    _e('BST-PROV-1005', 'KEYCLOAK_CREATE_RETRY', 'Nouvelle tentative de création Keycloak', ('iam',),
       legacy_action='account.keycloak_retry'),
    _e('BST-PROV-1006', 'ACCOUNT_GROUP_ASSIGNED', 'Groupe assigné au compte', ('iam',),
       legacy_action='account.group_assigned'),
    _e('BST-PROV-1007', 'ACCOUNT_GROUP_REMOVED', 'Groupe retiré du compte', ('iam',),
       legacy_action='account.group_removed'),
    _e('BST-PROV-1008', 'ACCOUNT_COMPANY_GROUP_ENSURED', 'Groupe société assuré', ('iam',),
       legacy_action='account.company_group_ensured'),
    _e('BST-PROV-1009', 'ACCOUNT_IDENTITY_UPDATED', 'Identité du compte mise à jour', ('iam',),
       legacy_action='account.identity_updated'),
    _e('BST-PROV-1010', 'ACCOUNT_PASSWORD_RESET', 'Mot de passe du compte réinitialisé', ('iam', 'authentication',),
       legacy_action='account.password_reset'),
    _e('BST-PROV-1011', 'ACCOUNT_EMAIL_VERIFIED', 'E-mail du compte vérifié', ('iam',),
       legacy_action='account.email_verified'),
    _e('BST-PROV-1012', 'ACCOUNT_CREDENTIALS_EMAILED', 'Identifiants envoyés par e-mail', ('iam',),
       legacy_action='account.credentials_emailed'),
    _e('BST-PROV-1013', 'ACCOUNT_CREDENTIAL_SYNCED', "Credential synchronisé vers l'application", ('iam',),
       legacy_action='account.credential_synced_to_app'),
    _e('BST-PROV-1014', 'ACCOUNT_APP_DELETED', 'Compte applicatif supprimé', ('iam',),
       legacy_action='account.app_deleted'),
    _e('BST-PROV-1015', 'PROVISIONING_SUCCESS', 'Provisioning réussi', ('iam',),
       legacy_action='account.provisioning.success'),
    _e('BST-PROV-1016', 'PROVISIONING_SKIPPED', 'Provisioning ignoré', ('iam',),
       legacy_action='account.provisioning.skipped'),
    _e('BST-PROV-1017', 'PROVISIONING_NOT_APPLICABLE', 'Provisioning non applicable', ('iam',),
       legacy_action='account.provisioning.not_applicable'),
    _e('BST-PROV-1018', 'ACCOUNT_REQUIRE_OTP', 'Configuration OTP exigée pour le compte', ('iam', 'authentication',),
       legacy_action='account.require_configure_otp'),
    _e('BST-PROV-2001', 'ACCOUNT_DELETE_INCOMPLETE', 'Suppression de compte incomplète', ('iam',),
       legacy_action='account.delete_incomplete'),
    _e('BST-PROV-3001', 'PROVISIONING_FAILED', 'Provisioning en échec', ('iam',),
       legacy_action='account.provisioning.failed'),
    _e('BST-PROV-3002', 'KEYCLOAK_CREATE_FAILED', 'Création Keycloak en échec', ('iam',),
       legacy_action='account.keycloak_create_failed'),
    _e('BST-PROV-3003', 'KEYCLOAK_DELETE_FAILED', 'Suppression Keycloak en échec', ('iam',),
       legacy_action='account.keycloak_delete_failed'),
    _e('BST-PROV-3004', 'ACCOUNT_GROUP_ASSIGN_FAILED', 'Assignation de groupe en échec', ('iam',),
       legacy_action='account.group_assign_failed'),
    _e('BST-PROV-3005', 'ACCOUNT_CREDENTIALS_EMAIL_FAILED', 'Envoi des identifiants en échec', ('iam',),
       legacy_action='account.credentials_email_failed'),
    _e('BST-PROV-3006', 'ACCOUNT_APP_DELETE_FAILED', 'Suppression compte applicatif en échec', ('iam',),
       legacy_action='account.app_delete_failed'),
    _e('BST-PROXY-1001', 'ACME_SETTINGS_UPDATED', 'Paramètres ACME mis à jour', ('configuration',),
       legacy_action='acme.settings_updated'),
    _e('BST-PROXY-1002', 'ACME_RECONCILED', 'Réconciliation ACME effectuée', ('configuration',),
       legacy_action='acme.reconcile'),
    _e('BST-PROXY-1003', 'PENDING_HOST_APPROVED', 'Hôte en attente approuvé', ('configuration',),
       legacy_action='pending_host.approved'),
    _e('BST-PROXY-1004', 'PENDING_HOST_REJECTED', 'Hôte en attente rejeté', ('configuration',),
       legacy_action='pending_host.rejected'),
    _e('BST-PROXY-2001', 'ACCESS_DENIED_UNKNOWN_HOST', 'Accès refusé : hôte inconnu', ('network',),
       legacy_action='access_denied_unknown_host'),
    _e('BST-PROXY-4001', 'TLS_CERT_EXPIRED', 'Certificat TLS expiré en production', ('configuration',),
       runbook='Forcer renouvellement ACME, vérifier sync nginx.'),
    _e('BST-RBAC-0001', 'USERS_EXPORT_CSV', 'Export CSV des utilisateurs', ('iam',),
       legacy_action='users.export_csv'),
    _e('BST-RBAC-1001', 'ACCESS_GRANT_CREATED', "Droit d'accès accordé", ('iam',),
       legacy_action='rbac.grant.created'),
    _e('BST-RBAC-1002', 'ACCESS_GRANT_REVOKED', "Droit d'accès retiré", ('iam',),
       legacy_action='rbac.grant.deleted'),
    _e('BST-RBAC-1003', 'GROUP_SYNCED_FROM_KEYCLOAK', 'Groupes synchronisés depuis Keycloak', ('iam',),
       legacy_action='rbac.groups.sync'),
    _e('BST-RBAC-1004', 'GROUP_DELETED', 'Groupe RBAC supprimé', ('iam',),
       legacy_action='rbac.group.deleted'),
    _e('BST-RBAC-1005', 'RBAC_ROLE_CREATED', 'Rôle RBAC créé', ('iam',),
       legacy_action='rbac_role_created'),
    _e('BST-RBAC-1006', 'ROLE_PERMISSION_UPDATED', 'Permissions de rôle mises à jour', ('iam',),
       legacy_action='role_permission_updated'),
    _e('BST-RBAC-1007', 'GROUP_RBAC_CONFIG_UPDATED', 'Configuration RBAC de groupe mise à jour', ('iam',),
       legacy_action='group_rbac_config_updated'),
    _e('BST-RBAC-1008', 'PORTAL_ADMIN_GRANT_CREATED', 'Droit admin portail accordé', ('iam',),
       legacy_action='portal_admin_grant_created'),
    _e('BST-RBAC-1009', 'PORTAL_ADMIN_GRANT_REVOKED', 'Droit admin portail retiré', ('iam',),
       legacy_action='portal_admin_grant_revoked'),
    _e('BST-RBAC-1010', 'ACCESS_REQUEST_SUBMITTED', "Demande d'accès soumise", ('iam',),
       legacy_action='access_request.submitted'),
    _e('BST-RBAC-1011', 'ACCESS_REQUEST_APPROVED', "Demande d'accès approuvée", ('iam',),
       legacy_action='access_request.approved'),
    _e('BST-RBAC-1012', 'ACCESS_REQUEST_REJECTED', "Demande d'accès rejetée", ('iam',),
       legacy_action='access_request.rejected'),
    _e('BST-RBAC-1013', 'PENDING_USER_APPROVED', 'Utilisateur en attente approuvé', ('iam',),
       legacy_action='pending_user.approved'),
    _e('BST-RBAC-1014', 'PENDING_USER_REJECTED', 'Utilisateur en attente rejeté', ('iam',),
       legacy_action='pending_user.rejected'),
    _e('BST-RBAC-1015', 'USERS_BULK_GROUP_ADD', "Ajout massif d'utilisateurs à un groupe", ('iam',),
       legacy_action='users.bulk_group_add'),
    _e('BST-RBAC-1016', 'USERS_BULK_GROUP_REMOVE', "Retrait massif d'utilisateurs d'un groupe", ('iam',),
       legacy_action='users.bulk_group_remove'),
    _e('BST-RBAC-1017', 'ROBOTIC_IMPERSONATE', 'Impersonation robotique effectuée', ('iam', 'authentication',),
       legacy_action='robotic.impersonate'),
    _e('BST-RBAC-1018', 'ROBOTIC_IMPERSONATE_GENERIC', 'Impersonation robotique générique', ('iam', 'authentication',),
       legacy_action='robotic.impersonate.generic'),
    _e('BST-RBAC-2001', 'ACCESS_DENIED_NO_GRANT', "Accès refusé : aucun droit sur l'application", ('iam',),
       legacy_action='access_denied_no_grant'),
    _e('BST-RBAC-2002', 'ACCESS_DENIED_NO_APP', 'Accès refusé : application inconnue', ('iam',),
       legacy_action='access_denied_no_app'),
    _e('BST-RBAC-2003', 'ACCESS_REQUEST_CAPTCHA_FAILED', "Captcha de demande d'accès échoué", ('iam',),
       legacy_action='access_request.captcha_failed'),
    _e('BST-RBAC-2004', 'ACCESS_REQUEST_HONEYPOT', "Honeypot de demande d'accès déclenché", ('iam', 'intrusion_detection',),
       legacy_action='access_request.honeypot'),
    _e('BST-RBAC-2005', 'ACCESS_REQUEST_RATE_LIMITED', "Demande d'accès limitée en débit", ('iam',),
       legacy_action='access_request.rate_limited'),
    _e('BST-RBAC-2006', 'ROBOTIC_IMPERSONATE_BLOCKED_GROUP', 'Impersonation bloquée : groupe exclu', ('iam',),
       legacy_action='robotic.impersonate.blocked_group_excluded'),
    _e('BST-RBAC-2007', 'ROBOTIC_IMPERSONATE_BLOCKED_NO_CRED', 'Impersonation bloquée : pas de credential', ('iam',),
       legacy_action='robotic.impersonate.blocked_no_credential'),
    _e('BST-RBAC-2008', 'ROBOTIC_IMPERSONATE_BLOCKED_IDENTITY', 'Impersonation bloquée : identité invalide', ('iam',),
       legacy_action='robotic.impersonate.blocked_identity'),
    _e('BST-RBAC-4001', 'PRIVILEGE_ESCALATION_SUSPECTED', 'Écart détecté entre droits déclarés et droits effectifs', ('iam', 'intrusion_detection',),
       runbook='Comparer grants effectifs vs Keycloak, révoquer si anomalie.'),
    _e('BST-SESS-1001', 'SESSION_CLOSED', 'Session fermée', ('session',),
       legacy_action='session.closed'),
    _e('BST-SESS-1002', 'SESSION_ISOLATED', 'Session isolée', ('session',),
       legacy_action='session.isolated'),
    _e('BST-SESS-1003', 'SSO_SESSIONS_REVOKED', 'Sessions SSO révoquées', ('session', 'authentication',),
       legacy_action='sessions.revoke_sso'),
    _e('BST-SESS-1004', 'ALL_APP_SESSIONS_REVOKED', 'Toutes les sessions applicatives révoquées', ('session',),
       legacy_action='sessions.revoke_all_app'),
    _e('BST-SESS-1005', 'SESSION_KEYS_ROTATED', 'Clés de session tournées', ('session', 'configuration',),
       legacy_action='session.rotate_keys'),
    _e('BST-SESS-2001', 'SESSION_BINDING_WEAK_MISMATCH', "Dérive de l'empreinte de session", ('session', 'intrusion_detection',),
       legacy_action='session_fingerprint_drift'),
    _e('BST-SESS-4001', 'SESSION_HIJACK_SUSPECTED', 'Usurpation de session suspectée', ('session', 'intrusion_detection',),
       legacy_action='session_hijack_suspected', runbook="Révoquer la session, contacter l'utilisateur, analyser l'IP."),
    _e('BST-SIEM-0001', 'SIEM_CONNECTIVITY_TEST', 'Test de connectivité SIEM', ('configuration',),
       legacy_action='siem.connectivity.test'),
    _e('BST-SIEM-1001', 'SIEM_CONFIG_CHANGED', 'Configuration du forwarder SIEM modifiée', ('configuration',),
       legacy_action='security.siem_forwarding_settings.updated'),
    _e('BST-SIEM-3001', 'SIEM_EVENT_DROPPED', 'Événement SIEM purgé sans livraison', ('configuration',),
       legacy_action='siem.forward.dropped', runbook='Vérifier la file outbox et la connectivité SIEM.'),
    _e('BST-SIEM-4001', 'SIEM_FORWARDING_DOWN', 'Forwarder hors service au-delà du seuil toléré', ('configuration',),
       runbook="Vérifier connectivité SIEM, file d'attente outbox, certificats TLS."),
    _e('BST-SYS-0001', 'HEALTH_PROBE', 'Sonde de santé', ('configuration',),
       legacy_action='health.probe'),
    _e('BST-SYS-0002', 'HEALTH_PROBE_ALL', 'Sondes de santé (toutes)', ('configuration',),
       legacy_action='health.probe_all'),
    _e('BST-SYS-0003', 'HOT_STORE_CONNECTION_TESTED', 'Connexion hot-store testée', ('configuration',),
       legacy_action='hot_store.connection_tested'),
    _e('BST-SYS-1001', 'HOT_STORE_CONFIG_SAVED', 'Configuration hot-store enregistrée', ('configuration',),
       legacy_action='hot_store.config_saved'),
    _e('BST-SYS-1002', 'HOT_STORE_ENABLED', 'Hot-store activé', ('configuration',),
       legacy_action='hot_store.enabled'),
    _e('BST-SYS-1003', 'HOT_STORE_DISABLED', 'Hot-store désactivé', ('configuration',),
       legacy_action='hot_store.disabled'),
    _e('BST-SYS-1004', 'HOT_STORE_SCHEMA_PREPARED', 'Schéma hot-store préparé', ('configuration',),
       legacy_action='hot_store.schema_prepared'),
    _e('BST-SYS-1005', 'HOT_STORE_MIGRATED', 'Migration hot-store effectuée', ('configuration',),
       legacy_action='hot_store.migrate'),
    _e('BST-SYS-1006', 'HOT_STORE_MIGRATE_SKIPPED', 'Migration hot-store ignorée', ('configuration',),
       legacy_action='hot_store.migrate_skipped'),
    _e('BST-SYS-1007', 'INFRA_APPLY_REQUESTED', "Application d'infrastructure demandée", ('configuration',),
       legacy_action='infrastructure.apply.requested'),
    _e('BST-SYS-1008', 'INFRA_APPLY_OK', "Application d'infrastructure réussie", ('configuration',),
       legacy_action='infrastructure.apply.ok'),
    _e('BST-SYS-2001', 'INFRA_APPLY_PENDING_TIMEOUT', "Application d'infrastructure en timeout", ('configuration',),
       legacy_action='infrastructure.apply.pending_timeout'),
    _e('BST-SYS-3001', 'AUDIT_WRITE_FAILED', "Écriture d'audit en échec", ('configuration',),
       runbook="Vérifier l'espace disque / DB ; le journal applicatif porte la trace."),
    _e('BST-SYS-3002', 'INFRA_APPLY_ERROR', "Application d'infrastructure en échec", ('configuration',),
       legacy_action='infrastructure.apply.error'),
    _e('BST-SYS-4001', 'DATABASE_UNAVAILABLE', 'Base de données inaccessible', ('configuration',),
       runbook='Vérifier hot-store / SQLite, disque, connexions.'),
    _e('BST-SYS-4002', 'AUDIT_TRAIL_GAP_DETECTED', "Discontinuité détectée dans le journal d'audit", ('configuration',),
       runbook="Comparer hash d'intégrité, investiguer suppressions."),
    _e('BST-VLT-0001', 'CREDENTIAL_TESTED', 'Test de credential applicatif', ('configuration',),
       legacy_action='credential.test'),
    _e('BST-VLT-0002', 'USER_CREDENTIAL_TESTED', 'Test de credential utilisateur', ('configuration',),
       legacy_action='credential.user.test'),
    _e('BST-VLT-1001', 'CREDENTIAL_SET', 'Credential applicatif enregistré', ('configuration',),
       legacy_action='credential.set'),
    _e('BST-VLT-1002', 'CREDENTIAL_ROTATED', 'Credential applicatif tourné', ('configuration',),
       legacy_action='credential.rotate'),
    _e('BST-VLT-1003', 'CREDENTIAL_DEACTIVATED', 'Credential applicatif désactivé', ('configuration',),
       legacy_action='credential.deactivate'),
    _e('BST-VLT-1004', 'GROUP_CREDENTIAL_SET', 'Credential de groupe enregistré', ('configuration',),
       legacy_action='credential.group.set'),
    _e('BST-VLT-1005', 'GROUP_CREDENTIAL_DELETED', 'Credential de groupe supprimé', ('configuration',),
       legacy_action='credential.group.delete'),
    _e('BST-VLT-1006', 'GROUP_CREDENTIAL_EXCLUSION_ADDED', 'Exclusion de credential de groupe ajoutée', ('configuration',),
       legacy_action='credential.group.exclusion_add'),
    _e('BST-VLT-1007', 'GROUP_CREDENTIAL_EXCLUSION_REMOVED', 'Exclusion de credential de groupe retirée', ('configuration',),
       legacy_action='credential.group.exclusion_remove'),
    _e('BST-VLT-1008', 'USER_CREDENTIAL_SET', 'Credential utilisateur enregistré', ('configuration',),
       legacy_action='credential.user.set'),
    _e('BST-VLT-1009', 'USER_CREDENTIAL_DELETED', 'Credential utilisateur supprimé', ('configuration',),
       legacy_action='credential.user.delete'),
    _e('BST-VLT-1010', 'FERNET_KEY_ROTATED', 'Clé Fernet tournée', ('configuration',),
       legacy_action='key_rotation'),
    _e('BST-VLT-1011', 'FERNET_KEY_GENERATED', 'Clé Fernet initiale générée', ('configuration',),
       legacy_action='key_generated_initial'),
    _e('BST-VLT-1012', 'FERNET_KEY_MIGRATED', "Clé Fernet migrée depuis l'environnement", ('configuration',),
       legacy_action='key_migrated_from_env'),
    _e('BST-VLT-1013', 'RUNTIME_SECRETS_ENSURED', 'Secrets runtime portail assurés', ('configuration',),
       legacy_action='portal_runtime_secrets_ensured'),
    _e('BST-VLT-1014', 'VAULT_ROTATION_DAYS_UPDATED', 'Délai de rotation du coffre modifié', ('configuration',),
       legacy_action='portal_settings.vault_key_rotation_days'),
    _e('BST-VLT-4001', 'FERNET_KEY_UNAVAILABLE', 'Clé de chiffrement absente : données inaccessibles', ('configuration',),
       runbook='Restaurer la clé Fernet depuis le coffre / backup, ne pas redémarrer à vide.'),
    _e('BST-VLT-4002', 'SECRET_EXPOSURE_SUSPECTED', 'Secret potentiellement exposé', ('intrusion_detection',),
       runbook='Tourner le secret concerné, auditer les accès.'),
    _e('BST-WAF-1001', 'IP_BAN_LIFTED', 'Bannissement levé', ('intrusion_detection',),
       legacy_action='security.ban.lifted'),
    _e('BST-WAF-1002', 'ALLOWLIST_ADDED', "IP ajoutée à l'allowlist", ('intrusion_detection', 'configuration',),
       legacy_action='security.allowlist.added'),
    _e('BST-WAF-1003', 'ALLOWLIST_REMOVED', "IP retirée de l'allowlist", ('intrusion_detection', 'configuration',),
       legacy_action='security.allowlist.removed'),
    _e('BST-WAF-1004', 'BAN_RULES_UPDATED', 'Règles de ban mises à jour', ('intrusion_detection', 'configuration',),
       legacy_action='security.ban_rules.updated'),
    _e('BST-WAF-1005', 'SECURITY_POLICY_UPDATED', 'Politique de sécurité mise à jour', ('intrusion_detection', 'configuration',),
       legacy_action='security.policy.updated'),
    _e('BST-WAF-1006', 'WAF_MODE_CHANGED', 'Mode WAF modifié', ('intrusion_detection', 'configuration',),
       legacy_action='security.waf.mode_changed'),
    _e('BST-WAF-1007', 'WAF_THRESHOLD_CHANGED', 'Seuil WAF modifié', ('intrusion_detection', 'configuration',),
       legacy_action='security.waf.threshold_changed'),
    _e('BST-WAF-1008', 'WAF_EXCLUSION_ADDED', 'Exclusion WAF ajoutée', ('intrusion_detection', 'configuration',),
       legacy_action='security.waf.exclusion_added'),
    _e('BST-WAF-1009', 'WAF_EXCLUSION_DISABLED', 'Exclusion WAF désactivée', ('intrusion_detection', 'configuration',),
       legacy_action='security.waf.exclusion_disabled'),
    _e('BST-WAF-1010', 'WAF_CONFIG_APPLIED', 'Configuration WAF appliquée', ('intrusion_detection', 'configuration',),
       legacy_action='security.waf.apply'),
    _e('BST-WAF-2001', 'CRS_RULE_TRIGGERED', 'Règle ModSecurity/CRS déclenchée (mode détection)', ('intrusion_detection',)),
    _e('BST-WAF-2002', 'BRUTE_FORCE_ATTEMPT', "Rafale d'échecs d'authentification détectée", ('intrusion_detection', 'authentication',)),
    _e('BST-WAF-2003', 'SURFACE_PROBING', 'Sondage de surfaces protégées', ('intrusion_detection',)),
    _e('BST-WAF-2004', 'SSRF_PROBING', "Pattern de sondage SSRF sur l'analyzer", ('intrusion_detection',)),
    _e('BST-WAF-2005', 'AUTHORIZED_REDTEAM_TEST', 'Activité de test red-team autorisée', ('intrusion_detection',)),
    _e('BST-WAF-2006', 'RATE_LIMITED', 'Requête limitée en débit', ('intrusion_detection',),
       legacy_action='security.rate_limited'),
    _e('BST-WAF-4001', 'IP_BANNED', 'IP bannie automatiquement', ('intrusion_detection',),
       legacy_action='security.ban.applied', runbook='Vérifier si légitime ; lever le ban si faux positif.'),
    _e('BST-WAF-4002', 'HACK_ATTEMPT_DETECTED', "Tentative d'intrusion caractérisée", ('intrusion_detection',),
       legacy_action='security.hack_attempt.detected', runbook="Analyser l'IP, corréler avec les bans."),
    _e('BST-WAF-4003', 'IP_SPOOFING_SUSPECTED', "Incohérence de chaîne d'IP, usurpation suspectée", ('intrusion_detection',),
       runbook='Vérifier trusted proxies et en-têtes CF-Connecting-IP / X-Forwarded-For.'),
    _e('BST-WAF-4004', 'SUCCESSFUL_LOGIN_HAMMERING', 'Rafale de connexions réussies anormale', ('intrusion_detection', 'authentication',),
       legacy_action='security.successful_login_hammering.detected', runbook='Vérifier les comptes concernés, forcer MFA / révocation.'),
)


def _build_catalog(raw: Iterable[EventDef]) -> dict[str, EventDef]:
    by_code: dict[str, EventDef] = {}
    labels: set[str] = set()
    actions: dict[str, str] = {}
    for ev in raw:
        domain, num = parse_event_code(ev.code)
        if num == 0:
            raise ValueError(f"catalog must not declare sentinel code {ev.code}")
        if num >= 5000:
            raise ValueError(f"code {ev.code} uses reserved extension band 5000+")
        # Touch severity to validate band
        _ = severity_from_number(num)
        if ev.code in by_code:
            raise ValueError(f"duplicate event code: {ev.code}")
        if ev.label in labels:
            raise ValueError(f"duplicate event label: {ev.label}")
        if domain not in DOMAINS:
            raise ValueError(f"undeclared domain on {ev.code}")
        if ev.legacy_action:
            if ev.legacy_action in actions:
                raise ValueError(
                    f"legacy_action {ev.legacy_action!r} mapped twice:"
                    f" {actions[ev.legacy_action]} and {ev.code}"
                )
            actions[ev.legacy_action] = ev.code
        labels.add(ev.label)
        by_code[ev.code] = ev
    return by_code


EVENTS: dict[str, EventDef] = _build_catalog(_RAW_EVENTS)
ACTION_TO_CODE: dict[str, str] = {
    ev.legacy_action: ev.code
    for ev in EVENTS.values()
    if ev.legacy_action and not ev.deprecated
}

SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 1,
    Severity.NOTICE: 2,
    Severity.WARNING: 3,
    Severity.ERROR: 4,
    Severity.CRITICAL: 5,
}

CEF_SEVERITY: dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.ERROR: 7,
    Severity.WARNING: 5,
    Severity.NOTICE: 3,
    Severity.INFO: 1,
}

SYSLOG_SEVERITY: dict[Severity, int] = {
    Severity.CRITICAL: 2,
    Severity.ERROR: 3,
    Severity.WARNING: 4,
    Severity.NOTICE: 5,
    Severity.INFO: 6,
}

# Longest-prefix-first matching for uncatalogued domain guess.
_ACTION_DOMAIN_PREFIXES: tuple[tuple[str, str], ...] = tuple(
    sorted(
        (
            ("breakglass", "BGL"),
            ("sessions.", "SESS"),
            ("session_", "SESS"),
            ("session.", "SESS"),
            ("oidc_", "AUTH"),
            ("activesync", "AUTH"),
            ("security.sso", "AUTH"),
            ("security.successful_login", "WAF"),
            ("security.ban_rules", "WAF"),
            ("security.allowlist", "WAF"),
            ("security.policy", "WAF"),
            ("security.ban", "WAF"),
            ("security.waf", "WAF"),
            ("security.hack", "WAF"),
            ("security.rate", "WAF"),
            ("security.siem", "SIEM"),
            ("siem.", "SIEM"),
            ("account.", "PROV"),
            ("file.", "FILE"),
            ("credential.", "VLT"),
            ("key_", "VLT"),
            ("rbac.", "RBAC"),
            ("rbac_", "RBAC"),
            ("robotic.", "RBAC"),
            ("access_denied", "RBAC"),
            ("access_request", "RBAC"),
            ("pending_user", "RBAC"),
            ("users.", "RBAC"),
            ("role_permission", "RBAC"),
            ("group_rbac", "RBAC"),
            ("portal_admin_grant", "RBAC"),
            ("acme.", "PROXY"),
            ("pending_host", "PROXY"),
            ("app.", "ADM"),
            ("app_", "ADM"),
            ("realm.", "ADM"),
            ("admin.", "ADM"),
            ("branding", "ADM"),
            ("portal_settings", "ADM"),
            ("portal.", "ADM"),
            ("portal_", "ADM"),
            ("notification.", "ADM"),
            ("smtp.", "ADM"),
            ("hot_store", "SYS"),
            ("infrastructure", "SYS"),
            ("health.", "SYS"),
        ),
        key=lambda item: len(item[0]),
        reverse=True,
    )
)


def guess_domain(action: str) -> str:
    a = (action or "").strip().lower()
    for prefix, domain in _ACTION_DOMAIN_PREFIXES:
        if a.startswith(prefix):
            return domain
    return "SYS"


def uncatalogued_event(action: str) -> EventDef:
    domain = guess_domain(action)
    return EventDef(
        code=f"BST-{domain}-0000",
        label="UNCATALOGUED_EVENT",
        title_fr="Événement non catalogué",
        ecs_category=("api",),
        legacy_action=action or None,
        runbook="Ajouter cet événement au registre event_catalog.py.",
    )


def get_event_by_code(code: str) -> EventDef | None:
    return EVENTS.get((code or "").strip().upper())


def resolve_event(
    *,
    action: str | None = None,
    code: str | EventDef | None = None,
) -> EventDef:
    """Resolve catalogue entry. Unknown actions yield uncatalogued sentinel."""
    if isinstance(code, EventDef):
        return code
    if isinstance(code, str) and code.strip():
        found = get_event_by_code(code)
        if found is not None:
            return found
        # Explicit unknown code → treat as uncatalogued under declared domain if parseable
        try:
            _domain, num = parse_event_code(code)
            if num == 0:
                return uncatalogued_event(action or "")
        except ValueError:
            pass
        return uncatalogued_event(action or code)
    act = (action or "").strip()
    if act and act in ACTION_TO_CODE:
        return EVENTS[ACTION_TO_CODE[act]]
    return uncatalogued_event(act)


def historical_severity_from_result(result: str | None) -> Severity:
    r = (result or "info").strip().lower()
    if r == "error":
        return Severity.ERROR
    if r == "success":
        return Severity.NOTICE
    return Severity.INFO


def format_log_line(
    ev: EventDef,
    *,
    actor: str = "",
    ip: str = "",
    result: str = "",
    request_id: str = "",
) -> str:
    parts = [f"[{ev.code}] {ev.severity.value} {ev.label}"]
    extras = []
    if actor:
        extras.append(f"actor={actor}")
    if ip:
        extras.append(f"ip={ip}")
    if result:
        extras.append(f"result={result}")
    if request_id:
        extras.append(f"request_id={request_id}")
    if extras:
        parts.append(" — " + " ".join(extras))
    return "".join(parts)
