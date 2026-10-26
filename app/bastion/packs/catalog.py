"""Virtual-patch pack catalog (pre-CRS).

Rule ID bands (Bastion 100096xxx, outside CRS 9xxxxx):
  php2shell        100096180–100096199
  wordpress_cms    100096200–100096249
  api_json_strict  100096300–100096349
  rce_extended     100096400–100096449
"""

from __future__ import annotations

from typing import Any

PACK_PHP2SHELL = "php2shell"
PACK_WORDPRESS_CMS = "wordpress_cms"
PACK_API_JSON_STRICT = "api_json_strict"
PACK_RCE_EXTENDED = "rce_extended"

PACK_MODE_OFF = "off"
PACK_MODE_DETECTION = "detection"
PACK_MODE_ON = "on"

# Paths inside the nginx image (COPY modsecurity/ → /etc/nginx/modsecurity/).
_PHP2SHELL_INCLUDE = "/etc/nginx/modsecurity/bastion-virtual-patches.conf"
_WP_INCLUDE = "/etc/nginx/modsecurity/bastion-pack-wordpress-cms.conf"
_API_INCLUDE = "/etc/nginx/modsecurity/bastion-pack-api-json-strict.conf"
_RCE_INCLUDE = "/etc/nginx/modsecurity/bastion-pack-rce-extended.conf"

PACK_CATALOG: dict[str, dict[str, Any]] = {
    PACK_PHP2SHELL: {
        "id": PACK_PHP2SHELL,
        "name": "PHP2Shell",
        "severity": "critical",
        "cves": ["CVE-2026-109618", "CVE-2026-109619"],
        "summary": (
            "Mitigations edge pour RCE PHP core (session upload progress / "
            "multipart) en attendant le patch PHP origin."
        ),
        "detail": (
            "Règles pre-CRS : PHPSESSID en champ POST, PHP_SESSION_UPLOAD_PROGRESS, "
            "balises PHP dans les noms de fichiers uploadés, multipart fortement "
            "imbriqué, multipart sans Content-Length."
        ),
        "conf_basename": "bastion-virtual-patches.conf",
        "include_path": _PHP2SHELL_INCLUDE,
        "profile_attr": "patch_php2shell_mode",
        "legacy_bool_attr": "patch_php2shell_enabled",
        "default_mode": PACK_MODE_ON,
        "id_range": (100096180, 100096199),
        "suggest_signals": ("php", "rce", "multipart", "php2shell"),
        "rules": [
            {
                "id": "100096180",
                "title": "PHPSESSID en champ POST",
                "phase": 2,
                "action": "deny/403",
                "targets": "ARGS_POST_NAMES",
            },
            {
                "id": "100096181",
                "title": "PHP_SESSION_UPLOAD_PROGRESS",
                "phase": 2,
                "action": "deny/403",
                "targets": "ARGS_POST_NAMES",
            },
            {
                "id": "100096182",
                "title": "Balise PHP dans nom de fichier uploadé",
                "phase": 2,
                "action": "deny/403",
                "targets": "FILES",
            },
            {
                "id": "100096183",
                "title": "Multipart imbriqué (≥12 niveaux)",
                "phase": 2,
                "action": "deny/403",
                "targets": "ARGS_POST_NAMES|FILES_NAMES",
            },
            {
                "id": "100096184",
                "title": "Multipart sans Content-Length",
                "phase": 1,
                "action": "deny/403",
                "targets": "REQUEST_HEADERS",
            },
        ],
    },
    PACK_WORDPRESS_CMS: {
        "id": PACK_WORDPRESS_CMS,
        "name": "WordPress / CMS Shield",
        "severity": "high",
        "cves": [],
        "summary": (
            "Sécurisation wp-login.php, xmlrpc.php et atténuation du brute-force "
            "sur l’API REST (énumération /wp-json/)."
        ),
        "detail": (
            "Pack détection d’attaques uniquement (pas d’exclusions FP WYSIWYG). "
            "POST sans Referer vers wp-login/xmlrpc, énumération users REST, "
            "exécution directe de scripts PHP sous wp-content/themes|plugins."
        ),
        "conf_basename": "bastion-pack-wordpress-cms.conf",
        "include_path": _WP_INCLUDE,
        "profile_attr": "patch_wordpress_cms_mode",
        "legacy_bool_attr": "",
        "default_mode": PACK_MODE_OFF,
        "id_range": (100096200, 100096249),
        "suggest_signals": ("wordpress", "wp-login", "wp-json", "xmlrpc"),
        "rules": [
            {
                "id": "100096200",
                "title": "POST wp-login/xmlrpc sans Referer",
                "phase": 2,
                "action": "deny/403",
                "targets": "REQUEST_METHOD|REQUEST_URI|Referer",
            },
            {
                "id": "100096201",
                "title": "Énumération users API REST",
                "phase": 2,
                "action": "deny/403",
                "targets": "REQUEST_URI",
            },
            {
                "id": "100096202",
                "title": "PHP direct sous wp-content themes/plugins",
                "phase": 2,
                "action": "deny/403",
                "targets": "REQUEST_URI",
            },
        ],
    },
    PACK_API_JSON_STRICT: {
        "id": PACK_API_JSON_STRICT,
        "name": "API & JSON Strict",
        "severity": "high",
        "cves": [],
        "summary": (
            "Validation stricte des structures de requêtes JSON et payloads "
            "d’API (NoSQL ops, confusion de types, pollution de prototype)."
        ),
        "detail": (
            "Détecte les opérateurs Mongo-like ($ne/$where…), le Content-Type "
            "application/json abusif (boundary multipart), et les clés "
            "__proto__/constructor dans args ou corps."
        ),
        "conf_basename": "bastion-pack-api-json-strict.conf",
        "include_path": _API_INCLUDE,
        "profile_attr": "patch_api_json_strict_mode",
        "legacy_bool_attr": "",
        "default_mode": PACK_MODE_OFF,
        "id_range": (100096300, 100096349),
        "suggest_signals": ("json", "application/json", "api"),
        "rules": [
            {
                "id": "100096300",
                "title": "Opérateurs NoSQL ($ne/$where…)",
                "phase": 2,
                "action": "deny/403",
                "targets": "ARGS|ARGS_NAMES|REQUEST_BODY",
            },
            {
                "id": "100096301",
                "title": "JSON Content-Type + boundary multipart",
                "phase": 1,
                "action": "deny/403",
                "targets": "REQUEST_HEADERS",
            },
            {
                "id": "100096302",
                "title": "Prototype pollution (__proto__/constructor)",
                "phase": 2,
                "action": "deny/403",
                "targets": "ARGS|REQUEST_BODY",
            },
        ],
    },
    PACK_RCE_EXTENDED: {
        "id": PACK_RCE_EXTENDED,
        "name": "RCE & Shells Étendu",
        "severity": "critical",
        "cves": [],
        "summary": (
            "Complément PHP2Shell : exécution de commandes multi-runtimes "
            "(Python, Perl, Node) et marqueurs de web shells."
        ),
        "detail": (
            "One-liners python/perl/node, appels os.system/subprocess, chaînes "
            "shell dans args/noms de fichiers, marqueurs JSP/ASP et "
            "Runtime.getRuntime."
        ),
        "conf_basename": "bastion-pack-rce-extended.conf",
        "include_path": _RCE_INCLUDE,
        "profile_attr": "patch_rce_extended_mode",
        "legacy_bool_attr": "",
        "default_mode": PACK_MODE_OFF,
        "id_range": (100096400, 100096449),
        "suggest_signals": ("rce", "shell", "webshell"),
        "rules": [
            {
                "id": "100096400",
                "title": "One-liners / os.system / subprocess",
                "phase": 2,
                "action": "deny/403",
                "targets": "ARGS|REQUEST_BODY",
            },
            {
                "id": "100096401",
                "title": "Chaînes shell (wget/curl/nc/backticks)",
                "phase": 2,
                "action": "deny/403",
                "targets": "ARGS|FILES_NAMES",
            },
            {
                "id": "100096402",
                "title": "Marqueurs web shell JSP/ASPX / Runtime",
                "phase": 2,
                "action": "deny/403",
                "targets": "REQUEST_URI|ARGS",
            },
        ],
    },
}

PACK_IDS = frozenset(PACK_CATALOG.keys())


def list_pack_ids() -> list[str]:
    return list(PACK_CATALOG.keys())


def get_pack_def(pack_id: str) -> dict[str, Any] | None:
    return PACK_CATALOG.get((pack_id or "").strip().lower())
