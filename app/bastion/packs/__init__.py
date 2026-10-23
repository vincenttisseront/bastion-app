"""ModSecurity virtual-patch pack definitions."""

from app.bastion.packs.catalog import (
    PACK_API_JSON_STRICT,
    PACK_CATALOG,
    PACK_IDS,
    PACK_PHP2SHELL,
    PACK_RCE_EXTENDED,
    PACK_WORDPRESS_CMS,
    get_pack_def,
    list_pack_ids,
)

__all__ = [
    "PACK_API_JSON_STRICT",
    "PACK_CATALOG",
    "PACK_IDS",
    "PACK_PHP2SHELL",
    "PACK_RCE_EXTENDED",
    "PACK_WORDPRESS_CMS",
    "get_pack_def",
    "list_pack_ids",
]
