"""Legacy path-proxy helpers.

Phase 2 placeholder — no FastAPI auth_request lives here.

Cartographie (2026-07-23, audit sessions §6.2) :
- Accès applicatif SSO direct = vhosts subdomain → ``/internal/subdomain-auth``
  (AccessGrant launch+ enforced there).
- Legacy ``/proxy/{slug}/`` : redirections Nginx vers le FQDN subdomain
  (``proxy_portal_legacy_redirects`` / ``proxy_subdomain_redirects``), pas un
  second handler RBAC. ``nginx_enforcement.proxy_location_lines`` ne génère
  qu'un commentaire ``# auth_request /internal/oauth2-auth`` (non actif).
- Portail générique = ``/internal/oauth2-auth`` (auth only, pas de grant app).
"""
