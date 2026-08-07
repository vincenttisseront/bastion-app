# 02.01 — Modes d’accès (`access_mode`)

## Définition

Le **mode d’accès** décrit *comment* le bastion expose une application au navigateur.
Il est indépendant du mode d’authentification applicative (`auth_mode`).

| Slug | Libellé UI | Catalogue `/apps` | FQDN dédié |
|------|------------|-------------------|------------|
| `sso_gate` | SSO Gate (lanceur) | Oui | Non (URL publique externe) |
| `subdomain_proxy` | Sous-domaine dédié | Oui | **Oui** |
| `legacy_path_proxy` | Chemin `/proxy/{slug}/` | Oui | Non |
| `public_proxy` | Proxy public (sans auth) | **Non** | Oui |

## SSO Gate

Après validation SSO portail, redirection vers l’URL de l’application.
**Aucun** reverse-proxy bastion vers l’upstream.

## Sous-domaine (`subdomain_proxy`)

- `public_fqdn` obligatoire (ex. `wikijs.example.com`)
- `upstream_url` = **origine seule** (`https://10.x.x.x/`) sans chemin métier
- nginx : TLS, `auth_request` → `/internal/subdomain-auth`, proxy upstream
- Option ActiveSync pour certaines apps messagerie

## Legacy path proxy

Proxy sous `/proxy/{slug}/` — uniquement si l’app tolère un `base_path`.

## Proxy public

Reverse-proxy **sans** auth bastion. Hors catalogue utilisateur. Usage contrôlé
(ex. endpoints techniques exposés volontairement).

## Chemin d’entrée portail

Pour un sous-domaine, la tuile ouvre `https://{fqdn}` ou un chemin dérivé de
`login_form_url` (ex. `/login` pour Wiki.js, `/web/` pour Grommunio).

Suite : [02.02 Modes d’auth](./02-02-modes-auth-vault.md)
