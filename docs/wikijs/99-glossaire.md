# Glossaire Bastion

| Terme | Définition |
|-------|------------|
| **AccessGrant** | Droit RBAC liant un sujet (user/groupe) à une ressource (app, rôle, fichier) |
| **ACME** | Protocole Let’s Encrypt ; ici DNS-01 via sidecar |
| **Apply infra** | Régénération + sync des exports nginx / oauth2 depuis la base |
| **auth_request** | Sous-requête nginx vers FastAPI pour autoriser une requête |
| **bastion_session** | Cookie JWT session OIDC native (BFF) |
| **bg_session** | Cookie JWT break-glass |
| **Break-glass** | Connexion admin locale de secours, hors IdP |
| **CRS** | OWASP Core Rule Set (WAF) |
| **FQDN** | Nom DNS complet d’une app (`app.example.com`) |
| **Hot store** | PostgreSQL optionnel pour tables à fort volume |
| **launch** | Niveau de grant permettant d’ouvrir une app protégée |
| **ModSecurity** | Moteur WAF embarqué dans nginx-bastion |
| **oauth2-proxy** | Composant session OIDC ; config générée depuis RealmConfig |
| **portal_admin** | Rôle système d’administration du portail |
| **Realm / RealmConfig** | Configuration OIDC d’un IdP en base (source de vérité) |
| **Robotic SSO** | Login automatisé vers une app legacy via vault |
| **SDD** | Software Design Decision (décision figée) |
| **SSO Gate** | Mode d’accès : redirection vers URL publique après SSO |
| **sso_bridge** | Sous-mode SSO : `trusted_headers` ou `app_oidc` |
| **subdomain_proxy** | Mode d’accès : reverse-proxy sur FQDN dédié |
| **Trusted headers** | En-têtes d’identité injectés que l’app consomme (`sso_bridge=trusted_headers`) |
| **Vault** | Stockage chiffré des secrets applicatifs |
| **Wiki.js Bypass Login** | Option Wiki.js qui envoie directement vers l’IdP depuis `/login` |

Retour : [Accueil](./00-accueil.md)
