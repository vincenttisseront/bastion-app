# Maintenance de la documentation Wiki.js

## Règle

Toute évolution **utilisateur-visible** ou **ops-critique** du bastion doit mettre à jour
les pages de `docs/wikijs/` **dans le même changement** (PR) que le code, ou juste après.

Les fichiers sous `docs/wikijs/` sont la source pour Wiki.js. Les docs techniques
longues (`docs/*.md`, SDD) restent des annexes ; le wiki doit rester **actionnable**.

## Quand mettre à jour

| Événement | Pages à revoir |
|-----------|----------------|
| Nouveau mode d’accès / auth | 02.01, 02.02, glossaire |
| Changement flux SSO / BFF / break-glass | 01.00, 01.01, 02.06, 03.02, 05.02 |
| Parcours / copy visible aux partenaires | **01.00** (accueil externes) |
| Apply infra / exports oauth2 / nginx | 04.02, 05.02, 05.03 |
| ACME / TLS | 04.04, 05.01 |
| WAF / ModSec | 04.05, `docs/ops-modsecurity-crs.md` |
| Sessions / logs UI | 04.03, 04.01 (dashboard), 01.x si UX change |
| RBAC / grants / fiche user | 02.04, 02.05, 06-11, 04.01 |
| Erreurs HTTP navigateur (400/422 admin) | 04.01, `docs/bastion-pro-visual-config.md` |
| Bump `APP_VERSION` | Accueil + README de ce dossier |
| Lancement app SSO (`trusted_headers` / `app_oidc`) | 01.03, 02.02, 04.02 |
| Doc technique ops / SDD | Mettre à jour **source** `docs/*.md` **et** copie `06-annexes/06-xx-*.md` |

## Format

- **Markdown uniquement** (`.md`) pour toutes les pages publiées dans Wiki.js.
- Pas de HTML source, AsciiDoc ou export PDF comme source de vérité.
- Inventaire : [`MANIFEST.md`](./MANIFEST.md).

## Checklist PR doc

- [ ] Sommaire [`README.md`](./README.md) encore exact (pas de page orpheline)
- [ ] Version produit alignée sur `app/web/constants.py` → `APP_VERSION`
- [ ] Pas de secret réel (client_secret, JWT, tokens) dans les exemples
- [ ] Exemples d’hôtes génériques (`portal.example.com`) sauf pages ops internes
- [ ] Rappeler : **RealmConfig en base = source de vérité OIDC** (pas les fichiers sous `exports/` / `docker/oauth2-core/`)
- [ ] Après merge : republier / synchroniser les pages concernées dans Wiki.js

## Convention de numérotation

- `00` — Accueil
- `01` — Utilisateur
- `02` — Fonctionnel
- `03` — Architecture
- `04` — Administrateur
- `05` — Configuration
- `99` — Glossaire

Nouveaux sujets : ajouter `NN-MM-slug.md` dans la bonne section et mettre à jour le sommaire.

## Style

- Français, phrases courtes, tableaux pour les matrices
- Titre H1 unique = titre Wiki.js
- Liens croisés relatifs entre pages du même arbre
- Ne pas dupliquer entièrement les SDD : citer + résumer
