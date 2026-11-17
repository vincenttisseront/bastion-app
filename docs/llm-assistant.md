# Assistant IA local (Ollama) — mise en œuvre

> Statut : implémenté sur `feat/llm-socle` (2026-11-17). Désactivé par défaut.

## Règle d'or

Aucune fonctionnalité du portail ne dépend d'Ollama. Sans `LLM_ENABLED=true` **et** la case « Activer l'assistant IA » (Admin → Configuration → Assistant IA), le module ne lit pas la base et n'ouvre aucune connexion. Le login, le MFA, `/internal/oauth2-auth`, le proxy, le WAF, les bans et `/api/health` n'appellent jamais le LLM.

## Activation

| Variable | Défaut | Rôle |
|---|---|---|
| `LLM_ENABLED` | `false` | Interrupteur serveur (ET logique avec la case admin) |
| `OLLAMA_URL` | `http://127.0.0.1:11434` | Ollama local uniquement |
| `LLM_MODEL` | `qwen3:14b` | Modèle (`ollama pull qwen3:14b`, Q4 ≈ 10 Go de VRAM) |
| `LLM_TIMEOUT_S` / `LLM_CONNECT_TIMEOUT_S` | 45 / 2 | Génération / connexion |
| `LLM_NUM_CTX` | 8192 | Fenêtre de contexte (le défaut d'Ollama tronque les prompts) |
| `LLM_MAX_CONCURRENCY` | 1 | Appels simultanés par worker |
| `LLM_BREAKER_FAILURES` / `LLM_BREAKER_COOLDOWN_S` | 3 / 300 | Disjoncteur |

Ansible : `sso_portal_llm_enabled`, `sso_portal_ollama_url`, `sso_portal_llm_model`.

## Socle (`app/llm/`)

- `client.py` : appels `/api/chat` avec `format` = schéma JSON, timeouts, créneaux bornés, disjoncteur (`breaker.py`), sonde `/api/tags` en demi-ouverture. Ne lève jamais d'exception.
- `redaction.py` : secrets, jetons, JWT, cookies, chiffrés Fernet, clés privées et identifiants d'URL masqués avant envoi ; taille plafonnée.
- `schema.py` : validation stricte de la sortie (clés en trop rejetées).
- `service.py` : `generate_json` / `run_task`, audit `llm.call` / `llm.call_failed` (modèle, empreinte du prompt, durée), état de la pastille.
- `insights.py` : sorties stockées dans `llm_insights` (`generated_by=llm`), jamais dans l'enregistrement d'origine. Les propositions attendent une décision humaine (`llm.insight_decided`, BST-ADM-1040).
- Données non fiables encadrées par des balises aléatoires ; pas de tool calling.

## Les 10 évolutions

| # | Où | Déclenchement | Repli (assistant éteint ou indisponible) |
|---|---|---|---|
| 1 | Journaux → « Question en langage naturel » | Admin (attend la réponse) | Filtres manuels |
| 2 | WAF → bilan → « Expliquer (IA) » | Admin (arrière-plan) | Événement brut |
| 3 | Assistant IA → « Analyser les connexions » + job leader 30 min | Seuils déterministes d'abord ; pas d'appel si rien ne dépasse | Règles de ban inchangées |
| 4 | Demandes d'accès → « Avis IA » | Admin (arrière-plan) | Demande telle quelle |
| 5 | Assistant IA → « Revue des permissions » | Admin (arrière-plan) | Export CSV brut `/admin/assistant/recertification.csv` |
| 6 | Realm → test OIDC en échec → « Diagnostic IA » | Admin (JSON, attend la réponse) | Messages techniques actuels |
| 7 | Santé → « Analyser la panne (IA) » + auto sur passage ok/warn → error | Thread détaché du cycle de sondes | Statut de sonde actuel |
| 8 | Job leader 2 min (si SIEM actif) | Événement séparé `llm.siem_enrichment` (BST-SIEM-0002) | Événements envoyés sans enrichissement |
| 9 | Dépendances → « Synthèse IA » | Admin (arrière-plan) | Liste brute |
| 10 | `python -m scripts.llm_generate_tests <module>` | Développeur, refusé en production | — |

### Ce qui reste humain

- **WAF** : la proposition d'exclusion est bornée à l'événement : même règle, même hôte, même URI, règle CRS excluable. L'admin l'accepte, crée l'exclusion via le formulaire existant, puis applique la configuration WAF.
- **Connexions** : `SecurityBanRule` contient une ligne fixe par type de règle et n'est jamais modifié. Le LLM peut proposer un ban manuel (score ≥ 70), que l'admin applique depuis Sécurité → Bannissements.
- **Demandes d'accès** : le realm et les applications suggérés sont filtrés pour ne garder que ce qui existe déjà chez les pairs. L'approbation passe par les boutons existants.

### Limites connues

- Le disjoncteur et les créneaux sont propres à chaque worker uvicorn.
- L'inventaire des dépendances ne contient aucune donnée CVE. La synthèse classe donc les mises à jour par exposition et par retard de version, et il est interdit au modèle de citer des CVE. Une source comme OSV pourrait être ajoutée plus tard.
- L'assistant de setup n'a pas de test OIDC propre : le diagnostic est disponible sur le formulaire de realm.
- Les brouillons de tests vont dans `tests/_llm_drafts/` (ignoré par git, jamais collecté).
