> **Format :** Markdown (source Wiki.js).  
> **Fichier dépôt d'origine :** docs/admin-logs-live-and-containers.md — garder les deux synchronisés (voir docs/wikijs/MAINTENANCE.md).

---
# Live audit + logs containers (`/admin/logs`)

## Choix sécurité containers : Option A (proxy socket)

**Décision :** `tecnativa/docker-socket-proxy` (ou équivalent) en **lecture seule**,
exposé uniquement sur le réseau docker interne. `bastion-app` parle HTTP à ce proxy via
l’URL configurée en base (`ContainerLogsSettings.proxy_url`) — **jamais** de montage de
`/var/run/docker.sock` dans `bastion-app`.

| Pourquoi pas Option B (fichiers json-file) | |
|---|---|
| Chemins `/var/lib/docker/containers/<id>/…` changent à chaque recreate | Fragile sous Ansible/Compose |
| Risque de monter trop large si mal borné | Moins clair qu’un proxy `POST=0` |

Le proxy est démarré via l’overlay optionnel
`docker-compose.docker-logs.yml` (`CONTAINERS=1`, `POST=0`). L’app n’appelle que
`GET /containers/{name}/logs` pour les noms de la liste blanche.

## Configuration (en base, Admin UI)

Source de vérité : table singleton `container_logs_settings` (id=1), éditable dans
**Admin → Sécurité → Logs containers** (`/admin/security#container-logs`) :

- toggle **Activer**
- URL du proxy (ex. `http://docker-socket-proxy:2375`)
- liste blanche (ajout / retrait, pas de textarea libre)
- nombre de lignes (tail)

Les variables `DOCKER_LOGS_*` ne sont **plus lues au runtime**. Elles ne servent qu’à
**initialiser** la ligne en base lors de la migration `034_container_logs_settings`
(si `DOCKER_LOGS_PROXY_URL` est déjà présent → `enabled=true` + reprise URL / whitelist).

Activation infra du proxy :

```bash
docker compose -f docker-compose.yml -f docker-compose.docker-logs.yml up -d
```

Puis dans l’UI : activer + renseigner l’URL du proxy. Sans activation, l’onglet Containers
renvoie vers `/admin/security#container-logs`.

## Endpoints

| Route | Rôle |
|-------|------|
| `GET /admin/logs` | Page (onglets Audit / Containers) |
| `GET /admin/logs/stream` | SSE audit (`action`, `actor`, dates) |
| `GET /admin/logs/containers/{name}/logs` | Snapshot (~tail) |
| `GET /admin/logs/containers/{name}/stream` | SSE follow |
| `POST /admin/security/container-logs` | Enregistrer enabled / proxy / tail |
| `POST /admin/security/container-logs/containers/add\|remove` | Liste blanche |

Hors liste blanche → **403** (pas de 404). Droit admin (`require_admin`) comme le reste de `/admin/*`.

Audit :

- consultation : `admin.container_logs.viewed` (métadonnées uniquement)
- config : `security.container_logs_settings.updated`
