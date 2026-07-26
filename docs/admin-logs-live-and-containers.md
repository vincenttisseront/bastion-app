# Live audit + logs containers (`/admin/logs`)

## Choix sécurité containers : Option A (proxy socket)

**Décision :** `tecnativa/docker-socket-proxy` (ou équivalent) en **lecture seule**,
exposé uniquement sur le réseau docker interne. `bastion-app` parle HTTP à ce proxy via
`DOCKER_LOGS_PROXY_URL` — **jamais** de montage de `/var/run/docker.sock` dans `bastion-app`.

| Pourquoi pas Option B (fichiers json-file) | |
|---|---|
| Chemins `/var/lib/docker/containers/<id>/…` changent à chaque recreate | Fragile sous Ansible/Compose |
| Risque de monter trop large si mal borné | Moins clair qu’un proxy `POST=0` |

Le proxy est démarré via l’overlay optionnel
`docker-compose.docker-logs.yml` (`CONTAINERS=1`, `POST=0`). L’app n’appelle que
`GET /containers/{name}/logs` pour les noms de la liste blanche.

## Configuration

```bash
# .env / portal.env
DOCKER_LOGS_PROXY_URL=http://docker-socket-proxy:2375
DOCKER_LOGS_WHITELIST=bastion-app,bastion-nginx,nginx
DOCKER_LOGS_TAIL_LINES=200
ADMIN_LOGS_SSE_TIMEOUT_SECONDS=1800
```

Activation locale / staging :

```bash
docker compose -f docker-compose.yml -f docker-compose.docker-logs.yml up -d
```

Sans `DOCKER_LOGS_PROXY_URL`, l’onglet Containers reste visible mais indique que le proxy
n’est pas configuré (pas d’appel Docker).

## Endpoints

| Route | Rôle |
|-------|------|
| `GET /admin/logs` | Page (onglets Audit / Containers) |
| `GET /admin/logs/stream` | SSE audit (`action`, `actor`, dates) |
| `GET /admin/logs/containers/{name}/logs` | Snapshot (~tail) |
| `GET /admin/logs/containers/{name}/stream` | SSE follow |

Hors liste blanche → **403** (pas de 404). Droit admin (`require_admin`) comme le reste de `/admin/*`.

Audit : `admin.container_logs.viewed` (métadonnées uniquement, jamais le contenu des logs).
