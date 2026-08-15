#!/usr/bin/env bash
# reset-hot-store-password.sh — réaligne le mot de passe du rôle PostgreSQL
# `bastion_hot` sur sa source unique : HOT_STORE_PG_PASSWORD dans .env.
#
# Pourquoi un script plutôt que trois commandes : les deux bouts ne se mettent
# pas à jour au même moment. L'entrypoint postgres ne réapplique le mot de passe
# qu'à la CRÉATION du conteneur, et `docker compose restart` ne relit pas .env —
# une reprise manuelle peut donc paraître correcte et laisser la panne en place.
#
# Le script ne réécrit PAS le rôle lui-même : il confie ce travail à
# docker/postgres/bastion-entrypoint.sh et vérifie qu'il l'a fait. Refaire ici
# l'échappement du mot de passe créerait une seconde implémentation, donc une
# seconde occasion de diverger.
#
# Usage :
#   scripts/reset-hot-store-password.sh --check       # diagnostic seul
#   scripts/reset-hot-store-password.sh --keep        # réaligne sur la valeur actuelle
#   scripts/reset-hot-store-password.sh --generate    # nouveau mot de passe aléatoire
#   scripts/reset-hot-store-password.sh --password V  # valeur explicite
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ENV_FILE="${ENV_FILE:-.env}"
COMPOSE=(${COMPOSE_CMD:-docker compose})
MODE=""
NEW_PASSWORD=""
FORCE=0

die() { echo "ÉCHEC: $*" >&2; exit 1; }
step() { echo; echo "=== $* ==="; }

# Empreinte courte : permet de comparer deux valeurs sans en afficher aucune.
fingerprint() {
  local value="${1-}"
  [[ -n "$value" ]] || { echo "absent"; return; }
  printf '%s' "$value" | md5sum | cut -c1-8
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) MODE="check"; shift ;;
    --keep) MODE="keep"; shift ;;
    --generate) MODE="generate"; shift ;;
    --password) MODE="explicit"; NEW_PASSWORD="${2:-}"; shift 2 ;;
    --force) FORCE=1; shift ;;
    -h|--help) sed -n '1,20p' "$0"; exit 0 ;;
    *) die "option inconnue : $1" ;;
  esac
done
[[ -n "$MODE" ]] || die "précisez --check, --keep, --generate ou --password"

command -v docker >/dev/null 2>&1 || die "docker introuvable"
[[ -f "$ENV_FILE" ]] || die "$ENV_FILE introuvable (lancez depuis le répertoire du projet)"

env_file_password() {
  # Dernière occurrence, comme le ferait docker compose. Guillemets retirés.
  local line
  line="$(grep -E '^[[:space:]]*HOT_STORE_PG_PASSWORD=' "$ENV_FILE" | tail -n 1 || true)"
  [[ -n "$line" ]] || return 0
  line="${line#*=}"
  line="${line%\"}"; line="${line#\"}"
  line="${line%\'}"; line="${line#\'}"
  printf '%s' "$line"
}

container_env() {
  # $1 = service, $2 = variable. Silencieux si le service est arrêté.
  "${COMPOSE[@]}" exec -T "$1" printenv "$2" 2>/dev/null | tr -d '\r\n' || true
}

step "Diagnostic — ce que chaque côté détient réellement"
ENV_PASSWORD="$(env_file_password)"
APP_PASSWORD="$(container_env bastion-app HOT_STORE_PG_PASSWORD)"
PG_PASSWORD="$(container_env postgres POSTGRES_PASSWORD)"

printf '  %-28s %s\n' "$ENV_FILE" "$(fingerprint "$ENV_PASSWORD")"
printf '  %-28s %s\n' "conteneur bastion-app" "$(fingerprint "$APP_PASSWORD")"
printf '  %-28s %s\n' "conteneur postgres" "$(fingerprint "$PG_PASSWORD")"

if [[ -z "$APP_PASSWORD" ]]; then
  echo "  → l'application ne reçoit pas la variable : elle retombe sur le mot de"
  echo "    passe chiffré en base, qui dérive silencieusement de celui du rôle."
elif [[ "$APP_PASSWORD" != "$PG_PASSWORD" ]]; then
  echo "  → les deux conteneurs divergent : ils n'ont pas été recréés ensemble"
  echo "    depuis la dernière modification de $ENV_FILE."
fi

if [[ "$MODE" == "check" ]]; then
  step "Test TCP avec la valeur de $ENV_FILE (chemin exact de l'application)"
  if [[ -z "$ENV_PASSWORD" ]]; then
    echo "  ignoré : HOT_STORE_PG_PASSWORD absent de $ENV_FILE"
  elif printf '%s' "$ENV_PASSWORD" | "${COMPOSE[@]}" exec -T postgres \
      sh -c 'PGPASSWORD="$(cat)" psql -w -h "${POSTGRES_HOST:-127.0.0.1}" \
             -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select 1" >/dev/null 2>&1'; then
    echo "  OK — le rôle accepte cette valeur, la panne est ailleurs."
  else
    echo "  REFUSÉ — le rôle ne connaît pas cette valeur. Relancez avec --keep."
  fi
  exit 0
fi

case "$MODE" in
  keep)
    [[ -n "$ENV_PASSWORD" ]] || die "HOT_STORE_PG_PASSWORD absent de $ENV_FILE : utilisez --generate"
    NEW_PASSWORD="$ENV_PASSWORD"
    ;;
  generate)
    command -v openssl >/dev/null 2>&1 || die "openssl introuvable"
    NEW_PASSWORD="$(openssl rand -hex 24)"
    ;;
  explicit)
    [[ -n "$NEW_PASSWORD" ]] || die "--password attend une valeur"
    ;;
esac

# Compose interpole ${...} dans docker-compose.yml (côté postgres) mais passe
# env_file tel quel (côté application) : un caractère de substitution peut donc
# séparer les deux bouts alors que .env est identique.
if printf '%s' "$NEW_PASSWORD" | LC_ALL=C grep -q '[^A-Za-z0-9._-]' && [[ "$FORCE" -eq 0 ]]; then
  die "mot de passe hors [A-Za-z0-9._-] : les deux côtés risquent de diverger.
     Préférez openssl rand -hex 24 (--generate), ou forcez avec --force."
fi

step "Écriture de $ENV_FILE"
BACKUP="${ENV_FILE}.bak.$(date +%Y%m%d%H%M%S)"
cp -p "$ENV_FILE" "$BACKUP"
NEW_PASSWORD="$NEW_PASSWORD" awk '
  /^[[:space:]]*HOT_STORE_PG_PASSWORD=/ { next }
  { print }
  END { print "HOT_STORE_PG_PASSWORD=" ENVIRON["NEW_PASSWORD"] }
' "$BACKUP" > "$ENV_FILE"
echo "  sauvegarde : $BACKUP"
echo "  empreinte  : $(fingerprint "$NEW_PASSWORD")"

step "Recréation de postgres (up -d, pas restart : restart ne relit pas $ENV_FILE)"
"${COMPOSE[@]}" up -d --force-recreate postgres

step "Attente de la synchronisation du rôle par l'entrypoint"
synced=0
for _ in $(seq 1 60); do
  if "${COMPOSE[@]}" logs --tail=200 postgres 2>/dev/null | grep -q 'bastion-pg: role .* password synced'; then
    synced=1
    break
  fi
  if "${COMPOSE[@]}" logs --tail=200 postgres 2>/dev/null | grep -q 'bastion-pg: password sync failed\|bastion-pg: POSTGRES_PASSWORD empty\|bastion-pg: pg_isready timeout'; then
    break
  fi
  sleep 2
done
"${COMPOSE[@]}" logs --tail=200 postgres 2>/dev/null | grep 'bastion-pg:' | tail -n 3 || true
[[ "$synced" -eq 1 ]] || die "l'entrypoint n'a pas synchronisé le rôle — voir les lignes bastion-pg ci-dessus"

step "Vérification TCP (scram), le chemin exact où l'application échouait"
if printf '%s' "$NEW_PASSWORD" | "${COMPOSE[@]}" exec -T postgres \
    sh -c 'PGPASSWORD="$(cat)" psql -w -h "${POSTGRES_HOST:-127.0.0.1}" \
           -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select 1" >/dev/null'; then
  echo "  OK"
else
  die "le rôle refuse encore la valeur — restaurez avec : cp $BACKUP $ENV_FILE"
fi

step "Recréation de bastion-app pour qu'elle prenne le nouvel environnement"
"${COMPOSE[@]}" up -d --force-recreate bastion-app

step "Contrôle final"
APP_PASSWORD="$(container_env bastion-app HOT_STORE_PG_PASSWORD)"
PG_PASSWORD="$(container_env postgres POSTGRES_PASSWORD)"
printf '  %-28s %s\n' "conteneur bastion-app" "$(fingerprint "$APP_PASSWORD")"
printf '  %-28s %s\n' "conteneur postgres" "$(fingerprint "$PG_PASSWORD")"
[[ -n "$APP_PASSWORD" && "$APP_PASSWORD" == "$PG_PASSWORD" ]] \
  || die "les deux côtés divergent encore — vérifiez que bastion-app lit bien $ENV_FILE"

echo
echo "Terminé. Les deux bouts partagent la même valeur."
echo "Vérifiez le badge dans Admin → Général → Configuration → Stockage chaud."
echo
echo "IMPORTANT : si $ENV_FILE est généré par AWX, reportez-y la même valeur,"
echo "sinon le prochain déploiement réintroduira la panne."
