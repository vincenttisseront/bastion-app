#!/bin/sh
# Wrap the official postgres entrypoint and (re)align the role password from
# POSTGRES_PASSWORD on every start. The stock image only applies POSTGRES_* on
# first init of an empty data dir — after that, .env changes are ignored and
# TCP auth (scram-sha-256) fails with "password authentication failed".
#
# Local socket uses "trust" in the official image, so we do not need the old
# password (useful when the cluster was never consciously bootstrapped).
set -eu

_bastion_sync_password() {
  user="${POSTGRES_USER:-bastion_hot}"
  db="${POSTGRES_DB:-$user}"
  pass="${POSTGRES_PASSWORD:-}"

  if [ -z "$pass" ]; then
    echo "bastion-pg: POSTGRES_PASSWORD empty — skip password sync" >&2
    return 0
  fi

  i=0
  while [ "$i" -lt 90 ]; do
    if pg_isready -U "$user" -d "$db" >/dev/null 2>&1; then
      break
    fi
    i=$((i + 1))
    sleep 1
  done

  if ! pg_isready -U "$user" -d "$db" >/dev/null 2>&1; then
    echo "bastion-pg: pg_isready timeout — skip password sync" >&2
    return 0
  fi

  # Escape single quotes for a SQL string literal. Do not use psql :'var'
  # interpolation with -c — some clients send it literally to the server
  # (syntax error at ":").
  esc=$(printf '%s' "$pass" | sed "s/'/''/g")
  if psql -v ON_ERROR_STOP=1 -U "$user" -d "$db" \
    -c "ALTER ROLE \"${user}\" WITH PASSWORD '${esc}'"; then
    echo "bastion-pg: role \"${user}\" password synced from POSTGRES_PASSWORD" >&2
  else
    echo "bastion-pg: password sync failed (non-fatal)" >&2
  fi
}

# Forward stop signals to the real postgres process.
docker-entrypoint.sh "$@" &
pid=$!
trap 'kill -TERM "$pid" 2>/dev/null; wait "$pid"' TERM INT

_bastion_sync_password

wait "$pid"
