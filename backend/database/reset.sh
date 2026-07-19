#!/usr/bin/env sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
database_url=${DATABASE_URL:-postgresql://bigeye:bigeye@127.0.0.1:5433/bigeye}
url_authority=${database_url#postgresql://}
url_authority=${url_authority%%/*}
database_host=${url_authority##*@}

case "$database_host" in
    127.0.0.1|127.0.0.1:*|localhost|localhost:*|"[::1]"|"[::1]":*) ;;
    *)
        echo "Refusing to reset a non-loopback database host." >&2
        exit 1
        ;;
esac

database_name=$(docker compose exec -T postgres psql -U "${POSTGRES_USER:-bigeye}" -d "${POSTGRES_DB:-bigeye}" --tuples-only --no-align --command 'SELECT current_database()')
if [ "$database_name" != "bigeye" ]; then
    echo "Refusing to reset database '$database_name'; only the BigEye development database is allowed." >&2
    exit 1
fi

docker compose exec -T postgres psql -U "${POSTGRES_USER:-bigeye}" -d "${POSTGRES_DB:-bigeye}" --set ON_ERROR_STOP=1 --command 'DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;'
docker compose exec -T postgres psql -U "${POSTGRES_USER:-bigeye}" -d "${POSTGRES_DB:-bigeye}" --set ON_ERROR_STOP=1 --file /docker-entrypoint-initdb.d/schema.sql
