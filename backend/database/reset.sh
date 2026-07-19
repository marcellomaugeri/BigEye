#!/usr/bin/env sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
database_url=${DATABASE_URL:-postgresql://bigeye:bigeye@127.0.0.1:5433/bigeye}

database_name=$(psql "$database_url" --tuples-only --no-align --command 'SELECT current_database()')
if [ "$database_name" != "bigeye" ]; then
    echo "Refusing to reset database '$database_name'; only the BigEye development database is allowed." >&2
    exit 1
fi

psql "$database_url" --set ON_ERROR_STOP=1 <<'SQL'
BEGIN;
DROP SCHEMA IF EXISTS public CASCADE;
CREATE SCHEMA public;
COMMIT;
SQL

psql "$database_url" --set ON_ERROR_STOP=1 --file "$script_dir/schema.sql"
