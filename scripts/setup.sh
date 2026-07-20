#!/usr/bin/env sh
set -eu

usage() {
    printf '%s\n' 'Usage: scripts/setup.sh' 'Verify prerequisites and prepare BigEye locally.'
}

case "${1-}" in
    -h|--help) usage; exit 0 ;;
    "") ;;
    *) usage >&2; exit 2 ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
env_file="$project_dir/.env"
compose_file="$project_dir/compose.yaml"
python="$project_dir/backend/.venv/bin/python"
requirements="$project_dir/backend/requirements.txt"

fail() {
    printf 'BigEye setup: %s\n' "$1" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "$1 is required but was not found on PATH."
}

compose() {
    if [ -f "$env_file" ]; then
        docker compose --env-file "$env_file" -f "$compose_file" "$@"
    else
        docker compose -f "$compose_file" "$@"
    fi
}

for command_name in python3.14 node npm git docker; do
    require_command "$command_name"
done
python3.14 -c 'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 14) else 1)' \
    || fail "python3.14 must run Python 3.14."
docker compose version >/dev/null 2>&1 \
    || fail "Docker Compose v2 is required. Start Docker Desktop or the Docker Engine."
docker info >/dev/null 2>&1 \
    || fail "The Docker Engine is unavailable. Start Docker Desktop or the Docker Engine."
platforms=$(docker buildx inspect --bootstrap 2>&1) \
    || fail "Docker Buildx could not inspect the active builder."
case "$platforms" in
    *linux/amd64*) ;;
    *) fail "The active Docker builder does not support linux/amd64." ;;
esac

if [ -f "$env_file" ]; then
    set -a
    . "$env_file"
    set +a
fi

if [ ! -x "$python" ]; then
    python3.14 -m venv "$project_dir/backend/.venv"
fi
"$python" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 14) else 1)' \
    || fail "backend/.venv was not created with Python 3.14; recreate it."
"$python" -m pip install -r "$requirements"
"$python" -m pip freeze | diff -u "$requirements" - \
    || fail "backend/.venv does not match backend/requirements.txt."

(cd "$project_dir/frontend" && npm ci)

compose up -d --wait postgres
database_user=${POSTGRES_USER:-bigeye}
database_name=${POSTGRES_DB:-bigeye}
schema_present=$(compose exec -T postgres psql -U "$database_user" -d "$database_name" \
    --tuples-only --no-align --command "SELECT to_regclass('public.projects') IS NOT NULL")
if [ "$schema_present" != "t" ]; then
    compose exec -T postgres psql -U "$database_user" -d "$database_name" \
        --set ON_ERROR_STOP=1 --file /docker-entrypoint-initdb.d/schema.sql
fi
table_count=$(compose exec -T postgres psql -U "$database_user" -d "$database_name" \
    --tuples-only --no-align --command "SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'public' AND tablename IN ('projects','tasks','assets','campaigns','campaign_contexts','campaign_container_counters','coverage_evidence','coverage_checkpoints','findings','campaign_crash_groups')")
[ "$table_count" = "10" ] \
    || fail "The development database schema is incomplete; back up workspace and run backend/database/reset.sh."

printf '%s\n' 'BigEye setup is ready. Copy .env_example to .env if needed, add OPENAI_API_KEY, then run scripts/start.sh.'
