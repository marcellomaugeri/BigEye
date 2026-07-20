#!/usr/bin/env sh
set -eu

usage() {
    printf '%s\n' 'Usage: scripts/start.sh [--no-browser] [--port PORT]' \
        'Build the frontend and run BigEye on 127.0.0.1.'
}

case "${1-}" in
    -h|--help) usage; exit 0 ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
env_file="$project_dir/.env"
compose_file="$project_dir/compose.yaml"
python="$project_dir/backend/.venv/bin/python"

if [ ! -f "$env_file" ]; then
    printf '%s\n' 'BigEye start: .env is missing. Run: cp .env_example .env' >&2
    exit 1
fi
if [ ! -x "$python" ]; then
    printf '%s\n' 'BigEye start: backend/.venv is missing. Run scripts/setup.sh first.' >&2
    exit 1
fi

set -a
. "$env_file"
set +a

(cd "$project_dir/frontend" && npm run build)
docker compose --env-file "$env_file" -f "$compose_file" up -d --wait postgres

cd "$project_dir"
exec "$python" -m backend.run "$@"
