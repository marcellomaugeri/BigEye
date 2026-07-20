#!/usr/bin/env sh
set -eu

usage() {
    printf '%s\n' 'Usage: scripts/check.sh [--live-docker]' \
        'Run local release checks. Real Docker campaigns are opt-in.'
}

live_docker=0
case "${1-}" in
    -h|--help) usage; exit 0 ;;
    --live-docker) live_docker=1 ;;
    "") ;;
    *) usage >&2; exit 2 ;;
esac
[ "$#" -le 1 ] || { usage >&2; exit 2; }

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
python="$project_dir/backend/.venv/bin/python"
requirements="$project_dir/backend/requirements.txt"
compose_file="$project_dir/compose.yaml"

if [ ! -x "$python" ]; then
    printf '%s\n' 'BigEye check: backend/.venv is missing. Run scripts/setup.sh first.' >&2
    exit 1
fi

cd "$project_dir"
"$python" -m pip freeze | diff -u "$requirements" -
docker compose -f "$compose_file" config --quiet
"$python" -m pytest backend/tests
(cd "$project_dir/frontend" && npm test && npm run typecheck && npm run build)

if [ "$live_docker" -eq 1 ]; then
    "$python" -m pytest -o addopts= -m docker backend/tests/test_real_campaigns.py
fi
