# BigEye

BigEye is a local backbone for a user-chosen HTTP(S) Git repository. It clones
the repository into a contained workspace, prepares the maintained LLVM image,
and publishes a cited repository analysis when an OpenAI key is configured.

## First run

```sh
cp .env.example .env
docker compose up -d postgres
docker compose ps
# only if a local development reset is needed
backend/database/reset.sh
python3.14 -m venv backend/.venv
backend/.venv/bin/python -m pip install -r backend/requirements.txt
backend/.venv/bin/uvicorn backend.api.app:app --reload
cd frontend && npm install && npm run dev
```

Open the URL printed by Vite (normally `http://127.0.0.1:5173`) and create a
project with an HTTP(S) repository URL of your choice. Vite proxies `/api` to
FastAPI at `127.0.0.1:8000`; set `VITE_API_BASE_URL` only when using another
API address. On later runs, start PostgreSQL with `docker compose up -d
postgres`, run Uvicorn from the repository root, then run `npm run dev` in
`frontend`.

Docker Desktop must be running for toolchain preparation. Docker uses
`linux/amd64`, which may use emulation on non-amd64 hosts. The first toolchain
preparation builds the image; later projects reuse its maintained tag. Set a
real `OPENAI_API_KEY` in `.env` before repository analysis can call the Agents
service. No key is stored or displayed by BigEye.

Project files are under `workspace/projects/<id>/`: the clone is in
`repository/`, the analysis is `analysis/repository.md`, and task logs are in
`logs/<task-id>.log`. If Git, Docker, or analysis fails, its task and log show
the real error and the project finishes with an aggregate error. Interrupted
work remains unfinished and is recovered at backend startup.
