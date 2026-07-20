"""Release contracts for the host-run BigEye application and its shell entrypoints."""

from __future__ import annotations

import importlib
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
from unittest.mock import AsyncMock
import warnings

import pytest

warnings.filterwarnings("ignore", message="Using `httpx` with `starlette.testclient` is deprecated")

from starlette.testclient import TestClient


ROOT = Path(__file__).resolve().parents[2]


def _services():
    return SimpleNamespace(recovery=SimpleNamespace(recover=AsyncMock()))


def _frontend_build(root: Path) -> Path:
    assets = root / "assets"
    assets.mkdir(parents=True)
    (root / "index.html").write_text(
        '<!doctype html><html><body><div id="root">BigEye release</div></body></html>',
        encoding="utf-8",
    )
    (assets / "application.js").write_text("window.bigeye = true;", encoding="utf-8")
    return root


def test_verified_frontend_build_serves_assets_and_spa_routes(tmp_path: Path) -> None:
    from backend.api.app import create_app

    build = _frontend_build(tmp_path / "dist")
    with TestClient(create_app(services=_services(), frontend_dist=build)) as client:
        root = client.get("/")
        nested = client.get("/projects/7/source")
        asset = client.get("/assets/application.js")

    assert root.status_code == nested.status_code == asset.status_code == 200
    assert root.headers["content-type"].startswith("text/html")
    assert nested.text == root.text
    assert asset.text == "window.bigeye = true;"


def test_api_and_missing_asset_errors_never_fall_through_to_spa(tmp_path: Path) -> None:
    from backend.api.app import create_app

    build = _frontend_build(tmp_path / "dist")
    with TestClient(create_app(services=_services(), frontend_dist=build)) as client:
        missing_api = client.get("/api/not-a-real-resource")
        invalid_api = client.post("/api/projects", json={})
        missing_asset = client.get("/assets/not-present.js")

    assert missing_api.status_code == 404
    assert invalid_api.status_code == 422
    assert missing_asset.status_code == 404
    for response in (missing_api, invalid_api, missing_asset):
        assert response.headers["content-type"].startswith("application/json")
        assert "BigEye release" not in response.text


@pytest.mark.parametrize("invalid_part", ["index.html", "assets"])
def test_missing_or_unsafe_frontend_build_returns_actionable_json(
    tmp_path: Path, invalid_part: str,
) -> None:
    from backend.api.app import create_app

    build = _frontend_build(tmp_path / "dist")
    if invalid_part == "index.html":
        (build / "index.html").unlink()
    else:
        (build / "assets" / "application.js").unlink()
        (build / "assets").rmdir()
    with TestClient(create_app(services=_services(), frontend_dist=build)) as client:
        response = client.get("/")
        missing_api = client.get("/api/not-a-real-resource")

    assert response.status_code == 503
    assert response.json() == {
        "detail": "Frontend build is unavailable. Run npm --prefix frontend run build."
    }
    assert missing_api.status_code == 404


def test_loopback_runner_disables_reload_and_browser_when_requested(monkeypatch) -> None:
    release = importlib.import_module("backend.run")
    captured = {}

    class Config:
        def __init__(self, app, **kwargs):
            captured.update(app=app, **kwargs)

    class Server:
        started = False

        def __init__(self, config):
            captured["config"] = config

        def run(self):
            captured["runs"] = captured.get("runs", 0) + 1

    opened = []
    monkeypatch.setattr(release.uvicorn, "Config", Config)
    monkeypatch.setattr(release.uvicorn, "Server", Server)
    monkeypatch.setattr(release.webbrowser, "open", opened.append)

    assert release.main(["--no-browser", "--port", "8123"]) == 0
    assert captured["app"] == "backend.api.app:app"
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 8123
    assert captured["reload"] is False
    assert captured["runs"] == 1
    assert opened == []


def test_loopback_runner_opens_product_once_only_after_server_readiness(monkeypatch) -> None:
    release = importlib.import_module("backend.run")
    opened = []

    class Config:
        def __init__(self, _app, **_kwargs):
            pass

    class Server:
        started = False

        def __init__(self, _config):
            pass

        def run(self):
            assert opened == []
            self.started = True
            assert release.wait_for(lambda: bool(opened), timeout=1.0)

    monkeypatch.setattr(release.uvicorn, "Config", Config)
    monkeypatch.setattr(release.uvicorn, "Server", Server)
    monkeypatch.setattr(release.webbrowser, "open", lambda url: opened.append(url))

    assert release.main(["--port", "8124"]) == 0
    assert opened == ["http://127.0.0.1:8124/"]


def test_loopback_runner_treats_keyboard_interrupt_as_a_clean_shutdown(monkeypatch) -> None:
    release = importlib.import_module("backend.run")

    class Config:
        def __init__(self, _app, **_kwargs):
            pass

    class Server:
        started = False

        def __init__(self, _config):
            pass

        def run(self):
            raise KeyboardInterrupt

    monkeypatch.setattr(release.uvicorn, "Config", Config)
    monkeypatch.setattr(release.uvicorn, "Server", Server)

    assert release.main(["--no-browser"]) == 0


def test_runner_has_no_non_loopback_host_option() -> None:
    release = importlib.import_module("backend.run")

    with pytest.raises(SystemExit):
        release.main(["--host", "0.0.0.0", "--no-browser"])


def _script(name: str) -> Path:
    return ROOT / "scripts" / name


@pytest.mark.parametrize("name", ["setup.sh", "start.sh", "check.sh"])
def test_release_scripts_are_posix_shell_and_work_from_a_spaced_directory(
    name: str, tmp_path: Path,
) -> None:
    script = _script(name)
    assert script.is_file()
    assert os.access(script, os.X_OK)
    assert subprocess.run(["sh", "-n", script], check=False).returncode == 0
    working_directory = tmp_path / "ordinary path with spaces"
    working_directory.mkdir()
    result = subprocess.run(
        ["sh", script, "--help"], cwd=working_directory,
        check=False, capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "Usage:" in result.stdout


def test_setup_verifies_tools_platform_and_frozen_dependencies_without_system_installs() -> None:
    setup = _script("setup.sh").read_text(encoding="utf-8")

    for command in ("python3.14", "node", "npm", "git", "docker"):
        assert command in setup
    assert "docker compose" in setup
    assert "docker buildx inspect --bootstrap" in setup
    assert "linux/amd64" in setup
    assert "python3.14 -m venv" in setup
    assert "pip install -r" in setup
    assert "pip freeze" in setup and "diff -u" in setup
    assert "npm ci" in setup
    assert "up -d --wait postgres" in setup
    assert "schema.sql" in setup
    assert "schema_contract.sql" in setup
    assert 'node -e' in setup
    assert "^20.19.0 || >=22.12.0" in setup
    assert '. "$env_file"' not in setup
    assert "SELECT COUNT(*) FROM pg_tables" not in setup
    for forbidden in ("apt-get", "brew install", "dnf install", "yum install", "sudo "):
        assert forbidden not in setup
    assert not any("pip freeze" in line and ">" in line for line in setup.splitlines())


def test_setup_uses_a_fail_closed_exact_schema_catalog_contract() -> None:
    contract = (ROOT / "backend/database/schema_contract.sql").read_text(encoding="utf-8")

    for relation in (
        "projects", "tasks", "assets", "campaigns", "campaign_contexts",
        "campaign_container_counters", "coverage_evidence", "coverage_checkpoints",
        "findings", "campaign_crash_groups", "campaign_artifacts",
    ):
        assert relation in contract
    assert "information_schema.columns" in contract
    assert "pg_constraint" in contract
    assert "pg_indexes" in contract
    assert "schema catalog does not match" in contract
    assert "COUNT(*) = 11" not in contract


def test_start_loads_env_without_echoing_secrets_and_execs_one_host_backend() -> None:
    start = _script("start.sh").read_text(encoding="utf-8")

    assert ".env_example" in start
    assert 'set -a' in start and '. "$env_file"' in start and "set +a" in start
    assert "npm" in start and "run build" in start
    assert "up -d --wait postgres" in start
    assert "exec" in start and "-m backend.run" in start
    assert "--reload" not in start
    build = start.index("npm run build")
    compose = start.index("up -d --wait postgres")
    source = start.index('. "$env_file"')
    assert build < compose < source < start.index("-m backend.run")
    for unsafe in ("set -x", "printenv", "env |", "echo $OPENAI_API_KEY", "echo ${OPENAI_API_KEY"):
        assert unsafe not in start


def test_check_runs_all_local_gates_and_keeps_real_docker_opt_in() -> None:
    check = _script("check.sh").read_text(encoding="utf-8")

    assert "backend/tests" in check
    assert "npm test" in check
    assert "npm run typecheck" in check
    assert "npm run build" in check
    assert "docker compose" in check and "config --quiet" in check
    assert "pip freeze" in check and "diff -u" in check
    assert "--live-docker" in check
    assert "test_real_campaigns.py" in check


def test_readme_uses_the_intended_environment_template_and_one_command_entrypoints() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "cp .env_example .env" in readme
    assert "scripts/setup.sh" in readme
    assert "scripts/start.sh" in readme
    assert "scripts/start.sh --no-browser" in readme
    assert "scripts/check.sh" in readme
    assert "Node.js `^20.19.0 || >=22.12.0`" in readme
    assert "Windows" not in readme


def test_frozen_requirements_match_the_release_environment() -> None:
    freeze = subprocess.run(
        [ROOT / "backend/.venv/bin/python", "-m", "pip", "freeze"],
        check=True, capture_output=True, text=True,
    ).stdout

    assert freeze == (ROOT / "backend/requirements.txt").read_text(encoding="utf-8")
