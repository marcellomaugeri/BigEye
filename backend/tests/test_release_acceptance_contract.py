"""Static release contracts for the real-browser and Linux acceptance gate."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_browser_dependencies_are_exact_and_the_cli_has_one_project_script() -> None:
    package = json.loads((ROOT / "frontend/package.json").read_text(encoding="utf-8"))
    lock = json.loads((ROOT / "frontend/package-lock.json").read_text(encoding="utf-8"))

    expected = {
        "@playwright/test": "1.61.1",
        "@axe-core/playwright": "4.12.1",
    }
    assert {name: package["devDependencies"].get(name) for name in expected} == expected
    assert package["scripts"]["e2e"] == (
        "npm run build && playwright test --config ../playwright.config.ts"
    )
    assert {
        name: lock["packages"][""]["devDependencies"].get(name) for name in expected
    } == expected


def test_playwright_configuration_is_serial_bounded_and_keeps_failure_evidence() -> None:
    config = (ROOT / "playwright.config.ts").read_text(encoding="utf-8")

    assert "tests/e2e" in config
    assert "BIGEYE_E2E_BASE_URL" in config
    assert "workers: 1" in config
    assert "fullyParallel: false" in config
    assert "chromium" in config
    assert "trace: 'retain-on-failure'" in config
    assert "screenshot: 'only-on-failure'" in config
    assert "webServer" not in config


def test_browser_acceptance_uses_real_services_and_covers_the_release_journey() -> None:
    spec = (ROOT / "tests/e2e/bigeye.spec.ts").read_text(encoding="utf-8")

    for required in (
        "backend/tests/fixtures/whole_loop_project",
        "BigEye is starting",
        "bigeye.intro.seen.v1",
        "Projects",
        "New project",
        "getByRole('dialog', { name: 'New project' })",
        "Start project",
        "Overview",
        "Activity",
        "Source assurance",
        "Download first testcase",
        "Findings",
        "Debug",
        "Fuzzing",
        "Autonomous fuzzing campaigns",
        "Reproduce finding",
        "Finding reproduction output",
        "@axe-core/playwright",
        "screenshot",
        "reducedMotion",
        "bigeye_acceptance",
        "workspace/e2e/runtime",
        "listen(0, '127.0.0.1',",
        "detached: true",
        "process.kill(-child.pid",
        "openSync",
        "closeSync(output)",
        "makeTreeDeletable(RUNTIME_ROOT)",
        "isSymbolicLink()",
        "new AggregateError",
        "['ls-tree', '-r', '--name-only', 'HEAD']",
        "/logs/debug?before=-1&limit=1000",
        "agent.start",
        "agent.end",
        "model.start",
        "model.end",
        "tool.start",
        "tool.end",
        "configuredOpenAIKey",
        "occurrence_count >= 2",
        "classification === 'true vulnerability'",
        "priority_rank",
        "priority_reason",
        "uncertainty",
        "replay:original:",
        "Reaching strategy",
        "cpu_exposure_seconds > 0",
        "target preparation accepted",
        "resumedCampaigns.some",
        "exactRunningCampaignContainers",
        "heartbeatAdvanced || cpuAdvanced",
        "engines.has('afl')",
        "engines.has('libfuzzer')",
        "fill('4')",
    ):
        assert required in spec
    for fixed_port in ("127.0.0.1:8000", "127.0.0.1:4173", "127.0.0.1:8128"):
        assert fixed_port not in spec
    for forbidden in ("page.route(", "route.fulfill(", "mock campaign", "fake finding"):
        assert forbidden not in spec.casefold()
    assert "createWriteStream" not in spec
    assert "rmSync(E2E_ROOT" not in spec
    assert "/pause" not in spec
    assert "/resume" not in spec


def test_browser_backend_environment_and_cleanup_are_isolated_and_fail_closed() -> None:
    spec = (ROOT / "tests/e2e/bigeye.spec.ts").read_text(encoding="utf-8")
    start_backend = spec.split("function startBackend", 1)[1].split(
        "async function assertNoSeriousAccessibilityViolations", 1,
    )[0]
    assert "'backend/.venv/bin/python'" in start_backend
    assert "configuredOpenAIKey = environmentValue('OPENAI_API_KEY', '')" in start_backend
    assert "OPENAI_API_KEY: configuredOpenAIKey" in start_backend
    assert "...process.env" in start_backend
    assert start_backend.index("...process.env") < start_backend.index("DATABASE_URL: databaseUrl")
    assert start_backend.index("...process.env") < start_backend.index("BIGEYE_WORKSPACE: RUNTIME_ROOT")
    for forbidden in ("'sh'", ". ./.env", "set -a", "set +a"):
        assert forbidden not in start_backend

    prepare_database = spec.split("function prepareAcceptanceDatabase", 1)[1].split(
        "function dropAcceptanceDatabase", 1,
    )[0]
    assert "DROP DATABASE" not in prepare_database
    assert prepare_database.index("CREATE DATABASE") < prepare_database.index("databasePrepared = true")
    assert prepare_database.index("databasePrepared = true") < prepare_database.index("schema.sql")

    database_identity = spec.split("const SERVICE_TIMEOUT", 1)[0]
    assert "randomBytes(" in database_identity
    assert "process.pid" in database_identity
    assert "const ACCEPTANCE_DATABASE = `bigeye_acceptance_${" in database_identity
    assert "const ACCEPTANCE_DATABASE = 'bigeye_acceptance'" not in database_identity

    cleanup = spec.split("test.afterAll", 1)[1].split("test('runs the complete", 1)[0]
    for required in ("com.bigeye.managed=fuzz-campaign", "stop(backendForShutdown)",
                     "stop(repositoryServer)", "dropAcceptanceDatabase", "AggregateError",
                     "com.bigeye.commit-sha", "docker', ['inspect'",
                     "acceptanceCleanupDecision", "cleanupFailures.push"):
        assert required in cleanup
    assert "com.bigeye.project-id=${projectId}" not in cleanup
    assert "acceptanceCommit !== null" in cleanup


def test_acceptance_cleanup_stops_the_backend_before_exact_container_removal() -> None:
    spec = (ROOT / "tests/e2e/bigeye.spec.ts").read_text(encoding="utf-8")
    stop = spec.split("async function stop", 1)[1].split(
        "async function availablePort", 1,
    )[0]
    cleanup = spec.split("test.afterAll", 1)[1].split("test('runs the complete", 1)[0]

    assert "signalCode === null" in stop
    assert "did not stop" in stop
    for required in (
        "backendForShutdown", "backendStopped = true", "backend = null",
        "if (backendStopped && acceptanceCommit !== null)", "remainingContainers",
        "refusing Docker cleanup because the backend did not stop",
    ):
        assert required in cleanup
    assert cleanup.index("stop(backendForShutdown)") < cleanup.index(
        "containers = run('docker'",
    )
    assert cleanup.index("backend = null") < cleanup.index("containers = run('docker'")
    assert cleanup.index("docker', ['rm', '-f', container]") < cleanup.index(
        "remainingContainers",
    )


def test_acceptance_commit_is_persisted_before_project_creation() -> None:
    spec = (ROOT / "tests/e2e/bigeye.spec.ts").read_text(encoding="utf-8")
    journey = spec.split("test('runs the complete", 1)[1]

    assert "let acceptanceCommit: string | null = null" in spec
    assert journey.index("acceptanceCommit = prepareRepository()") < journey.index("Start project")


def test_restart_requires_exact_container_and_advancing_runtime_evidence() -> None:
    spec = (ROOT / "tests/e2e/bigeye.spec.ts").read_text(encoding="utf-8")
    restart = spec.split("await stop(backend)", 1)[1].split(
        "await page.setViewportSize({ width: 390", 1,
    )[0]

    for required in (
        "campaignBeforeRestart.last_heartbeat_at",
        "campaignBeforeRestart.cpu_exposure_seconds",
        "exactRunningCampaignContainers",
        "com.bigeye.managed=fuzz-campaign",
        "com.bigeye.commit-sha=",
        "com.bigeye.project-id=",
        "com.bigeye.campaign-id=",
        "last_heartbeat_at",
        "cpu_exposure_seconds",
        "heartbeatAdvanced || cpuAdvanced",
    ):
        assert required in spec
    assert "exactRunningCampaignContainers(resumedCampaign.id)" in restart
    assert ".length === 1" in restart


def test_crash_acceptance_asserts_the_complete_deterministic_triage_contract() -> None:
    spec = (ROOT / "tests/e2e/bigeye.spec.ts").read_text(encoding="utf-8")
    triage = spec.split("let findings: Finding[]", 1)[1].split(
        "const configuredOpenAIKey", 1,
    )[0]

    for required in (
        "classification === 'true vulnerability'",
        "priority_rank === 1",
        "priority_reason",
        "description",
        "uncertainty",
        "replay.attempts",
        "replay.matching",
        "replay.compatible_variants",
        "replay.clean_variant",
        "replay:original:",
        "replay:clean",
    ):
        assert required in triage


def test_source_acceptance_proves_positive_exposure_and_filters_reaching_strategy() -> None:
    spec = (ROOT / "tests/e2e/bigeye.spec.ts").read_text(encoding="utf-8")
    source = spec.split("await openPrimaryView(page, 'Source')", 1)[1].split(
        "await openPrimaryView(page, 'Findings')", 1,
    )[0]

    assert "coveredFile.cpu_exposure_seconds > 0" in source
    assert "item.cpu_exposure_seconds >= 0" in source
    assert "item.cpu_exposure_seconds > 0" in source
    assert "getByRole('combobox', { name: 'Reaching strategy' })" in source
    assert ".selectOption(" in source
    assert "Download first testcase for ${strategyLabel}" in source


def test_acceptance_cleanup_helper_has_fail_closed_mount_and_identity_examples() -> None:
    helper = (ROOT / "tests/e2e/acceptanceCleanup.ts").read_text(encoding="utf-8")
    examples = (ROOT / "tests/e2e/acceptanceCleanup.spec.ts").read_text(encoding="utf-8")

    for required in (
        "com.bigeye.managed", "com.bigeye.commit-sha", "com.bigeye.project-id",
        "com.bigeye.campaign-id", "/campaign/corpus", "/campaign/output",
        "/campaign/config", "removable: false",
    ):
        assert required in helper
    for example in (
        "unrelated container that reuses the project id",
        "mount outside the acceptance runtime",
        "even when project capture failed",
    ):
        assert example in examples


def test_linux_workflow_runs_checked_in_release_and_browser_commands() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "runs-on: ubuntu-24.04" in workflow
    assert "python-version: '3.14'" in workflow
    assert "node-version:" in workflow
    for command in (
        "scripts/setup.sh",
        "scripts/check.sh",
        "npm --prefix frontend run e2e",
        "playwright install --with-deps chromium",
    ):
        assert command in workflow
    assert "OPENAI_API_KEY" in workflow
    job_before_steps = workflow.split("steps:", 1)[0]
    assert "OPENAI_API_KEY" not in job_before_steps
    assert "BIGEYE_LIVE_OPENAI" not in job_before_steps
    assert "actions/upload-artifact@" in workflow
    assert "if: failure()" in workflow
    assert "Skipping the live" not in workflow
    assert workflow.count("exit 1") >= 2


def test_controlled_system_fixture_is_healthy_then_one_mutation_from_one_grouped_defect() -> None:
    fixture = ROOT / "backend/tests/fixtures/system_project"
    source = (fixture / "src/main.c").read_text(encoding="utf-8")
    seed_one = (fixture / "seeds/plain.txt").read_bytes().rstrip(b"\n")
    seed_two = (fixture / "seeds/framed.txt").read_bytes().removeprefix(b"FRAME:").rstrip(b"\n")
    crash_one = (fixture / "crashes/duplicate-one.input").read_bytes().rstrip(b"\n")
    crash_two = (fixture / "crashes/duplicate-two.input").read_bytes().rstrip(b"\n")

    assert seed_one == seed_two
    assert {crash_one[:1], crash_two[:1]} == {b"B", b"C"}
    assert crash_one[1:] == crash_two[1:] == seed_one[1:]
    assert len(seed_one) == len(crash_one) == len(crash_two)
    assert all(
        sum(left != right for left, right in zip(seed_one, crash, strict=True)) == 1
        for crash in (crash_one, crash_two)
    )
    for required in (
        "BIGEYE_NOINLINE", "volatile", "mark_crash_path_b", "mark_crash_path_c",
        "data[0] == (unsigned char)'B'", "data[0] == (unsigned char)'C'",
    ):
        assert required in source
    assert source.count("memcpy(decoded, data, copy_size);") == 1


def test_host_app_acceptance_workspace_is_explicitly_overridable(monkeypatch, tmp_path: Path) -> None:
    from backend.api.app import configured_workspace

    monkeypatch.delenv("BIGEYE_WORKSPACE", raising=False)
    assert configured_workspace() == Path("workspace")
    isolated = tmp_path / "acceptance-workspace"
    monkeypatch.setenv("BIGEYE_WORKSPACE", str(isolated))
    assert configured_workspace() == isolated


def test_release_verification_distinguishes_observed_mac_results_from_pending_ci() -> None:
    evidence = (ROOT / "docs/release-verification.md").read_text(encoding="utf-8")

    assert "This page records observed evidence only." in evidence
    assert "It is not a substitute for running" in evidence
    assert "## macOS" in evidence
    assert "## Container platform" in evidence
    assert "## Linux CI" in evidence
    assert "**Pending.**" in evidence
    assert "linux/amd64" in evidence
    assert "Task18/19A" not in evidence
    assert "intentionally RED" not in evidence
