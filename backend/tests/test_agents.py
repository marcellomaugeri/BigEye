import asyncio
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from agents import Agent, RunContextWrapper

from backend.agents.context import AgentContext
from backend.agents.manager import build_manager_agent
from backend.agents.repository_analysis import build_repository_analysis_agent
from backend.agents.tools.agent_dispatch import repository_analysis_tool
from backend.agents.tools.code_navigation import (
    CodeNavigationError,
    inspect_git_metadata,
    list_project_files,
    read_source_lines,
    search_source_text,
)
from backend.agents.workflow import CitationValidationError, RepositoryAnalysisWorkflow, validate_citations


def write_repository(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    root.mkdir()
    (root / "src").mkdir()
    (root / "src" / "main.rs").write_text("fn main() {\n    println!(\"hello\");\n}\n", encoding="utf-8")
    (root / "README.md").write_text("BigEye\n", encoding="utf-8")
    return root


def test_navigation_lists_and_reads_contained_text_files(tmp_path: Path) -> None:
    root = write_repository(tmp_path)

    assert list_project_files(root) == ["README.md", "src/main.rs"]
    assert read_source_lines(root, "src/main.rs", 1, 2) == "fn main() {\n    println!(\"hello\");"
    assert search_source_text(root, "println") == [
        {"path": "src/main.rs", "line": 2, "text": '    println!("hello");'}
    ]


@pytest.mark.parametrize("path", ["/etc/passwd", "../outside", ".git/config", "src/.git/config", "src/../main.rs", "bad\x00path"])
def test_navigation_rejects_unsafe_model_paths(tmp_path: Path, path: str) -> None:
    root = write_repository(tmp_path)

    with pytest.raises(CodeNavigationError):
        read_source_lines(root, path, 1, 1)


def test_navigation_rejects_symlink_escape_binary_and_bounds(tmp_path: Path) -> None:
    root = write_repository(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("secret\n", encoding="utf-8")
    (root / "escape.txt").symlink_to(outside)
    (root / "binary.dat").write_bytes(b"\x00data")

    with pytest.raises(CodeNavigationError):
        read_source_lines(root, "escape.txt", 1, 1)
    with pytest.raises(CodeNavigationError):
        read_source_lines(root, "binary.dat", 1, 1)
    with pytest.raises(CodeNavigationError):
        read_source_lines(root, "src/main.rs", 1, 201)
    with pytest.raises(CodeNavigationError):
        search_source_text(root, "x" * 201)


def test_git_metadata_uses_bounded_argv_and_repository_root(tmp_path: Path) -> None:
    root = write_repository(tmp_path)
    calls: list[tuple[list[str], Path, bool, float]] = []

    def run(argv, *, cwd, capture_output, text, timeout, check):
        calls.append((argv, cwd, capture_output, timeout))
        return SimpleNamespace(returncode=0, stdout="a" * 40 + "\n", stderr="")

    assert inspect_git_metadata(root, run=run) == {"commit": "a" * 40, "branch": "a" * 40}
    assert calls == [
        (["git", "rev-parse", "HEAD"], root.resolve(), True, 5),
        (["git", "rev-parse", "--abbrev-ref", "HEAD"], root.resolve(), True, 5),
    ]


def test_agents_have_the_required_models_and_tool_boundary() -> None:
    worker = build_repository_analysis_agent()
    worker_tool = repository_analysis_tool(worker)
    manager = build_manager_agent(worker_tool)

    assert isinstance(worker, Agent)
    assert worker.model == "gpt-5.6-luna"
    assert {tool.name for tool in worker.tools} == {"list_project_files", "read_source_lines", "search_source_text", "inspect_git_metadata"}
    assert worker.handoffs == []
    assert worker_tool.name == "analyse_repository"
    assert isinstance(manager, Agent)
    assert manager.model == "gpt-5.6-terra"
    assert manager.tools == [worker_tool]
    assert manager.handoffs == []


def test_context_contains_only_project_id_and_resolved_repository_root(tmp_path: Path) -> None:
    root = write_repository(tmp_path)
    context = AgentContext(project_id=4, repository_root=root)

    assert context.project_id == 4
    assert context.repository_root == root.resolve()
    assert set(context.__dataclass_fields__) == {"project_id", "repository_root"}


def test_citation_validation_accepts_real_contained_line_ranges(tmp_path: Path) -> None:
    root = write_repository(tmp_path)

    assert validate_citations("The entry point is [src/main.rs:1-2].", root) == [("src/main.rs", 1, 2)]


@pytest.mark.parametrize(
    "text",
    [
        "No evidence.",
        "Bad [src/main.rs:2-1].",
        "Bad [missing.rs:1-1].",
        "Bad [../outside:1-1].",
        "Bad [.git/config:1-1].",
        "Bad [src/main.rs:1-99].",
        "Bad [src/main.rs:1-].",
    ],
)
def test_citation_validation_rejects_invalid_or_unbounded_evidence(tmp_path: Path, text: str) -> None:
    root = write_repository(tmp_path)

    with pytest.raises(CitationValidationError):
        validate_citations(text, root)


def test_workflow_publishes_only_valid_output_atomically(tmp_path: Path) -> None:
    root = write_repository(tmp_path)
    workspace = tmp_path / "workspace"
    calls = []

    async def runner(agent, prompt, *, context):
        calls.append((agent, prompt, context))
        return SimpleNamespace(final_output="The entry point is [src/main.rs:1-2].")

    path = asyncio.run(RepositoryAnalysisWorkflow(workspace, runner=runner).analyse(7, root))

    assert path == workspace / "projects" / "7" / "analysis" / "repository.md"
    assert path.read_text(encoding="utf-8") == "The entry point is [src/main.rs:1-2]."
    assert len(calls) == 1
    assert calls[0][0].model == "gpt-5.6-terra"
    assert calls[0][0].tools[0].name == "analyse_repository"


def test_workflow_retries_once_with_terra_worker_only_after_invalid_citations(tmp_path: Path) -> None:
    root = write_repository(tmp_path)
    outputs = iter(["No citation.", "Entry point [src/main.rs:1-1]."])
    calls = []

    async def runner(agent, prompt, *, context):
        calls.append(agent)
        return SimpleNamespace(final_output=next(outputs))

    path = asyncio.run(RepositoryAnalysisWorkflow(tmp_path / "workspace", runner=runner).analyse(8, root))

    assert path.read_text(encoding="utf-8") == "Entry point [src/main.rs:1-1]."
    assert len(calls) == 2
    assert calls[0].tools[0]._agent_instance.model == "gpt-5.6-luna"
    assert calls[1].tools[0]._agent_instance.model == "gpt-5.6-terra"


def test_workflow_does_not_retry_runner_errors_or_publish_two_invalid_outputs(tmp_path: Path) -> None:
    root = write_repository(tmp_path)
    workspace = tmp_path / "workspace"
    existing = workspace / "projects" / "9" / "analysis" / "repository.md"
    existing.parent.mkdir(parents=True)
    existing.write_text("Existing [src/main.rs:1-1].", encoding="utf-8")
    calls = 0

    async def failing_runner(agent, prompt, *, context):
        nonlocal calls
        calls += 1
        raise RuntimeError("runner failure")

    with pytest.raises(RuntimeError, match="runner failure"):
        asyncio.run(RepositoryAnalysisWorkflow(workspace, runner=failing_runner).analyse(9, root))
    assert calls == 1
    assert existing.read_text(encoding="utf-8") == "Existing [src/main.rs:1-1]."

    outputs = iter(["No citations.", "Still none."])

    async def invalid_runner(agent, prompt, *, context):
        return SimpleNamespace(final_output=next(outputs))

    with pytest.raises(CitationValidationError):
        asyncio.run(RepositoryAnalysisWorkflow(workspace, runner=invalid_runner).analyse(9, root))
    assert existing.read_text(encoding="utf-8") == "Existing [src/main.rs:1-1]."
