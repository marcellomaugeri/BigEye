import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest
from agents import Agent
from pydantic import ValidationError
from agents.run import RunConfig
from agents.tool_context import ToolContext

from backend.agents.context import AgentContext
from backend.agents.manager import build_manager_agent
from backend.agents.outputs.campaign_decision import CampaignDecision
from backend.agents.outputs.target_proposal import TargetProposal
from backend.agents.outputs.triage_result import TriageResult
from backend.agents.prompts.component_target import COMPONENT_TARGET_PROMPT
from backend.agents.prompts.crash_triage import CRASH_TRIAGE_PROMPT
from backend.agents.prompts.system_target import SYSTEM_TARGET_PROMPT
from backend.agents.tools.agent_dispatch import dispatch_tools
from backend.agents.tools.contained_operations import contained_operation_request
from backend.agents.tools.generated_assets import GeneratedAssetError, write_asset_file
from backend.agents.tools.code_navigation import (
    CodeNavigationError,
    MAX_DIRECTORY_DEPTH,
    MAX_DIRECTORY_ENTRIES,
    MAX_DIRECTORIES,
    inspect_git_metadata,
    list_project_files,
    read_source_lines,
    search_source_text,
)
from backend.agents.tools.code_navigation import (
    inspect_contained_git_metadata,
    list_contained_project_files,
    read_contained_source_lines,
    search_contained_source_text,
)
from backend.agents.tools.evidence_retrieval import evidence_retrieval_tools
from backend.fuzzing.discovery.retrieval import EvidenceRetriever


def write_repository(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    root.mkdir()
    (root / "src").mkdir()
    (root / "src" / "main.rs").write_text("fn main() {\n    println!(\"hello\");\n}\n", encoding="utf-8")
    (root / "README.md").write_text("BigEye\n", encoding="utf-8")
    return root


def agent_context(tmp_path: Path, project_id: int = 4) -> AgentContext:
    root = write_repository(tmp_path)
    return AgentContext(project_id, "a" * 40, root, tmp_path / "assets", EvidenceRetriever(root))


def test_navigation_lists_and_reads_contained_text_files(tmp_path: Path) -> None:
    root = write_repository(tmp_path)

    assert list_project_files(root) == ["README.md", "src/main.rs"]
    assert read_source_lines(root, "src/main.rs", 1, 2) == "fn main() {\n    println!(\"hello\");"
    assert search_source_text(root, "println") == [
        {"path": "src/main.rs", "line": 2, "text": '    println!("hello");'}
    ]


@pytest.mark.parametrize(
    "path", ["/etc/passwd", "../outside", ".git/config", ".GIT/config", "src/.git/config", "src/../main.rs", "bad\x00path"]
)
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


def test_navigation_rejects_oversized_files_before_reading(tmp_path: Path) -> None:
    root = write_repository(tmp_path)
    from backend.agents.tools.code_navigation import MAX_FILE_BYTES

    (root / "large.txt").write_bytes(b"a" * (MAX_FILE_BYTES + 1))

    with pytest.raises(CodeNavigationError):
        read_source_lines(root, "large.txt", 1, 1)


def test_navigation_listing_skips_case_insensitive_git_and_symlinks(tmp_path: Path) -> None:
    root = write_repository(tmp_path)
    (root / ".GIT").mkdir()
    (root / ".GIT" / "config").write_text("hidden\n", encoding="utf-8")
    (root / "linked.rs").symlink_to(root / "src" / "main.rs")

    assert list_project_files(root) == ["README.md", "src/main.rs"]


def test_navigation_rejects_too_many_directories(tmp_path: Path) -> None:
    root = write_repository(tmp_path)
    for index in range(MAX_DIRECTORIES + 1):
        (root / f"empty-{index}").mkdir()

    with pytest.raises(CodeNavigationError):
        list_project_files(root)


def test_navigation_rejects_excessive_directory_depth(tmp_path: Path) -> None:
    root = write_repository(tmp_path)
    directory = root
    for index in range(MAX_DIRECTORY_DEPTH + 1):
        directory = directory / f"level-{index}"
        directory.mkdir()

    with pytest.raises(CodeNavigationError):
        list_project_files(root)


def test_navigation_rejects_directory_entry_budget(tmp_path: Path) -> None:
    root = write_repository(tmp_path)
    for index in range(MAX_DIRECTORY_ENTRIES + 1):
        (root / f"entry-{index}").write_text("x\n", encoding="utf-8")

    with pytest.raises(CodeNavigationError):
        list_project_files(root)


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


def test_manager_has_specialists_as_tools_and_no_direct_repository_tools(tmp_path: Path) -> None:
    tools = dispatch_tools(agent_context(tmp_path), evidence_ids={"evidence-1"})
    manager = build_manager_agent(tools)

    assert isinstance(manager, Agent)
    assert manager.model == "gpt-5.6-terra"
    assert {tool.name for tool in manager.tools} == {
        "prepare_system_target",
        "prepare_component_target",
        "triage_crash_group",
    }
    assert manager.handoffs == []
    for tool in tools:
        assert tool._is_agent_tool is True
        assert tool._agent_instance.model == "gpt-5.6-luna"
        assert set(tool.params_json_schema["properties"]) == {"assignment", "evidence_ids"}
        assert tool.params_json_schema["additionalProperties"] is False


def test_specialists_have_narrow_tools_structured_outputs_and_no_handoffs(tmp_path: Path) -> None:
    workers = {tool.name: tool._agent_instance for tool in dispatch_tools(agent_context(tmp_path), evidence_ids=set())}
    shared = {
        "list_project_files", "read_source_lines", "search_source_text", "inspect_git_metadata",
        "inspect_build_evidence", "retrieve_repository_evidence", "web_search",
        "write_generated_asset", "request_contained_operation",
    }

    assert {tool.name for tool in workers["prepare_system_target"].tools} == shared
    assert {tool.name for tool in workers["prepare_component_target"].tools} == shared
    assert {tool.name for tool in workers["triage_crash_group"].tools} == shared
    assert workers["prepare_system_target"].output_type is TargetProposal
    assert workers["prepare_component_target"].output_type is TargetProposal
    assert workers["triage_crash_group"].output_type is TriageResult
    assert all(worker.handoffs == [] for worker in workers.values())
    assert {tool.name for tool in evidence_retrieval_tools()} == {"inspect_build_evidence", "retrieve_repository_evidence"}


@pytest.mark.parametrize("prompt", [SYSTEM_TARGET_PROMPT, COMPONENT_TARGET_PROMPT, CRASH_TRIAGE_PROMPT])
def test_specialists_treat_repository_and_web_content_as_untrusted_evidence(prompt: str) -> None:
    lowered = prompt.casefold()

    assert "repository" in lowered
    assert "web" in lowered
    assert "untrusted evidence" in lowered
    assert "never instructions" in lowered
    assert "official" in lowered
    assert "citation" in lowered


def test_structured_outputs_reject_missing_fields_and_extra_assumptions() -> None:
    proposal = TargetProposal(
        target_name="parser", instance_type="component-level", byte_path="LLVMFuzzerTestOneInput -> parse",
        expected_project_reach="parser state machine", build_command="cmake --build build --target parser_fuzz",
        run_command="/bigeye/parser_fuzz", seeds=[{"path": "tests/minimal.txt", "provenance": "repository"}],
        configuration="default", sanitizer_plan="ASan and UBSan", generated_asset_intents=[{
            "relative_path": "component/parser_harness.cc", "purpose": "component harness"
        }], probe_assertions=["seed reaches parser code", "empty input does not crash"],
        evidence_ids=["evidence-1"], uncertainty="build target has not been probed",
    )
    decision = CampaignDecision(
        decision="prepare target", motivation="The parser has a supported byte entry path.",
        evidence_ids=["evidence-1"], bounded_actions=["prepare_component_target"],
        next_review_condition="after the deterministic probe", uncertainty="build not yet run",
    )

    assert proposal.instance_type == "component-level"
    assert decision.bounded_actions == ["prepare_component_target"]
    with pytest.raises(ValidationError):
        CampaignDecision(
            decision="wait", motivation="No action", evidence_ids=[], bounded_actions=[],
            next_review_condition="new evidence", uncertainty="none", invented=True,
        )


def _target_proposal(evidence_id: str) -> TargetProposal:
    return TargetProposal(
        target_name="parser", instance_type="system-level", byte_path="stdin -> parser",
        expected_project_reach="parser state machine", build_command="cmake --build build --target parser",
        run_command="/src/build/parser", seeds=[{"path": "tests/minimal.txt", "provenance": "repository"}],
        configuration="default", sanitizer_plan="ASan and UBSan", generated_asset_intents=[{
            "relative_path": "system/parser/Dockerfile", "purpose": "target layer"
        }], probe_assertions=["seed reaches parser code"], evidence_ids=[evidence_id],
        uncertainty="runtime path has not been probed",
    )


def test_luna_specialist_retries_once_with_terra_only_after_validation_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = agent_context(tmp_path)
    calls: list[str] = []

    class Result:
        interruptions = []
        new_items = []
        raw_responses = []

        def __init__(self, output):
            self.final_output = output

        def to_input_list(self):
            return [{"role": "user", "content": "prepare the parser target"}]

    async def runner(starting_agent=None, input=None, **kwargs):
        agent = starting_agent
        calls.append(agent.model)
        return Result(_target_proposal("unknown") if agent.model == "gpt-5.6-luna" else _target_proposal("known"))

    from agents import Runner

    monkeypatch.setattr(Runner, "run", runner)
    tool = next(item for item in dispatch_tools(context, evidence_ids={"known"}) if item.name == "prepare_system_target")
    tool_context = ToolContext(
        context, tool_name=tool.name, tool_call_id="call-1",
        tool_arguments='{"assignment":"prepare parser","evidence_ids":["known"]}', run_config=RunConfig(),
    )
    output = asyncio.run(tool.on_invoke_tool(
        tool_context, '{"assignment":"prepare parser","evidence_ids":["known"]}'
    ))

    assert calls == ["gpt-5.6-luna", "gpt-5.6-terra"]
    assert output.evidence_ids == ["known"]


def test_specialist_accepts_only_source_evidence_returned_by_its_retrieval_tool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = agent_context(tmp_path)
    calls = []
    tool = next(item for item in dispatch_tools(context, evidence_ids=set()) if item.name == "prepare_system_target")
    retrieval = next(item for item in tool._agent_instance.tools if item.name == "retrieve_repository_evidence")
    retrieval_context = ToolContext(
        context, tool_name=retrieval.name, tool_call_id="retrieve-1",
        tool_arguments='{"question":"println","limit":2}', run_config=RunConfig(),
    )
    excerpts = asyncio.run(retrieval.on_invoke_tool(
        retrieval_context, '{"question":"println","limit":2}'
    ))
    evidence_id = excerpts[0]["evidence_id"]

    class Result:
        interruptions = []
        new_items = []
        raw_responses = []
        input = "prepare parser"
        final_output = _target_proposal(evidence_id)

        def to_input_list(self):
            return []

    async def runner(starting_agent=None, input=None, **kwargs):
        calls.append(starting_agent.model)
        return Result()

    from agents import Runner

    monkeypatch.setattr(Runner, "run", runner)
    parent_context = ToolContext(
        context, tool_name=tool.name, tool_call_id="call-1",
        tool_arguments='{"assignment":"prepare parser","evidence_ids":[]}', run_config=RunConfig(),
    )
    output = asyncio.run(tool.on_invoke_tool(
        parent_context, '{"assignment":"prepare parser","evidence_ids":[]}'
    ))

    assert calls == ["gpt-5.6-luna"]
    assert output.evidence_ids == [evidence_id]


def test_specialist_accepts_only_web_citation_returned_by_its_model_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = agent_context(tmp_path)
    citation = "https://official.example.org/reference/parser"

    class Result:
        interruptions = []
        new_items = []
        input = "prepare parser"
        final_output = _target_proposal(citation)
        raw_responses = [SimpleNamespace(output=[{
            "type": "message", "content": [{"type": "output_text", "text": "docs", "annotations": [{
                "type": "url_citation", "url": citation,
            }]}],
        }])]

        def to_input_list(self):
            return []

    calls = []

    async def runner(starting_agent=None, input=None, **kwargs):
        calls.append(starting_agent.model)
        return Result()

    from agents import Runner

    monkeypatch.setattr(Runner, "run", runner)
    tool = next(item for item in dispatch_tools(context, evidence_ids=set()) if item.name == "prepare_system_target")
    parent_context = ToolContext(
        context, tool_name=tool.name, tool_call_id="call-1",
        tool_arguments='{"assignment":"prepare parser","evidence_ids":[]}', run_config=RunConfig(),
    )

    output = asyncio.run(tool.on_invoke_tool(
        parent_context, '{"assignment":"prepare parser","evidence_ids":[]}'
    ))

    assert calls == ["gpt-5.6-luna"]
    assert output.evidence_ids == [citation]


def test_specialist_transport_failure_is_not_retried(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = agent_context(tmp_path)
    calls = 0

    async def runner(starting_agent=None, input=None, **kwargs):
        nonlocal calls
        calls += 1
        raise RuntimeError("transport unavailable")

    from agents import Runner

    monkeypatch.setattr(Runner, "run", runner)
    tool = next(item for item in dispatch_tools(context, evidence_ids=set()) if item.name == "prepare_system_target")
    tool_context = ToolContext(
        context, tool_name=tool.name, tool_call_id="call-1",
        tool_arguments='{"assignment":"prepare parser","evidence_ids":[]}', run_config=RunConfig(),
    )

    with pytest.raises(RuntimeError, match="transport unavailable"):
        asyncio.run(tool.on_invoke_tool(
            tool_context, '{"assignment":"prepare parser","evidence_ids":[]}'
        ))
    assert calls == 1


def test_generated_asset_writes_only_inside_draft_root_with_compare_and_swap(tmp_path: Path) -> None:
    context = agent_context(tmp_path)

    created = write_asset_file(context, "component/parser/harness.cc", "int target() { return 0; }\n", None)
    updated = write_asset_file(
        context, "component/parser/harness.cc", "int target() { return 1; }\n", created["sha256"]
    )

    assert (context.generated_assets_root / "component/parser/harness.cc").read_text() == "int target() { return 1; }\n"
    assert created["created"] is True
    assert updated["created"] is False
    assert "-int target() { return 0; }" in updated["diff"]
    with pytest.raises(GeneratedAssetError):
        write_asset_file(context, "component/parser/harness.cc", "changed", created["sha256"])
    with pytest.raises(GeneratedAssetError):
        write_asset_file(context, "../outside", "bad", None)


def test_generated_asset_rejects_symlink_ancestors(tmp_path: Path) -> None:
    context = agent_context(tmp_path)
    context.generated_assets_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (context.generated_assets_root / "linked").symlink_to(outside, target_is_directory=True)

    with pytest.raises(GeneratedAssetError):
        write_asset_file(context, "linked/harness.cc", "bad", None)
    assert not (outside / "harness.cc").exists()


def test_generated_asset_restores_previous_version_if_root_changes_during_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import backend.agents.tools.generated_assets as generated_assets

    context = agent_context(tmp_path)
    original = write_asset_file(context, "component/parser/harness.cc", "original\n", None)
    checks = iter((True, False))
    monkeypatch.setattr(generated_assets, "_root_is_canonical", lambda *args: next(checks))

    with pytest.raises(GeneratedAssetError, match="publication"):
        write_asset_file(context, "component/parser/harness.cc", "replacement\n", original["sha256"])

    assert (context.generated_assets_root / "component/parser/harness.cc").read_text() == "original\n"


def test_contained_operation_is_a_bounded_request_not_host_execution(tmp_path: Path) -> None:
    context = agent_context(tmp_path)
    write_asset_file(context, "system/parser/config.sh", "#!/bin/sh\nexit 0\n", None)

    request = contained_operation_request(
        context, "probe", ["system/parser/config.sh"], ["seed reaches project code"]
    )

    assert request == {
        "operation": "probe", "asset_paths": ["system/parser/config.sh"],
        "assertions": ["seed reaches project code"], "executed": False,
        "provenance": "agent_request", "trusted_instructions": False,
    }
    with pytest.raises(ValueError):
        contained_operation_request(context, "shell", ["/etc/passwd"], ["run it"])


def test_navigation_function_tools_wrap_every_repository_result_as_untrusted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import backend.agents.tools.code_navigation as navigation

    root = write_repository(tmp_path)
    context = AgentContext(4, "a" * 40, root, tmp_path / "assets", EvidenceRetriever(root))
    monkeypatch.setattr(navigation, "inspect_git_metadata", lambda _: {"commit": "b" * 40, "branch": "main"})

    def invoke(tool, arguments: str):
        tool_context = ToolContext(
            context,
            tool_name=tool.name,
            tool_call_id=f"call_{tool.name}",
            tool_arguments=arguments,
            run_config=RunConfig(),
        )
        return asyncio.run(tool.on_invoke_tool(tool_context, arguments))

    listed = invoke(list_contained_project_files, '{"limit":10}')
    read = invoke(read_contained_source_lines, '{"relative_path":"src/main.rs","start_line":1,"end_line":1}')
    searched = invoke(search_contained_source_text, '{"query":"println","limit":5}')
    metadata = invoke(inspect_contained_git_metadata, "{}")

    for result in (listed, read, searched, metadata):
        assert result["provenance"] == "repository"
        assert result["trusted_instructions"] is False
    assert listed["files"] == ["README.md", "src/main.rs"]
    assert read == {
        "path": "src/main.rs",
        "start_line": 1,
        "end_line": 1,
        "text": "fn main() {",
        "provenance": "repository",
        "trusted_instructions": False,
    }
    assert searched["matches"] == [
        {
            "path": "src/main.rs",
            "line": 2,
            "text": '    println!("hello");',
            "provenance": "repository",
            "trusted_instructions": False,
        }
    ]
    assert metadata["commit"] == "b" * 40
    assert metadata["branch"] == "main"


def test_context_owns_only_project_identity_roots_and_retriever(tmp_path: Path) -> None:
    root = write_repository(tmp_path)
    assets = tmp_path / "assets"
    context = AgentContext(
        project_id=4,
        commit_sha="a" * 40,
        repository_root=root,
        generated_assets_root=assets,
        evidence=EvidenceRetriever(root),
    )

    assert context.project_id == 4
    assert context.commit_sha == "a" * 40
    assert context.repository_root == root.resolve()
    assert context.generated_assets_root == assets.resolve()
    assert context.evidence.repository_root == root.resolve()
    assert set(context.__dataclass_fields__) == {
        "project_id",
        "commit_sha",
        "repository_root",
        "generated_assets_root",
        "evidence",
    }


@pytest.mark.parametrize("project_id", [0, -1, True])
def test_context_requires_a_positive_non_boolean_project_id(tmp_path: Path, project_id: int) -> None:
    root = write_repository(tmp_path)

    with pytest.raises(ValueError, match="project ID"):
        AgentContext(project_id, "a" * 40, root, tmp_path / "assets", EvidenceRetriever(root))


@pytest.mark.parametrize("commit_sha", ["", "unresolved", "g" * 40, "a" * 39, "a" * 41])
def test_context_requires_an_exact_resolved_commit_sha(tmp_path: Path, commit_sha: str) -> None:
    root = write_repository(tmp_path)

    with pytest.raises(ValueError, match="commit SHA"):
        AgentContext(4, commit_sha, root, tmp_path / "assets", EvidenceRetriever(root))


def test_context_has_no_implicit_identity_or_root_defaults() -> None:
    with pytest.raises(TypeError):
        AgentContext(project_id=4)


def test_context_rejects_generated_assets_in_or_outside_the_project_root(tmp_path: Path) -> None:
    root = write_repository(tmp_path)
    evidence = EvidenceRetriever(root)

    for unsafe in (root, root / "generated", tmp_path.parent / "outside-project"):
        with pytest.raises(ValueError, match="generated assets"):
            AgentContext(4, "a" * 40, root, unsafe, evidence)


def test_context_rejects_generated_assets_symlink_ancestors(tmp_path: Path) -> None:
    root = write_repository(tmp_path)
    outside = tmp_path.parent / f"outside-{tmp_path.name}"
    outside.mkdir()
    (tmp_path / "linked-assets").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="generated assets"):
        AgentContext(4, "a" * 40, root, tmp_path / "linked-assets" / "child", EvidenceRetriever(root))


def test_context_rejects_evidence_for_a_different_repository(tmp_path: Path) -> None:
    root = write_repository(tmp_path)
    other = tmp_path / "other"
    other.mkdir()

    with pytest.raises(ValueError, match="evidence"):
        AgentContext(4, "a" * 40, root, tmp_path / "assets", EvidenceRetriever(other))


def test_context_requires_a_repository_evidence_retriever(tmp_path: Path) -> None:
    root = write_repository(tmp_path)

    with pytest.raises(ValueError, match="evidence"):
        AgentContext(4, "a" * 40, root, tmp_path / "assets", None)
