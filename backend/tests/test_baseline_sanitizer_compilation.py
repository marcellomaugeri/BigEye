"""Application-owned compiler policy for initial target and coverage builds."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from backend.fuzzing.campaigns.production_factory import ProposalPreparationPlanner


def _generated_scripts(
    tmp_path,
    *,
    instance_type: str,
    sanitizer_plan: str = "address and undefined",
    build_command: str = "cmake --build /opt/bigeye/build --target fuzz-target",
) -> tuple[str, str]:
    project_root = tmp_path / "projects" / "7"
    repository = project_root / "repository"
    repository.mkdir(parents=True)
    (repository / "seed").write_bytes(b"seed")
    generated = project_root / "generated"
    context = SimpleNamespace(
        repository_root=repository,
        generated_assets_root=generated,
    )
    proposal = SimpleNamespace(
        instance_type=instance_type,
        build_command=build_command,
        run_command="/opt/bigeye/fuzz-target {input}",
        seeds=(SimpleNamespace(path="seed"),),
        sanitizer_plan=sanitizer_plan,
        generated_asset_intents=(),
    )
    planner = ProposalPreparationPlanner(
        discovery=SimpleNamespace(context=lambda _project_id: context),
        asset_store=AsyncMock(),
    )

    asyncio.run(planner.plan(SimpleNamespace(id=7), proposal))

    return (
        (generated / "application" / "target-build.sh").read_text(),
        (generated / "application" / "coverage-build.sh").read_text(),
    )


def test_system_target_uses_afl_compilers_and_baseline_sanitizers(tmp_path) -> None:
    target, _coverage = _generated_scripts(tmp_path, instance_type="system-level")

    assert "export CC=afl-clang-fast\n" in target
    assert "export CXX=afl-clang-fast++\n" in target
    assert (
        'export CFLAGS="${CFLAGS:-} -fsanitize=address,undefined '
        '-fno-omit-frame-pointer"\n'
    ) in target
    assert (
        'export CXXFLAGS="${CXXFLAGS:-} -fsanitize=address,undefined '
        '-fno-omit-frame-pointer"\n'
    ) in target
    assert 'export LDFLAGS="${LDFLAGS:-} -fsanitize=address,undefined"\n' in target
    assert "fuzzer-no-link" not in target


def test_system_direct_clang_link_is_rewritten_with_explicit_instrumentation(tmp_path) -> None:
    target, _coverage = _generated_scripts(
        tmp_path,
        instance_type="system-level",
        build_command="clang++ harness.cc -o /opt/bigeye/fuzz-target",
    )

    assert target.splitlines()[-1] == (
        "afl-clang-fast++ -fsanitize=address,undefined "
        "-fno-omit-frame-pointer harness.cc -o /opt/bigeye/fuzz-target"
    )


def test_component_target_compiles_with_clang_and_links_libfuzzer(tmp_path) -> None:
    target, _coverage = _generated_scripts(tmp_path, instance_type="component-level")

    assert "export CC=clang-18\n" in target
    assert "export CXX=clang++-18\n" in target
    assert (
        'export CFLAGS="${CFLAGS:-} -fsanitize=fuzzer-no-link,address,undefined '
        '-fno-omit-frame-pointer"\n'
    ) in target
    assert (
        'export CXXFLAGS="${CXXFLAGS:-} -fsanitize=fuzzer-no-link,address,undefined '
        '-fno-omit-frame-pointer"\n'
    ) in target
    assert 'export LDFLAGS="${LDFLAGS:-} -fsanitize=fuzzer,address,undefined"\n' in target


def test_component_direct_clang_link_keeps_libfuzzer_link_instrumentation(tmp_path) -> None:
    target, _coverage = _generated_scripts(
        tmp_path,
        instance_type="component-level",
        build_command="clang++ harness.cc -o /opt/bigeye/fuzz-target",
    )

    assert target.splitlines()[-1] == (
        "clang++-18 -fsanitize=fuzzer,address,undefined "
        "-fno-omit-frame-pointer harness.cc -o /opt/bigeye/fuzz-target"
    )


def test_component_direct_compile_uses_fuzzer_no_link_instrumentation(tmp_path) -> None:
    target, _coverage = _generated_scripts(
        tmp_path,
        instance_type="component-level",
        build_command="clang++ -c harness.cc -o harness.o",
    )

    assert target.splitlines()[-1] == (
        "clang++-18 -fsanitize=fuzzer-no-link,address,undefined "
        "-fno-omit-frame-pointer -c harness.cc -o harness.o"
    )


@pytest.mark.parametrize("instance_type", ("system-level", "component-level"))
def test_clean_coverage_uses_clang_coverage_and_replay_sanitizers(
    tmp_path, instance_type: str,
) -> None:
    _target, coverage = _generated_scripts(tmp_path, instance_type=instance_type)

    assert "export CC=clang-18\n" in coverage
    assert "export CXX=clang++-18\n" in coverage
    assert "afl-clang" not in coverage
    assert "-fprofile-instr-generate -fcoverage-mapping" in coverage
    assert "address,undefined" in coverage
    assert "-fno-omit-frame-pointer" in coverage
    assert "-fprofile-instr-generate" in next(
        line for line in coverage.splitlines() if line.startswith("export LDFLAGS=")
    )
    if instance_type == "component-level":
        assert "-fsanitize=fuzzer-no-link,address,undefined" in coverage
        assert "-fsanitize=fuzzer,address,undefined" in coverage
    else:
        assert "fuzzer-no-link" not in coverage


def test_model_sanitizer_plan_is_data_not_generated_shell(tmp_path) -> None:
    model_text = "address; touch /tmp/model-command; $(uname)"

    target, coverage = _generated_scripts(
        tmp_path,
        instance_type="system-level",
        sanitizer_plan=model_text,
    )

    assert model_text not in target
    assert model_text not in coverage
    assert "touch /tmp/model-command" not in target + coverage
