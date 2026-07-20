"""Application-owned compiler policy for initial target and coverage builds."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from backend.agents.prompts.component_target import COMPONENT_TARGET_PROMPT
from backend.agents.prompts.system_target import SYSTEM_TARGET_PROMPT
from backend.fuzzing.campaigns.production_factory import ProposalPreparationPlanner


def _host_cmake_and_clang() -> tuple[str, str, str]:
    cmake = shutil.which("cmake")
    clang = shutil.which("clang")
    clangxx = shutil.which("clang++")
    if cmake is None or clang is None or clangxx is None:
        pytest.skip("real CMake policy regression requires host CMake and Clang")
    return cmake, clang, clangxx


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


@pytest.mark.parametrize("prompt", (SYSTEM_TARGET_PROMPT, COMPONENT_TARGET_PROMPT))
def test_target_specialists_receive_the_supported_explicit_cmake_form(prompt: str) -> None:
    assert "cmake -S" in prompt
    assert "-B" in prompt
    assert "project -D options" in prompt
    assert "&& cmake --build" in prompt


def test_system_target_uses_afl_compilers_and_baseline_sanitizers(tmp_path) -> None:
    target, _coverage = _generated_scripts(tmp_path, instance_type="system-level")

    assert "export CC=afl-clang-fast\n" in target
    assert "export CXX=afl-clang-fast++\n" in target
    assert (
        'export CFLAGS="-fsanitize=address,undefined '
        '-fno-omit-frame-pointer"\n'
    ) in target
    assert (
        'export CXXFLAGS="-fsanitize=address,undefined '
        '-fno-omit-frame-pointer"\n'
    ) in target
    assert 'export LDFLAGS="-fsanitize=address,undefined"\n' in target
    assert "fuzzer-no-link" not in target
    assert '${CFLAGS:-}' not in target
    assert '${CXXFLAGS:-}' not in target
    assert '${LDFLAGS:-}' not in target


def test_cmake_build_is_reconfigured_in_application_owned_target_directory(tmp_path) -> None:
    target, coverage = _generated_scripts(
        tmp_path,
        instance_type="system-level",
        build_command="cmake --build /opt/bigeye/build --target fuzz-target --parallel 2",
    )

    assert 'cmake -S "$BIGEYE_SOURCE_DIR" -B "$BIGEYE_BUILD_ROOT/build-system-target"' in target
    assert 'cmake --build "$BIGEYE_BUILD_ROOT/build-system-target" --target fuzz-target --parallel 2' in target
    assert 'cmake -S "$BIGEYE_SOURCE_DIR" -B "$BIGEYE_BUILD_ROOT/build-system-coverage"' in coverage
    assert 'cmake --build "$BIGEYE_BUILD_ROOT/build-system-coverage" --target fuzz-target --parallel 2' in coverage
    assert "cmake --build /opt/bigeye/build" not in target + coverage


def test_explicit_cmake_configuration_options_are_replayed_in_fresh_tree(tmp_path) -> None:
    target, _coverage = _generated_scripts(
        tmp_path,
        instance_type="system-level",
        build_command=(
            "cmake -S /src -B /opt/bigeye/build -DENABLE_ENCRYPTION=ON "
            "-DPROTOCOL:STRING=auxiliary && "
            "cmake --build /opt/bigeye/build --target fuzz-target"
        ),
    )

    configure = next(line for line in target.splitlines() if line.startswith("cmake -S "))
    assert "-DENABLE_ENCRYPTION=ON" in configure
    assert "-DPROTOCOL:STRING=auxiliary" in configure
    assert '"$BIGEYE_BUILD_ROOT/build-system-target"' in configure
    assert "/opt/bigeye/build" not in configure


def test_build_only_cmake_command_refuses_to_guess_existing_cache_options(tmp_path) -> None:
    legacy = tmp_path / "legacy-build"
    legacy.mkdir()
    (legacy / "CMakeCache.txt").write_text("ENABLE_ENCRYPTION:BOOL=ON\n", encoding="utf-8")
    target, _coverage = _generated_scripts(
        tmp_path,
        instance_type="system-level",
        build_command=f"cmake --build {legacy} --target fuzz-target",
    )

    assert "CMakeCache.txt" in target
    assert "explicit cmake -S ... -B ... && cmake --build" in target
    script = tmp_path / "build-only.sh"
    script.write_text(target, encoding="utf-8")
    result = subprocess.run(
        ["/bin/sh", str(script)],
        capture_output=True,
        text=True,
        env={**os.environ, "BIGEYE_BUILD_ROOT": str(tmp_path / "new-builds")},
    )
    assert result.returncode == 2
    assert "existing CMake configuration requires explicit" in result.stderr
    assert not (tmp_path / "new-builds/build-system-target").exists()


@pytest.mark.parametrize(
    "build_command",
    (
        "cmake --build build -- -fno-sanitize=all",
        "cmake --build build -- -fno-sanitize=address",
        "cmake --build build -- CFLAGS=-fsanitize=thread",
        "CC=gcc cmake --build build",
        "cmake --build build -- CXX=g++",
        "cmake --build build -- -DCMAKE_C_COMPILER=gcc",
        "cmake --build build -- -DCMAKE_C_FLAGS:STRING=-O0",
        "cmake -S /src -B build -DENABLE_ASAN=OFF && cmake --build build",
        "cmake -S /src -B build -DHOST_CC=/usr/bin/gcc && cmake --build build",
        "cmake -S /src -B build -DCMAKE_TOOLCHAIN_FILE=other.cmake && cmake --build build",
        "sh -c 'gcc harness.c -o /opt/bigeye/fuzz-target'",
    ),
)
def test_agent_build_command_cannot_override_compiler_or_sanitizer_policy(
    tmp_path, build_command: str,
) -> None:
    with pytest.raises(ValueError, match="compiler or sanitizer policy"):
        _generated_scripts(
            tmp_path,
            instance_type="system-level",
            build_command=build_command,
        )


@pytest.mark.parametrize(
    ("agent_compiler", "application_compiler"),
    (("cc", "afl-clang-fast"), ("gcc", "afl-clang-fast"), ("c++", "afl-clang-fast++"), ("g++", "afl-clang-fast++")),
)
def test_direct_host_compiler_is_replaced_by_application_compiler(
    tmp_path, agent_compiler: str, application_compiler: str,
) -> None:
    target, _coverage = _generated_scripts(
        tmp_path,
        instance_type="system-level",
        build_command=f"{agent_compiler} harness.c -o /opt/bigeye/fuzz-target",
    )

    assert target.splitlines()[-1].startswith(
        f"{application_compiler} -fsanitize=address,undefined -fno-omit-frame-pointer "
    )


def test_benign_source_path_with_cc_directory_is_not_a_compiler_bypass(tmp_path) -> None:
    target, _coverage = _generated_scripts(
        tmp_path,
        instance_type="system-level",
        build_command="clang src/cc/parser.c -o /opt/bigeye/fuzz-target",
    )

    assert "src/cc/parser.c" in target.splitlines()[-1]


def test_real_cmake_reconfiguration_compiles_and_links_with_system_policy(tmp_path) -> None:
    cmake, clang, clangxx = _host_cmake_and_clang()
    source = tmp_path / "source"
    source.mkdir()
    (source / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.16)\n"
        "project(bigeye_policy C)\n"
        "option(BIGEYE_FEATURE \"exercise explicit configuration replay\" OFF)\n"
        "add_executable(fuzz-target main.c)\n"
        "if(BIGEYE_FEATURE)\n"
        "  target_compile_definitions(fuzz-target PRIVATE BIGEYE_FEATURE)\n"
        "endif()\n",
        encoding="utf-8",
    )
    (source / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    legacy = tmp_path / "legacy-build"
    subprocess.run(
        [cmake, "-S", str(source), "-B", str(legacy)],
        check=True,
        capture_output=True,
        text=True,
    )

    wrappers = tmp_path / "wrappers"
    wrappers.mkdir()
    compiler_log = tmp_path / "compiler.log"
    for name, delegate in (
        ("afl-clang-fast", clang),
        ("afl-clang-fast++", clangxx),
    ):
        wrapper = wrappers / name
        wrapper.write_text(
            "#!/bin/sh\n"
            f"printf '%s\\n' \"$0 $*\" >> {compiler_log!s}\n"
            f"exec {delegate} \"$@\"\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o755)

    target, _coverage = _generated_scripts(
        tmp_path,
        instance_type="system-level",
        build_command=(
            f"cmake -S /src -B {legacy} -DBIGEYE_FEATURE=ON && "
            f"cmake --build {legacy} --target fuzz-target"
        ),
    )
    script = tmp_path / "target-build.sh"
    script.write_text(target, encoding="utf-8")
    build_root = tmp_path / "application-builds"
    environment = os.environ.copy()
    environment.update({
        "PATH": f"{wrappers}{os.pathsep}{environment['PATH']}",
        "BIGEYE_SOURCE_DIR": str(source),
        "BIGEYE_BUILD_ROOT": str(build_root),
    })

    subprocess.run(
        ["/bin/sh", str(script)],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )

    actual_build = build_root / "build-system-target"
    commands = json.loads((actual_build / "compile_commands.json").read_text())
    compile_command = commands[0]["command"]
    link_command = (actual_build / "CMakeFiles/fuzz-target.dir/link.txt").read_text()
    assert "afl-clang-fast" in compile_command
    assert "-fsanitize=address,undefined" in compile_command
    assert "-fno-omit-frame-pointer" in compile_command
    assert "-DBIGEYE_FEATURE" in compile_command
    assert "afl-clang-fast" in link_command
    assert "-fsanitize=address,undefined" in link_command
    assert compiler_log.read_text()
    assert str(legacy) not in compile_command + link_command


def test_real_cmake_component_and_coverage_builds_use_required_instrumentation(tmp_path) -> None:
    _cmake, clang, clangxx = _host_cmake_and_clang()
    source = tmp_path / "component-source"
    source.mkdir()
    (source / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.16)\n"
        "project(bigeye_component_policy C)\n"
        "add_executable(fuzz-target harness.c)\n",
        encoding="utf-8",
    )
    (source / "harness.c").write_text(
        "#include <stddef.h>\n"
        "#include <stdint.h>\n"
        "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
        "  return size > 0 ? data[0] == 0xff : 0;\n"
        "}\n"
        "int main(void) { return 0; }\n",
        encoding="utf-8",
    )
    wrappers = tmp_path / "component-wrappers"
    wrappers.mkdir()
    for name, delegate in (("clang-18", clang), ("clang++-18", clangxx)):
        wrapper = wrappers / name
        wrapper.write_text(
            "#!/bin/bash\n"
            "arguments=()\n"
            "for argument in \"$@\"; do\n"
            "  case \"$argument\" in\n"
            "    -fsanitize=fuzzer-no-link,address,undefined|-fsanitize=fuzzer,address,undefined)\n"
            "      arguments+=(\"-fsanitize=address,undefined\") ;;\n"
            "    *) arguments+=(\"$argument\") ;;\n"
            "  esac\n"
            "done\n"
            f"exec {delegate} \"${{arguments[@]}}\"\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o755)

    target, coverage = _generated_scripts(
        tmp_path,
        instance_type="component-level",
        build_command=(
            "cmake -S /src -B /opt/bigeye/build && "
            "cmake --build /opt/bigeye/build --target fuzz-target"
        ),
    )
    environment = {
        **os.environ,
        "PATH": f"{wrappers}{os.pathsep}{os.environ['PATH']}",
        "BIGEYE_SOURCE_DIR": str(source),
        "BIGEYE_BUILD_ROOT": str(tmp_path / "component-builds"),
    }
    for name, content in (("target", target), ("coverage", coverage)):
        script = tmp_path / f"component-{name}.sh"
        script.write_text(content, encoding="utf-8")
        subprocess.run(
            ["/bin/sh", str(script)],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )

    target_build = tmp_path / "component-builds/build-component-target"
    target_compile = json.loads((target_build / "compile_commands.json").read_text())[0]["command"]
    target_link = (target_build / "CMakeFiles/fuzz-target.dir/link.txt").read_text()
    assert "-fsanitize=fuzzer-no-link,address,undefined" in target_compile
    assert "-fsanitize=fuzzer,address,undefined" in target_link

    coverage_build = tmp_path / "component-builds/build-component-coverage"
    coverage_compile = json.loads((coverage_build / "compile_commands.json").read_text())[0]["command"]
    coverage_link = (coverage_build / "CMakeFiles/fuzz-target.dir/link.txt").read_text()
    assert "-fprofile-instr-generate" in coverage_compile
    assert "-fcoverage-mapping" in coverage_compile
    assert "-fsanitize=fuzzer-no-link,address,undefined" in coverage_compile
    assert "-fprofile-instr-generate" in coverage_link
    assert "-fsanitize=fuzzer,address,undefined" in coverage_link


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
        'export CFLAGS="-fsanitize=fuzzer-no-link,address,undefined '
        '-fno-omit-frame-pointer"\n'
    ) in target
    assert (
        'export CXXFLAGS="-fsanitize=fuzzer-no-link,address,undefined '
        '-fno-omit-frame-pointer"\n'
    ) in target
    assert 'export LDFLAGS="-fsanitize=fuzzer,address,undefined"\n' in target


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
