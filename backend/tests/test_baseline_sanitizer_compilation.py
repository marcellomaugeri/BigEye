"""Application-owned compiler policy for initial target and coverage builds."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
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

    target, = generated.glob("application/preparation/*/target-build.sh")
    coverage, = generated.glob("application/preparation/*/coverage-build.sh")
    return (
        target.read_text(),
        coverage.read_text(),
    )


def test_concurrent_proposals_publish_from_distinct_immutable_preparation_sources(
    tmp_path,
) -> None:
    from backend.fuzzing.assets.store import AssetStore
    from backend.models.asset import CampaignAsset

    workspace = tmp_path / "workspace"
    project_root = workspace / "projects" / "7"
    repository = project_root / "repository"
    repository.mkdir(parents=True)
    (repository / "seed").write_bytes(b"seed")
    generated = project_root / "generated"
    context = SimpleNamespace(
        repository_root=repository,
        generated_assets_root=generated,
    )

    class Assets:
        def __init__(self):
            self.next_id = 1
            self.assets = {}
            self.first_creates = 0
            self.first_create_gate = asyncio.Event()

        async def create(self, project_id, kind, name, content_hash, parent_id):
            asset = CampaignAsset(
                id=self.next_id, project_id=project_id, kind=kind, name=name,
                content_hash=content_hash, parent_id=parent_id,
                created_at=datetime.now(UTC), validated_at=None, error=None,
            )
            self.next_id += 1
            self.assets[asset.id] = asset
            self.first_creates += 1
            if self.first_creates <= 2:
                if self.first_creates == 2:
                    self.first_create_gate.set()
                await self.first_create_gate.wait()
            return asset

        async def get(self, asset_id):
            return self.assets.get(asset_id)

        async def mark_validated(self, asset_id):
            asset = replace(self.assets[asset_id], validated_at=datetime.now(UTC))
            self.assets[asset_id] = asset
            return asset

        async def record_error(self, asset_id, error):
            self.assets[asset_id] = replace(self.assets[asset_id], error=error)

    assets = Assets()
    planner = ProposalPreparationPlanner(
        discovery=SimpleNamespace(context=lambda _project_id: context),
        asset_store=AssetStore(workspace, assets),
    )

    def selected(command: str):
        return SimpleNamespace(
            instance_type="system-level",
            build_command=command,
            run_command="/opt/bigeye/fuzz-target",
            seeds=(SimpleNamespace(path="seed"),),
            generated_asset_intents=(),
        )

    async def plan_both():
        return await asyncio.gather(
            planner.plan(SimpleNamespace(id=7), selected(
                "cmake -S /src -B /opt/bigeye/build -DFEATURE=OFF && "
                "cmake --build /opt/bigeye/build --target fuzz-target"
            )),
            planner.plan(SimpleNamespace(id=7), selected(
                "cmake -S /src -B /opt/bigeye/build -DFEATURE=ON && "
                "cmake --build /opt/bigeye/build --target fuzz-target"
            )),
        )

    first, second = asyncio.run(plan_both())
    first_target = first.existing_assets["configuration"]
    second_target = second.existing_assets["configuration"]
    first_coverage = first.existing_assets["coverage_configuration"]
    second_coverage = second.existing_assets["coverage_configuration"]

    assert "-DFEATURE=OFF" in (
        workspace / f"projects/7/assets/{first_target.id}/target-build.sh"
    ).read_text()
    assert "-DFEATURE=ON" in (
        workspace / f"projects/7/assets/{second_target.id}/target-build.sh"
    ).read_text()
    assert "-DFEATURE=OFF" in (
        workspace / f"projects/7/assets/{first_coverage.id}/coverage-build.sh"
    ).read_text()
    assert "-DFEATURE=ON" in (
        workspace / f"projects/7/assets/{second_coverage.id}/coverage-build.sh"
    ).read_text()
    target_sources = sorted(generated.glob("application/preparation/*/target-build.sh"))
    coverage_sources = sorted(generated.glob("application/preparation/*/coverage-build.sh"))
    assert len(target_sources) == 2
    assert len(coverage_sources) == 2
    assert all(len(path.parent.name) == 64 for path in (*target_sources, *coverage_sources))


def test_same_content_preparation_source_is_idempotent_during_concurrent_creation(
    tmp_path, monkeypatch,
) -> None:
    import backend.fuzzing.campaigns.production_factory as production_factory
    from backend.agents.tools.generated_assets import GeneratedAssetError

    repository = tmp_path / "projects/7/repository"
    repository.mkdir(parents=True)
    context = SimpleNamespace(
        repository_root=repository,
        generated_assets_root=repository.parent / "generated",
    )
    content = "#!/bin/sh\nset -eu\nexit 0\n"
    barrier = threading.Barrier(2)
    real_read = production_factory.read_asset_file

    def read_together(selected_context, relative_path):
        try:
            return real_read(selected_context, relative_path)
        except GeneratedAssetError:
            barrier.wait(timeout=5)
            raise

    monkeypatch.setattr(production_factory, "read_asset_file", read_together)

    with ThreadPoolExecutor(max_workers=2) as workers:
        paths = tuple(workers.map(
            lambda _index: production_factory._application_preparation_file(
                context, "target-build.sh", content,
            ),
            range(2),
        ))

    assert paths[0] == paths[1]
    assert paths[0].read_text() == content
    assert len(tuple(context.generated_assets_root.glob(
        "application/preparation/*/target-build.sh"
    ))) == 1


@pytest.mark.parametrize("prompt", (SYSTEM_TARGET_PROMPT, COMPONENT_TARGET_PROMPT))
def test_target_specialists_receive_the_supported_explicit_cmake_form(prompt: str) -> None:
    assert "cmake -S" in prompt
    assert "-B" in prompt
    assert "project -D options" in prompt
    assert "&& cmake --build" in prompt
    assert "direct Clang or GCC" in prompt
    assert "Do not use make, Ninja, a script" in prompt


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
    assert (
        'ln -s "build-system-target" "$BIGEYE_BUILD_ROOT/build"'
        in target
    )
    assert (
        'ln -s "build-system-coverage" "$BIGEYE_BUILD_ROOT/build"'
        in coverage
    )
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


@pytest.mark.parametrize(
    "configure_override",
    (
        "-DCMAKE_C_COMPILE_OBJECT=/bin/echo",
        "-DCMAKE_C_LINK_EXECUTABLE=/bin/echo",
        "-DCMAKE_PROJECT_INCLUDE=/src/override.cmake",
        "-C /src/override.cmake",
        "--preset hostile",
    ),
)
def test_cmake_configuration_rejects_rule_include_and_preset_overrides(
    tmp_path, configure_override: str,
) -> None:
    with pytest.raises(ValueError, match="CMake.*option"):
        _generated_scripts(
            tmp_path,
            instance_type="system-level",
            build_command=(
                f"cmake -S /src -B /opt/bigeye/build {configure_override} && "
                "cmake --build /opt/bigeye/build --target fuzz-target"
            ),
        )


def test_cmake_project_descriptions_may_name_compilers_without_overriding_them(tmp_path) -> None:
    target, _coverage = _generated_scripts(
        tmp_path,
        instance_type="system-level",
        build_command=(
            "cmake -S /src -B /opt/bigeye/build "
            "-DTOOL_DESCRIPTION:STRING=clang -DSOURCE_HINT=src/tools/gcc && "
            "cmake --build /opt/bigeye/build --target fuzz-target"
        ),
    )

    assert "-DTOOL_DESCRIPTION:STRING=clang" in target
    assert "-DSOURCE_HINT=src/tools/gcc" in target


@pytest.mark.parametrize(
    "project_option",
    (
        "-DENABLE_ENCRYPTION:BOOL=ON",
        "-DWORKER_COUNT=8",
        "-DPROTOCOL:STRING=auxiliary",
        "-DSCHEMA:FILEPATH=/src/config/schema.json",
        "-DSOURCE_HINT:PATH=src/tools/gcc",
        "'-DTOOL_DESCRIPTION:STRING=Clang based parser'",
    ),
)
def test_cmake_project_options_preserve_safe_scalar_values(
    tmp_path, project_option: str,
) -> None:
    target, _coverage = _generated_scripts(
        tmp_path,
        instance_type="system-level",
        build_command=(
            f"cmake -S /src -B /opt/bigeye/build {project_option} && "
            "cmake --build /opt/bigeye/build --target fuzz-target"
        ),
    )

    assert project_option in target


@pytest.mark.parametrize(
    "project_option",
    (
        "'-DEXTRA_OPTIONS:STRING=$<JOIN:-fno;-sanitize=all,>'",
        "'-DEXTRA_OPTIONS:STRING=$ENV{BIGEYE_FLAGS}'",
        "'-DEXTRA_OPTIONS:STRING=-O2'",
        "'-DEXTRA_OPTIONS:STRING=@/src/flags.rsp'",
        "'-DEXTRA_OPTIONS:STRING=debug;release'",
        "'-DEXTRA_OPTIONS:STRING=SHELL:-O2'",
        "'-DEXTRA_OPTIONS:STRING=LINKER:-z,defs'",
    ),
)
def test_cmake_project_options_reject_non_scalar_transformations(
    tmp_path, project_option: str,
) -> None:
    with pytest.raises(ValueError, match="safe scalar"):
        _generated_scripts(
            tmp_path,
            instance_type="system-level",
            build_command=(
                f"cmake -S /src -B /opt/bigeye/build {project_option} && "
                "cmake --build /opt/bigeye/build --target fuzz-target"
            ),
        )


@pytest.mark.parametrize(
    "project_option",
    (
        "-DEXTRA_C_FLAGS:STRING=-fno-sanitize=all",
        "-DEXTRA_OPTIONS:STRING=-mllvm;-asan-stack=0",
        "-DLINK_OPTIONS:STRING=-Xlinker;-plugin;/src/replace-sanitizer.so",
        "-DPASS_OPTIONS:STRING=-fpass-plugin=/src/replace-sanitizer.so",
        "-DEXTRA_LINK_OPTIONS:STRING=LINKER:--wrap=__asan_report_load1",
        "-DEXTRA_LINK_OPTIONS:STRING=SHELL:-Wl,--wrap=__ubsan_handle_type_mismatch_v1",
    ),
)
def test_cmake_project_option_values_cannot_weaken_instrumentation(
    tmp_path, project_option: str,
) -> None:
    with pytest.raises(ValueError, match="compiler or sanitizer policy"):
        _generated_scripts(
            tmp_path,
            instance_type="system-level",
            build_command=(
                f"cmake -S /src -B /opt/bigeye/build {project_option} && "
                "cmake --build /opt/bigeye/build --target fuzz-target"
            ),
        )


def test_real_cmake_late_target_flags_cannot_disable_baseline_sanitizers(tmp_path) -> None:
    _cmake, clang, clangxx = _host_cmake_and_clang()
    source = tmp_path / "late-flags-source"
    source.mkdir()
    (source / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.16)\n"
        "project(bigeye_late_flags C)\n"
        "set(EXTRA_C_FLAGS \"\" CACHE STRING \"project target flags\")\n"
        "separate_arguments(EXTRA_C_FLAGS)\n"
        "add_executable(fuzz-target main.c)\n"
        "target_compile_options(fuzz-target PRIVATE ${EXTRA_C_FLAGS})\n"
        "target_link_options(fuzz-target PRIVATE ${EXTRA_C_FLAGS})\n",
        encoding="utf-8",
    )
    (source / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")

    wrappers = tmp_path / "late-flags-wrappers"
    wrappers.mkdir()
    for name, delegate in (("afl-clang-fast", clang), ("afl-clang-fast++", clangxx)):
        wrapper = wrappers / name
        wrapper.write_text(
            "#!/bin/sh\n"
            f"exec {delegate} \"$@\"\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o755)

    target, _coverage = _generated_scripts(
        tmp_path,
        instance_type="system-level",
        build_command=(
            "cmake -S /src -B /opt/bigeye/build -DBIGEYE_MODE:STRING=debug && "
            "cmake --build /opt/bigeye/build --target fuzz-target"
        ),
    )
    script = tmp_path / "late-flags-target-build.sh"
    script.write_text(target, encoding="utf-8")
    build_root = tmp_path / "late-flags-builds"
    subprocess.run(
        ["/bin/sh", str(script)],
        check=True,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PATH": f"{wrappers}{os.pathsep}{os.environ['PATH']}",
            "BIGEYE_SOURCE_DIR": str(source),
            "BIGEYE_BUILD_ROOT": str(build_root),
        },
    )

    actual_build = build_root / "build-system-target"
    compile_command = json.loads((actual_build / "compile_commands.json").read_text())[0][
        "command"
    ]
    link_command = (actual_build / "CMakeFiles/fuzz-target.dir/link.txt").read_text()
    assert "-fsanitize=address,undefined" in compile_command
    assert "-fsanitize=address,undefined" in link_command

    with pytest.raises(ValueError, match="compiler or sanitizer policy"):
        _generated_scripts(
            tmp_path / "hostile-option",
            instance_type="system-level",
            build_command=(
                "cmake -S /src -B /opt/bigeye/build "
                "-DEXTRA_C_FLAGS:STRING=-fno-sanitize=all && "
                "cmake --build /opt/bigeye/build --target fuzz-target"
            ),
        )


@pytest.mark.parametrize(
    "build_directory",
    ("build", "~/build", "${PWD}/build", "/opt/bigeye/../build", "/tmp/build"),
)
def test_cmake_requires_the_canonical_application_build_directory(
    tmp_path, build_directory: str,
) -> None:
    with pytest.raises(ValueError, match="canonical.*build directory"):
        _generated_scripts(
            tmp_path,
            instance_type="system-level",
            build_command=f"cmake --build {build_directory} --target fuzz-target",
        )


@pytest.mark.parametrize("source_directory", ("/src/${PWD}", "/src/~/project", "/src/../project"))
def test_cmake_source_directory_rejects_expansion_and_traversal(
    tmp_path, source_directory: str,
) -> None:
    with pytest.raises(ValueError, match="inside /src"):
        _generated_scripts(
            tmp_path,
            instance_type="system-level",
            build_command=(
                f"cmake -S {source_directory} -B /opt/bigeye/build && "
                "cmake --build /opt/bigeye/build --target fuzz-target"
            ),
        )


@pytest.mark.parametrize(
    "build_command",
    (
        (
            "cmake -S '/src/sub\"; : injected; # ' -B /opt/bigeye/build && "
            "cmake --build /opt/bigeye/build --target fuzz-target"
        ),
        (
            "cmake '-S/src/sub\"; : injected; # ' -B /opt/bigeye/build && "
            "cmake --build /opt/bigeye/build --target fuzz-target"
        ),
    ),
)
def test_cmake_source_directory_rejects_double_quote_shell_breakout(
    tmp_path, build_command: str,
) -> None:
    with pytest.raises(ValueError, match="inside /src"):
        _generated_scripts(
            tmp_path,
            instance_type="system-level",
            build_command=build_command,
        )


def test_cmake_source_directory_preserves_safe_spaces_and_apostrophes(tmp_path) -> None:
    target, _coverage = _generated_scripts(
        tmp_path,
        instance_type="system-level",
        build_command=(
            'cmake -S "/src/sub dir/o\'clock" -B /opt/bigeye/build && '
            "cmake --build /opt/bigeye/build --target fuzz-target"
        ),
    )

    assert 'cmake -S "$BIGEYE_SOURCE_DIR/sub dir/o\'clock"' in target


def test_build_only_cmake_command_refuses_to_guess_existing_cache_options(tmp_path) -> None:
    target, _coverage = _generated_scripts(
        tmp_path,
        instance_type="system-level",
        build_command="cmake --build /opt/bigeye/build --target fuzz-target",
    )

    assert "/opt/bigeye/build/CMakeCache.txt" in target
    assert "explicit cmake -S ... -B ... && cmake --build" in target


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
        "clang @agent-flags.rsp harness.c -o /opt/bigeye/fuzz-target",
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


def test_benign_source_path_with_gcc_directory_is_not_a_compiler_bypass(tmp_path) -> None:
    target, _coverage = _generated_scripts(
        tmp_path,
        instance_type="system-level",
        build_command="clang src/tools/gcc/parser.c -o /opt/bigeye/fuzz-target",
    )

    assert "src/tools/gcc/parser.c" in target.splitlines()[-1]


@pytest.mark.parametrize(
    "build_command",
    (
        "clang -mllvm -asan-stack=0 harness.c -o /opt/bigeye/fuzz-target",
        "clang -Xclang -load -Xclang /src/replace-sanitizer.so harness.c -o /opt/bigeye/fuzz-target",
        "clang -fpass-plugin=/src/replace-sanitizer.so harness.c -o /opt/bigeye/fuzz-target",
        "clang -fplugin=/src/replace-sanitizer.so harness.c -o /opt/bigeye/fuzz-target",
        "clang -Xlinker -plugin -Xlinker /src/replace-sanitizer.so harness.c -o /opt/bigeye/fuzz-target",
        "clang -Wl,-plugin,/src/replace-sanitizer.so harness.c -o /opt/bigeye/fuzz-target",
    ),
)
def test_direct_compiler_rejects_backend_plugin_and_pass_through_policy(
    tmp_path, build_command: str,
) -> None:
    with pytest.raises(ValueError, match="compiler or sanitizer policy"):
        _generated_scripts(
            tmp_path,
            instance_type="system-level",
            build_command=build_command,
        )


@pytest.mark.parametrize(
    "build_command",
    (
        "clang --for-linker=-plugin harness.c -o /opt/bigeye/fuzz-target",
        "clang --for-linker -plugin harness.c -o /opt/bigeye/fuzz-target",
        "clang --ld-path=/src/tooling/ld harness.c -o /opt/bigeye/fuzz-target",
        "clang --ld-path /src/tooling/ld harness.c -o /opt/bigeye/fuzz-target",
        "clang --config=/src/tooling/hostile.cfg harness.c -o /opt/bigeye/fuzz-target",
        "clang --config /src/tooling/hostile.cfg harness.c -o /opt/bigeye/fuzz-target",
        "clang --config-system-dir=/src/tooling harness.c -o /opt/bigeye/fuzz-target",
        "clang --config-user-dir /src/tooling harness.c -o /opt/bigeye/fuzz-target",
        "clang --no-default-config harness.c -o /opt/bigeye/fuzz-target",
        "clang --driver-mode=g++ harness.c -o /opt/bigeye/fuzz-target",
        "clang --gcc-toolchain=/src/tooling harness.c -o /opt/bigeye/fuzz-target",
        "clang -gcc-toolchain /src/tooling harness.c -o /opt/bigeye/fuzz-target",
        "clang --gcc-install-dir=/src/tooling harness.c -o /opt/bigeye/fuzz-target",
        "clang --resource-dir=/src/tooling harness.c -o /opt/bigeye/fuzz-target",
        "clang -resource-dir /src/tooling harness.c -o /opt/bigeye/fuzz-target",
        "clang -ccc-install-dir /src/tooling harness.c -o /opt/bigeye/fuzz-target",
        "clang -cc1 harness.c -o /opt/bigeye/fuzz-target",
        "clang -cc1as harness.c -o /opt/bigeye/fuzz-target",
        "clang -Xarch_host=-fno-sanitize=all harness.c -o /opt/bigeye/fuzz-target",
        "clang -Xoffload-linker=x86_64=-plugin harness.c -o /opt/bigeye/fuzz-target",
        "clang --offload-linker=-plugin harness.c -o /opt/bigeye/fuzz-target",
    ),
)
def test_direct_compiler_rejects_driver_configuration_front_doors(
    tmp_path, build_command: str,
) -> None:
    with pytest.raises(ValueError, match="compiler or sanitizer policy"):
        _generated_scripts(
            tmp_path,
            instance_type="system-level",
            build_command=build_command,
        )


def test_direct_compiler_allows_benign_paths_named_after_backend_options(tmp_path) -> None:
    target, _coverage = _generated_scripts(
        tmp_path,
        instance_type="system-level",
        build_command=(
            "clang src/mllvm/parser.c src/plugins/fpass-plugin/registry.c "
            "src/config-system-dir/reader.c -DHELP_TEXT=--config "
            "-o /opt/bigeye/ld-path-target"
        ),
    )

    command = target.splitlines()[-1]
    assert "src/mllvm/parser.c" in command
    assert "src/plugins/fpass-plugin/registry.c" in command
    assert "src/config-system-dir/reader.c" in command
    assert "-DHELP_TEXT=--config" in command
    assert "/opt/bigeye/ld-path-target" in command


@pytest.mark.parametrize(
    "build_command",
    (
        "make -C build",
        "/src/build.sh",
        "ninja -C build",
        "sh -c 'gcc harness.c'",
        "/usr/bin/gcc-13 harness.c -o /opt/bigeye/fuzz-target",
    ),
)
def test_unattested_build_frontends_are_rejected(tmp_path, build_command: str) -> None:
    with pytest.raises(ValueError, match="supported build frontend"):
        _generated_scripts(
            tmp_path,
            instance_type="system-level",
            build_command=build_command,
        )


@pytest.mark.parametrize(
    ("agent_compiler", "application_compiler"),
    (("gcc-13", "afl-clang-fast"), ("g++-13", "afl-clang-fast++"), ("clang-19", "afl-clang-fast"), ("clang++-19", "afl-clang-fast++")),
)
def test_versioned_direct_compiler_is_rewritten(
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
            "cmake -S /src -B /opt/bigeye/build -DBIGEYE_FEATURE=ON && "
            "cmake --build /opt/bigeye/build --target fuzz-target"
        ),
    )
    script = tmp_path / "target-build.sh"
    script.write_text(target, encoding="utf-8")
    relative_build_root = Path("application-builds")
    build_root = tmp_path / relative_build_root
    environment = os.environ.copy()
    environment.update({
        "PATH": f"{wrappers}{os.pathsep}{environment['PATH']}",
        "BIGEYE_SOURCE_DIR": str(source),
        "BIGEYE_BUILD_ROOT": str(relative_build_root),
    })

    subprocess.run(
        ["/bin/sh", str(script)],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
        cwd=tmp_path,
    )

    actual_build = build_root / "build-system-target"
    canonical_build = build_root / "build"
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
    assert canonical_build.is_symlink()
    assert canonical_build.resolve() == actual_build.resolve()
    subprocess.run(
        [str(canonical_build / "fuzz-target")],
        check=True,
        capture_output=True,
        text=True,
    )


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

    canonical_build = tmp_path / "component-builds/build"
    coverage_build = tmp_path / "component-builds/build-component-coverage"
    assert canonical_build.is_symlink()
    assert canonical_build.resolve() == coverage_build.resolve()
    subprocess.run(
        [str(canonical_build / "fuzz-target")],
        check=True,
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )

    target_build = tmp_path / "component-builds/build-component-target"
    target_compile = json.loads((target_build / "compile_commands.json").read_text())[0]["command"]
    target_link = (target_build / "CMakeFiles/fuzz-target.dir/link.txt").read_text()
    assert "-fsanitize=fuzzer-no-link,address,undefined" in target_compile
    assert "-fsanitize=fuzzer,address,undefined" in target_link

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
