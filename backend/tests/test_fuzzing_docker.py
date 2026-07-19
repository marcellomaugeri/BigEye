"""Deterministic contracts for BigEye's Docker SDK boundary."""

from __future__ import annotations

import asyncio
import gc
import shutil
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest


def run(awaitable):
    return asyncio.run(awaitable)


class TestImageBuilder:
    def test_build_uses_engine_api_with_exact_context_platform_tag_and_forwards_logs(self, tmp_path: Path) -> None:
        from backend.fuzzing.docker.client import DOCKER_REQUEST_TIMEOUT_SECONDS
        from backend.fuzzing.docker.image_builder import ImageBuilder

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM ubuntu:24.04\n")
        calls = []
        class Api:
            def build(self, **kwargs):
                calls.append(kwargs)
                return iter(({"stream": "Step 1/1 : FROM ubuntu:24.04\n"}, {"aux": {"ID": "sha256:built"}}))
            def inspect_image(self, tag):
                assert tag == "bigeye-llvm:test"
                return {"Id": "sha256:canonical"}
        api = Api()
        logs: list[str] = []

        image_id = ImageBuilder(SimpleNamespace(api=api)).build(dockerfile, "bigeye-llvm:test", logs.append)

        assert image_id == "sha256:canonical"
        assert calls == [{"path": str(tmp_path), "dockerfile": "Dockerfile", "tag": "bigeye-llvm:test", "platform": "linux/amd64", "decode": True, "rm": True, "timeout": DOCKER_REQUEST_TIMEOUT_SECONDS}]
        assert logs == ["Step 1/1 : FROM ubuntu:24.04\n"]

    def test_build_forwards_daemon_error_text_and_does_not_report_success(self, tmp_path: Path) -> None:
        from backend.fuzzing.docker.image_builder import ImageBuildFailed, ImageBuilder

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM ubuntu:24.04\n")
        calls = []

        class Api:
            def build(self, **kwargs):
                calls.append(kwargs)
                return iter(({"stream": "building\n"}, {"errorDetail": {"message": "daemon build failed"}}))

        logs: list[str] = []
        with pytest.raises(ImageBuildFailed, match="daemon build failed"):
            ImageBuilder(SimpleNamespace(api=Api())).build(dockerfile, "bigeye-llvm:test", logs.append)
        assert logs == ["building\n", "daemon build failed\n"]
        assert calls[0]["platform"] == "linux/amd64"

    def test_build_supports_classic_success_stream_and_forwards_status_progress(self, tmp_path: Path) -> None:
        from backend.fuzzing.docker.image_builder import ImageBuilder

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM ubuntu:24.04\n")
        class Api:
            def build(self, **kwargs):
                return iter(({"id": "ubuntu", "status": "Pulling", "progress": "[====>    ]"}, {"stream": "Successfully built legacy\n"}))
            def inspect_image(self, tag): return {"Id": "sha256:classic"}
        logs: list[str] = []

        assert ImageBuilder(SimpleNamespace(api=Api())).build(dockerfile, "bigeye-llvm:classic", logs.append) == "sha256:classic"
        assert logs == ["ubuntu: Pulling [====>    ]\n", "Successfully built legacy\n"]

    def test_build_without_aux_raises_when_tag_is_not_inspectable(self, tmp_path: Path) -> None:
        from backend.fuzzing.docker.image_builder import ImageBuildFailed, ImageBuilder

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM ubuntu:24.04\n")
        class Api:
            def build(self, **kwargs): return iter(({"stream": "Successfully built legacy\n"},))
            def inspect_image(self, tag): raise RuntimeError("tag absent")
        with pytest.raises(ImageBuildFailed, match="could not be inspected"):
            ImageBuilder(SimpleNamespace(api=Api())).build(dockerfile, "bigeye-llvm:missing", lambda text: None)


class TestImageInspector:
    def test_inspector_returns_only_required_metadata_and_rejects_non_amd64(self) -> None:
        from backend.fuzzing.docker.image_inspector import ImageInspector, UnsupportedImagePlatform

        api = SimpleNamespace(inspect_image=lambda tag: {"Id": "sha256:one", "Os": "linux", "Architecture": "amd64", "Config": {"Env": ["secret"]}})
        assert ImageInspector(SimpleNamespace(api=api)).inspect("bigeye-llvm:test").image_id == "sha256:one"
        api.inspect_image = lambda tag: {"Id": "sha256:two", "Os": "linux", "Architecture": "arm64"}
        with pytest.raises(UnsupportedImagePlatform, match="linux/amd64"):
            ImageInspector(SimpleNamespace(api=api)).inspect("bigeye-llvm:test")

    def test_missing_image_is_distinct_from_daemon_failure(self) -> None:
        from backend.fuzzing.docker.image_inspector import ImageInspector, MissingImage

        class ImageNotFound(Exception):
            pass

        errors = SimpleNamespace(ImageNotFound=ImageNotFound)
        client = SimpleNamespace(api=SimpleNamespace(inspect_image=lambda tag: (_ for _ in ()).throw(ImageNotFound("missing"))), errors=errors)
        with pytest.raises(MissingImage, match="bigeye-llvm:missing"):
            ImageInspector(client).inspect("bigeye-llvm:missing")


class TestDockerClient:
    def test_facade_pings_and_translates_only_expected_connectivity_error(self) -> None:
        from backend.fuzzing.docker.client import DockerUnavailable, DockerClient

        class DockerException(Exception):
            pass
        client = SimpleNamespace(ping=lambda: (_ for _ in ()).throw(DockerException("cannot connect")))
        docker_module = SimpleNamespace(from_env=lambda **kwargs: client, errors=SimpleNamespace(DockerException=DockerException))
        with pytest.raises(DockerUnavailable, match="Docker is unavailable"):
            DockerClient(docker_module).connect()

        programming_error = ValueError("bug")
        client.ping = lambda: (_ for _ in ()).throw(programming_error)
        with pytest.raises(ValueError, match="bug"):
            DockerClient(docker_module).connect()


class TestContainerRunner:
    def test_runner_forces_bounded_non_privileged_container_and_removes_it(self) -> None:
        from backend.fuzzing.docker.container_runner import ContainerRunner

        created = []
        logs: list[str] = []

        class Container:
            id = "container-1"
            def start(self): pass
            def wait(self, timeout): return {"StatusCode": 0}
            def logs(self, **kwargs):
                assert kwargs == {"stream": True, "follow": False}
                return iter((b"clang works\n",))
            def remove(self, force=False): assert force is True

        class Containers:
            def create(self, image, command, **kwargs):
                created.append((image, command, kwargs))
                return Container()

        result = run(ContainerRunner(SimpleNamespace(containers=Containers())).run("bigeye-llvm:test", ["clang-18", "--version"], 12, logs.append))

        assert result.exit_code == 0 and result.output == "clang works\n"
        assert logs == ["clang works\n"]
        image, command, options = created[0]
        assert image == "bigeye-llvm:test" and command == ["clang-18", "--version"]
        assert options == {
            "platform": "linux/amd64", "network_disabled": True, "read_only": True,
            "cap_drop": ["ALL"], "security_opt": ["no-new-privileges"], "pids_limit": 64,
            "mem_limit": "512m", "nano_cpus": 1_000_000_000,
            "tmpfs": {"/tmp": "rw,nosuid,nodev,exec,size=64m,mode=1777"}, "detach": True,
        }

    def test_runner_cleans_exact_container_when_wait_times_out(self) -> None:
        from backend.fuzzing.docker.container_runner import ContainerRunner, ContainerTimedOut

        cleaned = []
        class Container:
            id = "container-timeout"
            def start(self): pass
            def wait(self, timeout): raise TimeoutError("timed out")
            def stop(self, timeout=0): cleaned.append(("stop", timeout))
            def kill(self): cleaned.append(("kill",))
            def remove(self, force=False): cleaned.append(("remove", force))
        class Containers:
            def create(self, *args, **kwargs): return Container()

        with pytest.raises(ContainerTimedOut):
            run(ContainerRunner(SimpleNamespace(containers=Containers())).run("image", ["true"], 1, lambda text: None))
        assert cleaned == [("stop", 0), ("kill",), ("remove", True)]

    def test_runner_bounds_output_and_cleans_the_exact_container(self) -> None:
        from backend.fuzzing.docker.container_runner import ContainerOutputExceeded, ContainerRunner, MAX_OUTPUT_BYTES

        cleaned, logs = [], []
        class Container:
            id = "container-output"
            def start(self): pass
            def wait(self, timeout): return {"StatusCode": 0}
            def logs(self, **kwargs): return iter((b"x" * (MAX_OUTPUT_BYTES + 1),))
            def stop(self, timeout=0): cleaned.append(("stop", timeout))
            def kill(self): cleaned.append(("kill",))
            def remove(self, force=False): cleaned.append(("remove", force))
        class Containers:
            def create(self, *args, **kwargs): return Container()

        with pytest.raises(ContainerOutputExceeded, match="output exceeded"):
            run(ContainerRunner(SimpleNamespace(containers=Containers())).run("image", ["true"], 1, logs.append))
        assert logs == [f"container output exceeded {MAX_OUTPUT_BYTES} bytes\n"]
        assert cleaned == [("stop", 0), ("kill",), ("remove", True)]

    def test_cancellation_before_create_publication_cleans_later_container(self) -> None:
        from backend.fuzzing.docker.container_runner import ContainerRunner

        entered, release, removed, cleaned = threading.Event(), threading.Event(), threading.Event(), []
        class Container:
            id = "container-race"
            def start(self): pass
            def wait(self, timeout): return {"StatusCode": 0}
            def logs(self, **kwargs): return iter(())
            def stop(self, timeout=0): cleaned.append(("stop", timeout))
            def kill(self): cleaned.append(("kill",))
            def remove(self, force=False): cleaned.append(("remove", force)); removed.set()
        class Containers:
            def create(self, *args, **kwargs):
                entered.set()
                assert release.wait(1)
                return Container()

        async def scenario():
            operation = asyncio.create_task(ContainerRunner(SimpleNamespace(containers=Containers())).run("image", ["true"], 10, lambda text: None))
            assert await asyncio.to_thread(entered.wait, 1)
            operation.cancel()
            with pytest.raises(asyncio.CancelledError):
                await operation
            release.set()
            assert await asyncio.to_thread(removed.wait, 1)
            assert cleaned == [("stop", 0), ("kill",), ("remove", True)]
        run(scenario())

    def test_late_cancelled_worker_exception_is_observed(self) -> None:
        from backend.fuzzing.docker.container_runner import ContainerRunner

        entered, release, removed = threading.Event(), threading.Event(), threading.Event()
        class Container:
            id = "container-observed"
            def start(self): pass
            def wait(self, timeout): return {"StatusCode": 0}
            def logs(self, **kwargs): return iter(())
            def stop(self, timeout=0): pass
            def kill(self): pass
            def remove(self, force=False): removed.set()
        class Containers:
            def create(self, *args, **kwargs):
                entered.set()
                assert release.wait(1)
                return Container()

        async def scenario():
            loop = asyncio.get_running_loop()
            contexts = []
            previous = loop.get_exception_handler()
            loop.set_exception_handler(lambda loop, context: contexts.append(context))
            try:
                operation = asyncio.create_task(ContainerRunner(SimpleNamespace(containers=Containers())).run("image", ["true"], 10, lambda text: None))
                assert await asyncio.to_thread(entered.wait, 1)
                operation.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await operation
                release.set()
                assert await asyncio.to_thread(removed.wait, 1)
                for _ in range(2):
                    await asyncio.sleep(0)
                gc.collect()
                await asyncio.sleep(0)
            finally:
                loop.set_exception_handler(previous)
            assert not contexts
        run(scenario())


class TestToolchainBuilder:
    def test_tag_is_content_and_platform_stable_and_verified_image_is_reused(self, tmp_path: Path) -> None:
        from backend.fuzzing.docker.image_inspector import ImageInfo
        from backend.fuzzing.toolchain.builder import ToolchainBuilder

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM --platform=linux/amd64 ubuntu:24.04\n")
        inspector = SimpleNamespace(inspect=lambda tag: ImageInfo("sha256:ready", "linux", "amd64"))
        image_builder = SimpleNamespace(build=lambda *args: (_ for _ in ()).throw(AssertionError("must reuse verified image")))
        builder = ToolchainBuilder(dockerfile, image_builder, inspector)

        first = builder.tag()
        assert first == builder.tag() and first.startswith("bigeye-llvm:")
        assert builder.ensure(lambda text: None).image_id == "sha256:ready"

    def test_invalid_present_image_is_not_silently_rebuilt(self, tmp_path: Path) -> None:
        from backend.fuzzing.docker.image_inspector import UnsupportedImagePlatform
        from backend.fuzzing.toolchain.builder import ToolchainBuilder

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM ubuntu:24.04\n")
        inspector = SimpleNamespace(inspect=lambda tag: (_ for _ in ()).throw(UnsupportedImagePlatform("wrong platform")))
        image_builder = SimpleNamespace(build=lambda *args: (_ for _ in ()).throw(AssertionError("must not replace")))
        with pytest.raises(UnsupportedImagePlatform):
            ToolchainBuilder(dockerfile, image_builder, inspector).ensure(lambda text: None)

    def test_concurrent_missing_tag_builds_once_then_reinspects(self, tmp_path: Path) -> None:
        from backend.fuzzing.docker.image_inspector import ImageInfo, MissingImage
        from backend.fuzzing.toolchain.builder import ToolchainBuilder

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM ubuntu:24.04\n")
        barrier, built, calls = threading.Barrier(2), False, []
        class Inspector:
            def inspect(self, tag):
                nonlocal built
                calls.append(tag)
                if not built and len(calls) <= 2:
                    barrier.wait(timeout=1)
                    raise MissingImage("missing")
                if not built: raise MissingImage("missing")
                return ImageInfo("sha256:ready", "linux", "amd64")
        class Builder:
            count = 0
            def build(self, dockerfile, tag, sink):
                nonlocal built
                self.count += 1
                built = True
        image_builder = Builder()
        builder = ToolchainBuilder(dockerfile, image_builder, Inspector())
        threads = [threading.Thread(target=builder.ensure, args=(lambda text: None,)) for _ in range(2)]
        for thread in threads: thread.start()
        for thread in threads: thread.join(timeout=2)
        assert all(not thread.is_alive() for thread in threads)
        assert image_builder.count == 1


class TestToolchainVerifier:
    def test_probe_source_uses_valid_std_integer_and_size_types(self, tmp_path: Path) -> None:
        from backend.fuzzing.toolchain.verifier import FUZZER_SOURCE

        assert "#include <cstddef>" in FUZZER_SOURCE
        assert "#include <cstdint>" in FUZZER_SOURCE
        assert "const std::uint8_t*" in FUZZER_SOURCE and "std::size_t" in FUZZER_SOURCE
        clang = shutil.which("clang++")
        if clang:
            source = tmp_path / "probe.cc"
            source.write_text(FUZZER_SOURCE)
            checked = subprocess.run([clang, "-std=c++17", "-fsyntax-only", str(source)], capture_output=True, text=True)
            assert checked.returncode == 0, checked.stderr

    def test_verifier_runs_real_llvm_and_sanitized_libfuzzer_probe(self) -> None:
        from backend.fuzzing.toolchain.verifier import ToolchainVerifier

        class Runner:
            async def run(self, image, command, timeout, sink): return _result(command, sink)
        run(ToolchainVerifier(SimpleNamespace(inspect=lambda image: SimpleNamespace(os="linux", architecture="amd64")), Runner()).verify("bigeye-llvm:test", lambda text: None))

    def test_verifier_raises_logged_failure_text(self) -> None:
        from backend.fuzzing.docker.container_runner import ContainerResult
        from backend.fuzzing.toolchain.verifier import ToolchainVerificationFailed, ToolchainVerifier

        logs: list[str] = []
        class Runner:
            async def run(self, image, command, timeout, sink):
                sink("undefined sanitizer missing\n")
                return ContainerResult(2, "undefined sanitizer missing\n")
        runner = Runner()
        with pytest.raises(ToolchainVerificationFailed, match="undefined sanitizer missing"):
            run(ToolchainVerifier(SimpleNamespace(inspect=lambda image: SimpleNamespace(os="linux", architecture="amd64")), runner).verify("image", logs.append))
        assert logs == ["undefined sanitizer missing\n"]


def _result(command, sink):
    assert command[0:2] == ["bash", "-lc"]
    assert "clang-18 --version" in command[2]
    assert "-fsanitize=fuzzer,address,undefined" in command[2]
    assert "-runs=1" in command[2]
    from backend.fuzzing.docker.container_runner import ContainerResult
    return ContainerResult(0, "verified\n")


class TestToolchainService:
    def test_service_only_finishes_task_after_verification_and_persists_truthful_failure(self, tmp_path: Path) -> None:
        from backend.fuzzing.toolchain.service import ToolchainService

        task = SimpleNamespace(id=11, project_id=7)
        tasks = SimpleNamespace(finish=_async_spy())
        logs = SimpleNamespace(append_sync=lambda task, text: (tmp_path / f"{task.id}.log").open("a", encoding="utf-8").write(text))
        builder = SimpleNamespace(ensure=lambda sink: SimpleNamespace(image_id="sha256:built"))
        async def fail(image, sink): raise RuntimeError("clang probe failed")
        verifier = SimpleNamespace(verify=fail)

        with pytest.raises(RuntimeError, match="clang probe failed"):
            run(ToolchainService(tasks, logs, builder, verifier).prepare(task))
        assert tasks.finish.calls == [(11, "clang probe failed")]
        assert (tmp_path / "11.log").read_text() == "clang probe failed\n"

    def test_cancelled_build_keeps_cancellation_when_worker_later_fails(self) -> None:
        from backend.fuzzing.toolchain.service import ToolchainService
        entered, release = threading.Event(), threading.Event()
        task = SimpleNamespace(id=11, project_id=7)
        tasks = SimpleNamespace(finish=_async_spy())
        logs = SimpleNamespace(append_sync=lambda task, text: None)
        def fail_after_release(sink):
            entered.set(); release.wait(1); raise RuntimeError("late build failure")
        service = ToolchainService(tasks, logs, SimpleNamespace(ensure=fail_after_release), SimpleNamespace())
        async def scenario():
            running = asyncio.create_task(service.prepare(task))
            assert await asyncio.to_thread(entered.wait, 1)
            running.cancel(); release.set()
            with pytest.raises(asyncio.CancelledError): await running
        run(scenario())
        assert tasks.finish.calls == []


class TestMaintainedImageDefinition:
    def test_image_is_bigeye_owned_amd64_ubuntu_llvm_without_forbidden_toolchains(self) -> None:
        dockerfile = (Path(__file__).parents[1] / "fuzzing/images/Dockerfile").read_text().lower()
        assert "from --platform=linux/amd64 ubuntu:24.04" in dockerfile
        for package in ("clang-18", "llvm-18", "lld-18", "libfuzzer-18-dev", "libclang-rt-18-dev", "cmake", "ninja-build", "make", "git", "ca-certificates"):
            assert package in dockerfile
        assert "oss-fuzz" not in dockerfile and "oss fuzz" not in dockerfile

    def test_production_docker_boundary_never_shells_out_to_the_cli(self) -> None:
        source = "\n".join(path.read_text() for path in (Path(__file__).parents[1] / "fuzzing").rglob("*.py"))
        assert "subprocess" not in source
        assert "os.system" not in source and "popen(" not in source.lower()


class _async_spy:
    def __init__(self): self.calls = []
    async def __call__(self, *args): self.calls.append(args)
