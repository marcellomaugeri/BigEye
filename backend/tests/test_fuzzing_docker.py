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
        from backend.fuzzing.docker.image_builder import ImageBuildFailed, ImageBuilder, ImageCompilationFailed

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM ubuntu:24.04\n")
        calls = []

        class Api:
            def build(self, **kwargs):
                calls.append(kwargs)
                return iter(({"stream": "building\n"}, {"errorDetail": {"message": "daemon build failed"}}))

        logs: list[str] = []
        with pytest.raises(ImageBuildFailed, match="daemon build failed") as captured:
            ImageBuilder(SimpleNamespace(api=Api())).build(dockerfile, "bigeye-llvm:test", logs.append)
        assert not isinstance(captured.value, ImageCompilationFailed)
        assert logs == ["building\n", "daemon build failed\n"]
        assert calls[0]["platform"] == "linux/amd64"

    def test_build_classifies_only_deterministic_command_exit_as_compilation_failure(self, tmp_path: Path) -> None:
        from backend.fuzzing.docker.image_builder import ImageBuilder, ImageCompilationFailed

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM ubuntu:24.04\n")

        class Api:
            def build(self, **kwargs):
                return iter(({
                    "errorDetail": {
                        "message": "process /bin/sh -c cmake --build build did not complete successfully: exit code: 2",
                    },
                },))

        with pytest.raises(ImageCompilationFailed, match="did not complete successfully") as captured:
            ImageBuilder(SimpleNamespace(api=Api())).build(
                dockerfile, "bigeye-target:test", lambda _text: None,
            )
        assert captured.value.detail.phase == "build-command"
        assert captured.value.detail.exit_code == 2

    @pytest.mark.parametrize("message", [
        "failed to solve: dockerfile parse error on line 3: unknown instruction: RNU",
        "failed to solve with frontend dockerfile.v0: failed to read dockerfile: failed to parse stage name",
        "COPY failed: file not found in build context or excluded by .dockerignore",
    ])
    def test_build_classifies_real_frontend_and_generated_config_shapes_as_repairable(
        self, tmp_path: Path, message: str,
    ) -> None:
        from backend.fuzzing.docker.image_builder import ImageBuilder, ImageCompilationFailed

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM ubuntu:24.04\n")

        class Api:
            def build(self, **kwargs):
                return iter(({"error": message, "errorDetail": {"message": message}},))

        with pytest.raises(ImageCompilationFailed) as captured:
            ImageBuilder(SimpleNamespace(api=Api())).build(
                dockerfile, "bigeye-target:test", lambda _text: None,
            )

        assert captured.value.detail.phase in {"dockerfile-frontend", "generated-build-config"}
        assert captured.value.detail.message == message

    def test_structured_build_command_exit_is_repairable_without_message_guessing(self, tmp_path: Path) -> None:
        from backend.fuzzing.docker.image_builder import ImageBuilder, ImageCompilationFailed

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM ubuntu:24.04\n")

        class Api:
            def build(self, **kwargs):
                return iter(({
                    "type": "error",
                    "error": "generated build step failed",
                    "errorDetail": {"phase": "build-command", "exitCode": 23, "code": "STEP_FAILED"},
                },))

        with pytest.raises(ImageCompilationFailed) as captured:
            ImageBuilder(SimpleNamespace(api=Api())).build(
                dockerfile, "bigeye-target:test", lambda _text: None,
            )

        assert captured.value.detail.exit_code == 23
        assert captured.value.detail.code == "STEP_FAILED"
        assert captured.value.detail.stream_type == "error"

    @pytest.mark.parametrize(("message", "phase"), [
        ("Cannot connect to the Docker daemon at unix:///var/run/docker.sock", "engine"),
        ("failed to resolve source metadata for docker.io/library/ubuntu: i/o timeout", "network"),
        ("failed to solve: process /bin/sh -c make did not complete successfully: exit code: 137: out of memory", "resource"),
        ("failed to solve: no space left on device", "resource"),
    ])
    def test_daemon_registry_network_and_resource_shapes_remain_fatal(
        self, tmp_path: Path, message: str, phase: str,
    ) -> None:
        from backend.fuzzing.docker.image_builder import ImageBuildFailed, ImageBuilder, ImageCompilationFailed

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM ubuntu:24.04\n")

        class Api:
            def build(self, **kwargs):
                return iter(({"error": message, "errorDetail": {"message": message}},))

        with pytest.raises(ImageBuildFailed) as captured:
            ImageBuilder(SimpleNamespace(api=Api())).build(
                dockerfile, "bigeye-target:test", lambda _text: None,
            )

        assert not isinstance(captured.value, ImageCompilationFailed)
        assert captured.value.detail.phase == phase

    def test_docker_api_transport_exception_is_wrapped_as_fatal_build_failure(self, tmp_path: Path) -> None:
        from backend.fuzzing.docker.image_builder import ImageBuildFailed, ImageBuilder, ImageCompilationFailed

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM ubuntu:24.04\n")

        class Api:
            def build(self, **kwargs):
                raise ConnectionError("Docker daemon disconnected")

        with pytest.raises(ImageBuildFailed, match="request failed") as captured:
            ImageBuilder(SimpleNamespace(api=Api())).build(
                dockerfile, "bigeye-target:test", lambda _text: None,
            )

        assert not isinstance(captured.value, ImageCompilationFailed)
        assert captured.value.detail.phase == "engine"

    def test_cancellation_closes_active_build_stream_and_joins_cleanly(self, tmp_path: Path) -> None:
        from backend.fuzzing.docker.image_builder import (
            BuildCancellationSignal,
            ImageBuildCancelled,
            ImageBuilder,
        )

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM ubuntu:24.04\n")
        entered = threading.Event()
        closed = threading.Event()

        class Stream:
            def __iter__(self):
                return self

            def __next__(self):
                entered.set()
                assert closed.wait(1.0)
                raise StopIteration

            def close(self):
                closed.set()

        class Api:
            def build(self, **kwargs):
                return Stream()

            def inspect_image(self, tag):
                raise AssertionError("cancelled build must not be inspected")

        signal = BuildCancellationSignal()
        errors = []

        def build():
            try:
                ImageBuilder(SimpleNamespace(api=Api())).build(
                    dockerfile, "bigeye-target:test", lambda _text: None,
                    cancellation_signal=signal,
                )
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=build)
        worker.start()
        assert entered.wait(1.0)
        signal.set()
        worker.join(1.0)

        assert not worker.is_alive()
        assert closed.is_set()
        assert len(errors) == 1 and isinstance(errors[0], ImageBuildCancelled)

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
    def test_reproduction_streams_demuxed_output_with_only_read_only_testcase(self, tmp_path: Path) -> None:
        from backend.fuzzing.docker.container_runner import ContainerRunner

        testcase = tmp_path / "minimal.input"
        testcase.write_bytes(b"crash")
        created, output, removed = [], [], []

        class Container:
            id = "reproduction-1"
            def start(self): pass
            def attach(self, **kwargs):
                assert kwargs == {
                    "stream": True, "logs": True, "stdout": True,
                    "stderr": True, "demux": True,
                }
                return iter(((b"stdout\xff\n", None), (None, b"asan\x1b[31m\n")))
            def wait(self, timeout): return {"StatusCode": 1}
            def remove(self, force=False): removed.append((self.id, force))

        class Containers:
            def create(self, image, command, **kwargs):
                created.append((image, command, kwargs))
                return Container()

        result = run(ContainerRunner(SimpleNamespace(containers=Containers())).run_reproduction(
            "sha256:" + "a" * 64, ["/opt/bigeye/reproduce", "/finding/input"], 12,
            lambda stream, text: output.append((stream, text)), testcase,
            environment={"ASAN_OPTIONS": "abort_on_error=1"},
        ))

        assert result.exit_code == 1
        assert output == [("stdout", "stdout\ufffd\n"), ("stderr", "asan\n")]
        assert removed == [("reproduction-1", True)]
        assert created[0][2] == {
            "platform": "linux/amd64", "network_disabled": True, "read_only": True,
            "cap_drop": ["ALL"], "security_opt": ["no-new-privileges"], "pids_limit": 64,
            "mem_limit": "512m", "nano_cpus": 1_000_000_000,
            "tmpfs": {"/tmp": "rw,nosuid,nodev,exec,size=64m,mode=1777"},
            "detach": True, "user": "65534:65534",
            "volumes": {str(testcase.resolve()): {"bind": "/finding/input", "mode": "ro"}},
            "environment": {"ASAN_OPTIONS": "abort_on_error=1"},
        }

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

    def test_runner_feeds_exact_bounded_stdin_and_closes_socket(self) -> None:
        import socket

        from backend.fuzzing.docker.container_runner import ContainerRunner

        class AttachedSocket:
            def __init__(self):
                self._sock = self
                self.sent = bytearray()
                self.shutdown_mode = None
                self.closed = False
                self.events = []
                self._response = SimpleNamespace(close=self._close_response)

            def sendall(self, value): self.sent.extend(value)
            def shutdown(self, value): self.shutdown_mode = value
            def _close_response(self): self.events.append("response")
            def close(self): self.events.append("socket"); self.closed = True

        class Container:
            id = "container-stdin"
            def __init__(self): self.socket = AttachedSocket()
            def attach_socket(self, params):
                assert params == {"stdin": 1, "stream": 1}
                return self.socket
            def start(self): pass
            def wait(self, timeout): return {"StatusCode": 0}
            def logs(self, **kwargs): return iter(())
            def remove(self, force=False): pass

        class Containers:
            def __init__(self): self.container = Container(); self.kwargs = None
            def create(self, *args, **kwargs): self.kwargs = kwargs; return self.container

        containers = Containers()
        result = run(ContainerRunner(SimpleNamespace(containers=containers)).run(
            "image", ["/opt/bigeye/parser"], 2, lambda _text: None,
            stdin_bytes=b"\x00exact\xff",
        ))

        assert result.exit_code == 0
        assert containers.kwargs["detach"] is False
        assert containers.kwargs["stdin_open"] is True
        assert containers.kwargs["tty"] is False
        assert bytes(containers.container.socket.sent) == b"\x00exact\xff"
        assert containers.container.socket.shutdown_mode == socket.SHUT_WR
        assert containers.container.socket.closed is True
        assert containers.container.socket.events == ["response", "socket"]

    def test_runner_timeout_closes_stdin_response_before_socket_and_container(self) -> None:
        from backend.fuzzing.docker.container_runner import ContainerRunner, ContainerTimedOut

        events = []

        class AttachedSocket:
            def __init__(self):
                self._sock = self
                self.closed = False
                self._response = SimpleNamespace(close=lambda: events.append("response"))
            def sendall(self, _value): pass
            def shutdown(self, _value): pass
            def close(self): events.append("socket"); self.closed = True

        class Container:
            id = "container-stdin-error"
            def __init__(self): self.socket = AttachedSocket()
            def attach_socket(self, params): return self.socket
            def start(self): pass
            def wait(self, timeout): raise TimeoutError("wait timed out")
            def stop(self, timeout=0): events.append("stop")
            def kill(self): events.append("kill")
            def remove(self, force=False): events.append("remove")

        container = Container()
        class Containers:
            def create(self, *args, **kwargs): return container

        with pytest.raises(ContainerTimedOut, match="exceeded"):
            run(ContainerRunner(SimpleNamespace(containers=Containers())).run(
                "image", ["/opt/bigeye/parser"], 2, lambda _text: None,
                stdin_bytes=b"exact",
            ))

        assert container.socket.closed is True
        assert events == ["response", "socket", "stop", "kill", "remove"]

    def test_runner_cancellation_closes_stdin_response_before_socket(self) -> None:
        from backend.fuzzing.docker.container_runner import ContainerRunner

        waiting = threading.Event()
        stopped = threading.Event()
        removed = threading.Event()
        events = []

        class AttachedSocket:
            def __init__(self):
                self._sock = self
                self._response = SimpleNamespace(close=lambda: events.append("response"))
            def sendall(self, _value): pass
            def shutdown(self, _value): pass
            def close(self): events.append("socket")

        class Container:
            id = "container-stdin-cancel"
            def __init__(self): self.socket = AttachedSocket()
            def attach_socket(self, params): return self.socket
            def start(self): pass
            def wait(self, timeout):
                waiting.set()
                assert stopped.wait(1)
                raise RuntimeError("stopped")
            def stop(self, timeout=0): stopped.set()
            def kill(self): pass
            def remove(self, force=False): removed.set()

        container = Container()
        created = {}
        class Containers:
            def create(self, *args, **kwargs): created.update(kwargs); return container

        async def scenario():
            operation = asyncio.create_task(ContainerRunner(
                SimpleNamespace(containers=Containers()),
            ).run(
                "image", ["/opt/bigeye/parser"], 10, lambda _text: None,
                stdin_bytes=b"exact",
            ))
            assert await asyncio.to_thread(waiting.wait, 1)
            operation.cancel()
            with pytest.raises(asyncio.CancelledError):
                await operation
            assert await asyncio.to_thread(removed.wait, 1)

        run(scenario())
        assert created["detach"] is False
        assert events == ["response", "socket"]

    def test_runner_removes_exact_container_when_stdin_attach_fails(self) -> None:
        from backend.fuzzing.docker.container_runner import ContainerRunner

        removed = []

        class Container:
            id = "container-attach-error"
            def attach_socket(self, params): raise RuntimeError("attach failed")
            def stop(self, timeout=0): pass
            def kill(self): pass
            def remove(self, force=False): removed.append((self.id, force))

        class Containers:
            def create(self, *args, **kwargs): return Container()

        with pytest.raises(RuntimeError, match="attach failed"):
            run(ContainerRunner(SimpleNamespace(containers=Containers())).run(
                "image", ["/opt/bigeye/parser"], 2, lambda _text: None,
                stdin_bytes=b"exact",
            ))

        assert removed == [("container-attach-error", True)]

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
        assert first == builder.tag() and first.startswith("bigeye-toolchain:")
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
        run(ToolchainVerifier(SimpleNamespace(inspect=lambda image: SimpleNamespace(os="linux", architecture="amd64")), Runner()).verify("bigeye-toolchain:test", lambda text: None))

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
    assert "llvm-profdata-18 --version" in command[2]
    assert "llvm-cov-18 --version" in command[2]
    assert "-fsanitize=fuzzer,address,undefined" in command[2]
    assert "afl-clang-fast" in command[2]
    assert "afl-showmap" in command[2]
    assert "ASAN_OPTIONS=detect_leaks=0" in command[2]
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
        assert "from --platform=linux/amd64 ubuntu@sha256:52df9b1ee71626e0088f7d400d5c6b5f7bb916f8f0c82b474289a4ece6cf3faf" in dockerfile
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
