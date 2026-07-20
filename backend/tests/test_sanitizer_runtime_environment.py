"""Regression coverage for the application-owned sanitizer runtime policy."""

import asyncio
from types import SimpleNamespace

import pytest


def run(awaitable):
    return asyncio.run(awaitable)


def test_baseline_sanitizer_environment_disables_only_unsupported_leak_runtime() -> None:
    from backend.fuzzing.sanitizer_environment import BASELINE_SANITIZER_ENVIRONMENT

    assert dict(BASELINE_SANITIZER_ENVIRONMENT) == {
        "ASAN_OPTIONS": "abort_on_error=1:symbolize=0:detect_leaks=0",
        "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
    }


def test_bounded_container_runner_passes_a_copied_sanitizer_environment() -> None:
    from backend.fuzzing.docker.container_runner import ContainerRunner
    from backend.fuzzing.sanitizer_environment import BASELINE_SANITIZER_ENVIRONMENT

    created = {}

    class Container:
        id = "sanitizer-probe"

        def start(self): pass
        def wait(self, timeout): return {"StatusCode": 0}
        def logs(self, **kwargs): return iter(())
        def remove(self, force=False): pass

    class Containers:
        def create(self, _image, _command, **options):
            created.update(options)
            return Container()

    environment = dict(BASELINE_SANITIZER_ENVIRONMENT)
    result = run(ContainerRunner(SimpleNamespace(containers=Containers())).run(
        "sha256:" + "a" * 64,
        ["/opt/bigeye/build/target"],
        2,
        lambda _text: None,
        environment=environment,
    ))
    environment["ASAN_OPTIONS"] = "changed-after-call"

    assert result.exit_code == 0
    assert created["environment"] == dict(BASELINE_SANITIZER_ENVIRONMENT)


@pytest.mark.parametrize("environment", [
    {"NOT-PORTABLE": "1"},
    {"SAFE": "nul\x00value"},
    {f"NAME_{index}": "1" for index in range(17)},
    {"SAFE": "x" * 4_097},
])
def test_bounded_container_runner_rejects_invalid_or_unbounded_environment(environment) -> None:
    from backend.fuzzing.docker.container_runner import ContainerRunner

    with pytest.raises(ValueError, match="environment"):
        run(ContainerRunner(SimpleNamespace()).run(
            "sha256:" + "a" * 64,
            ["/opt/bigeye/build/target"],
            2,
            lambda _text: None,
            environment=environment,
        ))


@pytest.mark.parametrize(
    ("command", "testcase", "expected_stdin"),
    [
        (("/opt/bigeye/build/target", "/src/seed"), b"file", None),
        (("/opt/bigeye/build/target", "{stdin}"), b"stdin", b"stdin"),
    ],
)
def test_deterministic_probe_applies_baseline_sanitizer_environment(
    command, testcase, expected_stdin,
) -> None:
    from backend.fuzzing.campaigns.probe import ProbeInvocation, ProbeRunner
    from backend.fuzzing.docker.container_runner import ContainerResult
    from backend.fuzzing.sanitizer_environment import BASELINE_SANITIZER_ENVIRONMENT

    class BoundedRunner:
        async def run(
            self, _image, _command, _timeout, _sink, *, stdin_bytes=None, environment=None,
        ):
            self.stdin_bytes = stdin_bytes
            self.environment = environment
            return ContainerResult(0, "")

    bounded = BoundedRunner()
    invocation = ProbeInvocation("seed", "seed", command, testcase)

    result = run(ProbeRunner(bounded).run(
        "sha256:" + "b" * 64, invocation, 2.0, lambda _text: None,
        BASELINE_SANITIZER_ENVIRONMENT,
    ))

    assert result.exit_code == 0
    assert bounded.stdin_bytes == expected_stdin
    assert bounded.environment == dict(BASELINE_SANITIZER_ENVIRONMENT)
