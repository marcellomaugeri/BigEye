"""Release contracts for BigEye's pinned fuzzing toolchain image."""

from __future__ import annotations

import asyncio
from pathlib import Path


ROOT = Path(__file__).parents[2]


def test_toolchain_is_owned_pinned_and_has_no_oss_fuzz_reference() -> None:
    dockerfile = (ROOT / "backend/fuzzing/images/Dockerfile").read_text()

    assert dockerfile.index("apt-get update") < dockerfile.index("ARG AFL_VERSION")
    assert "AFL_VERSION=v4.40c" in dockerfile
    assert "e5a8ba39ecf97d05e286fdd4e01da96554dbf64f" in dockerfile
    assert (
        "FROM --platform=linux/amd64 "
        "ubuntu@sha256:52df9b1ee71626e0088f7d400d5c6b5f7bb916f8f0c82b474289a4ece6cf3faf"
    ) in dockerfile
    assert "https://github.com/AFLplusplus/AFLplusplus.git" in dockerfile
    assert "rev-parse HEAD" in dockerfile
    assert "oss-fuzz" not in dockerfile.lower()
    assert "from aflplusplus/aflplusplus" not in dockerfile.lower()


def test_toolchain_builds_and_installs_the_pinned_upstream_grammar_mutator() -> None:
    dockerfile = (ROOT / "backend/fuzzing/images/Dockerfile").read_text()

    assert "run_with_heartbeat" in dockerfile
    assert "73a49d6810d903aa4827ee32126937b85d3bebec0a8e679b0dd963cbcc49ba5a" in dockerfile
    assert "sha256sum -c" in dockerfile
    assert "custom_mutators/grammar_mutator/grammar_mutator" in dockerfile
    assert "0a0da05305466bfe0b27bbb7cf24a7ddf8a66811" in dockerfile
    assert "libgrammarmutator-json.so" in dockerfile
    assert "grammar_generator-json" in dockerfile


def test_verifier_checks_both_engines_clean_coverage_and_mutator_tools() -> None:
    from backend.fuzzing.toolchain.verifier import ToolchainVerifier

    command = ToolchainVerifier.command()
    for binary in (
        "clang-18",
        "llvm-profdata-18",
        "llvm-cov-18",
        "afl-fuzz",
        "afl-cmin",
        "afl-tmin",
        "afl-showmap",
        "afl-clang-fast",
        "libgrammarmutator-json.so",
    ):
        assert binary in command
    assert "-fsanitize=fuzzer,address,undefined" in command
    assert "afl-fuzz --version" in command
    assert "++4.40c" in command


def test_content_tag_hashes_platform_and_both_tool_versions(tmp_path: Path) -> None:
    from backend.fuzzing.toolchain import builder as builder_module
    from backend.fuzzing.toolchain.builder import ToolchainBuilder

    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM scratch\n")
    builder = ToolchainBuilder(dockerfile, object(), object())

    assert builder.tag().startswith("bigeye-toolchain:")
    original = builder.tag()
    monkey_values = (
        ("PLATFORM", "linux/arm64"),
        ("LLVM_VERSION", "19"),
        ("AFL_VERSION", "v4.41c"),
    )
    for name, replacement in monkey_values:
        previous = getattr(builder_module, name)
        setattr(builder_module, name, replacement)
        try:
            assert builder.tag() != original
        finally:
            setattr(builder_module, name, previous)


def test_verify_image_main_returns_zero_after_success_and_nonzero_after_failure(monkeypatch, capsys) -> None:
    from backend.fuzzing.toolchain import verify_image

    async def succeeds() -> str:
        return "sha256:verified"

    monkeypatch.setattr(verify_image, "verify", succeeds)
    assert verify_image.main() == 0
    assert "sha256:verified linux/amd64 LLVM 18 AFL++ 4.40c verified" in capsys.readouterr().out

    async def fails() -> str:
        raise RuntimeError("probe failed")

    monkeypatch.setattr(verify_image, "verify", fails)
    assert verify_image.main() != 0
    assert "probe failed" in capsys.readouterr().err


def test_verify_image_verify_closes_the_exact_docker_client(monkeypatch) -> None:
    from backend.fuzzing.toolchain import verify_image

    calls: list[str] = []

    class Client:
        def close(self) -> None:
            calls.append("close")

    class Builder:
        def ensure(self, sink):
            return type("Image", (), {"image_id": "sha256:verified"})()

    class Verifier:
        async def verify(self, image, sink) -> None:
            calls.append(image)

    monkeypatch.setattr(verify_image, "connect", lambda: Client())
    monkeypatch.setattr(verify_image, "create_builder", lambda client: Builder())
    monkeypatch.setattr(verify_image, "create_verifier", lambda client: Verifier())

    assert asyncio.run(verify_image.verify()) == "sha256:verified"
    assert calls == ["sha256:verified", "close"]
