"""Verify the maintained image with genuine compiler and libFuzzer work."""

import asyncio

from backend.fuzzing.docker.image_inspector import UnsupportedImagePlatform


class ToolchainVerificationFailed(RuntimeError):
    """Raised when the maintained compiler image cannot satisfy its contract."""


FUZZER_SOURCE = """#include <cstddef>
#include <cstdint>
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t*, std::size_t) { return 0; }
"""


_PROBE = f"""set -eu
clang-18 --version
clang++-18 --version
ld.lld-18 --version
llvm-config-18 --version
cat > /tmp/bigeye-fuzzer.cc <<'BIGEYE_FUZZER_SOURCE'
{FUZZER_SOURCE}BIGEYE_FUZZER_SOURCE
clang++-18 -std=c++17 -fsanitize=fuzzer,address,undefined -g -O1 /tmp/bigeye-fuzzer.cc -o /tmp/bigeye-fuzzer
ASAN_OPTIONS=detect_leaks=0 /tmp/bigeye-fuzzer -runs=1
"""


class ToolchainVerifier:
    def __init__(self, inspector, runner):
        self._inspector = inspector
        self._runner = runner

    async def verify(self, image: str, sink) -> None:
        info = await asyncio.to_thread(self._inspector.inspect, image)
        if (info.os, info.architecture) != ("linux", "amd64"):
            raise UnsupportedImagePlatform(f"image {image} must be linux/amd64")
        result = await self._runner.run(image, ["bash", "-lc", _PROBE], 45, sink)
        if result.exit_code != 0:
            raise ToolchainVerificationFailed(result.output or f"toolchain verification exited {result.exit_code}")
