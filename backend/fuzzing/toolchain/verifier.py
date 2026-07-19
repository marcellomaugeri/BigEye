"""Verify the maintained image with genuine compiler and libFuzzer work."""

import asyncio

from backend.fuzzing.docker.image_inspector import UnsupportedImagePlatform


class ToolchainVerificationFailed(RuntimeError):
    """Raised when the maintained compiler image cannot satisfy its contract."""


FUZZER_SOURCE = """#include <cstddef>
#include <cstdint>
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t*, std::size_t) { return 0; }
"""

_AFL_SOURCE = """#include <unistd.h>
int main(void) {
  unsigned char input = 0;
  if (read(0, &input, 1) == 1 && input == 'A') input++;
  return input == 255;
}
"""


_PROBE = rf"""set -eu
test "$(uname -m)" = "x86_64"
clang-18 --version | grep -m 1 'clang version 18\.'
clang++-18 --version | grep -m 1 'clang version 18\.'
ld.lld-18 --version | grep -m 1 'LLD 18\.'
llvm-config-18 --version | grep -m 1 '^18\.'
llvm-profdata-18 --version | grep -m 1 'LLVM version 18\.'
llvm-cov-18 --version | grep -m 1 'LLVM version 18\.'
test "$(afl-fuzz --version)" = "afl-fuzz++4.40c"
command -v afl-cmin
command -v afl-tmin
command -v afl-showmap
command -v afl-clang-fast
test -s /usr/local/lib/afl/libgrammarmutator-json.so
test -x /usr/local/bin/grammar_generator-json
cat > /tmp/bigeye-fuzzer.cc <<'BIGEYE_FUZZER_SOURCE'
{FUZZER_SOURCE}
BIGEYE_FUZZER_SOURCE
clang++-18 -std=c++17 -fsanitize=fuzzer,address,undefined -g -O1 /tmp/bigeye-fuzzer.cc -o /tmp/bigeye-fuzzer
ASAN_OPTIONS=detect_leaks=0 /tmp/bigeye-fuzzer -runs=1
cat > /tmp/bigeye-afl.c <<'BIGEYE_AFL_SOURCE'
{_AFL_SOURCE}
BIGEYE_AFL_SOURCE
AFL_CC=clang-18 afl-clang-fast -O1 /tmp/bigeye-afl.c -o /tmp/bigeye-afl
printf A | afl-showmap -q -o /tmp/bigeye-afl.map -- /tmp/bigeye-afl
test -s /tmp/bigeye-afl.map
"""


class ToolchainVerifier:
    def __init__(self, inspector, runner):
        self._inspector = inspector
        self._runner = runner

    @staticmethod
    def command() -> str:
        return _PROBE

    async def verify(self, image: str, sink) -> None:
        info = await asyncio.to_thread(self._inspector.inspect, image)
        if (info.os, info.architecture) != ("linux", "amd64"):
            raise UnsupportedImagePlatform(f"image {image} must be linux/amd64")
        result = await self._runner.run(image, ["bash", "-lc", self.command()], 45, sink)
        if result.exit_code != 0:
            raise ToolchainVerificationFailed(result.output or f"toolchain verification exited {result.exit_code}")
