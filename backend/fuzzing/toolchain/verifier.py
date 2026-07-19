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
grammar_generator-json 1 64 /tmp/bigeye-grammar-seeds /tmp/bigeye-grammar-trees 1
test -s /tmp/bigeye-grammar-seeds/0
test -s /tmp/bigeye-grammar-trees/0
python3 -c 'import json; json.load(open("/tmp/bigeye-grammar-seeds/0", encoding="utf-8"))'
if ! AFL_CUSTOM_MUTATOR_LIBRARY=/usr/local/lib/afl/libgrammarmutator-json.so \
    AFL_CUSTOM_MUTATOR_ONLY=1 \
    AFL_NO_AFFINITY=1 \
    AFL_NO_UI=1 \
    AFL_SKIP_CPUFREQ=1 \
    afl-fuzz -V 1 -m none -i /tmp/bigeye-grammar-seeds \
      -o /tmp/bigeye-mutator-out -- /tmp/bigeye-afl \
      > /tmp/bigeye-mutator.log 2>&1; then
  cat /tmp/bigeye-mutator.log
  exit 1
fi
cat /tmp/bigeye-mutator.log
grep -F "Custom mutator '/usr/local/lib/afl/libgrammarmutator-json.so' installed successfully." /tmp/bigeye-mutator.log
test -s /tmp/bigeye-mutator-out/default/fuzzer_stats
awk '$1 == "execs_done" && $3 + 0 > 1 {{ print "JSON grammar mutator executed " $3 " target runs"; found=1 }} END {{ exit found ? 0 : 1 }}' \
  /tmp/bigeye-mutator-out/default/fuzzer_stats
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
