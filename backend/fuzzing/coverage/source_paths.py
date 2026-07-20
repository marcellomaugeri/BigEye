"""Shared clean-source path exclusions for coverage assurance."""

from pathlib import PurePosixPath


_FORBIDDEN_SEGMENTS = frozenset({
    ".bigeye",
    ".git",
    "build",
    "fuzz",
    "fuzzer",
    "fuzzers",
    "fuzz-target",
    "fuzz-targets",
    "fuzz_target",
    "fuzz_targets",
    "generated",
    "harness",
    "harnesses",
})


def is_forbidden_source_path(path: PurePosixPath) -> bool:
    """Return whether any path segment belongs to metadata or generated fuzzing output."""

    lowered = tuple(part.casefold() for part in path.parts)
    return (
        path.suffix.casefold() == ".patch"
        or any(part in _FORBIDDEN_SEGMENTS for part in lowered)
        or any(part.startswith("cmake-build") for part in lowered)
    )
