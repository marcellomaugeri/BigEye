"""Deterministic, read-only inventory of actionable repository evidence."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import re

from backend.agents.tools.code_navigation import (
    CodeNavigationError,
    _open_contained_file,
    _opened_repository_root,
    _read_open_text,
    list_project_files,
)


MAX_INVENTORY_FILES = 256
MAX_EVIDENCE_FILE_BYTES = 128_000
MAX_EVIDENCE_BYTES = 1_000_000
MAX_COMPILE_COMMANDS = 64

_BUILD_FILE_NAMES = frozenset(
    {
        "CMakeLists.txt",
        "Makefile",
        "GNUmakefile",
        "meson.build",
        "build.ninja",
        "Cargo.toml",
        "go.mod",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "package.json",
        "pyproject.toml",
        "compile_commands.json",
        "configure",
    }
)
_SOURCE_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".m", ".mm", ".rs", ".go", ".java", ".kt", ".swift", ".py"})
_HEADER_SUFFIXES = frozenset({".h", ".hh", ".hpp", ".hxx", ".inc"})
_SAMPLE_SUFFIXES = frozenset({".bin", ".dat", ".seed", ".corpus", ".txt", ".json", ".xml", ".yaml", ".yml"})
_HELP_SUFFIXES = frozenset({".md", ".rst", ".txt", ".adoc"})


@dataclass(frozen=True)
class Inventory:
    """Stable repository-relative evidence buckets used by target planning."""

    build_files: tuple[str, ...] = ()
    compile_commands: tuple[str, ...] = ()
    executables: tuple[str, ...] = ()
    libraries: tuple[str, ...] = ()
    components: tuple[str, ...] = ()
    public_headers: tuple[str, ...] = ()
    test_files: tuple[str, ...] = ()
    example_files: tuple[str, ...] = ()
    fixture_files: tuple[str, ...] = ()
    sample_inputs: tuple[str, ...] = ()
    help_files: tuple[str, ...] = ()
    fuzz_harnesses: tuple[str, ...] = ()
    text_files: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, list[str]]:
        return {name: list(value) for name, value in asdict(self).items()}


class RepositoryInventory:
    """Collect bounded file and manifest evidence without executing project code."""

    def collect(self, root: Path) -> Inventory:
        try:
            files = list_project_files(Path(root), limit=MAX_INVENTORY_FILES)
        except (CodeNavigationError, OSError):
            return Inventory()

        buckets: dict[str, set[str]] = {
            "build_files": set(), "executables": set(), "libraries": set(), "components": set(),
            "public_headers": set(), "test_files": set(), "example_files": set(), "fixture_files": set(),
            "sample_inputs": set(), "help_files": set(), "fuzz_harnesses": set(), "text_files": set(),
        }
        compile_commands: list[str] = []
        remaining_bytes = MAX_EVIDENCE_BYTES
        try:
            with _opened_repository_root(Path(root)) as (_, descriptor):
                for relative_path in files:
                    parts = tuple(relative_path.split("/"))
                    path = Path(relative_path)
                    self._classify_path(relative_path, path, buckets)
                    content, consumed = self._bounded_text(descriptor, parts, remaining_bytes)
                    remaining_bytes -= consumed
                    if content is None:
                        continue
                    buckets["text_files"].add(relative_path)
                    if path.name == "compile_commands.json":
                        compile_commands.extend(self._compile_commands(content, MAX_COMPILE_COMMANDS - len(compile_commands)))
                    if path.name == "CMakeLists.txt":
                        self._cmake_targets(content, buckets)
                    if self._looks_like_fuzz_harness(path, content):
                        buckets["fuzz_harnesses"].add(relative_path)
        except (CodeNavigationError, OSError):
            return Inventory()
        return Inventory(
            compile_commands=tuple(sorted(dict.fromkeys(compile_commands))[:MAX_COMPILE_COMMANDS]),
            **{name: tuple(sorted(values)) for name, values in buckets.items()},
        )

    @staticmethod
    def _bounded_text(root_descriptor: int, parts: tuple[str, ...], remaining: int) -> tuple[str | None, int]:
        try:
            descriptor = _open_contained_file(root_descriptor, parts)
        except (CodeNavigationError, OSError):
            return None, 0
        try:
            size = os.fstat(descriptor).st_size
            if size > MAX_EVIDENCE_FILE_BYTES or size > remaining:
                return None, 0
            content = _read_open_text(descriptor)
        except (CodeNavigationError, OSError):
            return None, 0
        finally:
            os.close(descriptor)
        return content, len(content.encode("utf-8"))

    @staticmethod
    def _classify_path(relative_path: str, path: Path, buckets: dict[str, set[str]]) -> None:
        name = path.name
        lower_parts = {part.casefold() for part in path.parts}
        suffix = path.suffix.casefold()
        if name in _BUILD_FILE_NAMES or name.endswith(".sln") or name.startswith("configure"):
            buckets["build_files"].add(relative_path)
        if suffix in _HEADER_SUFFIXES and ({"include", "public"} & lower_parts):
            buckets["public_headers"].add(relative_path)
        if {"test", "tests", "spec", "specs"} & lower_parts or name.casefold().startswith("test_"):
            buckets["test_files"].add(relative_path)
        if {"example", "examples", "demo", "demos"} & lower_parts:
            buckets["example_files"].add(relative_path)
        if {"fixture", "fixtures"} & lower_parts:
            buckets["fixture_files"].add(relative_path)
        if suffix in _SAMPLE_SUFFIXES and ({"sample", "samples", "seed", "seeds", "corpus", "fixture", "fixtures", "example", "examples", "test", "tests"} & lower_parts or any(token in name.casefold() for token in ("sample", "seed", "input"))):
            buckets["sample_inputs"].add(relative_path)
        if suffix in _HELP_SUFFIXES and ({"doc", "docs"} & lower_parts or name.casefold().startswith(("readme", "usage", "help"))):
            buckets["help_files"].add(relative_path)
        if suffix in _SOURCE_SUFFIXES and ("bin" in lower_parts or name.casefold().startswith("main.")):
            buckets["executables"].add(path.stem)
        if suffix in _SOURCE_SUFFIXES and ("lib" in lower_parts or path.stem.casefold().startswith("lib")):
            buckets["libraries"].add(path.stem.removeprefix("lib"))
        if suffix in _SOURCE_SUFFIXES:
            buckets["components"].add(path.stem)
        if "fuzz" in relative_path.casefold():
            buckets["fuzz_harnesses"].add(relative_path)

    @staticmethod
    def _compile_commands(content: str, remaining: int) -> list[str]:
        if remaining <= 0:
            return []
        try:
            entries = json.loads(content)
        except json.JSONDecodeError:
            return []
        if not isinstance(entries, list):
            return []
        commands: list[str] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            command = entry.get("command")
            if isinstance(command, str) and command.strip():
                commands.append(command.strip()[:500])
            elif isinstance(entry.get("arguments"), list) and all(isinstance(value, str) for value in entry["arguments"]):
                commands.append(" ".join(entry["arguments"])[:500])
            if len(commands) == remaining:
                break
        return commands

    @staticmethod
    def _cmake_targets(content: str, buckets: dict[str, set[str]]) -> None:
        for target in re.findall(r"(?im)^\s*add_executable\s*\(\s*([^\s)]+)", content):
            buckets["executables"].add(target)
        for target in re.findall(r"(?im)^\s*add_library\s*\(\s*([^\s)]+)", content):
            buckets["libraries"].add(target)

    @staticmethod
    def _looks_like_fuzz_harness(path: Path, content: str) -> bool:
        return "fuzz" in path.as_posix().casefold() or "LLVMFuzzerTestOneInput" in content
