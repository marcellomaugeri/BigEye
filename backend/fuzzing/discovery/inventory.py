"""Deterministic, read-only inventory of actionable repository evidence."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from itertools import islice
import io
import json
import os
from pathlib import Path
import re
import shlex
import tomllib

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
MAX_TARGETS_PER_KIND = 128
MAX_MANIFEST_LINES = 4_096

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
        "settings.gradle",
        "settings.gradle.kts",
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
                        commands = self._compile_commands(content, MAX_COMPILE_COMMANDS - len(compile_commands))
                        compile_commands.extend(commands)
                        self._compile_command_targets(commands, buckets)
                    if path.name == "CMakeLists.txt":
                        self._cmake_targets(content, buckets)
                    elif path.name == "meson.build":
                        self._meson_targets(content, buckets)
                    elif path.name == "Cargo.toml":
                        self._cargo_targets(content, buckets, set(files))
                    elif path.name in {"Makefile", "GNUmakefile"}:
                        self._make_targets(content, buckets)
                    elif path.name in {"build.gradle", "build.gradle.kts"}:
                        self._gradle_targets(content, buckets)
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
        for match in re.finditer(r"(?im)^\s*add_executable\s*\(\s*([^\s)]+)", content):
            RepositoryInventory._add_target(buckets["executables"], match.group(1))
        for match in re.finditer(r"(?im)^\s*add_library\s*\(\s*([^\s)]+)", content):
            RepositoryInventory._add_target(buckets["libraries"], match.group(1))

    @staticmethod
    def _meson_targets(content: str, buckets: dict[str, set[str]]) -> None:
        pattern = re.compile(r"(?im)\b(executable|library|static_library|shared_library)\s*\(\s*(['\"])([^'\"]+)\2")
        for match in pattern.finditer(content):
            kind, target = match.group(1), match.group(3)
            bucket = buckets["executables"] if kind == "executable" else buckets["libraries"]
            RepositoryInventory._add_target(bucket, target)

    @staticmethod
    def _cargo_targets(content: str, buckets: dict[str, set[str]], files: set[str]) -> None:
        try:
            manifest = tomllib.loads(content)
        except (tomllib.TOMLDecodeError, TypeError):
            return
        package = manifest.get("package") if isinstance(manifest, dict) else None
        package_name = package.get("name") if isinstance(package, dict) else None
        bins = manifest.get("bin", []) if isinstance(manifest, dict) else []
        if isinstance(bins, list):
            for target in bins:
                if isinstance(target, dict):
                    RepositoryInventory._add_target(buckets["executables"], target.get("name"))
        library = manifest.get("lib") if isinstance(manifest, dict) else None
        if isinstance(library, dict):
            RepositoryInventory._add_target(buckets["libraries"], library.get("name") or package_name)
        if isinstance(package_name, str) and isinstance(package, dict):
            if "src/main.rs" in files and package.get("autobins", True):
                RepositoryInventory._add_target(buckets["executables"], package_name)
            if "src/lib.rs" in files and package.get("autolib", True) and not isinstance(library, dict):
                RepositoryInventory._add_target(buckets["libraries"], package_name.replace("-", "_"))

    @staticmethod
    def _compile_command_targets(commands: list[str], buckets: dict[str, set[str]]) -> None:
        for command in commands:
            try:
                arguments = shlex.split(command)
            except ValueError:
                continue
            if "-c" in arguments:
                continue
            try:
                output = arguments[arguments.index("-o") + 1]
            except (ValueError, IndexError):
                continue
            name = Path(output).name
            if "-shared" in arguments or re.search(r"\.(?:a|so(?:\.\d+)*|dylib|dll|lib)$", name):
                RepositoryInventory._add_target(buckets["libraries"], RepositoryInventory._library_name(name))
            else:
                RepositoryInventory._add_target(buckets["executables"], name)

    @staticmethod
    def _make_targets(content: str, buckets: dict[str, set[str]]) -> None:
        lines = list(islice(io.StringIO(content), MAX_MANIFEST_LINES))
        ignored = {"all", "clean", "install", "uninstall", "check", "test", "help", ".PHONY"}
        for index, line in enumerate(lines[:-1]):
            match = re.fullmatch(r"([A-Za-z0-9_.+-]+)\s*:[^=]*\r?\n?", line)
            if match is None or match.group(1) in ignored:
                continue
            target = match.group(1)
            recipe = lines[index + 1].strip()
            if not lines[index + 1].startswith("\t"):
                continue
            if re.search(r"\.(?:a|so|dylib|dll|lib)$", target) and re.search(r"(?:\$\((?:AR|CC|CXX)\)|\bar\b|\blibtool\b|\bclang\b|\bgcc\b)", recipe):
                RepositoryInventory._add_target(buckets["libraries"], RepositoryInventory._library_name(target))
            elif re.search(r"(?:\$\((?:CC|CXX)\)|\bcc\b|\bgcc\b|\bclang(?:\+\+)?\b|\brustc\b)", recipe) and ("$@" in recipe or re.search(rf"(?:^|\s)-o\s+{re.escape(target)}(?:\s|$)", recipe)):
                RepositoryInventory._add_target(buckets["executables"], target)

    @staticmethod
    def _gradle_targets(content: str, buckets: dict[str, set[str]]) -> None:
        pattern = re.compile(r"tasks\.register\s*\(\s*(['\"])([^'\"]+)\1\s*,\s*(LinkExecutable|LinkSharedLibrary|LinkStaticLibrary)\b")
        for match in pattern.finditer(content):
            target, task_type = match.group(2), match.group(3)
            bucket = buckets["executables"] if task_type == "LinkExecutable" else buckets["libraries"]
            RepositoryInventory._add_target(bucket, target)

    @staticmethod
    def _library_name(value: str) -> str:
        name = re.sub(r"\.(?:a|so(?:\.\d+)*|dylib|dll|lib)$", "", Path(value).name)
        return name[3:] if name.startswith("lib") else name

    @staticmethod
    def _add_target(bucket: set[str], value: object) -> None:
        if (
            len(bucket) < MAX_TARGETS_PER_KIND
            and isinstance(value, str)
            and re.fullmatch(r"[A-Za-z0-9_.:+-]{1,128}", value) is not None
        ):
            bucket.add(value)

    @staticmethod
    def _looks_like_fuzz_harness(path: Path, content: str) -> bool:
        return "fuzz" in path.as_posix().casefold() or "LLVMFuzzerTestOneInput" in content
