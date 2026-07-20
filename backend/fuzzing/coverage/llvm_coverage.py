"""Replay admitted inputs against an exact clean image with LLVM coverage tools."""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import stat
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
from tempfile import mkdtemp
from typing import Protocol

from backend.fuzzing.campaigns.coverage_contract import (
    valid_replay_command_markers,
    valid_replay_environment,
)
from backend.fuzzing.coverage.source_paths import is_forbidden_source_path
from backend.fuzzing.docker.stdin import (
    MAX_STDIN_BYTES,
    close_attached_stdin,
    send_exact_stdin,
)


class CoverageIntegrityError(ValueError):
    """Raised when coverage cannot be bound to clean, immutable project source."""


_ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_FORBIDDEN_REPLAY_ENVIRONMENT = frozenset({"PATH", "PYTHONPATH"})
_MAX_FAILURE_STDERR_BYTES = 32 * 1_024


@dataclass(frozen=True)
class CoverageLine:
    source_path: str
    line_number: int
    function_name: str | None
    source_sha256: str | None = None


@dataclass(frozen=True)
class CoverageHit:
    source_path: str
    line_number: int
    testcase: bytes
    testcase_sha256: str


@dataclass(frozen=True)
class CoverageCount:
    covered: int
    total: int


@dataclass(frozen=True)
class CoverageBranch:
    source_path: str
    line_number: int
    start_column: int
    end_line: int
    end_column: int
    branch_index: int
    outcome_index: int
    covered: bool


@dataclass(frozen=True)
class CoverageFunction:
    source_path: str
    function_name: str
    start_line: int
    start_column: int
    covered: bool


@dataclass(frozen=True)
class CoverageSummary:
    lines: CoverageCount | None
    functions: CoverageCount | None
    branches: CoverageCount | None


@dataclass(frozen=True)
class CoverageSourceSummary:
    source_path: str
    source_sha256: str | None
    lines: CoverageCount | None
    functions: CoverageCount | None
    branches: CoverageCount | None


@dataclass(frozen=True)
class ParsedCoverage:
    lines: tuple[CoverageLine, ...]
    functions: tuple[CoverageFunction, ...]
    branches: tuple[CoverageBranch, ...]
    summary: CoverageSummary
    source_summaries: tuple[CoverageSourceSummary, ...]

    def __iter__(self):
        return iter(self.lines)

    def __len__(self):
        return len(self.lines)

    def __getitem__(self, index):
        return self.lines[index]


@dataclass(frozen=True)
class CoverageSnapshot:
    project_id: int
    campaign_id: int
    strategy_asset_id: int
    commit_sha: str
    clean_image_id: str
    clean_content_hash: str
    clean_parent_image_id: str
    target_asset_id: int
    configuration_asset_id: int | None
    coverage_asset_id: int
    replay_command: tuple[str, ...]
    cpu_exposure_seconds: float
    build_kind: str
    lines: tuple[CoverageLine, ...]
    hits: tuple[CoverageHit, ...]
    replay_environment: tuple[tuple[str, str], ...]
    functions: tuple[CoverageFunction, ...] = ()
    branches: tuple[CoverageBranch, ...] = ()
    summary: CoverageSummary = CoverageSummary(None, None, None)
    source_summaries: tuple[CoverageSourceSummary, ...] = ()


class CoverageExecutor(Protocol):
    def run(
        self,
        image_id: str,
        command: tuple[str, ...],
        environment: dict[str, str],
        profile_directory: Path,
        input_file: Path | None = None,
        stdin_bytes: bytes | None = None,
    ) -> bytes: ...


class DockerCoverageExecutor:
    """Run one bounded command with only profiles writable and one optional input read-only."""

    def __init__(self, client, timeout_seconds: int = 120, output_limit_bytes: int = 128 * 1024 * 1024):
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 600:
            raise ValueError("coverage timeout must be between 1 and 600 seconds")
        if type(output_limit_bytes) is not int or not 1 <= output_limit_bytes <= 256 * 1024 * 1024:
            raise ValueError("coverage output limit is invalid")
        self._client = client
        self._timeout = timeout_seconds
        self._output_limit = output_limit_bytes

    def run(
        self, image_id, command, environment, profile_directory, input_file=None,
        stdin_bytes=None,
    ) -> bytes:
        if not isinstance(command, tuple) or not 1 <= len(command) <= 256:
            raise ValueError("coverage command argument count is invalid")
        if any(not isinstance(argument, str) or not argument or len(argument.encode()) > 4096 for argument in command):
            raise ValueError("coverage command argument is invalid")
        if sum(len(argument.encode()) for argument in command) > 1024 * 1024:
            raise ValueError("coverage command arguments exceed their byte limit")
        if Path(command[0]).name.lower() in {"sh", "bash", "dash", "zsh", "fish"}:
            raise ValueError("coverage command cannot use a shell")
        if not _valid_coverage_environment(environment):
            raise ValueError("coverage environment is invalid")
        profile_directory = Path(os.path.abspath(profile_directory))
        if profile_directory.is_symlink() or not profile_directory.is_dir():
            raise CoverageIntegrityError("profile directory is not a regular directory")
        volumes = {str(profile_directory): {"bind": "/coverage/profiles", "mode": "rw"}}
        if stdin_bytes is not None and (
            not isinstance(stdin_bytes, bytes) or len(stdin_bytes) > MAX_STDIN_BYTES
            or input_file is not None
        ):
            raise ValueError("coverage stdin is invalid or conflicts with a file input")
        if input_file is not None:
            input_file = Path(os.path.abspath(input_file))
            if input_file.is_symlink() or not input_file.is_file():
                raise CoverageIntegrityError("coverage input is not a regular file")
            volumes[str(input_file)] = {"bind": "/coverage/input", "mode": "ro"}
        user_id, group_id = _unprivileged_user()
        options = dict(
            platform="linux/amd64",
            network_disabled=True,
            network_mode="none",
            ipc_mode="private",
            cgroupns="private",
            runtime="runc",
            restart_policy={"Name": "no"},
            publish_all_ports=False,
            privileged=False,
            read_only=True,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges"],
            pids_limit=128,
            mem_limit="1g",
            nano_cpus=1_000_000_000,
            tmpfs={"/tmp": "rw,nosuid,nodev,noexec,size=64m,mode=1777"},
            volumes=volumes,
            environment=environment,
            user=f"{user_id}:{group_id}",
            auto_remove=False,
            detach=True,
        )
        if stdin_bytes is not None:
            options.update({"detach": False, "stdin_open": True, "tty": False})
        container = self._client.containers.create(
            image_id,
            list(command),
            **options,
        )
        attached = None
        try:
            if stdin_bytes is not None:
                attached = container.attach_socket(params={"stdin": 1, "stream": 1})
            container.start()
            if attached is not None:
                send_exact_stdin(attached, stdin_bytes, self._timeout)
            result = container.wait(timeout=self._timeout)
            exit_code = int(result["StatusCode"])
            if exit_code != 0:
                stderr, truncated, unavailable = _bounded_failure_stderr(container)
                raise CoverageIntegrityError(
                    _coverage_failure_diagnostic(exit_code, stderr, truncated, unavailable)
                )
            output = bytearray()
            for chunk in container.logs(stdout=True, stderr=False, stream=True, follow=False):
                encoded = chunk if isinstance(chunk, bytes) else str(chunk).encode("utf-8", errors="replace")
                if len(output) + len(encoded) > self._output_limit:
                    raise CoverageIntegrityError("clean coverage output exceeded its byte limit")
                output.extend(encoded)
            return bytes(output)
        finally:
            if attached is not None:
                close_attached_stdin(attached)
            try:
                container.remove(force=True)
            except Exception:
                pass


def _bounded_failure_stderr(container) -> tuple[bytes, bool, bool]:
    output = bytearray()
    truncated = False
    try:
        for chunk in container.logs(stdout=False, stderr=True, stream=True, follow=False):
            encoded = (
                chunk if isinstance(chunk, bytes)
                else str(chunk).encode("utf-8", errors="replace")
            )
            remaining = _MAX_FAILURE_STDERR_BYTES - len(output)
            if len(encoded) > remaining:
                output.extend(encoded[:remaining])
                truncated = True
                break
            output.extend(encoded)
    except Exception:
        return bytes(output), truncated, True
    return bytes(output), truncated, False


def _coverage_failure_diagnostic(
    exit_code: int, stderr: bytes, truncated: bool, unavailable: bool,
) -> str:
    text = stderr.decode("utf-8", errors="replace")
    labels = []
    for marker, label in (
        ("AddressSanitizer", "AddressSanitizer"),
        ("UndefinedBehaviorSanitizer", "UndefinedBehaviorSanitizer"),
        ("LeakSanitizer", "LeakSanitizer"),
        ("MemorySanitizer", "MemorySanitizer"),
        ("ThreadSanitizer", "ThreadSanitizer"),
        ("runtime error:", "undefined-behaviour runtime error"),
        ("Failed spawning a tracer thread", "sanitizer tracer thread unavailable"),
    ):
        if marker in text:
            labels.append(label)
    if truncated:
        labels.append("stderr truncated")
    if unavailable:
        labels.append("stderr unavailable")
    detail = "; ".join(labels) if labels else "stderr withheld"
    return f"clean coverage command failed (exit {exit_code}; {detail})"


class LlvmCoverage:
    """Produce line evidence only from a verified clean image and isolated inputs."""

    def __init__(self, client, executor: CoverageExecutor, workspace: Path, max_inputs: int = 10_000):
        if type(max_inputs) is not int or not 1 <= max_inputs <= 100_000:
            raise ValueError("coverage input limit must be between 1 and 100000")
        self._client = client
        self._executor = executor
        self._workspace = Path(os.path.abspath(workspace))
        self._max_inputs = max_inputs

    def replay(self, campaign, inputs) -> CoverageSnapshot:
        self._validate_campaign(campaign)
        image = self._verify_clean_image(campaign)
        values = tuple(inputs)
        if len(values) > self._max_inputs:
            raise ValueError("coverage input limit exceeded")
        work = Path(mkdtemp(prefix=f"campaign-{campaign.id}-", dir=self._prepare_workspace()))
        try:
            aggregate = work / "aggregate"
            aggregate.mkdir(mode=0o700)
            per_input: list[tuple[bytes, str, tuple[CoverageLine, ...]]] = []
            merged_profiles: list[str] = []
            for index, source in enumerate(values):
                replay_root = work / f"replay-{index:06d}"
                replay_root.mkdir(mode=0o700)
                profile_dir = replay_root / "profiles"
                profile_dir.mkdir(mode=0o700)
                content, digest, input_path, input_identity = self._stage_input(source, replay_root)
                stem = f"input-{index:06d}"
                stdin_mode = "{stdin}" in campaign.replay_command
                command = tuple(
                    "/coverage/input" if value == "{input}" else value
                    for value in campaign.replay_command if value != "{stdin}"
                )
                profile_pattern = f"/coverage/profiles/{stem}-%p.profraw"
                replay_environment = dict(campaign.replay_environment)
                replay_environment["LLVM_PROFILE_FILE"] = profile_pattern
                if stdin_mode:
                    self._executor.run(
                        image["id"], command, replay_environment, profile_dir,
                        stdin_bytes=content,
                    )
                else:
                    self._executor.run(
                        image["id"], command, replay_environment, profile_dir, input_path,
                    )
                self._require_file(input_path, input_identity, digest)
                raw_names = self._profile_names(profile_dir, stem)
                raw_manifest = self._profile_manifest(profile_dir, raw_names)
                profdata = f"{stem}.profdata"
                self._executor.run(
                    image["id"],
                    ("llvm-profdata-18", "merge", "-sparse", *(f"/coverage/profiles/{name}" for name in raw_names),
                     "-o", f"/coverage/profiles/{profdata}"),
                    {},
                    profile_dir,
                )
                self._require_profile_directory(profile_dir, {*raw_names, profdata})
                self._require_profile_manifest(profile_dir, raw_manifest)
                replay_manifest = self._profile_manifest(profile_dir, (*raw_names, profdata))
                exported = self._executor.run(
                    image["id"],
                    ("llvm-cov-18", "export", campaign.binary_path,
                     f"-instr-profile=/coverage/profiles/{profdata}"),
                    {},
                    profile_dir,
                )
                self._require_profile_directory(profile_dir, {*raw_names, profdata})
                self._require_profile_manifest(profile_dir, replay_manifest)
                per_input.append((content, digest, self._parse_export(exported, campaign).lines))
                destination = aggregate / profdata
                self._copy_regular(profile_dir / profdata, destination)
                merged_profiles.append(f"/coverage/profiles/{profdata}")

            merged = ParsedCoverage((), (), (), CoverageSummary(None, None, None), ())
            if merged_profiles:
                self._require_profile_directory(aggregate, {Path(name).name for name in merged_profiles})
                aggregate_manifest = self._profile_manifest(
                    aggregate, tuple(Path(name).name for name in merged_profiles)
                )
                self._executor.run(
                    image["id"],
                    ("llvm-profdata-18", "merge", "-sparse", *merged_profiles,
                     "-o", "/coverage/profiles/merged.profdata"),
                    {},
                    aggregate,
                )
                self._require_profile_directory(
                    aggregate, {Path(name).name for name in merged_profiles} | {"merged.profdata"}
                )
                self._require_profile_manifest(aggregate, aggregate_manifest)
                merged_manifest = self._profile_manifest(
                    aggregate, tuple(Path(name).name for name in merged_profiles) + ("merged.profdata",)
                )
                exported = self._executor.run(
                    image["id"],
                    ("llvm-cov-18", "export", campaign.binary_path,
                     "-instr-profile=/coverage/profiles/merged.profdata"),
                    {},
                    aggregate,
                )
                self._require_profile_manifest(aggregate, merged_manifest)
                merged = self._parse_export(exported, campaign)

            merged = self._bind_clean_sources(merged, campaign, image["id"], aggregate)
            first_hits: dict[tuple[str, int], CoverageHit] = {}
            for content, digest, lines in per_input:
                for line in lines:
                    first_hits.setdefault(
                        (line.source_path, line.line_number),
                        CoverageHit(line.source_path, line.line_number, content, digest),
                    )
            merged_keys = {(line.source_path, line.line_number) for line in merged.lines}
            return CoverageSnapshot(
                project_id=campaign.project_id,
                campaign_id=campaign.id,
                strategy_asset_id=campaign.strategy_asset_id,
                commit_sha=campaign.commit_sha,
                clean_image_id=image["id"],
                clean_content_hash=image["content_hash"],
                clean_parent_image_id=image["parent_id"],
                target_asset_id=campaign.target_asset_id,
                configuration_asset_id=campaign.configuration_asset_id,
                coverage_asset_id=campaign.coverage_asset_id,
                replay_command=tuple(campaign.replay_command),
                cpu_exposure_seconds=float(campaign.cpu_exposure_seconds),
                build_kind="clean",
                lines=merged.lines,
                hits=tuple(first_hits[key] for key in sorted(first_hits) if key in merged_keys),
                replay_environment=campaign.replay_environment,
                functions=merged.functions,
                branches=merged.branches,
                summary=merged.summary,
                source_summaries=merged.source_summaries,
            )
        finally:
            shutil.rmtree(work)

    def _bind_clean_sources(self, parsed, campaign, image_id, profile_directory):
        hashes: dict[str, str] = {}
        allowed = {path.name for path in profile_directory.iterdir()}
        manifest = self._profile_manifest(profile_directory, tuple(sorted(allowed)))
        source_paths = {
            *(line.source_path for line in parsed.lines),
            *(function.source_path for function in parsed.functions),
            *(branch.source_path for branch in parsed.branches),
            *(summary.source_path for summary in parsed.source_summaries),
        }
        for source_path in sorted(source_paths):
            image_path = str(PurePosixPath(campaign.source_root) / PurePosixPath(source_path))
            clean_content = self._executor.run(image_id, ("cat", image_path), {}, profile_directory)
            self._require_profile_directory(profile_directory, allowed)
            self._require_profile_manifest(profile_directory, manifest)
            local_content = self._read_project_source(campaign.repository_root, source_path)
            if clean_content != local_content:
                raise CoverageIntegrityError("checkout source does not match the exact clean image")
            hashes[source_path] = sha256(clean_content).hexdigest()
        return ParsedCoverage(
            tuple(
                CoverageLine(line.source_path, line.line_number, line.function_name, hashes[line.source_path])
                for line in parsed.lines
            ),
            parsed.functions,
            parsed.branches,
            parsed.summary,
            tuple(
                CoverageSourceSummary(
                    summary.source_path, hashes[summary.source_path],
                    summary.lines, summary.functions, summary.branches,
                )
                for summary in parsed.source_summaries
            ),
        )

    def _prepare_workspace(self) -> str:
        self._workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        return str(self._workspace)

    def _verify_clean_image(self, campaign):
        data = self._client.api.inspect_image(campaign.clean_image)
        labels = data.get("Config", {}).get("Labels", {})
        expected = {
            "bigeye.project": str(campaign.project_id),
            "bigeye.commit": campaign.commit_sha,
            "bigeye.layer": "coverage",
            "bigeye.content-hash": campaign.clean_content_hash,
            "bigeye.parent-image": campaign.clean_parent_image_id,
            "bigeye.target-asset-id": str(campaign.target_asset_id),
            "bigeye.configuration-asset-id": (
                "" if campaign.clean_build_configuration_asset_id is None
                else str(campaign.clean_build_configuration_asset_id)
            ),
            "bigeye.coverage-asset-id": str(campaign.coverage_asset_id),
        }
        if data.get("Os") != "linux" or data.get("Architecture") != "amd64":
            raise CoverageIntegrityError("clean coverage image must be linux/amd64")
        if not isinstance(labels, dict) or any(labels.get(key) != value for key, value in expected.items()):
            raise CoverageIntegrityError("coverage image provenance does not match the requested clean build")
        if data.get("Id") != campaign.clean_image_id:
            raise CoverageIntegrityError("coverage image ID does not match the immutable request")
        return {"id": campaign.clean_image_id, "content_hash": labels["bigeye.content-hash"], "parent_id": labels["bigeye.parent-image"]}

    @staticmethod
    def _validate_campaign(campaign) -> None:
        identifiers = (
            campaign.id, campaign.project_id, campaign.target_asset_id,
            campaign.strategy_asset_id, campaign.coverage_asset_id,
        )
        if any(type(value) is not int or value <= 0 for value in identifiers):
            raise ValueError("coverage identities must be positive integers")
        if campaign.configuration_asset_id is not None and (
            type(campaign.configuration_asset_id) is not int or campaign.configuration_asset_id <= 0
        ):
            raise ValueError("configuration asset ID must be a positive integer")
        clean_configuration = getattr(campaign, "clean_build_configuration_asset_id", None)
        if (
            clean_configuration is not None
            and (type(clean_configuration) is not int or clean_configuration <= 0)
            or (campaign.configuration_asset_id is None) != (clean_configuration is None)
        ):
            raise ValueError("clean build configuration asset ID is invalid")
        _require_hex(campaign.commit_sha, {40, 64}, "coverage commit")
        _require_hex(campaign.clean_content_hash, {64}, "coverage content hash")
        _require_image_id(campaign.clean_image_id, "clean image ID")
        _require_image_id(campaign.clean_parent_image_id, "clean parent image ID")
        binary = _normalised_absolute(campaign.binary_path, "coverage binary")
        source_root = _normalised_absolute(campaign.source_root, "coverage source root")
        if source_root == "/":
            raise ValueError("coverage source root cannot be the filesystem root")
        command = campaign.replay_command
        if not isinstance(command, tuple) or not 2 <= len(command) <= 64:
            raise ValueError("coverage replay argument count is invalid")
        if any(not isinstance(value, str) or not value or len(value.encode()) > 4096 for value in command):
            raise ValueError("coverage replay argument is invalid")
        if sum(len(value.encode()) for value in command) > 16 * 1024:
            raise ValueError("coverage replay arguments exceed their byte limit")
        if command[0] != binary:
            raise ValueError("coverage replay binary must exactly match the clean binary")
        if not valid_replay_command_markers(command):
            raise ValueError("coverage replay command must contain one input marker")
        try:
            replay_environment_items = campaign.replay_environment
        except AttributeError as error:
            raise ValueError("coverage replay environment is required") from error
        if not valid_replay_environment(replay_environment_items):
            raise ValueError("coverage replay environment is invalid")
        replay_environment = dict(replay_environment_items)
        if (
            "LLVM_PROFILE_FILE" in replay_environment
            or not _valid_coverage_environment(replay_environment)
        ):
            raise ValueError("coverage replay environment is invalid")

    @staticmethod
    def _stage_input(source, replay_root):
        content, identity = _read_regular(Path(os.path.abspath(source)), 16 * 1024 * 1024)
        digest = sha256(content).hexdigest()
        target = replay_root / f"{digest}.input"
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        try:
            _write_all(descriptor, content)
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
            target_identity = _file_identity(os.fstat(descriptor))
        finally:
            os.close(descriptor)
        del identity
        return content, digest, target, target_identity

    @staticmethod
    def _require_file(path, identity, digest):
        content, current = _read_regular(path, 16 * 1024 * 1024)
        if current != identity or sha256(content).hexdigest() != digest:
            raise CoverageIntegrityError("coverage input changed during replay")

    @staticmethod
    def _profile_names(directory, stem):
        pattern = re.compile(rf"{re.escape(stem)}-[0-9]+\.profraw")
        names = LlvmCoverage._require_profile_directory(directory, None)
        if not names or len(names) > 64 or any(pattern.fullmatch(name) is None for name in names):
            raise CoverageIntegrityError("clean replay produced unexpected LLVM profile files")
        return tuple(sorted(names))

    @staticmethod
    def _require_profile_directory(directory, allowed):
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            names = []
            total = 0
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    names.append(entry.name)
                    details = os.stat(entry.name, dir_fd=descriptor, follow_symlinks=False)
                    if not stat.S_ISREG(details.st_mode) or details.st_size > 128 * 1024 * 1024:
                        raise CoverageIntegrityError("LLVM profile output is not a bounded regular file")
                    total += details.st_size
            if len(names) > 256 or (allowed is not None and set(names) != set(allowed)):
                raise CoverageIntegrityError("LLVM profile directory contains unexpected output")
            if total > 512 * 1024 * 1024:
                raise CoverageIntegrityError("LLVM profile output exceeds its total byte limit")
            return tuple(names)
        finally:
            os.close(descriptor)

    @staticmethod
    def _profile_manifest(directory, names):
        manifest = {}
        for name in names:
            content, identity = _read_regular(directory / name, 128 * 1024 * 1024)
            manifest[name] = (identity, sha256(content).hexdigest())
        return manifest

    @staticmethod
    def _require_profile_manifest(directory, manifest):
        for name, (identity, digest) in manifest.items():
            content, current = _read_regular(directory / name, 128 * 1024 * 1024)
            if current != identity or sha256(content).hexdigest() != digest:
                raise CoverageIntegrityError("LLVM profile changed during coverage processing")

    @staticmethod
    def _copy_regular(source, destination):
        content, _ = _read_regular(source, 128 * 1024 * 1024)
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        try:
            _write_all(descriptor, content)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _parse_export(self, content: bytes, campaign) -> ParsedCoverage:
        try:
            document = json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as error:
            raise CoverageIntegrityError("llvm-cov returned invalid JSON") from error
        if not isinstance(document, dict) or not isinstance(document.get("data"), list):
            raise CoverageIntegrityError("llvm-cov returned an invalid document")
        function_regions: dict[str, list[tuple[int, int, str]]] = {}
        function_inventory: set[tuple[str, str, int, int, bool]] = set()
        line_inventory: dict[tuple[str, int], bool] = {}
        branches: dict[tuple[str, int, int, int, int, int, int], bool] = {}
        source_counts: dict[str, dict[str, CoverageCount | None]] = {}
        sources_with_summary: set[str] = set()
        branches_available = False
        branches_malformed = False
        functions_available = False
        lines_available = False
        for unit in document["data"]:
            if not isinstance(unit, dict):
                raise CoverageIntegrityError("llvm-cov returned an invalid data unit")
            unit_functions = unit.get("functions")
            if isinstance(unit_functions, list):
                functions_available = True
                if len(unit_functions) > 100_000:
                    raise CoverageIntegrityError("llvm-cov functions exceed their limit")
                for function in unit_functions:
                    self._collect_function(
                        function_regions, function_inventory, function, campaign,
                    )
            for source in unit.get("files", ()):
                if not isinstance(source, dict):
                    continue
                relative = self._source_path(source.get("filename"), campaign)
                if relative is None:
                    continue
                exact_counts = self._file_summary(source.get("summary"))
                source_counts[relative] = exact_counts
                if isinstance(source.get("summary"), dict):
                    sources_with_summary.add(relative)
                segments = source.get("segments")
                segment_states = self._segment_line_states(segments) if isinstance(segments, list) else ()
                lines_available = lines_available or isinstance(segments, list)
                for line, covered in segment_states:
                    key = (relative, line)
                    line_inventory[key] = line_inventory.get(key, False) or covered
                    if len(line_inventory) > 2_000_000:
                        raise CoverageIntegrityError("llvm-cov line evidence exceeds its limit")
                if "branches" in source:
                    parsed_branches = self._branch_states(source["branches"])
                    if parsed_branches is None:
                        branches_malformed = True
                    else:
                        branches_available = True
                        for (line, start_column, end_line, end_column,
                             branch_index, outcome_index, covered) in parsed_branches:
                            key = (
                                relative, line, start_column, end_line, end_column,
                                branch_index, outcome_index,
                            )
                            branches[key] = branches.get(key, False) or covered
        result = []
        for (path, line), covered in sorted(line_inventory.items()):
            if not covered:
                continue
            names = [name for start, end, name in function_regions.get(path, ()) if start <= line <= end]
            result.append(CoverageLine(path, line, min(names) if names else None))
        function_records = tuple(
            CoverageFunction(path, name, line, column, covered)
            for path, name, line, column, covered in sorted(function_inventory)
        )
        branch_records = tuple(
            CoverageBranch(
                path, line, start_column, end_line, end_column,
                branch_index, outcome_index, covered,
            )
            for (path, line, start_column, end_line, end_column,
                 branch_index, outcome_index), covered
            in sorted(branches.items())
        ) if branches_available and not branches_malformed else ()
        paths = sorted(set(source_counts) | {path for path, _line in line_inventory} | {
            path for path, _name, _start, _column, _covered in function_inventory
        } | {path for path, *_identity in branches})
        source_summaries = []
        for path in paths:
            source_lines = [covered for (candidate, _line), covered in line_inventory.items() if candidate == path]
            source_functions = [
                covered for candidate, _name, _start, _column, covered in function_inventory if candidate == path
            ]
            source_branches = [
                covered for (candidate, *_identity), covered in branches.items() if candidate == path
            ]
            exact = source_counts.get(path, {})
            source_summaries.append(CoverageSourceSummary(
                path, None,
                exact.get("lines") if path in sources_with_summary else (
                    CoverageCount(sum(source_lines), len(source_lines)) if lines_available else None
                ),
                exact.get("functions") if path in sources_with_summary else (
                    CoverageCount(sum(source_functions), len(source_functions)) if functions_available else None
                ),
                None if branches_malformed else exact.get("branches"),
            ))
        line_count = _sum_source_counts(source_summaries, "lines")
        function_count = _sum_source_counts(source_summaries, "functions")
        branch_count = (
            _sum_source_counts(source_summaries, "branches") if not branches_malformed else None
        )
        return ParsedCoverage(
            tuple(result), function_records, branch_records,
            CoverageSummary(line_count, function_count, branch_count),
            tuple(source_summaries),
        )

    @staticmethod
    def _segment_lines(segments):
        return {
            line for line, covered in LlvmCoverage._segment_line_states(segments) if covered
        }

    @staticmethod
    def _segment_line_states(segments):
        maximum_lines = 2_000_000
        if not isinstance(segments, list) or len(segments) > maximum_lines:
            raise CoverageIntegrityError("llvm-cov segments are invalid or unbounded")
        spans = []
        expanded = 0
        for index, segment in enumerate(segments):
            if not isinstance(segment, list) or len(segment) < 6:
                raise CoverageIntegrityError("llvm-cov segment is invalid")
            line, column, count, has_count, entry, gap = segment[:6]
            if (
                type(line) is not int or type(column) is not int
                or not 1 <= line <= maximum_lines or not 1 <= column <= maximum_lines
                or isinstance(count, bool) or not isinstance(count, (int, float)) or not math.isfinite(count)
                or type(has_count) is not bool or type(entry) is not bool or type(gap) is not bool
            ):
                raise CoverageIntegrityError("llvm-cov segment coordinates are invalid")
            if has_count is not True or gap is True:
                continue
            end = line
            if index + 1 < len(segments):
                following = segments[index + 1]
                if not isinstance(following, list) or len(following) < 2:
                    raise CoverageIntegrityError("llvm-cov next segment is invalid")
                next_line, next_column = following[:2]
                if (
                    type(next_line) is not int or type(next_column) is not int
                    or not 1 <= next_line <= maximum_lines or not 1 <= next_column <= maximum_lines
                    or next_line < line or (next_line == line and next_column < column)
                ):
                    raise CoverageIntegrityError("llvm-cov next segment coordinates are invalid")
                end = next_line if next_column > 1 else next_line - 1
            start = line if entry else line + 1
            if end >= start:
                span = end - start + 1
                if span > maximum_lines - expanded:
                    raise CoverageIntegrityError("llvm-cov covered span exceeds its limit")
                spans.append((start, end, count > 0))
                expanded += span
        result: dict[int, bool] = {}
        for line, end, covered in spans:
            for line_number in range(line, end + 1):
                result[line_number] = result.get(line_number, False) or covered
        return tuple(sorted(result.items()))

    def _collect_function(self, collected, inventory, function, campaign):
        if not isinstance(function, dict) or not isinstance(function.get("name"), str):
            return
        filenames = function.get("filenames")
        regions = function.get("regions")
        if not isinstance(filenames, list) or not isinstance(regions, list):
            return
        function_count = function.get("count")
        if (
            isinstance(function_count, bool)
            or not isinstance(function_count, (int, float))
            or not math.isfinite(function_count)
        ):
            function_count = None
        identities = []
        for region in regions:
            if not isinstance(region, list) or len(region) < 6:
                continue
            start, start_column, end, count, file_id = (
                region[0], region[1], region[2], region[4], region[5]
            )
            if (
                type(start) is not int or type(start_column) is not int
                or type(end) is not int or start < 1 or start_column < 1 or end < start
                or isinstance(count, bool) or not isinstance(count, (int, float)) or not math.isfinite(count)
                or type(file_id) is not int or not 0 <= file_id < len(filenames)
            ):
                continue
            relative = self._source_path(filenames[file_id], campaign)
            if relative is not None:
                covered = (function_count if function_count is not None else count) > 0
                identities.append((relative, function["name"], start, start_column, covered))
                if covered:
                    collected.setdefault(relative, []).append((start, end, function["name"]))
        if identities:
            inventory.add(identities[0])

    @staticmethod
    def _branch_states(values):
        if not isinstance(values, list) or len(values) > 2_000_000:
            return None
        result = []
        coordinate_ordinals: dict[tuple[int, int, int, int], int] = {}
        for branch in values:
            if not isinstance(branch, list) or len(branch) < 9:
                return None
            start_line, start_column, end_line, end_column, true_count, false_count = branch[:6]
            if (
                type(start_line) is not int or type(start_column) is not int
                or type(end_line) is not int or type(end_column) is not int
                or not 1 <= start_line <= 2_000_000 or not 1 <= start_column <= 2_000_000
                or end_line < start_line or end_line > 2_000_000
                or not 1 <= end_column <= 2_000_000
                or isinstance(true_count, bool) or not isinstance(true_count, (int, float))
                or isinstance(false_count, bool) or not isinstance(false_count, (int, float))
                or not math.isfinite(true_count) or not math.isfinite(false_count)
                or true_count < 0 or false_count < 0
            ):
                return None
            coordinate = (start_line, start_column, end_line, end_column)
            branch_index = coordinate_ordinals.get(coordinate, 0)
            coordinate_ordinals[coordinate] = branch_index + 1
            result.extend((
                (start_line, start_column, end_line, end_column, branch_index, 0, true_count > 0),
                (start_line, start_column, end_line, end_column, branch_index, 1, false_count > 0),
            ))
        return tuple(result)

    @staticmethod
    def _file_summary(value):
        result = {"lines": None, "functions": None, "branches": None}
        if not isinstance(value, dict):
            return result
        for name in result:
            measurement = value.get(name)
            if not isinstance(measurement, dict):
                continue
            covered, total = measurement.get("covered"), measurement.get("count")
            if (
                type(covered) is int and type(total) is int
                and 0 <= covered <= total <= 2_000_000
            ):
                result[name] = CoverageCount(covered, total)
        return result

    @staticmethod
    def _source_path(filename, campaign):
        if not isinstance(filename, str) or not filename:
            return None
        source_root = PurePosixPath(campaign.source_root)
        path = PurePosixPath(filename)
        if path.is_absolute():
            try:
                path = path.relative_to(source_root)
            except ValueError:
                return None
        if not path.parts or any(part in {"", ".", ".."} for part in path.parts):
            return None
        if is_forbidden_source_path(path):
            return None
        try:
            _read_regular(Path(os.path.abspath(campaign.repository_root)).joinpath(*path.parts), 2 * 1024 * 1024)
        except (FileNotFoundError, NotADirectoryError, OSError, CoverageIntegrityError):
            return None
        return path.as_posix()

    @staticmethod
    def _read_project_source(root, source_path):
        return _read_regular(Path(os.path.abspath(root)).joinpath(*PurePosixPath(source_path).parts), 2 * 1024 * 1024)[0]


def _valid_coverage_environment(environment) -> bool:
    return (
        isinstance(environment, dict)
        and len(environment) <= 33
        and all(
            isinstance(key, str)
            and _ENVIRONMENT_NAME.fullmatch(key) is not None
            and key not in _FORBIDDEN_REPLAY_ENVIRONMENT
            and not key.startswith(("LD_", "DYLD_"))
            and isinstance(value, str)
            and bool(value)
            and "\x00" not in value
            and len(value) <= 4_096
            for key, value in environment.items()
        )
    )


def _sum_source_counts(summaries, name):
    values = [getattr(summary, name) for summary in summaries]
    if not values or any(value is None for value in values):
        return None
    return CoverageCount(
        sum(value.covered for value in values),
        sum(value.total for value in values),
    )


def _normalised_absolute(value, label):
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value:
        raise ValueError(f"{label} path is invalid")
    normalised = str(PurePosixPath(value))
    if normalised != value or ".." in PurePosixPath(value).parts:
        raise ValueError(f"{label} path is not normalized")
    return normalised


def _require_hex(value, lengths, label):
    if not isinstance(value, str) or len(value) not in lengths or any(char not in "0123456789abcdef" for char in value):
        raise ValueError(f"{label} is invalid")


def _require_image_id(value, label):
    if (
        not isinstance(value, str) or not value.startswith("sha256:") or len(value) != 71
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise ValueError(f"{label} is invalid")


def _read_regular(path, maximum):
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
                raise CoverageIntegrityError("file is not a bounded regular file")
            content = bytearray()
            while len(content) <= maximum:
                chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
            after = os.fstat(descriptor)
            if _file_identity(after) != _file_identity(before) or len(content) > maximum:
                raise CoverageIntegrityError("file changed while being read")
            return bytes(content), _file_identity(before)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)


def _write_all(descriptor, content):
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("file write did not progress")
        view = view[written:]


def _file_identity(details):
    return details.st_dev, details.st_ino, details.st_size, details.st_mtime_ns, details.st_ctime_ns


def _unprivileged_user():
    if os.getuid() == 0:
        return 65534, 65534
    return os.getuid(), os.getgid()
