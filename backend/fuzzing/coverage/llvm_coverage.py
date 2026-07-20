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


class CoverageIntegrityError(ValueError):
    """Raised when coverage cannot be bound to clean, immutable project source."""


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


class CoverageExecutor(Protocol):
    def run(
        self,
        image_id: str,
        command: tuple[str, ...],
        environment: dict[str, str],
        profile_directory: Path,
        input_file: Path | None = None,
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

    def run(self, image_id, command, environment, profile_directory, input_file=None) -> bytes:
        if not isinstance(command, tuple) or not 1 <= len(command) <= 256:
            raise ValueError("coverage command argument count is invalid")
        if any(not isinstance(argument, str) or not argument or len(argument.encode()) > 4096 for argument in command):
            raise ValueError("coverage command argument is invalid")
        if sum(len(argument.encode()) for argument in command) > 1024 * 1024:
            raise ValueError("coverage command arguments exceed their byte limit")
        if Path(command[0]).name.lower() in {"sh", "bash", "dash", "zsh", "fish"}:
            raise ValueError("coverage command cannot use a shell")
        if not isinstance(environment, dict) or set(environment) - {"LLVM_PROFILE_FILE"} or any(
            not isinstance(value, str) or len(value) > 4096 for value in environment.values()
        ):
            raise ValueError("coverage environment is invalid")
        profile_directory = Path(os.path.abspath(profile_directory))
        if profile_directory.is_symlink() or not profile_directory.is_dir():
            raise CoverageIntegrityError("profile directory is not a regular directory")
        volumes = {str(profile_directory): {"bind": "/coverage/profiles", "mode": "rw"}}
        if input_file is not None:
            input_file = Path(os.path.abspath(input_file))
            if input_file.is_symlink() or not input_file.is_file():
                raise CoverageIntegrityError("coverage input is not a regular file")
            volumes[str(input_file)] = {"bind": "/coverage/input", "mode": "ro"}
        user_id, group_id = _unprivileged_user()
        container = self._client.containers.create(
            image_id,
            list(command),
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
        try:
            container.start()
            result = container.wait(timeout=self._timeout)
            if int(result["StatusCode"]) != 0:
                raise CoverageIntegrityError("clean coverage command failed")
            output = bytearray()
            for chunk in container.logs(stdout=True, stderr=False, stream=True, follow=False):
                encoded = chunk if isinstance(chunk, bytes) else str(chunk).encode("utf-8", errors="replace")
                if len(output) + len(encoded) > self._output_limit:
                    raise CoverageIntegrityError("clean coverage output exceeded its byte limit")
                output.extend(encoded)
            return bytes(output)
        finally:
            try:
                container.remove(force=True)
            except Exception:
                pass


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
                command = tuple("/coverage/input" if value == "{input}" else value for value in campaign.replay_command)
                profile_pattern = f"/coverage/profiles/{stem}-%p.profraw"
                self._executor.run(image["id"], command, {"LLVM_PROFILE_FILE": profile_pattern}, profile_dir, input_path)
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
                per_input.append((content, digest, self._parse_export(exported, campaign)))
                destination = aggregate / profdata
                self._copy_regular(profile_dir / profdata, destination)
                merged_profiles.append(f"/coverage/profiles/{profdata}")

            merged_lines: tuple[CoverageLine, ...] = ()
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
                merged_lines = self._parse_export(exported, campaign)

            merged_lines = self._bind_clean_sources(merged_lines, campaign, image["id"], aggregate)
            first_hits: dict[tuple[str, int], CoverageHit] = {}
            for content, digest, lines in per_input:
                for line in lines:
                    first_hits.setdefault(
                        (line.source_path, line.line_number),
                        CoverageHit(line.source_path, line.line_number, content, digest),
                    )
            merged_keys = {(line.source_path, line.line_number) for line in merged_lines}
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
                lines=merged_lines,
                hits=tuple(first_hits[key] for key in sorted(first_hits) if key in merged_keys),
            )
        finally:
            shutil.rmtree(work)

    def _bind_clean_sources(self, lines, campaign, image_id, profile_directory):
        hashes: dict[str, str] = {}
        allowed = {path.name for path in profile_directory.iterdir()}
        manifest = self._profile_manifest(profile_directory, tuple(sorted(allowed)))
        for source_path in sorted({line.source_path for line in lines}):
            image_path = str(PurePosixPath(campaign.source_root) / PurePosixPath(source_path))
            clean_content = self._executor.run(image_id, ("cat", image_path), {}, profile_directory)
            self._require_profile_directory(profile_directory, allowed)
            self._require_profile_manifest(profile_directory, manifest)
            local_content = self._read_project_source(campaign.repository_root, source_path)
            if clean_content != local_content:
                raise CoverageIntegrityError("checkout source does not match the exact clean image")
            hashes[source_path] = sha256(clean_content).hexdigest()
        return tuple(
            CoverageLine(line.source_path, line.line_number, line.function_name, hashes[line.source_path])
            for line in lines
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
            "bigeye.configuration-asset-id": "" if campaign.configuration_asset_id is None else str(campaign.configuration_asset_id),
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
        if command.count("{input}") != 1:
            raise ValueError("coverage replay command must contain one input placeholder")

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

    def _parse_export(self, content: bytes, campaign) -> tuple[CoverageLine, ...]:
        try:
            document = json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as error:
            raise CoverageIntegrityError("llvm-cov returned invalid JSON") from error
        if not isinstance(document, dict) or not isinstance(document.get("data"), list):
            raise CoverageIntegrityError("llvm-cov returned an invalid document")
        functions: dict[str, list[tuple[int, int, str]]] = {}
        covered: set[tuple[str, int]] = set()
        for unit in document["data"]:
            if not isinstance(unit, dict):
                raise CoverageIntegrityError("llvm-cov returned an invalid data unit")
            for function in unit.get("functions", ()):
                self._collect_function(functions, function, campaign)
            for source in unit.get("files", ()):
                if not isinstance(source, dict):
                    continue
                relative = self._source_path(source.get("filename"), campaign)
                if relative is None:
                    continue
                for line in self._segment_lines(source.get("segments", ())):
                    covered.add((relative, line))
                    if len(covered) > 2_000_000:
                        raise CoverageIntegrityError("llvm-cov line evidence exceeds its limit")
        result = []
        for path, line in sorted(covered):
            names = [name for start, end, name in functions.get(path, ()) if start <= line <= end]
            result.append(CoverageLine(path, line, min(names) if names else None))
        return tuple(result)

    @staticmethod
    def _segment_lines(segments):
        maximum_lines = 2_000_000
        if not isinstance(segments, list) or len(segments) > maximum_lines:
            raise CoverageIntegrityError("llvm-cov segments are invalid or unbounded")
        spans = []
        expanded = 0
        for index, segment in enumerate(segments):
            if not isinstance(segment, list) or len(segment) < 6:
                raise CoverageIntegrityError("llvm-cov segment is invalid")
            line, column, count, has_count, _entry, gap = segment[:6]
            if (
                type(line) is not int or type(column) is not int
                or not 1 <= line <= maximum_lines or not 1 <= column <= maximum_lines
                or isinstance(count, bool) or not isinstance(count, (int, float)) or not math.isfinite(count)
                or type(has_count) is not bool or type(gap) is not bool
            ):
                raise CoverageIntegrityError("llvm-cov segment coordinates are invalid")
            if has_count is not True or count <= 0 or gap is True:
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
            if end >= line:
                span = end - line + 1
                if span > maximum_lines - expanded:
                    raise CoverageIntegrityError("llvm-cov covered span exceeds its limit")
                spans.append((line, end))
                expanded += span
        result = set()
        for line, end in spans:
            result.update(range(line, end + 1))
        return result

    def _collect_function(self, collected, function, campaign):
        if not isinstance(function, dict) or not isinstance(function.get("name"), str):
            return
        filenames = function.get("filenames")
        regions = function.get("regions")
        if not isinstance(filenames, list) or not isinstance(regions, list):
            return
        for region in regions:
            if not isinstance(region, list) or len(region) < 6:
                continue
            start, end, count, file_id = region[0], region[2], region[4], region[5]
            if (
                type(start) is not int or type(end) is not int or start < 1 or end < start
                or not isinstance(count, (int, float)) or count <= 0
                or type(file_id) is not int or not 0 <= file_id < len(filenames)
            ):
                continue
            relative = self._source_path(filenames[file_id], campaign)
            if relative is not None:
                collected.setdefault(relative, []).append((start, end, function["name"]))

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
        lowered = tuple(part.lower() for part in path.parts)
        if (
            path.suffix.lower() == ".patch"
            or lowered[0] in {".git", ".bigeye", "build", "generated", "harness", "fuzz-target", "fuzz_target"}
            or any(part.startswith("cmake-build") for part in lowered)
        ):
            return None
        try:
            _read_regular(Path(os.path.abspath(campaign.repository_root)).joinpath(*path.parts), 2 * 1024 * 1024)
        except (FileNotFoundError, NotADirectoryError, OSError, CoverageIntegrityError):
            return None
        return path.as_posix()

    @staticmethod
    def _read_project_source(root, source_path):
        return _read_regular(Path(os.path.abspath(root)).joinpath(*PurePosixPath(source_path).parts), 2 * 1024 * 1024)[0]


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
