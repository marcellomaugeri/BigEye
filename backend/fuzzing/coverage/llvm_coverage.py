"""Replay admitted inputs against the clean coverage image with LLVM tools."""

from __future__ import annotations

import json
import os
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
    target_asset_id: int
    configuration_asset_id: int | None
    replay_command: tuple[str, ...]
    cpu_exposure_seconds: float
    repository_root: Path
    build_kind: str
    lines: tuple[CoverageLine, ...]
    hits: tuple[CoverageHit, ...]


class CoverageExecutor(Protocol):
    def run(
        self,
        image_id: str,
        command: tuple[str, ...],
        environment: dict[str, str],
        workspace: Path,
    ) -> bytes: ...


class DockerCoverageExecutor:
    """Run short coverage commands in isolated linux/amd64 containers."""

    def __init__(self, client, timeout_seconds: int = 120):
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 600:
            raise ValueError("coverage timeout must be between 1 and 600 seconds")
        self._client = client
        self._timeout = timeout_seconds

    def run(self, image_id, command, environment, workspace) -> bytes:
        container = self._client.containers.create(
            image_id,
            list(command),
            platform="linux/amd64",
            network_disabled=True,
            network_mode="none",
            read_only=True,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges"],
            pids_limit=128,
            mem_limit="1g",
            nano_cpus=1_000_000_000,
            tmpfs={"/tmp": "rw,nosuid,nodev,size=64m,mode=1777"},
            volumes={str(workspace): {"bind": "/coverage", "mode": "rw"}},
            environment=environment,
            user=f"{os.getuid()}:{os.getgid()}",
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
                if len(output) + len(encoded) > 128 * 1024 * 1024:
                    raise CoverageIntegrityError("clean coverage output exceeded its byte limit")
                output.extend(encoded)
            return bytes(output)
        finally:
            try:
                container.remove(force=True)
            except Exception:
                pass


class LlvmCoverage:
    """Produce line evidence only from an exact clean coverage image."""

    def __init__(self, client, executor: CoverageExecutor, workspace: Path, max_inputs: int = 10_000):
        if type(max_inputs) is not int or not 1 <= max_inputs <= 100_000:
            raise ValueError("coverage input limit must be between 1 and 100000")
        self._client = client
        self._executor = executor
        self._workspace = Path(os.path.abspath(workspace))
        self._max_inputs = max_inputs

    def replay(self, campaign, inputs) -> CoverageSnapshot:
        image_id = self._verify_clean_image(campaign)
        values = tuple(inputs)
        if len(values) > self._max_inputs:
            raise ValueError("coverage input limit exceeded")
        self._validate_campaign(campaign)
        work = Path(mkdtemp(prefix=f"campaign-{campaign.id}-", dir=self._prepare_workspace()))
        try:
            (work / "inputs").mkdir(mode=0o700)
            (work / "profiles").mkdir(mode=0o700)
            held_inputs = tuple(self._stage_input(path, work / "inputs", index) for index, path in enumerate(values))
            per_input: list[tuple[bytes, str, tuple[CoverageLine, ...]]] = []
            raw_profiles: list[str] = []
            for index, (content, digest, container_path) in enumerate(held_inputs):
                stem = f"input-{index:06d}"
                profile_pattern = f"/coverage/profiles/{stem}-%p.profraw"
                command = tuple(
                    container_path if value == "{input}" else str(value)
                    for value in campaign.replay_command
                )
                self._executor.run(image_id, command, {"LLVM_PROFILE_FILE": profile_pattern}, work)
                matches = sorted((work / "profiles").glob(f"{stem}-*.profraw"))
                if not matches:
                    raise CoverageIntegrityError("clean replay produced no LLVM profile")
                raw = tuple(f"/coverage/profiles/{path.name}" for path in matches)
                raw_profiles.extend(raw)
                profdata = f"/coverage/profiles/{stem}.profdata"
                self._executor.run(
                    image_id,
                    ("llvm-profdata-18", "merge", "-sparse", *raw, "-o", profdata),
                    {},
                    work,
                )
                exported = self._executor.run(
                    image_id,
                    ("llvm-cov-18", "export", campaign.binary_path, f"-instr-profile={profdata}"),
                    {},
                    work,
                )
                per_input.append((content, digest, self._parse_export(exported, campaign)))

            merged_lines: tuple[CoverageLine, ...] = ()
            if raw_profiles:
                merged = "/coverage/profiles/merged.profdata"
                self._executor.run(
                    image_id,
                    ("llvm-profdata-18", "merge", "-sparse", *raw_profiles, "-o", merged),
                    {},
                    work,
                )
                exported = self._executor.run(
                    image_id,
                    ("llvm-cov-18", "export", campaign.binary_path, f"-instr-profile={merged}"),
                    {},
                    work,
                )
                merged_lines = self._parse_export(exported, campaign)

            merged_lines = self._bind_clean_sources(merged_lines, campaign, image_id, work)
            first_hits: dict[tuple[str, int], CoverageHit] = {}
            for content, digest, lines in per_input:
                for line in lines:
                    first_hits.setdefault(
                        (line.source_path, line.line_number),
                        CoverageHit(line.source_path, line.line_number, content, digest),
                    )
            merged_keys = {(line.source_path, line.line_number) for line in merged_lines}
            hits = tuple(first_hits[key] for key in sorted(first_hits) if key in merged_keys)
            return CoverageSnapshot(
                project_id=campaign.project_id,
                campaign_id=campaign.id,
                strategy_asset_id=campaign.strategy_asset_id,
                commit_sha=campaign.commit_sha,
                clean_image_id=image_id,
                target_asset_id=campaign.target_asset_id,
                configuration_asset_id=campaign.configuration_asset_id,
                replay_command=tuple(campaign.replay_command),
                cpu_exposure_seconds=float(campaign.cpu_exposure_seconds),
                repository_root=Path(campaign.repository_root),
                build_kind="clean",
                lines=merged_lines,
                hits=hits,
            )
        finally:
            shutil.rmtree(work)

    def _bind_clean_sources(self, lines, campaign, image_id, work):
        hashes: dict[str, str] = {}
        for source_path in sorted({line.source_path for line in lines}):
            image_path = str(PurePosixPath(str(campaign.source_root)) / PurePosixPath(source_path))
            clean_content = self._executor.run(image_id, ("cat", image_path), {}, work)
            local_content = self._read_project_source(campaign.repository_root, source_path)
            if clean_content != local_content:
                raise CoverageIntegrityError("checkout source does not match the exact clean image")
            hashes[source_path] = sha256(clean_content).hexdigest()
        return tuple(
            CoverageLine(line.source_path, line.line_number, line.function_name, hashes[line.source_path])
            for line in lines
        )

    @staticmethod
    def _read_project_source(root, source_path):
        parts = PurePosixPath(source_path).parts
        descriptor = os.open(Path(os.path.abspath(root)), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for component in parts[:-1]:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            source = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
            try:
                details = os.fstat(source)
                if not stat.S_ISREG(details.st_mode) or details.st_size > 2 * 1024 * 1024:
                    raise CoverageIntegrityError("project source must be a bounded regular file")
                content = b""
                while len(content) <= details.st_size:
                    chunk = os.read(source, min(64 * 1024, details.st_size + 1 - len(content)))
                    if not chunk:
                        break
                    content += chunk
                if _file_identity(os.fstat(source)) != _file_identity(details):
                    raise CoverageIntegrityError("project source changed during clean coverage")
                return content
            finally:
                os.close(source)
        finally:
            os.close(descriptor)

    def _prepare_workspace(self) -> str:
        self._workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        return str(self._workspace)

    def _verify_clean_image(self, campaign) -> str:
        data = self._client.api.inspect_image(campaign.clean_image)
        labels = data.get("Config", {}).get("Labels", {})
        expected = {
            "bigeye.project": str(campaign.project_id),
            "bigeye.commit": str(campaign.commit_sha),
            "bigeye.layer": "coverage",
        }
        if data.get("Os") != "linux" or data.get("Architecture") != "amd64":
            raise CoverageIntegrityError("clean coverage image must be linux/amd64")
        if not isinstance(labels, dict) or any(labels.get(key) != value for key, value in expected.items()):
            raise CoverageIntegrityError("coverage image does not match the clean project commit")
        image_id = data.get("Id")
        if not isinstance(image_id, str) or not image_id:
            raise CoverageIntegrityError("coverage image has no immutable image ID")
        return image_id

    @staticmethod
    def _validate_campaign(campaign) -> None:
        identifiers = (
            campaign.id,
            campaign.project_id,
            campaign.target_asset_id,
            campaign.strategy_asset_id,
        )
        if any(type(value) is not int or value <= 0 for value in identifiers):
            raise ValueError("coverage identities must be positive integers")
        if campaign.configuration_asset_id is not None and (
            type(campaign.configuration_asset_id) is not int or campaign.configuration_asset_id <= 0
        ):
            raise ValueError("configuration asset ID must be a positive integer")
        if not isinstance(campaign.commit_sha, str) or len(campaign.commit_sha) != 40 or any(
            char not in "0123456789abcdef" for char in campaign.commit_sha
        ):
            raise ValueError("coverage commit must be a lowercase 40-character SHA")
        if not campaign.replay_command or "{input}" not in campaign.replay_command:
            raise ValueError("coverage replay command must contain an input placeholder")
        if any(not isinstance(value, str) or not value for value in campaign.replay_command):
            raise ValueError("coverage replay command arguments must be non-empty strings")
        if Path(campaign.replay_command[0]).name.lower() in {"sh", "bash", "dash", "zsh", "fish"}:
            raise ValueError("coverage replay command cannot use a shell")
        if not isinstance(campaign.binary_path, str) or not campaign.binary_path.startswith("/"):
            raise ValueError("coverage binary path must be absolute inside the clean image")

    @staticmethod
    def _stage_input(source, destination: Path, index: int) -> tuple[bytes, str, str]:
        path = Path(os.path.abspath(source))
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                details = os.fstat(descriptor)
                if not stat.S_ISREG(details.st_mode) or details.st_size > 16 * 1024 * 1024:
                    raise ValueError("coverage input must be a bounded regular file")
                content = b""
                while len(content) <= 16 * 1024 * 1024:
                    chunk = os.read(descriptor, min(64 * 1024, 16 * 1024 * 1024 + 1 - len(content)))
                    if not chunk:
                        break
                    content += chunk
                if len(content) > 16 * 1024 * 1024:
                    raise ValueError("coverage input exceeds its byte limit")
                if _file_identity(os.fstat(descriptor)) != _file_identity(details):
                    raise CoverageIntegrityError("coverage input changed while being staged")
            finally:
                os.close(descriptor)
        finally:
            os.close(parent)
        name = f"input-{index:06d}"
        target = destination / name
        target.write_bytes(content)
        target.chmod(0o400)
        return content, sha256(content).hexdigest(), f"/coverage/inputs/{name}"

    def _parse_export(self, content: bytes, campaign) -> tuple[CoverageLine, ...]:
        try:
            document = json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as error:
            raise CoverageIntegrityError("llvm-cov returned invalid JSON") from error
        functions: dict[str, list[tuple[int, int, str]]] = {}
        lines: set[tuple[str, int]] = set()
        for unit in document.get("data", ()) if isinstance(document, dict) else ():
            if not isinstance(unit, dict):
                continue
            for function in unit.get("functions", ()):
                self._collect_function(functions, function, campaign)
            for source in unit.get("files", ()):
                if not isinstance(source, dict):
                    continue
                relative = self._source_path(source.get("filename"), campaign)
                if relative is None:
                    continue
                for segment in source.get("segments", ()):
                    if (
                        isinstance(segment, list)
                        and len(segment) >= 5
                        and type(segment[0]) is int
                        and segment[0] > 0
                        and isinstance(segment[2], (int, float))
                        and segment[2] > 0
                        and segment[3] is True
                    ):
                        lines.add((relative, segment[0]))
        result = []
        for path, line in sorted(lines):
            names = [name for start, end, name in functions.get(path, ()) if start <= line <= end]
            result.append(CoverageLine(path, line, min(names) if names else None))
        return tuple(result)

    def _collect_function(self, collected, function, campaign) -> None:
        if not isinstance(function, dict) or not isinstance(function.get("name"), str):
            return
        filenames = function.get("filenames", ())
        regions = function.get("regions", ())
        for index, filename in enumerate(filenames):
            relative = self._source_path(filename, campaign)
            if relative is None:
                continue
            for region in regions:
                if isinstance(region, list) and len(region) >= 4 and all(type(region[position]) is int for position in (0, 2)):
                    collected.setdefault(relative, []).append((region[0], region[2], function["name"]))

    @staticmethod
    def _source_path(filename, campaign) -> str | None:
        if not isinstance(filename, str) or not filename:
            return None
        source_root = PurePosixPath(str(campaign.source_root))
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
        root = Path(os.path.abspath(campaign.repository_root))
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for component in path.parts[:-1]:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            file_descriptor = os.open(path.parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
            try:
                if not stat.S_ISREG(os.fstat(file_descriptor).st_mode):
                    return None
            finally:
                os.close(file_descriptor)
        except (FileNotFoundError, NotADirectoryError, OSError):
            return None
        finally:
            os.close(descriptor)
        return path.as_posix()


def _file_identity(details) -> tuple[int, int, int, int, int]:
    return details.st_dev, details.st_ino, details.st_size, details.st_mtime_ns, details.st_ctime_ns
