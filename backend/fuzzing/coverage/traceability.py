"""Persist the first testcase that reproducibly reaches each source line."""

from __future__ import annotations

import json
import os
import stat
from collections import defaultdict
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath

from backend.fuzzing.coverage.llvm_coverage import CoverageIntegrityError


@dataclass(frozen=True)
class _RetainedHit:
    directory: Path
    descriptor: int
    identity: tuple[int, int]
    testcase_name: str
    metadata_name: str
    testcase_created: bool
    metadata_created: bool
    testcase_content: bytes
    metadata_content: bytes


class TraceabilityService:
    def __init__(self, workspace: Path, repository, replay_verifier):
        self._workspace = Path(os.path.abspath(workspace))
        self._repository = repository
        self._replay_verifier = replay_verifier

    async def record(self, snapshot):
        if snapshot.build_kind != "clean":
            raise CoverageIntegrityError("only clean coverage can be recorded")
        existing = await self._repository.list_for_project(snapshot.project_id)
        known = {
            (item.commit_sha, item.source_path, item.line_number, item.asset_id)
            for item in existing
        }
        lines = {(item.source_path, item.line_number): item for item in snapshot.lines}
        created = []
        for hit in snapshot.hits:
            line = lines.get((hit.source_path, hit.line_number))
            if line is None:
                raise CoverageIntegrityError("testcase hit is absent from the clean snapshot")
            self._validate_source(snapshot.repository_root, hit.source_path)
            key = (snapshot.commit_sha, hit.source_path, hit.line_number, snapshot.strategy_asset_id)
            if key in known:
                continue
            if sha256(hit.testcase).hexdigest() != hit.testcase_sha256:
                raise CoverageIntegrityError("testcase content does not match its SHA-256")
            actual_source_sha256 = self._source_sha256(snapshot.repository_root, hit.source_path)
            if line.source_sha256 is not None and line.source_sha256 != actual_source_sha256:
                raise CoverageIntegrityError("clean source hash does not match the checkout")
            retained = self._persist_first_hit(snapshot, hit, actual_source_sha256)
            try:
                self._require_retained(retained)
                testcase = retained.directory / retained.testcase_name
                if not self._replay_verifier(snapshot, hit, testcase):
                    self._remove_uncommitted(retained)
                    raise CoverageIntegrityError("retained testcase did not reproduce the source line")
                self._require_retained(retained)
                evidence = await self._repository.create(
                    project_id=snapshot.project_id,
                    commit_sha=snapshot.commit_sha,
                    source_path=hit.source_path,
                    line_number=hit.line_number,
                    function_name=line.function_name,
                    campaign_id=snapshot.campaign_id,
                    asset_id=snapshot.strategy_asset_id,
                    first_testcase_sha256=hit.testcase_sha256,
                    cpu_exposure_seconds=snapshot.cpu_exposure_seconds,
                )
            finally:
                os.close(retained.descriptor)
            known.add(key)
            created.append(evidence)
        return created

    async def project_tree(self, project_id: int):
        evidence = await self._repository.list_for_project(project_id)
        commit = self._single_commit(evidence)
        grouped = defaultdict(list)
        for item in evidence:
            grouped[item.source_path].append(item)
        return {
            "project_id": project_id,
            "commit_sha": commit,
            "files": [
                {
                    "path": path,
                    "covered_lines": len({item.line_number for item in items}),
                    "cpu_exposure_seconds": sum(item.cpu_exposure_seconds for item in items),
                }
                for path, items in sorted(grouped.items())
            ],
        }

    async def source_file(self, project_id: int, path: str, start_line: int, end_line: int):
        self._validate_range(start_line, end_line)
        evidence = await self._repository.list_for_project(project_id)
        commit = self._single_commit(evidence)
        relative = self._safe_source_path(path)
        selected = [item for item in evidence if item.source_path == relative]
        if not selected:
            raise KeyError("source coverage not found")
        expected_hashes = {
            self._read_metadata(
                project_id, item.campaign_id, item.asset_id, item.first_testcase_sha256
            )["source_sha256"]
            for item in selected
        }
        if len(expected_hashes) != 1:
            raise CoverageIntegrityError("source evidence does not identify one clean source blob")
        source = self._read_source(project_id, commit, relative, next(iter(expected_hashes)))
        lines = source.decode("utf-8", errors="replace").splitlines()
        by_line = defaultdict(list)
        for item in selected:
            by_line[item.line_number].append(item)
        actual_end = min(end_line, len(lines))
        return {
            "project_id": project_id,
            "commit_sha": commit,
            "path": relative,
            "start_line": start_line,
            "end_line": actual_end,
            "lines": [
                {
                    "number": number,
                    "text": lines[number - 1],
                    "covered": bool(by_line[number]),
                    "strategy_count": len({item.asset_id for item in by_line[number]}),
                    "cpu_exposure_seconds": sum(item.cpu_exposure_seconds for item in by_line[number]),
                }
                for number in range(start_line, actual_end + 1)
            ],
        }

    async def function_summaries(self, project_id: int, path: str):
        relative = self._safe_source_path(path)
        evidence = await self._repository.list_for_project(project_id)
        grouped = defaultdict(list)
        for item in evidence:
            if item.source_path == relative and item.function_name:
                grouped[item.function_name].append(item)
        return [
            {
                "name": name,
                "path": relative,
                "covered_lines": len({item.line_number for item in items}),
                "cpu_exposure_seconds": sum(item.cpu_exposure_seconds for item in items),
            }
            for name, items in sorted(grouped.items())
        ]

    async def line_evidence(self, project_id: int, path: str, line_number: int):
        if type(line_number) is not int or line_number < 1:
            raise ValueError("line number must be positive")
        relative = self._safe_source_path(path)
        evidence = await self._repository.list_for_project(project_id)
        result = []
        for item in evidence:
            if item.source_path != relative or item.line_number != line_number:
                continue
            metadata = self._read_metadata(project_id, item.campaign_id, item.asset_id, item.first_testcase_sha256)
            result.append({
                "campaign_id": item.campaign_id,
                "strategy_asset_id": item.asset_id,
                "testcase_sha256": item.first_testcase_sha256,
                "replay_command": metadata["replay_command"],
                "target_asset_id": metadata["target_asset_id"],
                "configuration_asset_id": metadata["configuration_asset_id"],
                "clean_image_id": metadata["clean_image_id"],
                "cpu_exposure_seconds": item.cpu_exposure_seconds,
            })
        return result

    def _persist_first_hit(self, snapshot, hit, source_sha256):
        descriptor, directory = self._open_strategy_directory(
            snapshot.project_id, snapshot.campaign_id, snapshot.strategy_asset_id
        )
        testcase_name = f"{hit.testcase_sha256}.input"
        metadata_name = f"{hit.testcase_sha256}.json"
        metadata = {
            "campaign_id": snapshot.campaign_id,
            "clean_image_id": snapshot.clean_image_id,
            "configuration_asset_id": snapshot.configuration_asset_id,
            "replay_command": list(snapshot.replay_command),
            "strategy_asset_id": snapshot.strategy_asset_id,
            "target_asset_id": snapshot.target_asset_id,
            "testcase_sha256": hit.testcase_sha256,
            "source_sha256": source_sha256,
        }
        testcase_created = False
        metadata_created = False
        metadata_content = (json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n").encode()
        try:
            testcase_created = self._write_once(descriptor, testcase_name, hit.testcase)
            metadata_created = self._write_once(
                descriptor,
                metadata_name,
                metadata_content,
            )
            os.fsync(descriptor)
        except BaseException:
            self._remove_created(descriptor, testcase_name, metadata_name, testcase_created, metadata_created)
            os.close(descriptor)
            raise
        details = os.fstat(descriptor)
        return _RetainedHit(
            directory,
            descriptor,
            (details.st_dev, details.st_ino),
            testcase_name,
            metadata_name,
            testcase_created,
            metadata_created,
            hit.testcase,
            metadata_content,
        )

    @staticmethod
    def _write_once(parent: int, name: str, content: bytes) -> bool:
        try:
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=parent)
        except FileExistsError:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode) or os.read(descriptor, len(content) + 1) != content:
                    raise CoverageIntegrityError("retained first-hit artifact does not match")
            finally:
                os.close(descriptor)
            return False
        try:
            view = memoryview(content)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("could not persist first-hit artifact")
                view = view[written:]
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return True

    def _open_strategy_directory(self, project_id, campaign_id, strategy_id, create: bool = True):
        identifiers = (project_id, campaign_id, strategy_id)
        if any(type(value) is not int or value <= 0 for value in identifiers):
            raise ValueError("coverage path identities must be positive integers")
        if create:
            self._workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        root = os.open(self._workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptor = root
        parts = ("projects", str(project_id), "coverage", str(campaign_id), str(strategy_id))
        try:
            for part in parts:
                if create:
                    try:
                        os.mkdir(part, 0o700, dir_fd=descriptor)
                        os.fsync(descriptor)
                    except FileExistsError:
                        pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                if descriptor != root:
                    os.close(descriptor)
                descriptor = child
            os.close(root)
            return descriptor, self._workspace.joinpath(*parts)
        except BaseException:
            if descriptor != root:
                os.close(descriptor)
            os.close(root)
            raise

    def _require_retained(self, retained: _RetainedHit) -> None:
        try:
            canonical, _ = self._open_strategy_directory_from_path(retained.directory)
        except OSError as error:
            raise CoverageIntegrityError("coverage strategy directory changed during replay") from error
        try:
            details = os.fstat(canonical)
            if (details.st_dev, details.st_ino) != retained.identity:
                raise CoverageIntegrityError("coverage strategy directory changed during replay")
        finally:
            os.close(canonical)
        for name, expected in (
            (retained.testcase_name, retained.testcase_content),
            (retained.metadata_name, retained.metadata_content),
        ):
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=retained.descriptor)
            try:
                details = os.fstat(descriptor)
                if not stat.S_ISREG(details.st_mode) or details.st_size != len(expected):
                    raise CoverageIntegrityError("retained first-hit artifact changed during replay")
                if self._read_descriptor(descriptor, len(expected)) != expected:
                    raise CoverageIntegrityError("retained first-hit artifact changed during replay")
            finally:
                os.close(descriptor)

    def _open_strategy_directory_from_path(self, directory: Path):
        relative = directory.relative_to(self._workspace)
        descriptor = os.open(self._workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        root = descriptor
        try:
            for part in relative.parts:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                if descriptor != root:
                    os.close(descriptor)
                descriptor = child
            os.close(root)
            return descriptor, directory
        except BaseException:
            if descriptor != root:
                os.close(descriptor)
            os.close(root)
            raise

    @staticmethod
    def _read_descriptor(descriptor: int, expected: int) -> bytes:
        content = bytearray()
        while len(content) <= expected:
            chunk = os.read(descriptor, min(64 * 1024, expected + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        return bytes(content)

    @staticmethod
    def _remove_created(parent, testcase_name, metadata_name, testcase_created, metadata_created):
        for name, created in ((testcase_name, testcase_created), (metadata_name, metadata_created)):
            if created:
                try:
                    os.unlink(name, dir_fd=parent)
                except FileNotFoundError:
                    pass
        os.fsync(parent)

    @staticmethod
    def _remove_uncommitted(retained: _RetainedHit):
        TraceabilityService._remove_created(
            retained.descriptor,
            retained.testcase_name,
            retained.metadata_name,
            retained.testcase_created,
            retained.metadata_created,
        )

    def _read_metadata(self, project_id, campaign_id, strategy_id, digest):
        descriptor, _ = self._open_strategy_directory(project_id, campaign_id, strategy_id, create=False)
        try:
            file_descriptor = os.open(f"{digest}.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
            try:
                details = os.fstat(file_descriptor)
                if not stat.S_ISREG(details.st_mode) or details.st_size > 16 * 1024:
                    raise CoverageIntegrityError("first-hit metadata is invalid")
                content = os.read(file_descriptor, 16 * 1024 + 1)
            finally:
                os.close(file_descriptor)
        finally:
            os.close(descriptor)
        try:
            document = json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CoverageIntegrityError("first-hit metadata is invalid") from error
        if not isinstance(document, dict) or (
            document.get("campaign_id") != campaign_id
            or document.get("strategy_asset_id") != strategy_id
            or document.get("testcase_sha256") != digest
        ):
            raise CoverageIntegrityError("first-hit metadata identity does not match its evidence")
        source_digest = document.get("source_sha256")
        image_id = document.get("clean_image_id")
        target_id = document.get("target_asset_id")
        configuration_id = document.get("configuration_asset_id")
        replay = document.get("replay_command")
        if (
            not isinstance(source_digest, str)
            or len(source_digest) != 64
            or any(character not in "0123456789abcdef" for character in source_digest)
            or not isinstance(image_id, str)
            or not image_id.startswith("sha256:")
            or type(target_id) is not int
            or target_id <= 0
            or (configuration_id is not None and (type(configuration_id) is not int or configuration_id <= 0))
            or not isinstance(replay, list)
            or not 1 <= len(replay) <= 64
            or any(not isinstance(argument, str) or not argument or len(argument) > 4096 for argument in replay)
            or "{input}" not in replay
        ):
            raise CoverageIntegrityError("first-hit metadata is invalid")
        return document

    @staticmethod
    def _validate_source(root: Path, source_path: str):
        relative = TraceabilityService._safe_source_path(source_path)
        descriptor = os.open(Path(os.path.abspath(root)), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in PurePosixPath(relative).parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            source = os.open(PurePosixPath(relative).parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
            try:
                if not stat.S_ISREG(os.fstat(source).st_mode):
                    raise CoverageIntegrityError("coverage source is not a regular checkout file")
            finally:
                os.close(source)
        finally:
            os.close(descriptor)

    @staticmethod
    def _source_sha256(root: Path, source_path: str) -> str:
        return sha256(TraceabilityService._source_content(root, source_path)).hexdigest()

    @staticmethod
    def _source_content(root: Path, source_path: str) -> bytes:
        TraceabilityService._validate_source(root, source_path)
        relative = PurePosixPath(source_path)
        descriptor = os.open(Path(os.path.abspath(root)), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in relative.parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            source = os.open(relative.parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
            try:
                details = os.fstat(source)
                if details.st_size > 2 * 1024 * 1024:
                    raise CoverageIntegrityError("project source exceeds its byte limit")
                content = TraceabilityService._read_descriptor(source, details.st_size)
                after = os.fstat(source)
                if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
                    details.st_dev, details.st_ino, details.st_size, details.st_mtime_ns, details.st_ctime_ns
                ):
                    raise CoverageIntegrityError("project source changed while being recorded")
                return content
            finally:
                os.close(source)
        finally:
            os.close(descriptor)

    @staticmethod
    def _safe_source_path(path: str) -> str:
        if not isinstance(path, str) or not path:
            raise ValueError("source path is required")
        value = PurePosixPath(path)
        if value.is_absolute() or not value.parts or any(part in {"", ".", "..", ".git"} for part in value.parts):
            raise ValueError("source path must be repository-relative")
        if value.suffix.lower() == ".patch":
            raise ValueError("patches are not project source")
        first = value.parts[0].lower()
        if first in {"build", "generated", "harness", "fuzz-target", "fuzz_target", ".bigeye"} or first.startswith("cmake-build"):
            raise ValueError("generated and fuzz-only paths are not project source")
        return value.as_posix()

    @staticmethod
    def _validate_range(start, end):
        if type(start) is not int or type(end) is not int or start < 1 or end < start or end - start + 1 > 500:
            raise ValueError("source range must contain between 1 and 500 lines")

    @staticmethod
    def _single_commit(evidence):
        commits = {item.commit_sha for item in evidence}
        if not commits:
            raise KeyError("coverage not found")
        if len(commits) != 1:
            raise CoverageIntegrityError("project coverage spans multiple commits")
        return next(iter(commits))

    def _read_source(self, project_id, commit, relative, expected_sha256):
        root = self._workspace / "projects" / str(project_id) / "repository"
        self._validate_source(root, relative)
        if not isinstance(commit, str) or len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
            raise CoverageIntegrityError("coverage commit is invalid")
        content = self._source_content(root, relative)
        if sha256(content).hexdigest() != expected_sha256:
            raise CoverageIntegrityError("checkout source does not match the exact clean image")
        return content
