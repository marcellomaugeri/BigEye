"""Atomically retain the first testcase that reproducibly reaches each clean source line."""

from __future__ import annotations

import inspect
import json
import math
import os
import stat
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
from uuid import uuid4

from backend.fuzzing.campaigns.coverage_contract import valid_replay_environment
from backend.fuzzing.coverage.llvm_coverage import CoverageIntegrityError
from backend.fuzzing.coverage.source_paths import is_forbidden_source_path
from backend.services.projects.clone_repository import GitCommandFailed, run_command


@dataclass(frozen=True)
class TrustedCheckout:
    project_id: int
    commit_sha: str
    root: Path
    device: int
    inode: int


class ProjectCheckoutRegistry:
    """Resolve a project checkout only after database and detached-HEAD verification."""

    def __init__(self, workspace: Path, projects):
        self._workspace = Path(os.path.abspath(workspace))
        self._projects = projects

    async def commit_for_project(self, project_id: int) -> str:
        _positive(project_id, "project ID")
        project = await self._projects.get(project_id)
        if project is None or project.commit_sha is None:
            raise KeyError("project commit not found")
        _commit(project.commit_sha)
        return project.commit_sha

    async def resolve(self, project_id: int, commit_sha: str) -> TrustedCheckout:
        _positive(project_id, "project ID")
        _commit(commit_sha)
        project = await self._projects.get(project_id)
        if project is None or project.commit_sha != commit_sha:
            raise CoverageIntegrityError("coverage commit does not match the project")
        root = self._workspace / "projects" / str(project_id) / "repository"
        descriptor = _open_checkout(self._workspace, project_id)
        try:
            details = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        head = await run_command(["git", "rev-parse", "HEAD"], cwd=root)
        if head != commit_sha:
            raise CoverageIntegrityError("checkout HEAD does not match the coverage commit")
        try:
            symbolic_head = await run_command(["git", "symbolic-ref", "-q", "HEAD"], cwd=root)
        except GitCommandFailed:
            symbolic_head = None
        if symbolic_head is not None:
            raise CoverageIntegrityError("coverage requires a detached project checkout")
        descriptor = _open_checkout(self._workspace, project_id)
        try:
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if (after.st_dev, after.st_ino) != (details.st_dev, details.st_ino):
            raise CoverageIntegrityError("project checkout changed during commit verification")
        return TrustedCheckout(project_id, commit_sha, root, details.st_dev, details.st_ino)

    async def verify(self, checkout: TrustedCheckout) -> None:
        current = await self.resolve(checkout.project_id, checkout.commit_sha)
        if (current.device, current.inode) != (checkout.device, checkout.inode):
            raise CoverageIntegrityError("project checkout changed during coverage processing")


@dataclass(frozen=True)
class ReplayVerification:
    project_id: int
    commit_sha: str
    campaign_id: int
    strategy_asset_id: int
    target_asset_id: int
    configuration_asset_id: int | None
    coverage_asset_id: int
    clean_image_id: str
    clean_content_hash: str
    clean_parent_image_id: str
    source_path: str
    line_number: int
    testcase_path: Path
    testcase_sha256: str
    replay_command: tuple[str, ...]
    replay_environment: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class _RetainedHit:
    parent_descriptor: int
    final_descriptor: int
    final_name: str
    directory: Path
    directory_identity: tuple[int, int]
    testcase_name: str
    metadata_name: str
    testcase_identity: tuple[int, int, int, int, int]
    metadata_identity: tuple[int, int, int, int, int]
    testcase_content: bytes
    metadata_content: bytes
    created: bool


class TraceabilityService:
    def __init__(self, workspace: Path, repository, replay_verifier, checkout_registry, events=None):
        self._workspace = Path(os.path.abspath(workspace))
        self._repository = repository
        self._replay_verifier = replay_verifier
        self._checkouts = checkout_registry
        self._events = events

    async def record(self, snapshot):
        self._validate_snapshot(snapshot)
        checkout = await self._checkouts.resolve(snapshot.project_id, snapshot.commit_sha)
        inventory_persisted = False
        if snapshot.source_summaries:
            for summary in snapshot.source_summaries:
                source_path = self._safe_source_path(summary.source_path)
                source_hash = sha256(_read_checkout_source(checkout, source_path)).hexdigest()
                if summary.source_sha256 != source_hash:
                    raise CoverageIntegrityError("clean source hash does not match the checkout")
            await self._checkouts.verify(checkout)
            persist = getattr(self._repository, "upsert_snapshot", None)
            if persist is None:
                raise CoverageIntegrityError("coverage inventory repository is not configured")
            await persist(snapshot)
            inventory_persisted = True
        lines = {(item.source_path, item.line_number): item for item in snapshot.lines}
        created = []
        for hit in snapshot.hits:
            line = lines.get((hit.source_path, hit.line_number))
            if line is None:
                raise CoverageIntegrityError("testcase hit is absent from the clean snapshot")
            source_path = self._safe_source_path(hit.source_path)
            source_content = _read_checkout_source(checkout, source_path)
            source_hash = sha256(source_content).hexdigest()
            if line.source_sha256 is not None and line.source_sha256 != source_hash:
                raise CoverageIntegrityError("clean source hash does not match the checkout")
            if sha256(hit.testcase).hexdigest() != hit.testcase_sha256:
                raise CoverageIntegrityError("testcase content does not match its SHA-256")
            retained = None
            attempt_active = False
            won = True
            try:
                async with self._repository.claim(
                    project_id=snapshot.project_id,
                    commit_sha=snapshot.commit_sha,
                    source_path=source_path,
                    line_number=hit.line_number,
                    asset_id=snapshot.strategy_asset_id,
                ) as claim:
                    if claim.existing is not None:
                        continue
                    retained = self._publish(snapshot, hit, source_hash)
                    attempt_active = True
                    self._require_retained(retained)
                    verification = self._verification(snapshot, hit, retained)
                    if self._replay_verifier is None:
                        raise CoverageIntegrityError("coverage replay verifier is not configured")
                    outcome = self._replay_verifier(verification)
                    if inspect.isawaitable(outcome):
                        outcome = await outcome
                    if outcome is not True:
                        raise CoverageIntegrityError("retained testcase did not reproduce the source line")
                    await self._checkouts.verify(checkout)
                    self._require_retained(retained)
                    evidence = await claim.create(
                        function_name=line.function_name,
                        campaign_id=snapshot.campaign_id,
                        first_testcase_sha256=hit.testcase_sha256,
                        cpu_exposure_seconds=0.0,
                    )
                    won = getattr(claim, "created", True) is True
                    if won:
                        await self._checkouts.verify(checkout)
                        self._require_retained(retained)
                    else:
                        self._remove_attempt(retained)
                        attempt_active = False
            except BaseException:
                if retained is not None and attempt_active:
                    self._remove_attempt(retained)
                raise
            finally:
                if retained is not None:
                    os.close(retained.final_descriptor)
                    os.close(retained.parent_descriptor)
            if not won:
                continue
            created.append(evidence)
        if (created or inventory_persisted) and self._events is not None:
            outcome = self._events.append(snapshot.project_id, "events", {"name": "coverage"})
            if inspect.isawaitable(outcome):
                await outcome
        return created

    async def project_tree(self, project_id: int, limit: int = 1_000, offset: int = 0):
        commit = await self._project_commit(project_id, allow_empty=True)
        page = await self._repository.aggregate_project(project_id, commit, limit=limit, offset=offset)
        await self._checkouts.resolve(project_id, commit)
        files = [self._coverage_file(item) for item in page.items]
        return {
            "project_id": project_id,
            "commit_sha": commit,
            "files": files,
            "summary": {
                dimension: self._sum_measurement(files, dimension)
                for dimension in ("lines", "functions", "branches")
            },
            "pagination": {"limit": limit, "offset": offset, "total": page.total},
        }

    async def source_file(self, project_id: int, path: str, start_line: int, end_line: int):
        self._validate_range(start_line, end_line)
        commit = await self._project_commit(project_id)
        relative = self._safe_source_path(path)
        source_summary_method = getattr(self._repository, "source_summary", None)
        source_summary = (
            await source_summary_method(project_id, commit, relative)
            if source_summary_method is not None else None
        )
        identity = await self._repository.first_for_source(project_id, commit, relative)
        if source_summary is None and identity is None:
            raise KeyError("coverage not found")
        if identity is not None:
            self._require_commit((identity,), commit)
        expected_hash = (
            source_summary["source_sha256"] if source_summary is not None
            else self._read_metadata(identity)["source_sha256"]
        )
        aggregate = await self._repository.aggregate_source_range(
            project_id, commit, relative, start_line, end_line,
        )
        branch_method = getattr(self._repository, "branch_states", None)
        branch_states = (
            await branch_method(project_id, commit, relative, start_line, end_line)
            if branch_method is not None else {}
        )
        checkout = await self._checkouts.resolve(project_id, commit)
        source = _read_checkout_source(checkout, relative)
        if sha256(source).hexdigest() != expected_hash:
            raise CoverageIntegrityError("checkout source does not match the exact clean image")
        lines = source.decode("utf-8", errors="replace").splitlines()
        by_line = {item["line_number"]: item for item in aggregate}
        branch_available = source_summary is not None and source_summary["total_branches"] is not None
        actual_end = min(end_line, len(lines))
        if actual_end < start_line:
            raise KeyError("coverage not found")
        return {
            "project_id": project_id,
            "commit_sha": commit,
            "path": relative,
            "start_line": start_line,
            "end_line": actual_end,
            "total_lines": len(lines),
            "lines": [
                {
                    "number": number,
                    "text": lines[number - 1],
                    "covered": number in by_line,
                    "branches": list(branch_states.get(number, ())) if branch_available else None,
                    "strategy_count": by_line.get(number, {}).get("strategy_count", 0),
                    "cpu_exposure_seconds": by_line.get(number, {}).get("cpu_exposure_seconds", 0.0),
                }
                for number in range(start_line, actual_end + 1)
            ],
        }

    @staticmethod
    def _measurement(covered, total):
        if covered is None or total is None:
            return None
        return {
            "covered": int(covered),
            "total": int(total),
            "percent": (float(covered) * 100.0 / total) if total else 0.0,
        }

    @classmethod
    def _coverage_file(cls, item):
        lines = cls._measurement(item.get("covered_lines"), item.get("total_lines"))
        return {
            **item,
            "lines": lines,
            "functions": cls._measurement(
                item.get("covered_functions"), item.get("total_functions"),
            ),
            "branches": cls._measurement(
                item.get("covered_branches"), item.get("total_branches"),
            ),
        }

    @classmethod
    def _sum_measurement(cls, files, dimension):
        values = [item[dimension] for item in files]
        if not values or any(value is None for value in values):
            return None
        return cls._measurement(
            sum(value["covered"] for value in values),
            sum(value["total"] for value in values),
        )

    async def function_summaries(self, project_id: int, path: str, limit: int = 1_000, offset: int = 0):
        commit = await self._project_commit(project_id)
        relative = self._safe_source_path(path)
        page = await self._repository.aggregate_functions(
            project_id, commit, relative, limit=limit, offset=offset,
        )
        if page.total == 0:
            raise KeyError("coverage not found")
        await self._checkouts.resolve(project_id, commit)
        return {
            "functions": list(page.items),
            "pagination": {"limit": limit, "offset": offset, "total": page.total},
        }

    async def line_evidence(
        self, project_id: int, path: str, line_number: int, limit: int = 500, offset: int = 0,
    ):
        if type(line_number) is not int or line_number < 1:
            raise ValueError("line number must be positive")
        commit = await self._project_commit(project_id)
        relative = self._safe_source_path(path)
        page = await self._repository.page_for_line(
            project_id, commit, relative, line_number, limit=limit, offset=offset
        )
        if page.total == 0:
            raise KeyError("coverage not found")
        self._require_commit(page.items, commit)
        await self._checkouts.resolve(project_id, commit)
        result = []
        for item in page.items:
            metadata = self._read_metadata(item)
            result.append({
                "campaign_id": item.campaign_id,
                "strategy_asset_id": item.asset_id,
                "testcase_sha256": item.first_testcase_sha256,
                "replay_command": metadata["replay_command"],
                "replay_environment": dict(metadata["replay_environment"]),
                "target_asset_id": metadata["target_asset_id"],
                "configuration_asset_id": metadata["configuration_asset_id"],
                "clean_image_id": metadata["clean_image_id"],
                "cpu_exposure_seconds": item.cpu_exposure_seconds,
            })
        return {
            "evidence": result,
            "pagination": {"limit": limit, "offset": offset, "total": page.total},
        }

    async def retained_testcase(
        self, project_id: int, path: str, line_number: int,
        strategy_asset_id: int, testcase_sha256: str,
    ) -> bytes:
        _positive(line_number, "line number")
        _positive(strategy_asset_id, "strategy asset ID")
        _digest(testcase_sha256, "testcase SHA-256")
        commit = await self._project_commit(project_id)
        relative = self._safe_source_path(path)
        page = await self._repository.page_for_line(
            project_id, commit, relative, line_number, limit=500, offset=0,
        )
        if page.total > 500:
            raise CoverageIntegrityError("line evidence exceeds the retained testcase read bound")
        self._require_commit(page.items, commit)
        evidence = next((
            item for item in page.items
            if item.asset_id == strategy_asset_id
            and item.first_testcase_sha256 == testcase_sha256
        ), None)
        if evidence is None:
            raise KeyError("coverage testcase not found")
        await self._checkouts.resolve(project_id, commit)
        _, testcase = self._read_artifact(evidence)
        return testcase

    async def _project_commit(self, project_id, *, allow_empty=False):
        _positive(project_id, "project ID")
        commits = await self._repository.list_commits(project_id)
        if not commits:
            if allow_empty:
                return await self._checkouts.commit_for_project(project_id)
            raise KeyError("coverage not found")
        if len(commits) != 1:
            raise CoverageIntegrityError("project coverage spans multiple commits")
        _commit(commits[0])
        return commits[0]

    @staticmethod
    def _require_commit(evidence, commit):
        if any(item.commit_sha != commit for item in evidence):
            raise CoverageIntegrityError("coverage row commit does not match the project")

    def _publish(self, snapshot, hit, source_hash):
        parent, parent_path, logical = self._open_logical_parent(
            snapshot.project_id, snapshot.commit_sha, snapshot.strategy_asset_id,
            hit.source_path, hit.line_number,
        )
        metadata = self._metadata(snapshot, hit, source_hash, logical)
        metadata_content = (json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n").encode()
        testcase_name = f"{hit.testcase_sha256}.input"
        metadata_name = "evidence.json"
        try:
            try:
                existing = os.open(logical, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            except FileNotFoundError:
                existing = None
            if existing is not None:
                try:
                    self._require_files(existing, testcase_name, hit.testcase, metadata_name, metadata_content)
                finally:
                    os.close(existing)
                self._remove_orphan(parent, logical, testcase_name, metadata_name)
            staging = f".{logical}.staging-{uuid4().hex}"
            os.mkdir(staging, 0o700, dir_fd=parent)
            staging_fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                testcase_identity = self._write_file(staging_fd, testcase_name, hit.testcase)
                metadata_identity = self._write_file(staging_fd, metadata_name, metadata_content)
                os.fsync(staging_fd)
                os.fchmod(staging_fd, 0o500)
                os.fsync(staging_fd)
                os.rename(staging, logical, src_dir_fd=parent, dst_dir_fd=parent)
                os.fsync(parent)
            except BaseException:
                self._remove_directory(parent, staging_fd, staging, testcase_name, metadata_name)
                os.close(staging_fd)
                raise
            details = os.fstat(staging_fd)
            return _RetainedHit(
                parent, staging_fd, logical, parent_path / logical, (details.st_dev, details.st_ino),
                testcase_name, metadata_name, testcase_identity, metadata_identity,
                hit.testcase, metadata_content, True,
            )
        except BaseException:
            os.close(parent)
            raise

    def _open_logical_parent(self, project_id, commit, strategy_id, source_path, line_number):
        _positive(project_id, "project ID")
        _positive(strategy_id, "strategy asset ID")
        _positive(line_number, "line number")
        _commit(commit)
        source_path = self._safe_source_path(source_path)
        logical = sha256(
            f"{project_id}\0{commit}\0{source_path}\0{line_number}\0{strategy_id}".encode()
        ).hexdigest()
        self._workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(self._workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        root = descriptor
        parts = ("projects", str(project_id), "coverage", "first-hits", commit, str(strategy_id))
        try:
            for part in parts:
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
            return descriptor, self._workspace.joinpath(*parts), logical
        except BaseException:
            if descriptor != root:
                os.close(descriptor)
            os.close(root)
            raise

    @staticmethod
    def _write_file(parent, name, content):
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=parent)
        try:
            _write_all(descriptor, content)
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
            return _file_identity(os.fstat(descriptor))
        finally:
            os.close(descriptor)

    def _require_retained(self, retained):
        details = os.stat(retained.final_name, dir_fd=retained.parent_descriptor, follow_symlinks=False)
        if not stat.S_ISDIR(details.st_mode) or (details.st_dev, details.st_ino) != retained.directory_identity:
            raise CoverageIntegrityError("coverage artifact directory changed during replay")
        self._require_files(
            retained.final_descriptor,
            retained.testcase_name, retained.testcase_content,
            retained.metadata_name, retained.metadata_content,
            retained.testcase_identity, retained.metadata_identity,
        )

    @staticmethod
    def _require_files(parent, testcase_name, testcase, metadata_name, metadata, testcase_identity=None, metadata_identity=None):
        names = []
        with os.scandir(parent) as entries:
            names.extend(entry.name for entry in entries)
        if set(names) != {testcase_name, metadata_name}:
            raise CoverageIntegrityError("coverage artifact directory contains unexpected files")
        for name, expected, identity in (
            (testcase_name, testcase, testcase_identity), (metadata_name, metadata, metadata_identity),
        ):
            content, current = _read_at(parent, name, max(len(expected), 16 * 1024))
            if content != expected or (identity is not None and current != identity):
                raise CoverageIntegrityError("coverage artifact changed during replay")

    def _remove_attempt(self, retained):
        try:
            details = os.stat(retained.final_name, dir_fd=retained.parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return
        if not stat.S_ISDIR(details.st_mode) or (details.st_dev, details.st_ino) != retained.directory_identity:
            return
        self._remove_directory(
            retained.parent_descriptor, retained.final_descriptor, retained.final_name,
            retained.testcase_name, retained.metadata_name,
        )

    @staticmethod
    def _remove_orphan(parent, name, testcase_name, metadata_name):
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            TraceabilityService._remove_directory(parent, descriptor, name, testcase_name, metadata_name)
        finally:
            os.close(descriptor)

    @staticmethod
    def _remove_directory(parent, descriptor, name, testcase_name, metadata_name):
        os.fchmod(descriptor, 0o700)
        for filename in (testcase_name, metadata_name):
            try:
                os.unlink(filename, dir_fd=descriptor)
            except FileNotFoundError:
                pass
        os.fsync(descriptor)
        os.rmdir(name, dir_fd=parent)
        os.fsync(parent)

    def _read_metadata(self, evidence):
        document, _ = self._read_artifact(evidence)
        return document

    def _read_artifact(self, evidence):
        parent, _, logical = self._open_logical_parent(
            evidence.project_id, evidence.commit_sha, evidence.asset_id,
            evidence.source_path, evidence.line_number,
        )
        try:
            directory = os.open(logical, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                details = os.fstat(directory)
                if stat.S_IMODE(details.st_mode) != 0o500:
                    raise CoverageIntegrityError("first-hit artifact directory is not immutable")
                testcase_name = f"{evidence.first_testcase_sha256}.input"
                with os.scandir(directory) as entries:
                    names = {entry.name for entry in entries}
                if names != {testcase_name, "evidence.json"}:
                    raise CoverageIntegrityError("first-hit artifact directory contains unexpected files")
                for name in names:
                    file_details = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    if not stat.S_ISREG(file_details.st_mode) or stat.S_IMODE(file_details.st_mode) != 0o400:
                        raise CoverageIntegrityError("first-hit artifact file is not immutable")
                testcase, _ = _read_at(directory, testcase_name, 16 * 1024 * 1024)
                if sha256(testcase).hexdigest() != evidence.first_testcase_sha256:
                    raise CoverageIntegrityError("first-hit testcase does not match its evidence")
                content, _ = _read_at(directory, "evidence.json", 16 * 1024)
            finally:
                os.close(directory)
        finally:
            os.close(parent)
        try:
            document = json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CoverageIntegrityError("first-hit metadata is invalid") from error
        expected = {
            "project_id": evidence.project_id,
            "commit_sha": evidence.commit_sha,
            "source_path": evidence.source_path,
            "line_number": evidence.line_number,
            "strategy_asset_id": evidence.asset_id,
            "testcase_sha256": evidence.first_testcase_sha256,
            "logical_key": logical,
            "campaign_id": evidence.campaign_id,
        }
        if not isinstance(document, dict) or any(document.get(key) != value for key, value in expected.items()):
            raise CoverageIntegrityError("first-hit metadata identity does not match its evidence")
        for key in ("source_sha256", "clean_content_hash"):
            _digest(document.get(key), key.replace("_", " "))
        replay_environment = (
            _stored_replay_environment(document["replay_environment"])
            if isinstance(document, dict) and "replay_environment" in document
            else None
        )
        if (
            not isinstance(document.get("clean_image_id"), str)
            or not _is_image_id(document["clean_image_id"])
            or not isinstance(document.get("clean_parent_image_id"), str)
            or not _is_image_id(document["clean_parent_image_id"])
            or type(document.get("target_asset_id")) is not int
            or document["target_asset_id"] <= 0
            or type(document.get("coverage_asset_id")) is not int
            or document["coverage_asset_id"] <= 0
            or (
                document.get("configuration_asset_id") is not None
                and (type(document["configuration_asset_id"]) is not int or document["configuration_asset_id"] <= 0)
            )
            or not isinstance(document.get("replay_command"), list)
            or not 1 <= len(document["replay_command"]) <= 64
            or any(not isinstance(argument, str) or not argument or len(argument) > 4096 for argument in document["replay_command"])
            or sum(len(argument) for argument in document["replay_command"]) > 16 * 1024
            or replay_environment is None
        ):
            raise CoverageIntegrityError("first-hit metadata is invalid")
        document["replay_environment"] = replay_environment
        return document, testcase

    @staticmethod
    def _metadata(snapshot, hit, source_hash, logical):
        return {
            "project_id": snapshot.project_id,
            "commit_sha": snapshot.commit_sha,
            "source_path": hit.source_path,
            "line_number": hit.line_number,
            "strategy_asset_id": snapshot.strategy_asset_id,
            "logical_key": logical,
            "campaign_id": snapshot.campaign_id,
            "clean_image_id": snapshot.clean_image_id,
            "clean_content_hash": snapshot.clean_content_hash,
            "clean_parent_image_id": snapshot.clean_parent_image_id,
            "configuration_asset_id": snapshot.configuration_asset_id,
            "coverage_asset_id": snapshot.coverage_asset_id,
            "replay_command": list(snapshot.replay_command),
            "replay_environment": [list(item) for item in snapshot.replay_environment],
            "target_asset_id": snapshot.target_asset_id,
            "testcase_sha256": hit.testcase_sha256,
            "source_sha256": source_hash,
        }

    @staticmethod
    def _verification(snapshot, hit, retained):
        return ReplayVerification(
            snapshot.project_id, snapshot.commit_sha, snapshot.campaign_id,
            snapshot.strategy_asset_id, snapshot.target_asset_id, snapshot.configuration_asset_id,
            snapshot.coverage_asset_id, snapshot.clean_image_id, snapshot.clean_content_hash,
            snapshot.clean_parent_image_id, hit.source_path, hit.line_number,
            retained.directory / retained.testcase_name, hit.testcase_sha256,
            snapshot.replay_command,
            snapshot.replay_environment,
        )

    @staticmethod
    def _validate_snapshot(snapshot):
        if snapshot.build_kind != "clean":
            raise CoverageIntegrityError("only clean coverage can be recorded")
        for value, label in (
            (snapshot.project_id, "project ID"), (snapshot.campaign_id, "campaign ID"),
            (snapshot.strategy_asset_id, "strategy asset ID"), (snapshot.target_asset_id, "target asset ID"),
            (snapshot.coverage_asset_id, "coverage asset ID"),
        ):
            _positive(value, label)
        if snapshot.configuration_asset_id is not None:
            _positive(snapshot.configuration_asset_id, "configuration asset ID")
        _commit(snapshot.commit_sha)
        _digest(snapshot.clean_content_hash, "clean content hash")
        if (
            not _is_image_id(snapshot.clean_image_id)
            or not _is_image_id(snapshot.clean_parent_image_id)
        ):
            raise CoverageIntegrityError("clean image provenance is invalid")
        if (
            not isinstance(snapshot.replay_command, tuple)
            or not 1 <= len(snapshot.replay_command) <= 64
            or any(not isinstance(argument, str) or not argument or len(argument) > 4096 for argument in snapshot.replay_command)
            or sum(len(argument) for argument in snapshot.replay_command) > 16 * 1024
        ):
            raise CoverageIntegrityError("replay command is invalid")
        if not valid_replay_environment(snapshot.replay_environment):
            raise CoverageIntegrityError("replay environment is invalid")
        if (
            isinstance(snapshot.cpu_exposure_seconds, bool)
            or not isinstance(snapshot.cpu_exposure_seconds, (int, float))
            or not math.isfinite(snapshot.cpu_exposure_seconds)
            or snapshot.cpu_exposure_seconds < 0
        ):
            raise CoverageIntegrityError("CPU exposure is invalid")
        for count in (snapshot.summary.lines, snapshot.summary.functions, snapshot.summary.branches):
            _validate_count(count)
        source_paths = set()
        for summary in snapshot.source_summaries:
            path = TraceabilityService._safe_source_path(summary.source_path)
            if path in source_paths:
                raise CoverageIntegrityError("coverage source inventory contains duplicates")
            source_paths.add(path)
            _digest(summary.source_sha256, "source SHA-256")
            for count in (summary.lines, summary.functions, summary.branches):
                _validate_count(count)
        branch_keys = set()
        for branch in snapshot.branches:
            path = TraceabilityService._safe_source_path(branch.source_path)
            key = (path, branch.line_number, branch.branch_index)
            if (
                type(branch.line_number) is not int or branch.line_number <= 0
                or type(branch.branch_index) is not int or branch.branch_index < 0
                or type(branch.covered) is not bool or key in branch_keys
            ):
                raise CoverageIntegrityError("coverage branch inventory is invalid")
            branch_keys.add(key)

    @staticmethod
    def _safe_source_path(path):
        if not isinstance(path, str) or not path:
            raise ValueError("source path is required")
        value = PurePosixPath(path)
        if value.is_absolute() or not value.parts or any(part in {"", ".", ".."} for part in value.parts):
            raise ValueError("source path must be repository-relative")
        if is_forbidden_source_path(value):
            raise ValueError("generated and fuzz-only paths are not project source")
        return value.as_posix()

    @staticmethod
    def _validate_range(start, end):
        if type(start) is not int or type(end) is not int or start < 1 or end < start or end - start + 1 > 500:
            raise ValueError("source range must contain between 1 and 500 lines")


def _open_checkout(workspace, project_id):
    descriptor = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    root = descriptor
    try:
        for part in ("projects", str(project_id), "repository"):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            if descriptor != root:
                os.close(descriptor)
            descriptor = child
        os.close(root)
        return descriptor
    except BaseException:
        if descriptor != root:
            os.close(descriptor)
        os.close(root)
        raise


def _read_checkout_source(checkout, source_path):
    descriptor = os.open(checkout.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    details = os.fstat(descriptor)
    if (details.st_dev, details.st_ino) != (checkout.device, checkout.inode):
        os.close(descriptor)
        raise CoverageIntegrityError("project checkout changed during source read")
    try:
        parts = PurePosixPath(source_path).parts
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return _read_at(descriptor, parts[-1], 2 * 1024 * 1024)[0]
    finally:
        os.close(descriptor)


def _read_at(parent, name, maximum):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise CoverageIntegrityError("artifact is not a bounded regular file")
        content = bytearray()
        while len(content) <= maximum:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
        if _file_identity(before) != _file_identity(after) or len(content) > maximum:
            raise CoverageIntegrityError("artifact changed while being read")
        return bytes(content), _file_identity(before)
    finally:
        os.close(descriptor)


def _write_all(descriptor, content):
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("file write did not progress")
        view = view[written:]


def _file_identity(details):
    return details.st_dev, details.st_ino, details.st_size, details.st_mtime_ns, details.st_ctime_ns


def _positive(value, label):
    if type(value) is not int or value <= 0:
        raise ValueError(f"{label} must be a positive integer")


def _commit(value):
    if not isinstance(value, str) or len(value) not in {40, 64} or any(char not in "0123456789abcdef" for char in value):
        raise CoverageIntegrityError("coverage commit is invalid")


def _is_image_id(value):
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and len(value) == 71
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _stored_replay_environment(value):
    if not isinstance(value, list) or any(
        not isinstance(item, list) or len(item) != 2
        for item in value
    ):
        return None
    environment = tuple(tuple(item) for item in value)
    return environment if valid_replay_environment(environment) else None


def _digest(value, label):
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise CoverageIntegrityError(f"{label} is invalid")


def _validate_count(value):
    if value is None:
        return
    if (
        type(value.covered) is not int or type(value.total) is not int
        or value.covered < 0 or value.total < 0 or value.covered > value.total
    ):
        raise CoverageIntegrityError("coverage count is invalid")
