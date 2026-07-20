"""Production adapters from monitored files to existing corpus, coverage, and crash services."""

from __future__ import annotations

import asyncio
from hashlib import sha256
import inspect
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
from tempfile import mkdtemp

from backend.fuzzing.campaigns.monitor import CampaignArtifactObservation
from backend.fuzzing.docker.campaign_workspace import CampaignWorkspace
from backend.fuzzing.corpus.admission import CorpusAdmission, CorpusCandidate, ExecutionEvidence
from backend.fuzzing.corpus.minimisation import CorpusCampaign, CorpusResult
from backend.fuzzing.crashes.quarantine import CrashObservation
from backend.fuzzing.coverage.replay_verifier import ResolvedCoverageTarget
from backend.models.campaign_artifact import ProcessedCampaignArtifact
from backend.services.campaigns.production_evidence import ArtifactProcessingOutcome
from backend.services.projects.clone_repository import contained_path


_MAX_ARTIFACT_BYTES = 16 * 1024 * 1024


class CampaignCoverageTargetResolver:
    """Resolve a persisted clean-coverage contract and validated project assets."""

    def __init__(self, workspace: Path, contracts, assets):
        self._workspace = Path(os.path.abspath(workspace))
        self._contracts = contracts
        self._assets = assets

    async def resolve(self, *, project, campaign) -> ResolvedCoverageTarget:
        contract = self._contracts.load_coverage(project.id, campaign.id)
        if (
            campaign.project_id != project.id
            or contract.project_id != project.id
            or contract.commit_sha != project.commit_sha
            or contract.target_asset_id != campaign.target_asset_id
            or contract.configuration_asset_id != campaign.configuration_asset_id
        ):
            raise ValueError("clean-coverage contract does not match its persisted campaign")
        for asset_id in {
            contract.target_asset_id,
            contract.configuration_asset_id,
            contract.clean_build_configuration_asset_id,
            contract.coverage_asset_id,
        } - {None}:
            asset = await self._assets.get(asset_id)
            if (
                asset is None or asset.project_id != project.id
                or asset.validated_at is None or asset.error is not None
            ):
                raise ValueError("clean-coverage contract references an unvalidated asset")
        project_root = contained_path(self._workspace, "projects", str(project.id))
        repository = contained_path(project_root, "repository").resolve(strict=True)
        return ResolvedCoverageTarget(
            id=campaign.id,
            project_id=project.id,
            commit_sha=project.commit_sha,
            clean_image=contract.clean_image_id,
            clean_image_id=contract.clean_image_id,
            clean_content_hash=contract.clean_content_hash,
            clean_parent_image_id=contract.clean_parent_image_id,
            binary_path=contract.binary_path,
            replay_command=contract.replay_command,
            target_asset_id=contract.target_asset_id,
            configuration_asset_id=contract.configuration_asset_id,
            clean_build_configuration_asset_id=contract.clean_build_configuration_asset_id,
            strategy_asset_id=contract.configuration_asset_id or contract.target_asset_id,
            coverage_asset_id=contract.coverage_asset_id,
            cpu_exposure_seconds=0.0,
            repository_root=repository,
            replay_environment=contract.replay_environment,
        )
class ProductionCorpusArtifactHandler:
    """Run clean coverage, admission, traceability, then publish one durable corpus input."""

    def __init__(self, *, workspace, journal, target_resolver, clean_coverage, traceability):
        self._workspace = Path(os.path.abspath(workspace))
        self._journal = journal
        self._targets = target_resolver
        self._coverage = clean_coverage
        self._traceability = traceability

    async def process(self, *, project, campaign, invocation, progress, artifact):
        del progress, invocation
        if artifact.kind != "corpus":
            raise ValueError("corpus handler received another artifact kind")
        previous = await self._journal.get(
            project.id, campaign.id, artifact.kind, artifact.content_sha256,
        )
        if previous is not None:
            return _prior_outcome(artifact, previous)
        raw_content = _read_artifact(
            self._workspace, project.id, campaign.id, artifact,
        )
        target = await _await(self._targets.resolve(
            project=project, campaign=campaign,
        ))
        contract = _coverage_contract(target)
        snapshots = []
        validated_content = []
        directory = Path(mkdtemp(
            prefix="corpus-admission-",
            dir=_temporary_root(self._workspace, project.id),
        ))
        staged = directory / artifact.content_sha256
        try:
            _publish_path(staged, raw_content)

            def execute(prepared, _contract):
                snapshot = self._coverage.replay(target, (staged,))
                if getattr(snapshot, "build_kind", None) != "clean":
                    return ExecutionEvidence(
                        True, False, False, content_sha256=prepared.content_sha256,
                        target_contract=contract,
                    )
                lines = frozenset(
                    f"{item.source_path}:{item.line_number}" for item in snapshot.lines
                )
                if any(hit.testcase_sha256 != prepared.content_sha256 for hit in snapshot.hits):
                    raise ValueError("clean coverage snapshot references another testcase")
                snapshots.append(snapshot)
                validated_content.append(prepared.content)
                return ExecutionEvidence(
                    True, True, True, lines, frozenset(), prepared.content_sha256, contract,
                )

            candidate = CorpusCandidate(
                staged,
                f"campaign:{campaign.id}:{artifact.relative_path}",
                (f"campaign-artifact:{campaign.id}:{artifact.content_sha256}",),
                artifact.content_sha256,
            )
            result = await asyncio.to_thread(
                CorpusAdmission(execute, _MAX_ARTIFACT_BYTES).validate,
                candidate,
                contract,
            )
            evidence_id = f"corpus:{campaign.id}:{artifact.content_sha256}"
            if (
                not result.admitted or not result.durable
                or len(snapshots) != 1 or len(validated_content) != 1
            ):
                return await self._retain(
                    project.id, campaign.id, artifact, False, evidence_id, result.reason, None,
                )
            created = await self._traceability.record(snapshots[0])
            if not created:
                return await self._retain(
                    project.id, campaign.id, artifact, False, evidence_id,
                    "candidate adds no new first-hit clean coverage", None,
                )
            durable = _publish_corpus(
                self._workspace, project.id, campaign.id,
                validated_content[0], artifact.content_sha256,
            )
            return await self._retain(
                project.id, campaign.id, artifact, True, evidence_id,
                "clean replay added first-hit project coverage", durable,
            )
        finally:
            shutil.rmtree(directory)

    async def _retain(
        self, project_id, campaign_id, artifact, accepted, evidence_id, reason, durable,
    ):
        record = ProcessedCampaignArtifact(
            project_id, campaign_id, "corpus", artifact.content_sha256,
            accepted, evidence_id, reason, durable,
        )
        await self._journal.record(record)
        return ArtifactProcessingOutcome(artifact, accepted, evidence_id, reason, durable)


class ProductionCrashArtifactHandler:
    """Build exact immutable crash provenance and call CrashPipeline before sealing identity."""

    def __init__(self, workspace: Path, journal, pipeline, target_resolver=None):
        self._workspace = Path(os.path.abspath(workspace))
        self._journal = journal
        self._pipeline = pipeline
        self._targets = target_resolver

    async def process(self, *, project, campaign, invocation, progress, artifact):
        del progress
        if artifact.kind != "crash":
            raise ValueError("crash handler received another artifact kind")
        previous = await self._journal.get(
            project.id, campaign.id, artifact.kind, artifact.content_sha256,
        )
        if previous is not None:
            return _prior_outcome(artifact, previous)
        content = _read_artifact(
            self._workspace, project.id, campaign.id, artifact,
        )
        clean_target = (
            await _await(self._targets.resolve(project=project, campaign=campaign))
            if self._targets is not None else None
        )
        observation = CrashObservation(
            project_id=project.id,
            campaign_id=campaign.id,
            commit_sha=project.commit_sha,
            engine=invocation.engine,
            image_id=invocation.image_id,
            target_asset_id=campaign.target_asset_id,
            configuration_asset_id=campaign.configuration_asset_id,
            sanitizer=_sanitizers(invocation.environment),
            command=_crash_command(invocation),
            input_bytes=content,
            input_mode=_crash_input_mode(invocation),
            clean_image_id=(
                clean_target.clean_image_id if clean_target is not None else None
            ),
            clean_command=(
                tuple(
                    "/bigeye/input/crash" if item == "{input}" else item
                    for item in clean_target.replay_command
                )
                if clean_target is not None else ()
            ),
        )
        finding = await self._pipeline.process(observation)
        if finding is None or finding.project_id != project.id:
            raise RuntimeError("crash pipeline returned no durable project finding")
        evidence_id = f"finding:{finding.fingerprint}"
        durable = f"findings/{finding.fingerprint}"
        reason = "deterministic replay and triage evidence retained"
        await self._journal.record(ProcessedCampaignArtifact(
            project.id, campaign.id, "crash", artifact.content_sha256, True,
            evidence_id, reason, durable,
        ))
        return ArtifactProcessingOutcome(artifact, True, evidence_id, reason, durable)


class ProductionCorpusMinimisation:
    """Invoke CorpusMinimiser only after enough newly admitted durable corpus entries."""

    def __init__(self, *, workspace, journal, minimiser, threshold: int = 64):
        if type(threshold) is not int or not 2 <= threshold <= 20_000:
            raise ValueError("corpus minimisation threshold must be between two and 20000")
        self._workspace = Path(os.path.abspath(workspace))
        self._journal = journal
        self._minimiser = minimiser
        self._threshold = threshold

    async def minimise_if_needed(self, *, project, campaign, invocation):
        count = await self._journal.accepted_count(project.id, campaign.id, "corpus")
        if count < self._threshold:
            return None
        corpus = self._workspace / "projects" / str(project.id) / "campaigns" / str(campaign.id) / "corpus"
        manifest_hash = await asyncio.to_thread(_corpus_manifest_hash, corpus)
        previous = await self._journal.get(
            project.id, campaign.id, "corpus-minimisation", manifest_hash,
        )
        if previous is not None:
            return None
        value = await asyncio.to_thread(self._minimiser.minimise, CorpusCampaign(
            "afl++" if invocation.engine == "afl" else "libfuzzer",
            corpus,
            _target_command(invocation),
            campaign.id,
            project.id,
        ))
        if not isinstance(value, CorpusResult):
            raise TypeError("corpus minimiser returned an invalid result")
        evidence_id = (
            f"corpus-minimisation:{project.id}:{campaign.id}:"
            f"{value.before_count}:{value.after_count}"
        )
        await self._journal.record(ProcessedCampaignArtifact(
            project.id,
            campaign.id,
            "corpus-minimisation",
            manifest_hash,
            value.replaced,
            evidence_id,
            value.reason,
            "corpus" if value.replaced else None,
        ))
        return evidence_id if value.replaced else None


def _prior_outcome(artifact, previous):
    return ArtifactProcessingOutcome(
        artifact, False, previous.evidence_id,
        "artifact already processed", previous.durable_relative_path,
    )


def _read_artifact(workspace, project_id, campaign_id, artifact):
    path = PurePosixPath(artifact.relative_path)
    if (
        path.is_absolute() or not path.parts
        or path.parts[0] not in {"corpus", "output"}
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("campaign artifact path is invalid")
    with CampaignWorkspace(Path(workspace)).open_campaign(
        project_id, campaign_id, create=False,
    ) as campaign:
        parent = os.dup(campaign.descriptor)
        try:
            for component in path.parts[:-1]:
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=parent,
                )
                os.close(parent)
                parent = child
            descriptor = os.open(path.parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                before = os.fstat(descriptor)
                if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_ARTIFACT_BYTES:
                    raise ValueError("campaign artifact is invalid or exceeds its bound")
                content = os.read(descriptor, _MAX_ARTIFACT_BYTES + 1)
                after = os.fstat(descriptor)
                if (
                    len(content) > _MAX_ARTIFACT_BYTES
                    or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                    != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    or len(content) != artifact.size_bytes
                    or sha256(content).hexdigest() != artifact.content_sha256
                ):
                    raise ValueError("campaign artifact changed after observation")
                return content
            finally:
                os.close(descriptor)
        finally:
            os.close(parent)


def _publish_corpus(workspace, project_id, campaign_id, content, digest):
    if not isinstance(content, bytes) or sha256(content).hexdigest() != digest:
        raise ValueError("durable corpus publication content is invalid")
    with CampaignWorkspace(Path(workspace)).open_campaign(
        project_id, campaign_id, create=False,
    ) as campaign:
        corpus = os.open(
            "corpus", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=campaign.descriptor,
        )
        try:
            try:
                descriptor = os.open(
                    digest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600, dir_fd=corpus,
                )
            except FileExistsError:
                descriptor = os.open(digest, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=corpus)
                try:
                    details = os.fstat(descriptor)
                    existing = os.read(descriptor, _MAX_ARTIFACT_BYTES + 1)
                    if not stat.S_ISREG(details.st_mode) or existing != content:
                        raise ValueError("durable corpus identity already contains different bytes")
                finally:
                    os.close(descriptor)
            else:
                try:
                    _write_all(descriptor, content)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                os.fsync(corpus)
        finally:
            os.close(corpus)
    return f"campaigns/{campaign_id}/corpus/{digest}"


def _publish_path(path: Path, content: bytes) -> None:
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
    )
    try:
        _write_all(descriptor, content)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _coverage_contract(target) -> str:
    provided = getattr(target, "contract_hash", None)
    if isinstance(provided, str) and provided:
        return provided
    fields = (
        getattr(target, "commit_sha", ""), getattr(target, "clean_image_id", ""),
        str(getattr(target, "target_asset_id", "")),
        str(getattr(target, "configuration_asset_id", "")),
        str(getattr(target, "clean_build_configuration_asset_id", "")),
        str(getattr(target, "coverage_asset_id", "")),
        "\0".join(getattr(target, "replay_command", ())),
        "\0".join(
            f"{key}={value}" for key, value in getattr(target, "replay_environment", ())
        ) or "no-environment",
    )
    if any(not isinstance(value, str) or not value for value in fields):
        raise ValueError("clean coverage target contract is incomplete")
    return sha256("\0".join(fields).encode()).hexdigest()


def _temporary_root(workspace: Path, project_id: int) -> str:
    root = workspace / "projects" / str(project_id) / "coverage-inputs"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.is_symlink():
        raise ValueError("coverage input root must not be a symlink")
    return os.fspath(root)


def _sanitizers(environment) -> str:
    values = []
    if "ASAN_OPTIONS" in environment:
        values.append("address")
    if "UBSAN_OPTIONS" in environment:
        values.append("undefined")
    return "+".join(values) or "none"


def _crash_command(invocation) -> tuple[str, ...]:
    command = list(_target_command(invocation))
    for index, value in enumerate(command):
        if value == "@@":
            command[index] = "/bigeye/input/crash"
    if invocation.engine == "libfuzzer":
        command.extend(("-runs=1", "/bigeye/input/crash"))
    return tuple(command)


def _crash_input_mode(invocation) -> str:
    if invocation.engine == "libfuzzer":
        return "inprocess"
    if invocation.engine != "afl":
        raise ValueError("unsupported campaign engine")
    return "file" if "@@" in _target_command(invocation) else "stdin"


def _target_command(invocation) -> tuple[str, ...]:
    command = tuple(invocation.command)
    if invocation.engine == "afl":
        try:
            return command[command.index("--") + 1:]
        except ValueError as error:
            raise ValueError("AFL++ invocation has no target separator") from error
    if invocation.engine == "libfuzzer":
        try:
            corpus = command.index("/campaign/corpus")
        except ValueError as error:
            raise ValueError("libFuzzer invocation has no campaign corpus") from error
        return command[:corpus]
    raise ValueError("unsupported campaign engine")


def _corpus_manifest_hash(corpus: Path) -> str:
    descriptor = os.open(corpus, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        digest = sha256()
        names = sorted(os.listdir(descriptor))
        if len(names) > 20_000:
            raise OverflowError("corpus manifest exceeds its entry bound")
        for name in names:
            details = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISREG(details.st_mode):
                raise ValueError("corpus manifest contains an unsafe entry")
            file_descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
            try:
                content = os.read(file_descriptor, _MAX_ARTIFACT_BYTES + 1)
            finally:
                os.close(file_descriptor)
            if len(content) > _MAX_ARTIFACT_BYTES:
                raise OverflowError("corpus entry exceeds its size bound")
            digest.update(name.encode()); digest.update(b"\0"); digest.update(sha256(content).digest())
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("artifact publication did not progress")
        view = view[written:]


async def _await(value):
    return await value if inspect.isawaitable(value) else value
