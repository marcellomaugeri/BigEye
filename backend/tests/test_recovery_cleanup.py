from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
from types import SimpleNamespace


COMMIT = "a" * 40
IMAGE_ID = "sha256:" + "b" * 64
TARGET_HASH = "c" * 64
CONFIGURATION_HASH = "d" * 64
NOW = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)


class RecoveryControl:
    def __init__(self):
        self.calls = []

    def adopt(self, campaign, container):
        self.calls.append(("adopt", campaign.campaign_id, container.container_id))

    def restart(self, campaign, container):
        self.calls.append((
            "restart", campaign.campaign_id,
            None if container is None else container.container_id,
        ))

    def quarantine(self, campaign, container, reason):
        self.calls.append(("quarantine", campaign.campaign_id, container.container_id, reason))


def _asset_identities():
    from backend.fuzzing.campaigns.recovery import RecoveryAssetIdentity

    return (
        RecoveryAssetIdentity(31, TARGET_HASH),
        RecoveryAssetIdentity(32, CONFIGURATION_HASH),
    )


def _campaign(*, project_id=7, campaign_id=3, healthy=True, pending=("review:3",)):
    from backend.fuzzing.campaigns.recovery import RecoverableCampaign

    return RecoverableCampaign(
        project_id=project_id,
        campaign_id=campaign_id,
        commit_sha=COMMIT,
        image_id=IMAGE_ID,
        asset_identities=_asset_identities(),
        healthy=healthy,
        pending_evidence_ids=pending,
    )


def _container(**changes):
    from backend.fuzzing.campaigns.recovery import RecoveryContainer

    values = {
        "container_id": "container-3",
        "managed_as": "fuzz-campaign",
        "project_id": 7,
        "campaign_id": 3,
        "commit_sha": COMMIT,
        "image_id": IMAGE_ID,
        "asset_identities": _asset_identities(),
        "platform": "linux/amd64",
        "state": "running",
    }
    values.update(changes)
    return RecoveryContainer(**values)


def _campaign_workspace(root: Path, project_id=7, campaign_id=3, *, seed=True) -> Path:
    campaign = root / "projects" / str(project_id) / "campaigns" / str(campaign_id)
    for name in ("corpus", "output", "config", "logs"):
        (campaign / name).mkdir(parents=True, exist_ok=True)
    if seed:
        (campaign / "corpus" / "seed").write_bytes(b"seed")
    return campaign


def test_recovery_adopts_only_the_exact_running_campaign(tmp_path: Path) -> None:
    from backend.fuzzing.campaigns.recovery import CampaignRecovery

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _campaign_workspace(workspace)
    control = RecoveryControl()

    records = CampaignRecovery(workspace, control).recover(
        project_id=7,
        campaigns=(_campaign(),),
        containers=(_container(),),
    )

    assert control.calls == [("adopt", 3, "container-3")]
    assert records[0].action == "adopted"
    assert records[0].pending_evidence_ids == ("review:3",)


def test_recovery_restarts_a_stopped_healthy_campaign_from_its_durable_corpus(tmp_path: Path) -> None:
    from backend.fuzzing.campaigns.recovery import CampaignRecovery

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _campaign_workspace(workspace)
    control = RecoveryControl()

    records = CampaignRecovery(workspace, control).recover(
        project_id=7,
        campaigns=(_campaign(),),
        containers=(_container(state="exited"),),
    )

    assert control.calls == [("restart", 3, "container-3")]
    assert records[0].action == "restarted"


def test_recovery_resumes_a_paused_healthy_campaign_from_its_durable_corpus(tmp_path: Path) -> None:
    from backend.fuzzing.campaigns.recovery import CampaignRecovery

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _campaign_workspace(workspace)
    control = RecoveryControl()

    records = CampaignRecovery(workspace, control).recover(
        project_id=7,
        campaigns=(_campaign(),),
        containers=(_container(state="paused"),),
    )

    assert control.calls == [("restart", 3, "container-3")]
    assert records[0].action == "restarted"


def test_recovery_quarantines_a_same_campaign_identity_mismatch(tmp_path: Path) -> None:
    from backend.fuzzing.campaigns.recovery import CampaignRecovery

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _campaign_workspace(workspace)
    control = RecoveryControl()
    mismatched = _container(commit_sha="e" * 40)

    records = CampaignRecovery(workspace, control).recover(
        project_id=7,
        campaigns=(_campaign(healthy=False),),
        containers=(mismatched,),
    )

    assert control.calls == [("quarantine", 3, "container-3", "container identity does not match durable campaign evidence")]
    assert [record.action for record in records] == ["quarantined", "retained"]
    assert all(record.pending_evidence_ids == ("review:3",) for record in records)


def test_recovery_quarantines_runtime_mismatch_without_hiding_an_exact_candidate(
    tmp_path: Path,
) -> None:
    from backend.fuzzing.campaigns.recovery import CampaignRecovery

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _campaign_workspace(workspace)
    control = RecoveryControl()
    mismatched = _container(
        container_id="container-mismatch", runtime_contract_matches=False,
    )
    exact = _container(container_id="container-exact")

    records = CampaignRecovery(workspace, control).recover(
        project_id=7,
        campaigns=(_campaign(),),
        containers=(mismatched, exact),
    )

    assert control.calls == [
        (
            "quarantine", 3, "container-mismatch",
            "container identity does not match durable campaign evidence",
        ),
        ("adopt", 3, "container-exact"),
    ]
    assert [record.action for record in records] == ["quarantined", "adopted"]


def test_production_recovery_routes_mismatch_quarantine_through_container_service(
    tmp_path: Path,
) -> None:
    from backend.fuzzing.docker.fuzz_container import ContainerCandidateObservation
    from backend.services.campaigns.production_runtime import DeferredCampaignContainers

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    mismatch = ContainerCandidateObservation("container-a", 3, 7, "running", False)
    exact = ContainerCandidateObservation("container-b", 3, 7, "running", True)

    class Service:
        def __init__(self): self.calls = []
        def observe_candidates(self, campaign, invocation):
            assert (campaign.project_id, campaign.id, invocation.image_id) == (7, 3, IMAGE_ID)
            return mismatch, exact
        def quarantine_candidate(self, candidate):
            self.calls.append(("quarantine", candidate.container_id))
        def adopt_candidate(self, candidate):
            self.calls.append(("adopt", candidate.container_id))

    class Invocations:
        def load(self, project_id, campaign_id):
            assert (project_id, campaign_id) == (7, 3)
            return SimpleNamespace(image_id=IMAGE_ID)

    service = Service()
    client = SimpleNamespace(api=SimpleNamespace(inspect_image=lambda _image: {
        "Id": IMAGE_ID, "Os": "linux", "Architecture": "amd64",
    }))
    deferred = DeferredCampaignContainers(
        workspace, docker_client=SimpleNamespace(), invocation_store=Invocations(),
    )
    project = SimpleNamespace(id=7, commit_sha=COMMIT)
    campaign = SimpleNamespace(
        id=3, project_id=7, target_asset_id=31, configuration_asset_id=32,
        next_review_reason=None, error=None,
    )
    assets = (
        SimpleNamespace(
            id=31, project_id=7, validated_at=NOW, error=None, content_hash=TARGET_HASH,
        ),
        SimpleNamespace(
            id=32, project_id=7, validated_at=NOW, error=None,
            content_hash=CONFIGURATION_HASH,
        ),
    )

    evidence = deferred._recover_lifecycle(client, service, project, (campaign,), assets)

    assert service.calls == [("quarantine", "container-a"), ("adopt", "container-b")]
    assert [item["action"] for item in evidence] == ["quarantined", "adopted"]


def test_production_recovery_quarantines_every_duplicate_exact_candidate(
    tmp_path: Path,
) -> None:
    from backend.fuzzing.docker.fuzz_container import ContainerCandidateObservation
    from backend.services.campaigns.production_runtime import DeferredCampaignContainers

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    candidates = (
        ContainerCandidateObservation("container-a", 3, 7, "running", True),
        ContainerCandidateObservation("container-b", 3, 7, "running", True),
    )

    class Service:
        def __init__(self): self.calls = []
        def observe_candidates(self, _campaign, _invocation): return candidates
        def quarantine_candidate(self, candidate):
            self.calls.append(("quarantine", candidate.container_id))

    service = Service()
    deferred = DeferredCampaignContainers(
        workspace,
        docker_client=SimpleNamespace(),
        invocation_store=SimpleNamespace(load=lambda _project, _campaign: SimpleNamespace(
            image_id=IMAGE_ID,
        )),
    )
    client = SimpleNamespace(api=SimpleNamespace(inspect_image=lambda _image: {
        "Id": IMAGE_ID, "Os": "linux", "Architecture": "amd64",
    }))
    project = SimpleNamespace(id=7, commit_sha=COMMIT)
    campaign = SimpleNamespace(
        id=3, project_id=7, target_asset_id=31, configuration_asset_id=32,
        next_review_reason=None, error=None,
    )
    assets = (
        SimpleNamespace(
            id=31, project_id=7, validated_at=NOW, error=None, content_hash=TARGET_HASH,
        ),
        SimpleNamespace(
            id=32, project_id=7, validated_at=NOW, error=None,
            content_hash=CONFIGURATION_HASH,
        ),
    )

    evidence = deferred._recover_lifecycle(client, service, project, (campaign,), assets)

    assert service.calls == [
        ("quarantine", "container-a"), ("quarantine", "container-b"),
    ]
    assert [item["action"] for item in evidence] == [
        "quarantined", "quarantined", "retained",
    ]


def test_recovery_never_controls_a_container_from_another_project(tmp_path: Path) -> None:
    from backend.fuzzing.campaigns.recovery import CampaignRecovery

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _campaign_workspace(workspace, seed=False)
    control = RecoveryControl()

    records = CampaignRecovery(workspace, control).recover(
        project_id=7,
        campaigns=(_campaign(),),
        containers=(_container(project_id=8),),
    )

    assert control.calls == []
    assert [record.action for record in records] == ["retained"]


def test_recovery_does_not_restart_from_an_empty_or_symlinked_corpus(tmp_path: Path) -> None:
    from backend.fuzzing.campaigns.recovery import CampaignRecovery

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    campaign = _campaign_workspace(workspace, seed=False)
    control = RecoveryControl()

    first = CampaignRecovery(workspace, control).recover(7, (_campaign(),), ())
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "seed").write_bytes(b"not contained")
    (campaign / "corpus").rmdir()
    (campaign / "corpus").symlink_to(outside, target_is_directory=True)
    second = CampaignRecovery(workspace, control).recover(7, (_campaign(),), ())

    assert control.calls == []
    assert [first[0].action, second[0].action] == ["retained", "retained"]


class DockerContainer:
    def __init__(self, *, container_id="container-3", labels=None, state="exited", finished_at=None):
        self.id = container_id
        self.status = state
        self.attrs = {
            "Id": container_id,
            "Image": IMAGE_ID,
            "Platform": "linux",
            "Config": {"Labels": labels or {}},
            "State": {
                "Status": state,
                "FinishedAt": (finished_at or (NOW - timedelta(hours=2))).isoformat().replace("+00:00", "Z"),
            },
        }
        self.removed = []

    def reload(self):
        return None

    def remove(self, force=False):
        self.removed.append(force)


class DockerImage:
    def __init__(
        self, *, image_id=IMAGE_ID, labels=None, created_at=None,
        rootfs_layers=("sha256:" + "8" * 64, "sha256:" + "9" * 64),
    ):
        self.id = image_id
        self.attrs = {
            "Id": image_id,
            "Os": "linux",
            "Architecture": "amd64",
            "Created": (created_at or (NOW - timedelta(hours=2))).isoformat().replace("+00:00", "Z"),
            "Config": {"Labels": labels or {}},
            "RootFS": {"Type": "layers", "Layers": list(rootfs_layers)},
        }


def _image_labels():
    return {
        "bigeye.project": "7",
        "bigeye.commit": COMMIT,
        "bigeye.layer": "target",
        "bigeye.content-hash": "f" * 64,
        "bigeye.parent-image": "sha256:" + "1" * 64,
        "bigeye.target-asset": "31",
        "bigeye.target-content-hash": TARGET_HASH,
    }


def _container_labels():
    return {
        **_image_labels(),
        "com.bigeye.managed": "fuzz-campaign",
        "com.bigeye.campaign-id": "3",
        "com.bigeye.project-id": "7",
        "com.bigeye.commit-sha": COMMIT,
        "com.bigeye.image-id": IMAGE_ID,
        "com.bigeye.engine": "afl",
    }


class Containers:
    def __init__(self, entries):
        self.entries = list(entries)
        self.list_calls = []

    def list(self, **kwargs):
        self.list_calls.append(kwargs)
        if "ancestor" in kwargs.get("filters", {}):
            return []
        return list(self.entries)


class Images:
    def __init__(self, entries):
        self.entries = list(entries)
        self.removed = []

    def list(self, **_kwargs):
        return list(self.entries)

    def get(self, image_id):
        return next(image for image in self.entries if image.id == image_id)

    def remove(self, image_id, force=False, noprune=False):
        self.removed.append((image_id, force, noprune))


class DockerClient:
    def __init__(self, containers, images):
        self.containers = Containers(containers)
        self.images = Images(images)


def _temporary_context(workspace: Path, *, project_id=7, commit=COMMIT) -> Path:
    context = workspace / "projects" / str(project_id) / "build-contexts" / ".temporary-probe"
    context.mkdir(parents=True)
    (context / "scratch").write_text("temporary")
    (context / ".bigeye-temporary.json").write_text(json.dumps({
        "managed": "temporary-build-context",
        "project_id": project_id,
        "commit_sha": commit,
        "created_at": (NOW - timedelta(hours=2)).isoformat(),
    }))
    return context


def _cleanup_image_identity():
    from backend.fuzzing.campaigns.cleanup import CleanupAssetIdentity, CleanupImageIdentity

    labels = _image_labels()
    return CleanupImageIdentity(
        image_id=IMAGE_ID,
        layer="target",
        content_hash=labels["bigeye.content-hash"],
        parent_image_id=labels["bigeye.parent-image"],
        asset_identities=(CleanupAssetIdentity("target", 31, TARGET_HASH),),
    )


def test_cleanup_is_idempotent_and_preserves_durable_project_evidence(tmp_path: Path) -> None:
    from backend.fuzzing.campaigns.cleanup import ProjectCleaner

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    campaign = _campaign_workspace(workspace)
    project = workspace / "projects" / "7"
    for name in ("assets", "findings", "coverage", "logs"):
        (project / name).mkdir(parents=True)
        (project / name / "keep").write_text("durable")
    (project / "pending-manager-decision.json").write_text("{}")
    temporary = _temporary_context(workspace)
    container = DockerContainer(labels=_container_labels())
    parent_id = _image_labels()["bigeye.parent-image"]
    parent = DockerImage(
        image_id=parent_id,
        labels={
            "bigeye.project": "7", "bigeye.commit": COMMIT,
            "bigeye.layer": "project", "bigeye.content-hash": "2" * 64,
            "bigeye.parent-image": "sha256:" + "3" * 64,
        },
        rootfs_layers=("sha256:" + "8" * 64,),
    )
    image = DockerImage(labels=_image_labels())
    client = DockerClient([container], [parent, image])
    cleaner = ProjectCleaner(client, workspace, grace_seconds=300, clock=lambda: NOW)

    first = cleaner.clean(
        7, COMMIT, referenced_image_ids=(),
        persisted_image_identities=(_cleanup_image_identity(),),
    )
    second = cleaner.clean(
        7, COMMIT, referenced_image_ids=(),
        persisted_image_identities=(_cleanup_image_identity(),),
    )

    assert first.removed_contexts == (temporary.as_posix(),)
    assert first.removed_container_ids == ("container-3",)
    assert first.removed_image_ids == (IMAGE_ID,)
    assert second.removed_contexts == second.removed_container_ids == second.removed_image_ids == ()
    assert container.removed == [False]
    assert client.images.removed == [(IMAGE_ID, False, True)]
    for path in (
        project / "assets", campaign / "corpus", project / "findings",
        project / "coverage", project / "logs", campaign / "logs",
        project / "pending-manager-decision.json",
    ):
        assert path.exists()


def test_cleanup_ignores_unlabelled_active_or_wrong_commit_resources(tmp_path: Path) -> None:
    from backend.fuzzing.campaigns.cleanup import ProjectCleaner

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _campaign_workspace(workspace)
    unlabelled = DockerContainer(container_id="unlabelled")
    active = DockerContainer(container_id="active", labels=_container_labels(), state="running")
    wrong_commit_labels = {**_container_labels(), "com.bigeye.commit-sha": "e" * 40}
    wrong_commit = DockerContainer(container_id="wrong-commit", labels=wrong_commit_labels)
    referenced = DockerImage(labels=_image_labels())
    client = DockerClient([unlabelled, active, wrong_commit], [referenced])

    result = ProjectCleaner(client, workspace, grace_seconds=300, clock=lambda: NOW).clean(
        7, COMMIT, referenced_image_ids=(IMAGE_ID,),
        persisted_image_identities=(_cleanup_image_identity(),),
    )

    assert result.removed_container_ids == result.removed_image_ids == ()
    assert unlabelled.removed == active.removed == wrong_commit.removed == []
    assert client.images.removed == []


def test_cleanup_never_follows_a_temporary_context_symlink(tmp_path: Path) -> None:
    from backend.fuzzing.campaigns.cleanup import ProjectCleaner

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    contexts = workspace / "projects" / "7" / "build-contexts"
    contexts.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_text("outside")
    (contexts / ".temporary-probe").symlink_to(outside, target_is_directory=True)
    client = DockerClient([], [])

    result = ProjectCleaner(client, workspace, grace_seconds=300, clock=lambda: NOW).clean(
        7, COMMIT, referenced_image_ids=(), persisted_image_identities=(),
    )

    assert result.removed_contexts == ()
    assert (outside / "keep").read_text() == "outside"


def test_cleanup_requires_persisted_asset_identity_and_actual_parent_ancestry(tmp_path: Path) -> None:
    from backend.fuzzing.campaigns.cleanup import (
        CleanupAssetIdentity,
        CleanupImageIdentity,
        ProjectCleaner,
    )

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _campaign_workspace(workspace)
    parent_id = "sha256:" + "1" * 64
    parent_layers = ("sha256:" + "8" * 64,)
    parent = DockerImage(
        image_id=parent_id,
        labels={
            "bigeye.project": "7", "bigeye.commit": COMMIT,
            "bigeye.layer": "project", "bigeye.content-hash": "2" * 64,
            "bigeye.parent-image": "sha256:" + "3" * 64,
        },
        rootfs_layers=parent_layers,
    )
    exact = DockerImage(labels=_image_labels(), rootfs_layers=(*parent_layers, "sha256:" + "9" * 64))
    wrong_asset_id = "sha256:" + "4" * 64
    wrong_asset = DockerImage(
        image_id=wrong_asset_id,
        labels={**_image_labels(), "bigeye.target-content-hash": "5" * 64},
        rootfs_layers=(*parent_layers, "sha256:" + "6" * 64),
    )
    false_parent_id = "sha256:" + "7" * 64
    false_parent = DockerImage(
        image_id=false_parent_id,
        labels=_image_labels(),
        rootfs_layers=("sha256:" + "0" * 64, "sha256:" + "9" * 64),
    )
    identities = (
        CleanupImageIdentity(
            IMAGE_ID, "target", "f" * 64, parent_id,
            (CleanupAssetIdentity("target", 31, TARGET_HASH),),
        ),
        CleanupImageIdentity(
            wrong_asset_id, "target", "f" * 64, parent_id,
            (CleanupAssetIdentity("target", 31, TARGET_HASH),),
        ),
        CleanupImageIdentity(
            false_parent_id, "target", "f" * 64, parent_id,
            (CleanupAssetIdentity("target", 31, TARGET_HASH),),
        ),
    )
    client = DockerClient([], [parent, exact, wrong_asset, false_parent])

    result = ProjectCleaner(client, workspace, grace_seconds=300, clock=lambda: NOW).clean(
        7, COMMIT, referenced_image_ids=(), persisted_image_identities=identities,
    )

    assert result.removed_image_ids == (IMAGE_ID,)
    assert client.images.removed == [(IMAGE_ID, False, True)]


def test_cleanup_removes_only_persisted_same_hash_raw_corpus_and_duplicate_crash_copies(
    tmp_path: Path,
) -> None:
    from backend.fuzzing.campaigns.cleanup import (
        DuplicateCrashCopy,
        ProjectCleaner,
        RedundantCorpusCopy,
    )

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    campaign = _campaign_workspace(workspace)
    queue = campaign / "output" / "main" / "queue"
    crashes = campaign / "output" / "main" / "crashes"
    queue.mkdir(parents=True)
    crashes.mkdir(parents=True)
    project = workspace / "projects" / "7"
    finding = project / "findings" / "finding-1"
    finding.mkdir(parents=True)
    corpus_bytes = b"admitted-corpus"
    crash_bytes = b"duplicate-crash"
    corpus_hash = __import__("hashlib").sha256(corpus_bytes).hexdigest()
    crash_hash = __import__("hashlib").sha256(crash_bytes).hexdigest()
    raw_corpus = queue / "id:000001"
    raw_crash = crashes / "id:000002"
    raw_corpus.write_bytes(corpus_bytes)
    raw_crash.write_bytes(crash_bytes)
    durable_corpus = campaign / "corpus" / corpus_hash
    durable_crash = finding / "minimal.bin"
    durable_corpus.write_bytes(corpus_bytes)
    durable_crash.write_bytes(crash_bytes)
    unmatched = queue / "id:000003"
    unmatched.write_bytes(b"keep-unrecorded")
    client = DockerClient([], [])

    result = ProjectCleaner(client, workspace, grace_seconds=300, clock=lambda: NOW).clean(
        7,
        COMMIT,
        referenced_image_ids=(),
        persisted_image_identities=(),
        redundant_corpus_copies=(RedundantCorpusCopy(
            campaign_id=3,
            raw_relative_path="output/main/queue/id:000001",
            durable_relative_path=f"campaigns/3/corpus/{corpus_hash}",
            content_sha256=corpus_hash,
            provenance_id="coverage-admission:1",
        ),),
        duplicate_crash_copies=(DuplicateCrashCopy(
            campaign_id=3,
            raw_relative_path="output/main/crashes/id:000002",
            durable_relative_path="findings/finding-1/minimal.bin",
            content_sha256=crash_hash,
            provenance_id="finding:1:occurrence:2",
        ),),
    )

    assert result.removed_raw_corpus_copies == (raw_corpus.as_posix(),)
    assert result.removed_duplicate_crash_copies == (raw_crash.as_posix(),)
    assert not raw_corpus.exists() and not raw_crash.exists()
    assert durable_corpus.read_bytes() == corpus_bytes
    assert durable_crash.read_bytes() == crash_bytes
    assert unmatched.read_bytes() == b"keep-unrecorded"


def test_first_party_fixture_contracts_are_present_and_bounded() -> None:
    fixtures = Path(__file__).parent / "fixtures"
    system = fixtures / "system_project"
    component = fixtures / "component_project"

    system_source = (system / "src" / "main.c").read_text()
    assert "--file" in system_source and "--mode" in system_source
    assert "BIGEYE_MAX_INPUT_BYTES" in system_source
    assert (system / "seeds" / "plain.txt").stat().st_size <= 1_024
    duplicate_one = (system / "crashes" / "duplicate-one.input").read_bytes()
    duplicate_two = (system / "crashes" / "duplicate-two.input").read_bytes()
    assert duplicate_one != duplicate_two

    parser_header = (component / "include" / "parser.h").read_text()
    correct_harness = (component / "harnesses" / "correct.c").read_text()
    incorrect_harness = (component / "harnesses" / "incorrect.c").read_text()
    assert "output must not be NULL" in parser_header
    assert "BigEyeRecord record" in correct_harness
    assert "bigeye_parse(data, size, NULL)" in incorrect_harness
