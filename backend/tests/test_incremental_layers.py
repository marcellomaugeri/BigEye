"""Contracts for dependency-isolated, reusable generated build layers."""

from __future__ import annotations

from pathlib import Path
from hashlib import sha256
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest


def test_corpus_change_does_not_change_target_layer(tmp_path: Path) -> None:
    from backend.fuzzing.layers.target_layer import TargetLayerService

    service = TargetLayerService(tmp_path, SimpleNamespace(), SimpleNamespace())
    assert service.tag(harness_hash="h1", build_hash="b1", corpus_hash="c1") == service.tag(
        harness_hash="h1", build_hash="b1", corpus_hash="c2"
    )


def test_fuzz_patch_is_rejected_from_clean_coverage_context() -> None:
    from backend.fuzzing.layers.policy import LayerPolicy, LayerPolicyError

    with pytest.raises(LayerPolicyError, match="fuzz-only patch"):
        LayerPolicy().validate_coverage_inputs(["target.patch"])


@pytest.mark.parametrize("text", [
    "FROM base:latest\nRUN --mount=type=secret,id=token true\n",
    "FROM base:latest\nFROM other:latest\n",
    "FROM base:latest\nCOPY --from=other /src /src\n",
    "FROM base:latest\nADD https://example.test/tool /tool\n",
    "FROM base:latest\nRUN curl https://example.test\n",
])
def test_dockerfile_policy_rejects_unsafe_generated_instructions(text: str) -> None:
    from backend.fuzzing.layers.policy import LayerPolicyError, validate_generated_dockerfile

    with pytest.raises(LayerPolicyError):
        validate_generated_dockerfile(text, "base:latest")


def test_project_dependency_build_is_the_only_layer_with_network_access(tmp_path: Path) -> None:
    from backend.fuzzing.layers.coverage_layer import CoverageLayerService
    from backend.fuzzing.layers.project_layer import ProjectLayerService
    from backend.fuzzing.layers.target_layer import TargetLayerService

    builder = _Builder()
    inspector = SimpleNamespace(inspect=lambda tag: SimpleNamespace(image_id=f"sha256:{tag}", os="linux", architecture="amd64"))
    project = SimpleNamespace(id=7, commit_sha="a" * 40)
    repository = _manifest(tmp_path, "repository", "repository:tag")
    asset = SimpleNamespace(id=1, content_hash="build", name="build.sh", kind="build")
    _asset(tmp_path, 7, asset, "build.sh", "#!/bin/sh\nexit 0\n")
    project_manifest = ProjectLayerService(tmp_path, builder, inspector).prepare(project, repository, asset, lambda text: None)
    TargetLayerService(tmp_path, builder, inspector).prepare(project, project_manifest, asset, asset, lambda text: None)
    CoverageLayerService(tmp_path, builder, inspector).prepare(project, project_manifest, asset, asset, lambda text: None)

    assert builder.network_modes == [None, "none", "none"]


def test_target_patch_changes_identity_but_corpus_and_dictionary_do_not(tmp_path: Path) -> None:
    from backend.fuzzing.layers.target_layer import TargetLayerService

    service = TargetLayerService(tmp_path, SimpleNamespace(), SimpleNamespace())
    assert service.tag(harness_hash="h", build_hash="b", corpus_hash="first", fuzz_patch_hash="p1") != service.tag(
        harness_hash="h", build_hash="b", corpus_hash="second", fuzz_patch_hash="p2"
    )


def test_concurrent_layer_builds_do_not_cross_sink_output(tmp_path: Path) -> None:
    from backend.fuzzing.layers.project_layer import ProjectLayerService

    project = SimpleNamespace(id=7, commit_sha="a" * 40)
    repository = _manifest(tmp_path, "repository", "repository:tag")
    asset = SimpleNamespace(id=1, content_hash="build", name="build.sh", kind="build", project_id=7, validated_at=object(), error=None)
    _asset(tmp_path, 7, asset, "build.sh", "#!/bin/sh\nexit 0\n")
    builder = _ConcurrentBuilder()
    inspector = SimpleNamespace(inspect=lambda tag: SimpleNamespace(image_id="sha256:repository", os="linux", architecture="amd64"))
    service = ProjectLayerService(tmp_path, builder, inspector)
    first, second = [], []

    with ThreadPoolExecutor(max_workers=2) as executor:
        list(executor.map(lambda sink: service.prepare(project, repository, asset, sink), (first.append, second.append)))

    assert builder.calls == 1
    assert {tuple(first), tuple(second)} == {(), ("build\n",)}


@pytest.mark.parametrize(("service_name", "parent_kind"), [
    ("ProjectLayerService", "repository"), ("TargetLayerService", "project"), ("CoverageLayerService", "project"),
])
def test_layer_rejects_foreign_or_retagged_parent_before_context_or_build(tmp_path: Path, service_name: str, parent_kind: str) -> None:
    from backend.fuzzing.layers.coverage_layer import CoverageLayerService
    from backend.fuzzing.layers.project_layer import ProjectLayerService
    from backend.fuzzing.layers.target_layer import TargetLayerService

    project = SimpleNamespace(id=7, commit_sha="a" * 40)
    parent = _manifest(tmp_path, parent_kind, f"{parent_kind}:tag")
    parent = parent.__class__(parent.kind, parent.tag, "hash", parent.parent_tag, parent.dockerfile, parent.context_dir, {
        "bigeye.project": "8", "bigeye.commit": "b" * 40, "bigeye.layer": parent_kind,
        "bigeye.content-hash": "hash", "bigeye.parent-image": "sha256:parent",
    })
    asset = SimpleNamespace(id=1, content_hash="asset", name="build.sh", kind="build", project_id=7, validated_at=object(), error=None)
    _asset(tmp_path, 7, asset, "build.sh", "#!/bin/sh\ntrue\n")
    builder = _Builder()
    inspector = SimpleNamespace(inspect=lambda tag: SimpleNamespace(image_id="sha256:parent", os="linux", architecture="amd64"))
    service = {"ProjectLayerService": ProjectLayerService, "TargetLayerService": TargetLayerService, "CoverageLayerService": CoverageLayerService}[service_name](tmp_path, builder, inspector)

    with pytest.raises(ValueError, match="parent"):
        if service_name == "ProjectLayerService":
            service.prepare(project, parent, asset, lambda text: None)
        else:
            service.prepare(project, parent, asset, asset, lambda text: None)
    assert builder.network_modes == []
    assert not (tmp_path / "projects/7/build-contexts").exists()


def test_agent_dockerfile_is_validated_before_build_and_changes_only_its_layer(tmp_path: Path) -> None:
    from backend.fuzzing.layers.project_layer import ProjectLayerService

    project = SimpleNamespace(id=7, commit_sha="a" * 40)
    parent = _manifest(tmp_path, "repository", "repository:tag")
    parent = parent.__class__(parent.kind, parent.tag, "hash", parent.parent_tag, parent.dockerfile, parent.context_dir, {
        "bigeye.project": "7", "bigeye.commit": "a" * 40, "bigeye.layer": "repository",
        "bigeye.content-hash": "hash", "bigeye.parent-image": "sha256:parent",
    })
    asset = SimpleNamespace(id=1, content_hash="asset", name="build.sh", kind="build", project_id=7, validated_at=object(), error=None)
    _asset(tmp_path, 7, asset, "build.sh", "#!/bin/sh\ntrue\n")
    dockerfile = tmp_path / "projects/7/assets/1/Dockerfile"
    dockerfile.write_text("FROM repository:tag\nWORKDIR /src\nCOPY build/ /bigeye/build/\nRUN /bin/sh /bigeye/build/build.sh\n")
    _rehash_asset(asset, dockerfile.parent)
    builder = _Builder()
    inspector = SimpleNamespace(inspect=lambda tag: SimpleNamespace(image_id="sha256:parent", os="linux", architecture="amd64"))
    service = ProjectLayerService(tmp_path, builder, inspector)
    first = service.prepare(project, parent, asset, lambda text: None)
    dockerfile.write_text("FROM wrong:tag\n")
    _rehash_asset(asset, dockerfile.parent)
    with pytest.raises(ValueError, match="required parent"):
        service.prepare(project, parent, asset, lambda text: None)
    assert builder.network_modes == [None]
    assert "bigeye.layer=\"project\"" in first.dockerfile.read_text()


@pytest.mark.parametrize("text", [
    "FROM base:latest\nRUN --network=host true\n",
    "FROM base:latest\nRUN --security=insecure true\n",
])
def test_policy_rejects_run_network_and_security_even_for_project_layers(text: str) -> None:
    from backend.fuzzing.layers.policy import LayerPolicyError, validate_generated_dockerfile

    with pytest.raises(LayerPolicyError):
        validate_generated_dockerfile(text, "base:latest", allow_network=True)


class _Builder:
    def __init__(self):
        self.network_modes: list[str | None] = []

    def inspect_matching(self, tag, labels):
        return None

    def verify_parent(self, tag, labels, image_id):
        return labels.get("bigeye.project") == "7" and labels.get("bigeye.commit") == "a" * 40

    def build(self, dockerfile, tag, sink, network_mode=None):
        self.network_modes.append(network_mode)
        return "sha256:built"


class _ConcurrentBuilder(_Builder):
    def __init__(self):
        super().__init__()
        self.calls = 0

    def inspect_matching(self, tag, labels):
        return "sha256:built" if self.calls else None

    def build(self, dockerfile, tag, sink, network_mode=None):
        self.calls += 1
        sink("build\n")
        return "sha256:built"


def _manifest(tmp_path: Path, kind: str, tag: str):
    from backend.fuzzing.layers.manifest import LayerManifest

    context = tmp_path / kind
    context.mkdir(exist_ok=True)
    dockerfile = context / "Dockerfile"
    dockerfile.write_text("FROM parent:tag\n")
    return LayerManifest(kind, tag, "hash", "parent:tag", dockerfile, context, {
        "bigeye.project": "7", "bigeye.commit": "a" * 40, "bigeye.layer": kind,
        "bigeye.content-hash": "hash", "bigeye.parent-image": "sha256:parent",
    })


def _asset(workspace: Path, project_id: int, asset, name: str, text: str) -> None:
    from backend.fuzzing.assets.validation import collection_hash

    root = workspace / "projects" / str(project_id) / "assets" / str(asset.id)
    root.mkdir(parents=True)
    source = root / name
    source.write_text(text)
    _rehash_asset(asset, root)
    asset.project_id = project_id
    asset.validated_at = object()
    asset.error = None


def _rehash_asset(asset, root: Path) -> None:
    from backend.fuzzing.assets.validation import collection_hash

    asset.content_hash = collection_hash({
        entry.relative_to(root).as_posix(): (entry, None) for entry in root.rglob("*") if entry.is_file()
    }, asset.kind)
