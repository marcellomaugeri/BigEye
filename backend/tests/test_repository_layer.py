"""Contracts for immutable, content-addressed repository image layers."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace


def test_clone_argv_uses_no_checkout_for_requested_revision_resolution() -> None:
    from backend.services.projects.clone_repository import clone_argv

    assert clone_argv("https://example.test/demo.git", "stable", "/repo") == [
        "git", "clone", "--no-checkout", "--", "https://example.test/demo.git", "/repo"
    ]


def test_repository_context_excludes_git_secrets_workspace_and_escaping_symlinks(tmp_path: Path) -> None:
    from backend.fuzzing.layers.repository_layer import RepositoryLayerService

    repository = tmp_path / "checkout"
    repository.mkdir()
    (repository / "main.c").write_text("int main(void) { return 0; }\n")
    (repository / ".git").mkdir()
    (repository / ".git" / "config").write_text("token=never-copy\n")
    (repository / ".env").write_text("TOKEN=never-copy\n")
    (repository / "workspace").mkdir()
    (repository / "workspace" / "corpus").write_text("not source\n")
    outside = tmp_path / "outside.txt"
    outside.write_text("never-copy\n")
    (repository / "outside-link").symlink_to(outside)

    builder = _Builder()
    service = RepositoryLayerService(tmp_path / "workspace", builder, _Inspector())
    manifest = service.prepare(7, repository, "a" * 40, "bigeye-toolchain:test", lambda text: None)

    copied = manifest.context_dir / "repository"
    assert (copied / "main.c").is_file()
    assert not (copied / ".git").exists()
    assert not (copied / ".env").exists()
    assert not (copied / "workspace").exists()
    assert not (copied / "outside-link").exists()
    assert "never-copy" not in "".join(
        path.read_text(errors="ignore") for path in manifest.context_dir.rglob("*") if path.is_file()
    )
    assert manifest.labels["bigeye.commit"] == "a" * 40
    assert manifest.labels["bigeye.layer"] == "repository"
    assert 'FROM bigeye-toolchain:test' in manifest.dockerfile.read_text()
    assert "COPY repository/ /src/" in manifest.dockerfile.read_text()
    assert 'bigeye.parent-image="sha256:parent"' in manifest.dockerfile.read_text()
    assert builder.calls == [(manifest.dockerfile, manifest.tag)]


def test_repository_tag_changes_only_for_safe_context_or_parent_identity(tmp_path: Path) -> None:
    from backend.fuzzing.layers.repository_layer import RepositoryLayerService

    repository = tmp_path / "checkout"
    repository.mkdir()
    (repository / "main.c").write_text("one\n")
    (repository / "workspace").mkdir()
    corpus = repository / "workspace" / "corpus"
    corpus.write_text("first\n")
    service = RepositoryLayerService(tmp_path / "workspace", _Builder(), _Inspector())

    first = service.prepare(7, repository, "b" * 40, "bigeye-toolchain:test", lambda text: None)
    corpus.write_text("second\n")
    unchanged = service.prepare(7, repository, "b" * 40, "bigeye-toolchain:test", lambda text: None)
    (repository / "main.c").write_text("two\n")
    changed = service.prepare(7, repository, "b" * 40, "bigeye-toolchain:test", lambda text: None)
    parent_changed = RepositoryLayerService(
        tmp_path / "workspace", _Builder(), _Inspector("sha256:other-parent")
    ).prepare(7, repository, "b" * 40, "bigeye-toolchain:test", lambda text: None)

    assert first.tag == unchanged.tag
    assert first.tag != changed.tag
    assert changed.tag != parent_changed.tag


def test_repository_layer_reuses_only_matching_inspected_labels(tmp_path: Path) -> None:
    from backend.fuzzing.layers.repository_layer import RepositoryLayerService

    repository = tmp_path / "checkout"
    repository.mkdir()
    (repository / "main.c").write_text("one\n")
    builder = _Builder(reuse=True)
    manifest = RepositoryLayerService(tmp_path / "workspace", builder, _Inspector()).prepare(
        7, repository, "c" * 40, "bigeye-toolchain:test", lambda text: None
    )

    assert builder.calls == []
    assert builder.matching == [(manifest.tag, manifest.labels)]


def test_image_reuse_requires_amd64_and_every_expected_label() -> None:
    from backend.fuzzing.docker.image_builder import ImageBuilder

    labels = {"bigeye.commit": "a" * 40, "bigeye.layer": "repository"}
    api = SimpleNamespace(inspect_image=lambda tag: {
        "Id": "sha256:repository", "Os": "linux", "Architecture": "amd64",
        "Config": {"Labels": {**labels, "bigeye.project": "7"}},
    })
    builder = ImageBuilder(SimpleNamespace(api=api))

    assert builder.inspect_matching("bigeye-repository:test", labels) == "sha256:repository"
    assert builder.inspect_matching("bigeye-repository:test", {**labels, "bigeye.project": "8"}) is None
    api.inspect_image = lambda tag: {
        "Id": "sha256:repository", "Os": "linux", "Architecture": "arm64", "Config": {"Labels": labels},
    }
    assert builder.inspect_matching("bigeye-repository:test", labels) is None


class _Inspector:
    def __init__(self, image_id: str = "sha256:parent"):
        self.image_id = image_id

    def inspect(self, tag: str):
        assert tag == "bigeye-toolchain:test"
        return SimpleNamespace(image_id=self.image_id, os="linux", architecture="amd64")


class _Builder:
    def __init__(self, reuse: bool = False):
        self.reuse = reuse
        self.calls: list[tuple[Path, str]] = []
        self.matching: list[tuple[str, dict[str, str]]] = []

    def inspect_matching(self, tag: str, labels: dict[str, str]):
        self.matching.append((tag, labels))
        return "sha256:reused" if self.reuse else None

    def build(self, dockerfile: Path, tag: str, sink):
        self.calls.append((dockerfile, tag))
        return "sha256:built"
