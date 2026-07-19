"""Contracts for immutable, content-addressed repository image layers."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import shutil
import threading
import time
from types import SimpleNamespace

import pytest


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


def test_repository_context_preserves_modes_empty_directories_and_safe_symlinks(tmp_path: Path) -> None:
    from backend.fuzzing.layers.repository_layer import RepositoryLayerService

    repository = tmp_path / "checkout"
    scripts = repository / "scripts"
    empty = repository / "empty"
    links = repository / "links"
    scripts.mkdir(parents=True)
    empty.mkdir()
    links.mkdir()
    executable = scripts / "run.sh"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o751)
    scripts.chmod(0o750)
    empty.chmod(0o710)
    (links / "relative-run").symlink_to("../scripts/run.sh")
    (links / "absolute-run").symlink_to(executable.resolve())

    manifest = RepositoryLayerService(tmp_path / "workspace", _Builder(), _Inspector()).prepare(
        7, repository, "d" * 40, "bigeye-toolchain:test", lambda text: None
    )
    copied = manifest.context_dir / "repository"

    assert (copied / "scripts").stat().st_mode & 0o777 == 0o750
    assert (copied / "scripts/run.sh").stat().st_mode & 0o777 == 0o751
    assert (copied / "empty").is_dir()
    assert (copied / "empty").stat().st_mode & 0o777 == 0o710
    assert os.readlink(copied / "links/relative-run") == "../scripts/run.sh"
    assert os.readlink(copied / "links/absolute-run") == "../scripts/run.sh"
    assert (copied / "links/absolute-run").resolve() == (copied / "scripts/run.sh").resolve()


def test_repository_tag_hashes_file_directory_and_symlink_semantics(tmp_path: Path) -> None:
    from backend.fuzzing.layers.repository_layer import RepositoryLayerService

    repository = tmp_path / "checkout"
    directory = repository / "bin"
    directory.mkdir(parents=True)
    executable = directory / "run"
    executable.write_text("run\n")
    executable.chmod(0o755)
    link = repository / "run-link"
    link.symlink_to("bin/run")
    service = RepositoryLayerService(tmp_path / "workspace", _Builder(), _Inspector())

    original = service.prepare(7, repository, "e" * 40, "bigeye-toolchain:test", lambda text: None)
    executable.chmod(0o644)
    file_mode_changed = service.prepare(7, repository, "e" * 40, "bigeye-toolchain:test", lambda text: None)
    directory.chmod(0o700)
    directory_mode_changed = service.prepare(7, repository, "e" * 40, "bigeye-toolchain:test", lambda text: None)
    link.unlink()
    link.symlink_to("bin")
    link_changed = service.prepare(7, repository, "e" * 40, "bigeye-toolchain:test", lambda text: None)

    assert len({original.tag, file_mode_changed.tag, directory_mode_changed.tag, link_changed.tag}) == 4


def test_concurrent_identical_prepare_publishes_and_builds_once(tmp_path: Path) -> None:
    from backend.fuzzing.layers.repository_layer import RepositoryLayerService

    class CountingRepositoryLayerService(RepositoryLayerService):
        publications = 0

        @classmethod
        def _publish_context(cls, *args):
            cls.publications += 1
            return super()._publish_context(*args)

    repository = tmp_path / "checkout"
    repository.mkdir()
    (repository / "main.c").write_text("int main(void) { return 0; }\n")
    builder = _ConcurrentBuilder()
    service = CountingRepositoryLayerService(tmp_path / "workspace", builder, _Inspector())

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(service.prepare, 7, repository, "f" * 40, "bigeye-toolchain:test", lambda text: None)
            for _ in range(2)
        ]
        manifests = [future.result() for future in futures]

    assert manifests[0].tag == manifests[1].tag
    assert manifests[0].context_dir == manifests[1].context_dir
    assert service.publications == 1
    assert builder.build_calls == 1
    assert (manifests[0].context_dir / "repository/main.c").is_file()


def test_interrupted_context_population_never_publishes_partial_context(tmp_path: Path, monkeypatch) -> None:
    from backend.fuzzing.layers.repository_layer import RepositoryLayerService

    repository = tmp_path / "checkout"
    repository.mkdir()
    (repository / "main.c").write_text("int main(void) { return 0; }\n")
    copyfile = shutil.copyfile

    def interrupted(source, destination):
        copyfile(source, destination)
        raise RuntimeError("interrupted copy")

    monkeypatch.setattr("backend.fuzzing.layers.repository_layer.shutil.copyfile", interrupted)
    workspace = tmp_path / "workspace"

    with pytest.raises(RuntimeError, match="interrupted copy"):
        RepositoryLayerService(workspace, _Builder(), _Inspector()).prepare(
            7, repository, "1" * 40, "bigeye-toolchain:test", lambda text: None
        )

    layers = workspace / "projects/7/layers"
    assert not layers.exists() or list(layers.iterdir()) == []


def test_invalid_published_context_is_rebuilt_before_image_reuse(tmp_path: Path) -> None:
    from backend.fuzzing.layers.repository_layer import RepositoryLayerService

    repository = tmp_path / "checkout"
    repository.mkdir()
    (repository / "main.c").write_text("safe\n")
    builder = _Builder()
    service = RepositoryLayerService(tmp_path / "workspace", builder, _Inspector())
    first = service.prepare(7, repository, "2" * 40, "bigeye-toolchain:test", lambda text: None)
    (first.context_dir / ".env").write_text("TOKEN=partial\n")
    builder.reuse = True

    second = service.prepare(7, repository, "2" * 40, "bigeye-toolchain:test", lambda text: None)

    assert not (second.context_dir / ".env").exists()
    (second.context_dir / "repository/main.c").unlink()
    third = service.prepare(7, repository, "2" * 40, "bigeye-toolchain:test", lambda text: None)

    assert (third.context_dir / "repository/main.c").read_text() == "safe\n"
    assert len(builder.calls) == 1


def test_dangling_internal_symlinks_are_preserved_rebased_and_hashed(tmp_path: Path) -> None:
    from backend.fuzzing.layers.repository_layer import RepositoryLayerService

    repository = tmp_path / "checkout"
    repository.mkdir()
    relative_link = repository / "generated-header"
    absolute_link = repository / "absolute-generated-header"
    relative_link.symlink_to("generated/later.h")
    absolute_link.symlink_to(repository / "generated/absolute-later.h")
    service = RepositoryLayerService(tmp_path / "workspace", _Builder(), _Inspector())

    first = service.prepare(7, repository, "4" * 40, "bigeye-toolchain:test", lambda text: None)
    copied = first.context_dir / "repository"
    relative_link.unlink()
    relative_link.symlink_to("generated/other.h")
    changed = service.prepare(7, repository, "4" * 40, "bigeye-toolchain:test", lambda text: None)

    assert os.readlink(copied / "generated-header") == "generated/later.h"
    assert os.readlink(copied / "absolute-generated-header") == "generated/absolute-later.h"
    assert first.tag != changed.tag


def test_in_tree_symlink_cycle_is_preserved_without_resolution(tmp_path: Path) -> None:
    from backend.fuzzing.layers.repository_layer import RepositoryLayerService

    repository = tmp_path / "checkout"
    repository.mkdir()
    (repository / "first").symlink_to("second")
    (repository / "second").symlink_to("first")

    manifest = RepositoryLayerService(tmp_path / "workspace", _Builder(), _Inspector()).prepare(
        7, repository, "5" * 40, "bigeye-toolchain:test", lambda text: None
    )
    copied = manifest.context_dir / "repository"

    assert os.readlink(copied / "first") == "second"
    assert os.readlink(copied / "second") == "first"


def test_symlink_with_lexical_repository_escape_is_excluded(tmp_path: Path) -> None:
    from backend.fuzzing.layers.repository_layer import RepositoryLayerService

    repository = tmp_path / "checkout"
    repository.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("not repository content\n")
    (repository / "escape").symlink_to("../outside")

    manifest = RepositoryLayerService(tmp_path / "workspace", _Builder(), _Inspector()).prepare(
        7, repository, "6" * 40, "bigeye-toolchain:test", lambda text: None
    )

    assert not (manifest.context_dir / "repository/escape").exists()
    assert not (manifest.context_dir / "repository/escape").is_symlink()


def test_dangling_and_cyclic_link_digest_matches_validated_context(tmp_path: Path) -> None:
    from backend.fuzzing.layers.repository_layer import RepositoryLayerService

    repository = tmp_path / "checkout"
    repository.mkdir()
    (repository / "dangling").symlink_to("generated/output")
    (repository / "cycle-a").symlink_to("cycle-b")
    (repository / "cycle-b").symlink_to("cycle-a")
    builder = _Builder()
    service = RepositoryLayerService(tmp_path / "workspace", builder, _Inspector())

    manifest = service.prepare(7, repository, "7" * 40, "bigeye-toolchain:test", lambda text: None)
    source_digest = service._context_digest(repository)
    copied = manifest.context_dir / "repository"

    assert service._context_digest(copied) == source_digest
    assert service._valid_context(manifest.context_dir, manifest.dockerfile.read_text(), source_digest)
    (copied / "dangling").unlink()
    (copied / "dangling").symlink_to("../../escape")
    builder.reuse = True
    repaired = service.prepare(7, repository, "7" * 40, "bigeye-toolchain:test", lambda text: None)
    assert os.readlink(repaired.context_dir / "repository/dangling") == "generated/output"


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


class _ConcurrentBuilder:
    def __init__(self):
        self._lock = threading.Lock()
        self._built = False
        self.build_calls = 0

    def inspect_matching(self, tag: str, labels: dict[str, str]):
        with self._lock:
            return "sha256:built" if self._built else None

    def build(self, dockerfile: Path, tag: str, sink):
        with self._lock:
            self.build_calls += 1
        time.sleep(0.05)
        with self._lock:
            self._built = True
        return "sha256:built"
