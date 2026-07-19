"""Contracts for immutable, project-contained campaign assets."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest

from backend.models.asset import CampaignAsset


def run(awaitable):
    return asyncio.run(awaitable)


class _Assets:
    def __init__(self, project_id: int = 7):
        self.project_id = project_id
        self.created: list[CampaignAsset] = []
        self.validated: list[int] = []
        self.errors: list[tuple[int, str]] = []

    async def create(self, project_id, kind, name, content_hash, parent_id):
        asset = CampaignAsset(
            id=len(self.created) + 1, project_id=project_id, kind=kind, name=name,
            content_hash=content_hash, parent_id=parent_id, created_at=datetime.now(UTC),
            validated_at=None, error=None,
        )
        self.created.append(asset)
        return asset

    async def get(self, asset_id):
        return next((asset for asset in self.created if asset.id == asset_id), None)

    async def mark_validated(self, asset_id):
        self.validated.append(asset_id)
        return next(asset for asset in self.created if asset.id == asset_id)

    async def record_error(self, asset_id, error):
        self.errors.append((asset_id, error))


def test_asset_is_published_only_after_hash_validation_and_repository_confirmation(tmp_path: Path) -> None:
    from backend.fuzzing.assets.store import AssetStore

    repository = _Assets()
    source = tmp_path / "workspace/projects/7/drafts/adapter.py"
    source.parent.mkdir(parents=True)
    source.write_text("print('safe')\n")
    asset = run(AssetStore(tmp_path / "workspace", repository).create(
        7, "adapter", "adapter.py", {"adapter.py": (source, sha256(source.read_bytes()).hexdigest())}, None,
    ))

    published = tmp_path / "workspace/projects/7/assets" / str(asset.id) / "adapter.py"
    assert published.read_text() == "print('safe')\n"
    assert repository.validated == [asset.id]
    assert not published.parent.with_name(f"{asset.id}.staging").exists()


def test_asset_rejects_parent_from_another_project_and_records_the_error(tmp_path: Path) -> None:
    from backend.fuzzing.assets.store import AssetStore

    repository = _Assets()
    repository.created.append(CampaignAsset(
        id=8, project_id=9, kind="adapter", name="parent.py", content_hash="a" * 64,
        parent_id=None, created_at=datetime.now(UTC), validated_at=None, error=None,
    ))
    source = tmp_path / "workspace/projects/7/drafts/child.py"
    source.parent.mkdir(parents=True)
    source.write_text("pass\n")

    with pytest.raises(ValueError, match="parent asset does not belong"):
        run(AssetStore(tmp_path / "workspace", repository).create(
            7, "adapter", "child.py", {"child.py": source}, 8,
        ))

    assert [asset.id for asset in repository.created] == [8]
    assert repository.errors == []
    assert not (tmp_path / "workspace/projects/7/assets/2.staging").exists()


def test_asset_rejects_unsafe_names_and_host_executables_except_generated_shell_scripts(tmp_path: Path) -> None:
    from backend.fuzzing.assets.store import AssetStore

    repository = _Assets()
    executable = tmp_path / "workspace/projects/7/drafts/adapter.py"
    executable.parent.mkdir(parents=True)
    executable.write_text("print('unsafe')\n")
    executable.chmod(0o755)
    store = AssetStore(tmp_path / "workspace", repository)

    with pytest.raises(ValueError, match="safe relative"):
        run(store.create(7, "adapter", "adapter.py", {"../escape": executable}, None))
    with pytest.raises(ValueError, match="non-executable"):
        run(store.create(7, "adapter", "adapter.py", {"adapter.py": executable}, None))

    shell = tmp_path / "workspace/projects/7/drafts/run.sh"
    shell.write_text("#!/bin/sh\nexit 0\n")
    shell.chmod(0o755)
    asset = run(store.create(7, "script", "run.sh", {"run.sh": shell}, None))
    assert (tmp_path / "workspace/projects/7/assets" / str(asset.id) / "run.sh").stat().st_mode & 0o777 == 0o500


def test_asset_rejects_source_outside_its_project_before_persisting(tmp_path: Path) -> None:
    from backend.fuzzing.assets.store import AssetStore

    repository = _Assets()
    source = tmp_path / "outside.py"
    source.write_text("pass\n")

    with pytest.raises(ValueError, match="contained project workspace"):
        run(AssetStore(tmp_path / "workspace", repository).create(7, "adapter", "adapter.py", {"adapter.py": source}, None))
    assert repository.created == []


def test_source_swapped_to_symlink_after_validation_never_publishes_host_bytes(tmp_path: Path) -> None:
    from backend.fuzzing.assets.store import AssetStore

    workspace = tmp_path / "workspace"
    source = workspace / "projects/7/drafts/adapter.py"
    source.parent.mkdir(parents=True)
    source.write_text("safe\n")
    host = tmp_path / "host-secret.py"
    host.write_text("host-only\n")

    class SwappingAssets(_Assets):
        async def create(self, *args):
            asset = await super().create(*args)
            source.unlink()
            source.symlink_to(host)
            return asset

    repository = SwappingAssets()
    with pytest.raises(OSError):
        run(AssetStore(workspace, repository).create(7, "adapter", "adapter.py", {"adapter.py": source}, None))

    assert not (workspace / "projects/7/assets/1").exists()
    assert repository.errors and "host-only" not in repository.errors[0][1]


def test_source_content_changed_after_validation_does_not_publish_new_bytes_under_old_hash(tmp_path: Path) -> None:
    from backend.fuzzing.assets.store import AssetStore

    workspace = tmp_path / "workspace"
    source = workspace / "projects/7/drafts/adapter.py"
    source.parent.mkdir(parents=True)
    source.write_text("first\n")

    class RewritingAssets(_Assets):
        async def create(self, *args):
            asset = await super().create(*args)
            source.write_text("second\n")
            return asset

    repository = RewritingAssets()
    with pytest.raises(ValueError, match="changed after content validation"):
        run(AssetStore(workspace, repository).create(7, "adapter", "adapter.py", {"adapter.py": source}, None))

    assert not (workspace / "projects/7/assets/1").exists()
    assert repository.errors


def test_symlinked_projects_component_is_rejected_before_reading_external_source(tmp_path: Path) -> None:
    from backend.fuzzing.assets.store import AssetStore

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    external = tmp_path / "external"
    source = external / "7/drafts/adapter.py"
    source.parent.mkdir(parents=True)
    source.write_text("external-only\n")
    (workspace / "projects").symlink_to(external, target_is_directory=True)
    repository = _Assets()

    with pytest.raises(OSError):
        run(AssetStore(workspace, repository).create(7, "adapter", "adapter.py", {"adapter.py": workspace / "projects/7/drafts/adapter.py"}, None))

    assert repository.created == []


def test_symlinked_assets_component_never_receives_published_asset(tmp_path: Path) -> None:
    from backend.fuzzing.assets.store import AssetStore

    workspace = tmp_path / "workspace"
    source = workspace / "projects/7/drafts/adapter.py"
    source.parent.mkdir(parents=True)
    source.write_text("safe\n")
    external = tmp_path / "external-assets"
    external.mkdir()
    (workspace / "projects/7/assets").symlink_to(external, target_is_directory=True)
    repository = _Assets()

    with pytest.raises(OSError):
        run(AssetStore(workspace, repository).create(7, "adapter", "adapter.py", {"adapter.py": source}, None))

    assert list(external.iterdir()) == []
    assert repository.validated == []
