"""Descriptor-contained campaign directories under one explicit workspace root."""

from __future__ import annotations

import errno
import os
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CampaignDirectory:
    descriptor: int
    path: Path
    device: int
    inode: int


class CampaignWorkspace:
    """Open every project/campaign path one component at a time without symlinks."""

    def __init__(self, root: Path):
        self.root = Path(os.path.abspath(root))
        descriptor = _open_absolute_directory(self.root)
        try:
            root_stat = os.fstat(descriptor)
            self._root_identity = (root_stat.st_dev, root_stat.st_ino)
        finally:
            os.close(descriptor)

    @contextmanager
    def open_campaign(self, project_id: int, campaign_id: int, create: bool):
        descriptor = self._open_root()
        try:
            for component in ("projects", str(project_id), "campaigns", str(campaign_id)):
                next_descriptor = _open_component(descriptor, component, create)
                os.close(descriptor)
                descriptor = next_descriptor
            current = os.fstat(descriptor)
            handle = CampaignDirectory(
                descriptor=descriptor,
                path=self.root / "projects" / str(project_id) / "campaigns" / str(campaign_id),
                device=current.st_dev,
                inode=current.st_ino,
            )
            yield handle
        finally:
            os.close(descriptor)

    def is_canonical(self, project_id: int, campaign_id: int, expected: tuple[int, int]) -> bool:
        try:
            with self.open_campaign(project_id, campaign_id, create=False) as current:
                return (current.device, current.inode) == expected
        except (OSError, ValueError):
            return False

    def prepare_mounts(self, campaign: CampaignDirectory, root_fallback: bool) -> dict[str, dict[str, str]]:
        volumes = {}
        for name, mode in (("corpus", "rw"), ("output", "rw"), ("config", "ro")):
            descriptor = _open_component(campaign.descriptor, name, create=True)
            try:
                if root_fallback:
                    os.fchmod(descriptor, 0o755 if mode == "ro" else 0o777)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            volumes[str(campaign.path / name)] = {"bind": f"/campaign/{name}", "mode": mode}
        self.prepare_logs(campaign)
        return volumes

    def existing_mounts(self, campaign: CampaignDirectory) -> dict[str, dict[str, str]]:
        volumes = {}
        for name, mode in (("corpus", "rw"), ("output", "rw"), ("config", "ro")):
            descriptor = _open_component(campaign.descriptor, name, create=False)
            os.close(descriptor)
            volumes[str(campaign.path / name)] = {"bind": f"/campaign/{name}", "mode": mode}
        return volumes

    @staticmethod
    def prepare_logs(campaign: CampaignDirectory) -> None:
        descriptor = _open_component(campaign.descriptor, "logs", create=True)
        try:
            os.fchmod(descriptor, 0o700)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def validate_log_destination(campaign: CampaignDirectory) -> None:
        logs = _open_component(campaign.descriptor, "logs", create=False)
        try:
            try:
                target = os.stat("container.log", dir_fd=logs, follow_symlinks=False)
            except FileNotFoundError:
                return
            if not stat.S_ISREG(target.st_mode):
                raise ValueError("campaign log destination must be a regular file, not a symlink")
        finally:
            os.close(logs)

    @staticmethod
    def open_log(campaign: CampaignDirectory) -> int:
        logs = _open_component(campaign.descriptor, "logs", create=False)
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
            descriptor = os.open("container.log", flags, 0o600, dir_fd=logs)
        except BaseException:
            os.close(logs)
            raise
        os.close(logs)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise ValueError("campaign log destination must be a regular file")
        return descriptor

    def _open_root(self) -> int:
        descriptor = _open_absolute_directory(self.root)
        current = os.fstat(descriptor)
        if (current.st_dev, current.st_ino) != self._root_identity:
            os.close(descriptor)
            raise ValueError("workspace root changed after service initialisation")
        return descriptor


def _open_absolute_directory(path: Path) -> int:
    if not path.is_absolute():
        raise ValueError("workspace root must be absolute")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            next_descriptor = _open_component(descriptor, component, create=False)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_component(parent: int, component: str, create: bool) -> int:
    if not component or component in {".", ".."} or "/" in component:
        raise ValueError("workspace path component is invalid")
    if create:
        created = False
        try:
            os.mkdir(component, mode=0o700, dir_fd=parent)
            created = True
        except FileExistsError:
            pass
        if created:
            os.fsync(parent)
    try:
        return os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise ValueError("workspace path contains a symlink or non-directory component") from error
        raise
