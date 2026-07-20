"""Exact clean-coverage contract published with a validated campaign."""

from dataclasses import dataclass
import re

from backend.services.observability.redaction import is_secret_key, is_secret_value


_OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_FORBIDDEN_ENVIRONMENT = frozenset({"PATH", "PYTHONPATH", "LLVM_PROFILE_FILE"})


@dataclass(frozen=True)
class CampaignCoverageContract:
    project_id: int
    commit_sha: str
    clean_image_id: str
    clean_content_hash: str
    clean_parent_image_id: str
    target_asset_id: int
    configuration_asset_id: int | None
    coverage_asset_id: int
    binary_path: str
    replay_command: tuple[str, ...]
    replay_environment: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.project_id) is not int or self.project_id <= 0
            or not isinstance(self.commit_sha, str) or _OBJECT_ID.fullmatch(self.commit_sha) is None
            or not isinstance(self.clean_image_id, str) or _IMAGE_ID.fullmatch(self.clean_image_id) is None
            or not isinstance(self.clean_content_hash, str) or _SHA256.fullmatch(self.clean_content_hash) is None
            or not isinstance(self.clean_parent_image_id, str) or _IMAGE_ID.fullmatch(self.clean_parent_image_id) is None
            or type(self.target_asset_id) is not int or self.target_asset_id <= 0
            or self.configuration_asset_id is not None
            and (type(self.configuration_asset_id) is not int or self.configuration_asset_id <= 0)
            or type(self.coverage_asset_id) is not int or self.coverage_asset_id <= 0
            or not isinstance(self.binary_path, str) or not self.binary_path.startswith("/opt/bigeye/")
            or not isinstance(self.replay_command, tuple)
            or not 1 <= len(self.replay_command) <= 256
            or self.replay_command[0] != self.binary_path
            or self.replay_command.count("{input}") != 1
            or any(
                not isinstance(value, str) or not value or "\x00" in value or len(value) > 4_096
                for value in self.replay_command
            )
            or not valid_replay_environment(self.replay_environment)
        ):
            raise ValueError("campaign clean-coverage contract is invalid")


def valid_replay_environment(values) -> bool:
    if not isinstance(values, tuple) or len(values) > 32:
        return False
    seen = set()
    total_bytes = 0
    for item in values:
        if not isinstance(item, tuple) or len(item) != 2:
            return False
        key, value = item
        if (
            not isinstance(key, str) or len(key) > 128 or _ENVIRONMENT_NAME.fullmatch(key) is None
            or key in seen or key in _FORBIDDEN_ENVIRONMENT
            or key.startswith(("LD_", "DYLD_"))
            or is_secret_key(key)
            or not isinstance(value, str) or not value or "\x00" in value or len(value) > 4_096
            or is_secret_value(value)
        ):
            return False
        total_bytes += len(key.encode("utf-8")) + len(value.encode("utf-8"))
        if total_bytes > 16 * 1024:
            return False
        seen.add(key)
    return True
