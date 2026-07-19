"""Campaign-writer quiescence for transactional corpus publication."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Generic, Protocol, TypeVar


Result = TypeVar("Result")


class CampaignWriterStillActive(RuntimeError):
    """Raised when the exact campaign writer is not verifiably inactive."""


@dataclass(frozen=True)
class CampaignWriterIdentity:
    campaign_id: int
    container_id: str

    def __post_init__(self) -> None:
        if isinstance(self.campaign_id, bool) or not isinstance(self.campaign_id, int) or self.campaign_id < 1:
            raise ValueError("campaign_id must be a positive integer")
        if not isinstance(self.container_id, str) or not self.container_id.strip():
            raise ValueError("container_id cannot be blank")


class CampaignWriterController(Protocol):
    """Control and inspect a service-owned deterministic campaign writer."""

    def is_active(self, identity: CampaignWriterIdentity) -> bool: ...

    def quiesce(self, identity: CampaignWriterIdentity) -> None: ...

    def resume(self, identity: CampaignWriterIdentity) -> None: ...


class QuiescedOperation(Protocol, Generic[Result]):
    """A transaction that keeps its rollback source until commit."""

    def run(self) -> Result: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...


class CampaignQuiescenceService:
    """Run one publication transition while its exact campaign writer is stopped."""

    def __init__(self, controller: CampaignWriterController):
        self._controller = controller
        self._locks: dict[int, threading.Lock] = {}
        self._locks_guard = threading.Lock()

    def execute(self, identity: CampaignWriterIdentity, operation: QuiescedOperation[Result]) -> Result:
        with self._campaign_lock(identity.campaign_id):
            was_active = self._controller.is_active(identity)
            if was_active:
                self._controller.quiesce(identity)
            try:
                self._require_inactive(identity)
                try:
                    result = operation.run()
                    self._require_inactive(identity)
                    operation.commit()
                    return result
                except BaseException as error:
                    try:
                        operation.rollback()
                    except BaseException as rollback_error:
                        error.add_note(f"corpus publication rollback also failed: {rollback_error}")
                    raise
            finally:
                if was_active:
                    self._controller.resume(identity)

    def _campaign_lock(self, campaign_id: int) -> threading.Lock:
        with self._locks_guard:
            return self._locks.setdefault(campaign_id, threading.Lock())

    def _require_inactive(self, identity: CampaignWriterIdentity) -> None:
        if self._controller.is_active(identity):
            raise CampaignWriterStillActive(
                f"campaign writer is still active: {identity.container_id}"
            )
