"""Campaign-owned writer quiescence for transactional corpus publication."""

from __future__ import annotations

import os
import stat
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Generic, Protocol, TypeVar


Result = TypeVar("Result")


class CampaignWriterStillActive(RuntimeError):
    """Raised when the exact campaign writer is not verifiably inactive."""


class CampaignOwnershipMismatch(RuntimeError):
    """Raised before controlling a writer that does not own the exact corpus."""


class CampaignQuiescenceRecoveryError(RuntimeError):
    """Preserve transition, recovery, and resume failures for manual recovery."""

    def __init__(
        self,
        message: str,
        *,
        primary_error: BaseException | None,
        recovery_error: BaseException | None = None,
        resume_error: BaseException | None = None,
        writer_state: CampaignWriterState | None = None,
        recovery_required: bool,
    ):
        super().__init__(message)
        self.primary_error = primary_error
        self.recovery_error = recovery_error
        self.resume_error = resume_error
        self.writer_state = writer_state
        self.recovery_required = recovery_required


@dataclass(frozen=True)
class CampaignCorpusOwnership:
    campaign_id: int
    project_id: int
    corpus_path: Path
    corpus_device: int
    corpus_inode: int

    def __post_init__(self) -> None:
        _require_positive_id(self.campaign_id, "campaign_id")
        _require_positive_id(self.project_id, "project_id")
        _require_filesystem_identity(self.corpus_device, "corpus_device")
        _require_filesystem_identity(self.corpus_inode, "corpus_inode")
        object.__setattr__(self, "corpus_path", Path(os.path.abspath(self.corpus_path)))


@dataclass(frozen=True)
class CampaignWriterIdentity:
    campaign_id: int
    project_id: int
    container_id: str
    corpus_path: Path
    corpus_device: int
    corpus_inode: int

    def __post_init__(self) -> None:
        _require_positive_id(self.campaign_id, "campaign_id")
        _require_positive_id(self.project_id, "project_id")
        _require_filesystem_identity(self.corpus_device, "corpus_device")
        _require_filesystem_identity(self.corpus_inode, "corpus_inode")
        if not isinstance(self.container_id, str) or not self.container_id.strip():
            raise ValueError("container_id cannot be blank")
        object.__setattr__(self, "corpus_path", Path(os.path.abspath(self.corpus_path)))


@dataclass(frozen=True)
class CampaignWriterState:
    identity: CampaignWriterIdentity
    state: str
    active: bool | None

    def __post_init__(self) -> None:
        if not isinstance(self.state, str) or not self.state.strip():
            raise ValueError("writer state cannot be blank")
        if self.active is not None and not isinstance(self.active, bool):
            raise ValueError("writer activity must be true, false, or unknown")


class CampaignWriterController(Protocol):
    """Resolve, control, and inspect a registry-owned deterministic writer."""

    def resolve(self, project_id: int, campaign_id: int) -> CampaignWriterIdentity: ...

    def inspect(self, identity: CampaignWriterIdentity) -> CampaignWriterState: ...

    def quiesce(self, identity: CampaignWriterIdentity) -> None: ...

    def resume(self, identity: CampaignWriterIdentity, prior_state: CampaignWriterState) -> None: ...

    def replace(
        self, identity: CampaignWriterIdentity, prior_state: CampaignWriterState,
    ) -> CampaignWriterIdentity: ...


class QuiescedOperation(Protocol, Generic[Result]):
    """A transaction that keeps its rollback source until verified commit."""

    def run(self) -> Result: ...

    def commit(self) -> None: ...

    def verify_commit(self) -> None: ...

    def rollback(self) -> None: ...

    def verify_rollback(self) -> None: ...


class CampaignQuiescenceService:
    """Run one publication transition for a registry-resolved campaign writer."""

    def __init__(self, controller: CampaignWriterController):
        self._controller = controller
        self._locks: dict[tuple[int, int], threading.Lock] = {}
        self._locks_guard = threading.Lock()

    def execute(self, ownership: CampaignCorpusOwnership, operation: QuiescedOperation[Result]) -> Result:
        lock_key = (ownership.project_id, ownership.campaign_id)
        with self._campaign_lock(lock_key):
            self._require_canonical_corpus(ownership)
            identity = self._resolve_owned_writer(ownership)
            prior_state = self._inspect_exact(identity)
            if prior_state.active is None:
                raise CampaignQuiescenceRecoveryError(
                    "campaign writer state is unknown before publication",
                    primary_error=None,
                    writer_state=prior_state,
                    recovery_required=True,
                )
            if prior_state.active:
                try:
                    self._controller.quiesce(identity)
                except BaseException as primary_error:
                    self._handle_partial_quiesce(
                        ownership,
                        identity,
                        prior_state,
                        primary_error,
                    )
            try:
                stopped_state = self._inspect_exact(identity)
            except BaseException as inspection_error:
                raise CampaignQuiescenceRecoveryError(
                    "campaign writer state is unknown after quiescing",
                    primary_error=inspection_error,
                    writer_state=None,
                    recovery_required=True,
                ) from inspection_error
            if stopped_state.active is not False:
                if stopped_state.active is True:
                    raise CampaignWriterStillActive(
                        f"campaign writer is still active: {identity.container_id}"
                    )
                raise CampaignQuiescenceRecoveryError(
                    "campaign writer state became unknown before publication",
                    primary_error=None,
                    writer_state=stopped_state,
                    recovery_required=True,
                )
            try:
                self._require_canonical_corpus(ownership)
            except BaseException as ownership_error:
                raise CampaignQuiescenceRecoveryError(
                    "campaign corpus ownership changed after stopping its writer",
                    primary_error=ownership_error,
                    writer_state=stopped_state,
                    recovery_required=True,
                ) from ownership_error
            return self._execute_stopped(
                ownership,
                identity,
                prior_state,
                operation,
            )

    def _execute_stopped(
        self,
        ownership: CampaignCorpusOwnership,
        identity: CampaignWriterIdentity,
        prior_state: CampaignWriterState,
        operation: QuiescedOperation[Result],
    ) -> Result:
        try:
            result = operation.run()
            stopped_state = self._inspect_exact(identity)
            if stopped_state.active is not False:
                raise CampaignWriterStillActive(
                    f"campaign writer is still active: {identity.container_id}"
                )
            operation.commit()
            operation.verify_commit()
        except BaseException as primary_error:
            try:
                operation.rollback()
                operation.verify_rollback()
                self._require_canonical_corpus(ownership)
            except BaseException as recovery_error:
                raise CampaignQuiescenceRecoveryError(
                    "corpus recovery is required while the campaign writer remains stopped",
                    primary_error=primary_error,
                    recovery_error=recovery_error,
                    writer_state=self._safe_inspect(identity),
                    recovery_required=True,
                ) from primary_error
            if prior_state.active:
                self._resume_or_raise(identity, prior_state, primary_error)
            raise
        self._replace_or_raise(identity, prior_state)
        return result

    def _handle_partial_quiesce(
        self,
        ownership: CampaignCorpusOwnership,
        identity: CampaignWriterIdentity,
        prior_state: CampaignWriterState,
        primary_error: BaseException,
    ) -> None:
        try:
            current_state = self._inspect_exact(identity)
        except BaseException as inspection_error:
            raise CampaignQuiescenceRecoveryError(
                "campaign writer state is unknown after a failed stop",
                primary_error=primary_error,
                recovery_error=inspection_error,
                writer_state=None,
                recovery_required=True,
            ) from primary_error
        if current_state.active is False:
            try:
                self._require_canonical_corpus(ownership)
            except BaseException as ownership_error:
                raise CampaignQuiescenceRecoveryError(
                    "campaign corpus is not safe after a failed stop",
                    primary_error=primary_error,
                    recovery_error=ownership_error,
                    writer_state=current_state,
                    recovery_required=True,
                ) from primary_error
            self._resume_or_raise(identity, prior_state, primary_error)
        if current_state.active is None:
            raise CampaignQuiescenceRecoveryError(
                "campaign writer state is unknown after a failed stop",
                primary_error=primary_error,
                writer_state=current_state,
                recovery_required=True,
            ) from primary_error
        raise primary_error

    def _resume_or_raise(
        self,
        identity: CampaignWriterIdentity,
        prior_state: CampaignWriterState,
        primary_error: BaseException | None,
    ) -> None:
        try:
            self._controller.resume(identity, prior_state)
            resumed = self._inspect_exact(identity)
            if resumed.state != prior_state.state or resumed.active != prior_state.active:
                raise RuntimeError("campaign writer did not return to its prior exact state")
        except BaseException as resume_error:
            raise CampaignQuiescenceRecoveryError(
                "campaign writer could not be restored to its prior state",
                primary_error=primary_error,
                resume_error=resume_error,
                writer_state=self._safe_inspect(identity),
                recovery_required=False,
            ) from (primary_error or resume_error)

    def _replace_or_raise(
        self,
        identity: CampaignWriterIdentity,
        prior_state: CampaignWriterState,
    ) -> None:
        try:
            replacement = self._controller.replace(identity, prior_state)
            current = os.stat(identity.corpus_path, follow_symlinks=False)
            if (
                not isinstance(replacement, CampaignWriterIdentity)
                or replacement.project_id != identity.project_id
                or replacement.campaign_id != identity.campaign_id
                or replacement.container_id == identity.container_id
                or replacement.corpus_path != identity.corpus_path
                or replacement.corpus_device != current.st_dev
                or replacement.corpus_inode != current.st_ino
                or (replacement.corpus_device, replacement.corpus_inode)
                == (identity.corpus_device, identity.corpus_inode)
                or not stat.S_ISDIR(current.st_mode)
            ):
                raise CampaignOwnershipMismatch(
                    "replacement writer does not own the committed corpus"
                )
            replaced = self._inspect_exact(replacement)
            if replaced.state != prior_state.state or replaced.active != prior_state.active:
                raise RuntimeError("replacement writer did not restore the prior exact state")
        except BaseException as replacement_error:
            raise CampaignQuiescenceRecoveryError(
                "committed corpus requires campaign writer recovery",
                primary_error=None,
                resume_error=replacement_error,
                writer_state=self._safe_inspect(identity),
                recovery_required=True,
            ) from replacement_error

    def _resolve_owned_writer(self, ownership: CampaignCorpusOwnership) -> CampaignWriterIdentity:
        identity = self._controller.resolve(ownership.project_id, ownership.campaign_id)
        if not isinstance(identity, CampaignWriterIdentity) or (
            identity.project_id != ownership.project_id
            or identity.campaign_id != ownership.campaign_id
            or identity.corpus_path != ownership.corpus_path
            or identity.corpus_device != ownership.corpus_device
            or identity.corpus_inode != ownership.corpus_inode
        ):
            raise CampaignOwnershipMismatch(
                "resolved writer does not own the requested campaign corpus"
            )
        return identity

    def _inspect_exact(self, identity: CampaignWriterIdentity) -> CampaignWriterState:
        state = self._controller.inspect(identity)
        if not isinstance(state, CampaignWriterState) or state.identity != identity:
            raise CampaignOwnershipMismatch("writer inspection returned a foreign identity")
        return state

    @staticmethod
    def _require_canonical_corpus(ownership: CampaignCorpusOwnership) -> None:
        try:
            current = os.stat(ownership.corpus_path, follow_symlinks=False)
        except OSError as error:
            raise CampaignOwnershipMismatch("campaign corpus path is no longer canonical") from error
        if (
            not stat.S_ISDIR(current.st_mode)
            or current.st_dev != ownership.corpus_device
            or current.st_ino != ownership.corpus_inode
        ):
            raise CampaignOwnershipMismatch("campaign corpus path is no longer canonical")

    def _safe_inspect(self, identity: CampaignWriterIdentity) -> CampaignWriterState | None:
        try:
            return self._inspect_exact(identity)
        except BaseException:
            return None

    def _campaign_lock(self, key: tuple[int, int]) -> threading.Lock:
        with self._locks_guard:
            return self._locks.setdefault(key, threading.Lock())


def _require_positive_id(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")


def _require_filesystem_identity(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
