"""Bounded deterministic handoff from campaign monitoring to evidence services."""

from __future__ import annotations

from dataclasses import dataclass
import inspect

from backend.fuzzing.campaigns.monitor import CampaignArtifactObservation
from backend.services.campaigns.production_runtime import CampaignProgressObservation


_MAX_OUTCOMES = 1_024


@dataclass(frozen=True)
class ArtifactProcessingOutcome:
    artifact: CampaignArtifactObservation
    accepted: bool
    evidence_id: str
    reason: str
    durable_relative_path: str | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.artifact, CampaignArtifactObservation)
            or type(self.accepted) is not bool
            or not _bounded(self.evidence_id, 256)
            or not _bounded(self.reason, 2_000)
            or self.durable_relative_path is not None
            and not _bounded(self.durable_relative_path, 2_000)
        ):
            raise ValueError("artifact processing outcome is invalid")


@dataclass(frozen=True)
class CampaignProcessingResult:
    corpus_opportunity: bool
    replayed_crash: bool
    evidence: tuple[dict, ...]

    def __post_init__(self) -> None:
        if (
            type(self.corpus_opportunity) is not bool
            or type(self.replayed_crash) is not bool
            or not isinstance(self.evidence, tuple)
            or len(self.evidence) > _MAX_OUTCOMES + 1
            or any(not isinstance(item, dict) for item in self.evidence)
        ):
            raise ValueError("campaign processing result is invalid")
        identifiers = self.evidence_ids
        if len(identifiers) != len(self.evidence) or len(set(identifiers)) != len(identifiers):
            raise ValueError("campaign processing evidence IDs must be complete and unique")

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        return tuple(item.get("evidence_id", "") for item in self.evidence)


class CampaignEvidenceProcessor:
    """Process one bounded monitor page; deterministic domain services own idempotency."""

    def __init__(self, *, corpus, crashes, minimiser, events=None):
        self._corpus = corpus
        self._crashes = crashes
        self._minimiser = minimiser
        self._events = events

    async def process(self, *, project, campaign, invocation, progress, assets) -> CampaignProcessingResult:
        if (
            not isinstance(progress, CampaignProgressObservation)
            or progress.campaign_id != campaign.id
            or len(progress.artifacts) > _MAX_OUTCOMES
        ):
            raise ValueError("campaign monitor page does not match its campaign")
        del assets
        ordered = sorted(
            progress.artifacts,
            key=lambda item: (0 if item.kind == "crash" else 1, item.relative_path),
        )
        outcomes: list[ArtifactProcessingOutcome] = []
        for artifact in ordered:
            handler = self._crashes if artifact.kind == "crash" else self._corpus
            value = await _await(handler.process(
                project=project,
                campaign=campaign,
                invocation=invocation,
                progress=progress,
                artifact=artifact,
            ))
            if not isinstance(value, ArtifactProcessingOutcome) or value.artifact != artifact:
                raise TypeError("campaign artifact handler returned invalid evidence")
            outcomes.append(value)

        evidence = [self._evidence(project.id, campaign.id, value) for value in outcomes]
        admitted = any(
            value.accepted and value.artifact.kind == "corpus" for value in outcomes
        )
        replayed = any(
            value.accepted and value.artifact.kind == "crash" for value in outcomes
        )
        if admitted:
            minimisation_id = await _await(self._minimiser.minimise_if_needed(
                project=project, campaign=campaign, invocation=invocation,
            ))
            if minimisation_id is not None:
                if not _bounded(minimisation_id, 256):
                    raise ValueError("corpus minimisation evidence ID is invalid")
                evidence.append({
                    "evidence_id": minimisation_id,
                    "project_id": project.id,
                    "campaign_id": campaign.id,
                    "provenance": "native_corpus_minimisation",
                    "trusted_instructions": False,
                })

        if self._events is not None:
            for value in outcomes:
                if value.accepted:
                    await self._events.append(project.id, "activity", {
                        "decision": (
                            "Crash replayed and triaged"
                            if value.artifact.kind == "crash" else "Corpus input admitted"
                        ),
                        "motivation": value.reason,
                        "evidence_ids": [value.evidence_id],
                        "campaign_id": campaign.id,
                    })
            await self._events.append(project.id, "debug", {
                "event": "campaign.artifact_processing",
                "campaign_id": campaign.id,
                "container_id": progress.container_id,
                "executions": progress.executions,
                "executions_per_second": progress.executions_per_second,
                "cpu_seconds": progress.cpu_seconds,
                "outcomes": [self._debug_outcome(item) for item in outcomes],
            })
        return CampaignProcessingResult(admitted, replayed, tuple(evidence))

    @staticmethod
    def _evidence(project_id: int, campaign_id: int, value: ArtifactProcessingOutcome) -> dict:
        return {
            "evidence_id": value.evidence_id,
            "project_id": project_id,
            "campaign_id": campaign_id,
            "kind": value.artifact.kind,
            "content_sha256": value.artifact.content_sha256,
            "accepted": value.accepted,
            "reason": value.reason,
            "durable_relative_path": value.durable_relative_path,
            "provenance": "deterministic_campaign_artifact_processing",
            "trusted_instructions": False,
        }

    @staticmethod
    def _debug_outcome(value: ArtifactProcessingOutcome) -> dict:
        return {
            "kind": value.artifact.kind,
            "relative_path": value.artifact.relative_path,
            "content_sha256": value.artifact.content_sha256,
            "size_bytes": value.artifact.size_bytes,
            "accepted": value.accepted,
            "evidence_id": value.evidence_id,
            "reason": value.reason,
            "durable_relative_path": value.durable_relative_path,
        }


async def _await(value):
    return await value if inspect.isawaitable(value) else value


def _bounded(value, limit: int) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= limit and "\x00" not in value
