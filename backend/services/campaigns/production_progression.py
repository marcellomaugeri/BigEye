"""Derive one evidence-backed campaign improvement without polling an agent."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re

from backend.fuzzing.campaigns.configuration import (
    ConfigurationEvidence,
    ConfigurationHypothesis,
    ConfigurationPlanner,
)
from backend.fuzzing.campaigns.progression import (
    CampaignProgression,
    ProgressionAction,
    ProgressionEvidence,
)
from backend.fuzzing.campaigns.sanitizers import SanitizerPlanner, SanitizerTarget


_GRAMMAR_LIBRARY = "/usr/local/lib/afl/libgrammarmutator-json.so"
_DOCUMENT_PATH = re.compile(r"(?:^|/)(?:readme(?:\.[^/]+)?|docs?)(?:/|$)", re.IGNORECASE)
_OPTION = re.compile(r"(?<![A-Za-z0-9_-])(--[a-z][a-z0-9-]{1,63})(?![A-Za-z0-9_-])", re.IGNORECASE)
_COMPARISON = re.compile(r"\b(?:strcmp|strncmp|memcmp|strcasecmp|strncasecmp)\s*\(", re.IGNORECASE)
_LITERAL = re.compile(r"(?:\"[^\"\n]{1,128}\"|'[^'\n]{1,128}')")
_CONCURRENCY = re.compile(r"\b(?:pthread_|std::thread|std::mutex|mutex_|atomic_)\b", re.IGNORECASE)
_JSON = re.compile(r"\b(?:json|rapidjson|nlohmann|yyjson|cjson)[A-Za-z0-9_:.-]*\b", re.IGNORECASE)


@dataclass(frozen=True)
class ProgressionRecommendation:
    evidence_id: str
    campaign_id: int
    action: ProgressionAction
    supporting_evidence_ids: tuple[str, ...]
    dictionary_content: str | None = None

    def as_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id,
            "kind": "campaign_progression",
            "campaign_id": self.campaign_id,
            "action": self.action.name,
            "detail": self.action.detail,
            "arguments": list(self.action.arguments),
            "environment": [list(item) for item in self.action.environment],
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "provenance": "deterministic_campaign_progression",
            "trusted_instructions": False,
        }


class ProductionProgression:
    """Compose the deterministic progression planners from bounded runtime facts."""

    def next_recommendation(
        self,
        *,
        project_id: int,
        worker_count: int,
        engine: str,
        progress,
        initial_complete: bool,
        unhealthy: bool,
        repository_evidence,
        campaign_contexts,
    ) -> ProgressionRecommendation | None:
        evidence = tuple(
            item for item in repository_evidence
            if isinstance(item, dict)
            and isinstance(item.get("evidence_id"), str)
            and item["evidence_id"].strip()
        )
        completed, tried = self._completed(campaign_contexts)
        comparisons = self._matching_ids(
            evidence,
            lambda item, text: bool(_COMPARISON.search(text) and _LITERAL.search(text)),
        )
        concurrency = self._matching_ids(
            evidence, lambda item, text: bool(_CONCURRENCY.search(text)),
        )
        json_evidence = self._matching_ids(
            evidence, lambda item, text: bool(_JSON.search(text)),
        )
        gaps = self._matching_ids(
            evidence,
            lambda item, _text: (
                item.get("kind") == "system_coverage_gap"
                and item.get("provenance") == "clean_coverage"
            ),
        )
        configuration = (
            ConfigurationPlanner.next_candidate(
                ConfigurationEvidence(self._configuration_hypotheses(evidence)), tried,
            )
            if engine == "afl" else None
        )
        sanitizer_plan = SanitizerPlanner.plan(
            SanitizerTarget(concurrent=bool(concurrency)), worker_count,
        )
        special = sanitizer_plan.replay_variants[0] if sanitizer_plan.replay_variants else None
        action = CampaignProgression.next_step(ProgressionEvidence(
            engine="afl++" if engine == "afl" else engine,
            normal_build_ready=initial_complete,
            baseline_sanitizers_validated=True,
            seed_coverage_healthy=(
                getattr(progress, "queue_files", 0) > 0
                and getattr(progress, "executions", 0) > 0
            ),
            basic_fuzzer_running=True,
            basic_campaign_healthy=(
                not unhealthy and getattr(progress, "executions_per_second", 0.0) > 0
            ),
            dictionary_evidence_ids=comparisons,
            cmplog_evidence_ids=comparisons,
            configuration=configuration,
            component_gap_evidence_ids=gaps,
            special_sanitizer=special,
            special_sanitizer_evidence_ids=concurrency if special is not None else (),
            grammar_library=_GRAMMAR_LIBRARY if engine == "afl" else None,
            grammar_evidence_ids=json_evidence,
            completed_actions=completed,
        ))
        if action is None:
            return None
        identity = "\0".join((
            str(project_id), str(progress.campaign_id), action.key, *action.evidence_ids,
        )).encode("utf-8")
        evidence_id = (
            f"campaign-progression:{project_id}:{progress.campaign_id}:"
            f"{sha256(identity).hexdigest()[:16]}"
        )
        dictionary_content = (
            self._dictionary_content(evidence, comparisons)
            if action.name == "enable dictionary" else None
        )
        return ProgressionRecommendation(
            evidence_id, progress.campaign_id, action, action.evidence_ids,
            dictionary_content,
        )

    @staticmethod
    def _completed(campaign_contexts) -> tuple[tuple[str, ...], tuple[str, ...]]:
        values = tuple(
            context.get("configuration_purpose", "").strip()
            for context in campaign_contexts.values()
            if isinstance(context, dict)
            and isinstance(context.get("configuration_purpose"), str)
            and context["configuration_purpose"].strip()
        )
        tried = tuple(
            value.removeprefix("try configuration:")
            for value in values
        )
        return values, tried

    @staticmethod
    def _matching_ids(evidence, predicate) -> tuple[str, ...]:
        values = []
        for item in evidence:
            text = "\n".join(
                value for value in (item.get("path"), item.get("excerpt"), item.get("source_path"))
                if isinstance(value, str)
            )
            if predicate(item, text):
                values.append(item["evidence_id"])
        return tuple(dict.fromkeys(values))

    @staticmethod
    def _dictionary_content(evidence, identifiers: tuple[str, ...]) -> str:
        selected = set(identifiers)
        literals: list[str] = []
        for item in evidence:
            if item["evidence_id"] not in selected:
                continue
            excerpt = item.get("excerpt")
            if not isinstance(excerpt, str):
                continue
            for literal in _LITERAL.findall(excerpt):
                value = literal[1:-1]
                if value and value not in literals:
                    literals.append(value)
                if len(literals) >= 32:
                    break
        if not literals:
            raise ValueError("dictionary progression has no bounded literal tokens")
        return "".join(
            f"token_{index:03d}={json.dumps(value, ensure_ascii=True)}\n"
            for index, value in enumerate(literals)
        )

    @staticmethod
    def _configuration_hypotheses(evidence) -> tuple[ConfigurationHypothesis, ...]:
        values: list[ConfigurationHypothesis] = []
        seen: set[str] = set()
        for item in evidence:
            path = item.get("path")
            excerpt = item.get("excerpt")
            if (
                not isinstance(path, str)
                or not isinstance(excerpt, str)
                or not _DOCUMENT_PATH.search(path)
            ):
                continue
            for option in _OPTION.findall(excerpt):
                option = option.casefold()
                if option in seen:
                    continue
                seen.add(option)
                values.append(ConfigurationHypothesis(
                    option, (option,), (), (item["evidence_id"],), documented=True,
                ))
        return tuple(values)
