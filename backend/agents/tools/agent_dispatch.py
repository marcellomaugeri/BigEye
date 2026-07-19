"""Expose typed, validated specialists to the manager through Agent.as_tool()."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import PurePosixPath

from agents import RunConfig, RunContextWrapper, Runner, function_tool
from agents.agent_tool_input import default_tool_input_builder
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from backend.agents.context import AgentContext
from backend.agents.outputs.target_proposal import TargetProposal
from backend.agents.outputs.triage_result import TriageResult
from backend.agents.specialists.component_target import build_component_target_agent
from backend.agents.specialists.crash_triage import build_crash_triage_agent
from backend.agents.specialists.system_target import build_system_target_agent
from backend.agents.tools.generated_assets import _relative_path
from backend.agents.tools.evidence_retrieval import retrieve_repository_evidence
from backend.agents.tracing.local_trace import web_citations


class SpecialistValidationError(ValueError):
    """Raised when structured specialist evidence cannot be verified."""


class SpecialistRequest(BaseModel):
    """The complete bounded assignment passed across an agent-tool boundary."""

    model_config = ConfigDict(extra="forbid")

    assignment: str = Field(min_length=1, max_length=4_000)
    evidence_ids: list[str] = Field(max_length=64)


def _validate_evidence_ids(values: Iterable[str], allowed: frozenset[str]) -> None:
    values = list(values)
    if len(values) != len(set(values)):
        raise SpecialistValidationError("specialist returned duplicate evidence identifiers")
    if any(not isinstance(value, str) or not value or len(value) > 2_000 for value in values):
        raise SpecialistValidationError("specialist returned an invalid evidence identifier")
    unknown = set(values) - allowed
    if unknown:
        raise SpecialistValidationError("specialist cited evidence outside its assignment")


def _safe_seed_path(value: str) -> None:
    path = PurePosixPath(value)
    if (
        not isinstance(value, str) or not value or len(value) > 500 or path.is_absolute()
        or any(part in {"", ".", ".."} or part.casefold() == ".git" for part in path.parts)
    ):
        raise SpecialistValidationError("specialist returned an unsafe seed path")


def _validate_target(output, allowed: frozenset[str], expected_type: str) -> TargetProposal:
    try:
        proposal = output if isinstance(output, TargetProposal) else TargetProposal.model_validate(output)
    except (ValidationError, TypeError) as error:
        raise SpecialistValidationError("specialist returned an invalid target proposal") from error
    if proposal.instance_type != expected_type:
        raise SpecialistValidationError("specialist returned the wrong instance type")
    _validate_evidence_ids(proposal.evidence_ids, allowed)
    for seed in proposal.seeds:
        _safe_seed_path(seed.path)
    for intent in proposal.generated_asset_intents:
        try:
            _relative_path(intent.relative_path)
        except ValueError as error:
            raise SpecialistValidationError("specialist returned an unsafe generated asset intent") from error
    if any(not value.strip() or len(value) > 500 for value in proposal.probe_assertions):
        raise SpecialistValidationError("specialist returned an invalid probe assertion")
    return proposal


def _validate_triage(output, allowed: frozenset[str]) -> TriageResult:
    try:
        result = output if isinstance(output, TriageResult) else TriageResult.model_validate(output)
    except (ValidationError, TypeError) as error:
        raise SpecialistValidationError("specialist returned an invalid triage result") from error
    if result.classification not in {
        "harness-induced false positive", "improper contract usage", "true vulnerability",
        "flaky or environmental", "unresolved",
    }:
        raise SpecialistValidationError("specialist returned an unsupported crash classification")
    _validate_evidence_ids(result.evidence_ids, allowed)
    return result


def _tool(
    *, context: AgentContext, evidence_ids: set[str], builder, tool_name: str,
    description: str, validator, hooks=None, trace=None,
):
    validated_ids = evidence_ids

    @function_tool(name_override="retrieve_repository_evidence", failure_error_function=None)
    async def registered_retrieval(
        tool_context: RunContextWrapper[AgentContext], question: str, limit: int = 12,
    ) -> list[dict[str, int | str | bool]]:
        """Retrieve source evidence and register its exact deterministic identifiers for validation."""
        results = retrieve_repository_evidence(tool_context.context.evidence, question, limit)
        validated_ids.update(
            value["evidence_id"] for value in results if isinstance(value.get("evidence_id"), str)
        )
        return results

    def build(model: str):
        worker = builder(model)
        worker.tools = [
            registered_retrieval if getattr(tool, "name", None) == "retrieve_repository_evidence" else tool
            for tool in worker.tools
        ]
        return worker

    luna = build("gpt-5.6-luna")

    def input_builder(options):
        params = options.get("params") or {}
        requested = params.get("evidence_ids", []) if isinstance(params, dict) else []
        _validate_evidence_ids(requested, frozenset(validated_ids))
        return default_tool_input_builder(options)

    async def output_extractor(result):
        validated_ids.update(web_citations(getattr(result, "raw_responses", ())))
        if trace is not None:
            trace.record_result(luna, getattr(result, "input", None), result)
        try:
            return validator(getattr(result, "final_output", None), frozenset(validated_ids))
        except SpecialistValidationError as error:
            if trace is not None:
                trace.retry(luna, error)
            terra = build("gpt-5.6-terra")
            retry_input = list(result.to_input_list())
            retry_input.append({
                "role": "user",
                "content": (
                    "The prior proposal failed deterministic validation: " + str(error)
                    + ". Correct only that bounded proposal using the assigned evidence."
                ),
            })
            run_config = trace.run_config(f"{tool_name} validation retry") if trace is not None else RunConfig(
                workflow_name=f"{tool_name} validation retry", trace_include_sensitive_data=False,
            )
            retry_result = await Runner.run(
                terra, retry_input, context=context, hooks=hooks, run_config=run_config,
            )
            validated_ids.update(web_citations(getattr(retry_result, "raw_responses", ())))
            if trace is not None:
                trace.record_result(terra, retry_input, retry_result, retry_count=1)
            return validator(getattr(retry_result, "final_output", None), frozenset(validated_ids))

    return luna.as_tool(
        tool_name=tool_name, tool_description=description, parameters=SpecialistRequest,
        input_builder=input_builder, include_input_schema=True, custom_output_extractor=output_extractor,
        hooks=hooks, failure_error_function=None,
    )


def dispatch_tools(
    context: AgentContext, evidence_ids: set[str] | frozenset[str], hooks=None, trace=None,
    evidence_registry: set[str] | None = None,
) -> list:
    """Return exactly the three typed specialist tools available to the manager."""
    allowed = evidence_registry if evidence_registry is not None else set(evidence_ids)
    allowed.update(evidence_ids)
    return [
        _tool(
            context=context, evidence_ids=allowed, builder=build_system_target_agent,
            tool_name="prepare_system_target",
            description="Prepare or repair one evidence-backed AFL++ system target and deterministic probe.",
            validator=lambda output, values: _validate_target(output, values, "system-level"),
            hooks=hooks, trace=trace,
        ),
        _tool(
            context=context, evidence_ids=allowed, builder=build_component_target_agent,
            tool_name="prepare_component_target",
            description="Prepare or repair one evidence-backed libFuzzer component target and deterministic probe.",
            validator=lambda output, values: _validate_target(output, values, "component-level"),
            hooks=hooks, trace=trace,
        ),
        _tool(
            context=context, evidence_ids=allowed, builder=build_crash_triage_agent,
            tool_name="triage_crash_group",
            description="Interpret one replayed and minimised crash group without claiming unsupported exploitability.",
            validator=_validate_triage, hooks=hooks, trace=trace,
        ),
    ]
