"""One isolated Terra repair of an existing generated target asset."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
from uuid import uuid4

from agents import Runner

from backend.agents.context import AgentContext
from backend.agents.prompts.target_repair import TARGET_REPAIR_ASSIGNMENT
from backend.agents.specialists.component_target import build_component_target_agent
from backend.agents.specialists.system_target import build_system_target_agent
from backend.agents.tools.agent_dispatch import _validate_target
from backend.agents.tools.generated_assets import (
    list_asset_files,
    read_asset_file,
    write_asset_file,
)
from backend.agents.tools.web_research import official_documentation_domains
from backend.agents.tracing.hooks import AgentTraceHooks
from backend.agents.tracing.local_trace import LocalTrace
from backend.fuzzing.campaigns.target_preparation import TargetRepair


class TargetRepairAgent:
    """Use the same specialist capability in an isolated draft root for one Terra correction."""

    def __init__(self, discovery, event_store=None, runner=Runner.run):
        self._discovery = discovery
        self._events = event_store
        self._runner = runner

    async def repair(self, project, proposal, failure, model: str) -> TargetRepair:
        if model != "gpt-5.6-terra":
            raise ValueError("target repair requires exactly Terra")
        original = self._discovery.context(project.id)
        if original.commit_sha != project.commit_sha:
            raise ValueError("target repair context does not match the project commit")
        declared = tuple(intent.relative_path for intent in proposal.generated_asset_intents)
        intended = tuple(
            intent.relative_path for intent in proposal.generated_asset_intents
            if "dependenc" not in intent.purpose.casefold()
        )
        if (
            not intended or len(declared) != len(set(declared))
            or len(intended) != len(set(intended))
        ):
            raise ValueError("target repair requires existing unique generated asset intents")
        sandbox = original.repository_root.parent / f"repair-sandbox-{uuid4().hex}"
        sandbox.mkdir(mode=0o700)
        context = AgentContext(
            original.project_id, original.commit_sha, original.repository_root,
            sandbox, original.evidence,
        )
        originals: dict[str, dict] = {}
        try:
            for path in intended:
                record = read_asset_file(original, path)
                originals[path] = record
                write_asset_file(context, path, str(record["content"]), None)
            expected_type = "system-level" if proposal.instance_type == "system-level" else "component-level"
            builder = build_system_target_agent if expected_type == "system-level" else build_component_target_agent
            agent = builder(model, official_documentation_domains(context))
            trace = LocalTrace(self._events, project.id)
            prompt = TARGET_REPAIR_ASSIGNMENT + "\n" + json.dumps({
                "proposal": proposal.model_dump(mode="json"),
                "deterministic_failure": str(failure)[:2_000],
                "allowed_evidence_ids": list(proposal.evidence_ids),
                "allowed_generated_paths": list(intended),
            }, ensure_ascii=False, indent=2)
            result = await self._runner(
                agent, prompt, context=context, hooks=AgentTraceHooks(trace),
                run_config=trace.run_config("BigEye target repair"),
            )
            trace.record_result(agent, prompt, result)
            repaired = _validate_target(
                getattr(result, "final_output", None),
                frozenset(proposal.evidence_ids), expected_type,
            )
            if (
                (repaired.target_name, repaired.instance_type, repaired.configuration)
                != (proposal.target_name, proposal.instance_type, proposal.configuration)
                or {intent.relative_path for intent in repaired.generated_asset_intents} != set(declared)
            ):
                raise ValueError("Terra repair changed the target or generated asset identity")
            after = {item["relative_path"]: item for item in list_asset_files(context)}
            if set(after) != set(intended):
                raise ValueError("Terra repair created an unassigned generated asset")
            changed = [path for path in intended if after[path]["sha256"] != originals[path]["sha256"]]
            if len(changed) != 1:
                raise ValueError("Terra repair must change exactly one existing generated asset")
            selected = changed[0]
            content = read_asset_file(context, selected)["content"]
            write_asset_file(original, selected, str(content), str(originals[selected]["sha256"]))
            return TargetRepair(repaired, model)
        finally:
            if sandbox.exists() and not sandbox.is_symlink():
                shutil.rmtree(sandbox)
