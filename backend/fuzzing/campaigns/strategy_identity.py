"""Stable, semantic identity for one proposed fuzzing strategy."""

from __future__ import annotations

from hashlib import sha256
import json
import shlex


def proposal_strategy_document(proposal) -> dict[str, object]:
    """Return the operational proposal fields that can change campaign behaviour."""
    try:
        build_argv = shlex.split(proposal.build_command, posix=True)
        run_argv = shlex.split(proposal.run_command, posix=True)
    except ValueError as error:
        raise ValueError("target proposal commands are not parseable") from error
    if not build_argv or not run_argv:
        raise ValueError("target proposal commands are empty")
    instance_type = proposal.instance_type
    engine = {
        "system-level": "afl",
        "component-level": "libfuzzer",
    }.get(instance_type)
    if engine is None:
        raise ValueError("target proposal instance type is unsupported")
    return {
        "instance_type": instance_type,
        "engine": engine,
        "build_argv": build_argv,
        "run_argv": run_argv,
        "seed_paths": sorted(seed.path for seed in proposal.seeds),
        "generated_asset_paths": sorted(
            intent.relative_path for intent in proposal.generated_asset_intents
        ),
    }


def proposal_strategy_identity(proposal) -> str:
    encoded = json.dumps(
        proposal_strategy_document(proposal),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(encoded).hexdigest()
