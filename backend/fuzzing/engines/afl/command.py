"""Build shell-free AFL++ commands from data-only specifications."""

from __future__ import annotations

from backend.fuzzing.engines.contracts import ContainerInvocation, EngineSpec
from backend.fuzzing.engines.validation import (
    validate_afl_asan_environment,
    validate_campaign_path,
    validate_common,
    validate_container_path,
)


class AflCommand:
    @staticmethod
    def build(spec: EngineSpec) -> ContainerInvocation:
        validate_common(spec, "afl", frozenset({"file", "stdin"}))
        if spec.dictionary_path is not None:
            validate_campaign_path(spec.dictionary_path, "dictionary_path", "/campaign/config")
        if spec.grammar_path is not None:
            validate_container_path(spec.grammar_path, "grammar_path")
        validate_afl_asan_environment(spec.sanitizer_environment)

        command = ["afl-fuzz", "-i", spec.corpus_path, "-o", spec.output_path]
        command.extend(("-M", "main") if spec.role == "main" else ("-S", spec.role))
        command.extend(("-t", f"{spec.timeout_ms}+", "-m", "0"))
        if spec.dictionary_path is not None:
            command.extend(("-x", spec.dictionary_path))
        command.append("--")
        command.extend(spec.target_command)
        if spec.input_mode == "file" and "@@" not in command:
            command.append("@@")

        environment = dict(spec.sanitizer_environment)
        environment["AFL_NO_UI"] = "1"
        if spec.grammar_path is not None:
            environment["AFL_CUSTOM_MUTATOR_LIBRARY"] = spec.grammar_path

        return ContainerInvocation(
            engine="afl",
            image_id=spec.image_id,
            command=command,
            environment=environment,
            campaign_labels=dict(spec.campaign_labels),
            network_disabled=True,
            read_only_source=True,
            timeout_ms=spec.timeout_ms,
            memory_limit_mb=spec.memory_limit_mb,
        )
