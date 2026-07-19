"""Build shell-free libFuzzer commands from data-only specifications."""

from __future__ import annotations

from math import ceil

from backend.fuzzing.engines.contracts import ContainerInvocation, EngineSpec
from backend.fuzzing.engines.validation import validate_campaign_path, validate_common


class LibFuzzerCommand:
    @staticmethod
    def build(spec: EngineSpec) -> ContainerInvocation:
        validate_common(spec, "libfuzzer", frozenset({"inprocess"}))
        if spec.grammar_path is not None:
            raise ValueError("libFuzzer does not support the AFL++ grammar mutator")
        if spec.dictionary_path is not None:
            validate_campaign_path(spec.dictionary_path, "dictionary_path", "/campaign/config")

        command = [*spec.target_command, spec.corpus_path]
        command.extend((
            f"-artifact_prefix={spec.output_path.rstrip('/')}/",
            f"-timeout={ceil(spec.timeout_ms / 1_000)}",
            f"-rss_limit_mb={spec.memory_limit_mb}",
        ))
        if spec.dictionary_path is not None:
            command.append(f"-dict={spec.dictionary_path}")

        return ContainerInvocation(
            engine="libfuzzer",
            image_id=spec.image_id,
            command=command,
            environment=dict(spec.sanitizer_environment),
            campaign_labels=dict(spec.campaign_labels),
            network_disabled=True,
            read_only_source=True,
            timeout_ms=spec.timeout_ms,
            memory_limit_mb=spec.memory_limit_mb,
        )
