"""Deterministic policy for BigEye-generated Dockerfiles and clean coverage inputs."""

from __future__ import annotations

import re


class LayerPolicyError(ValueError):
    """Raised when a generated layer would cross a containment boundary."""


_ALLOWED = frozenset({"ARG", "FROM", "WORKDIR", "COPY", "ENV", "RUN", "LABEL"})
_FORBIDDEN = re.compile(r"oss[-_ ]?fuzz|--mount(?:=|\s).*?(?:secret|cache|ssh)|--(?:privileged|device)|--(?:network|security)(?:=|\s)|/var/run/docker\.sock|docker\.sock", re.I)
_MAX_RUN_STEPS = 8
_MAX_INSTRUCTION_BYTES = 4096
_MAX_DOCKERFILE_BYTES = 64 * 1024


def _instructions(text: str):
    lines: list[str] = []
    pending = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pending = f"{pending} {line}".strip()
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue
        lines.append(pending)
        pending = ""
    if pending:
        raise LayerPolicyError("Dockerfile has an unfinished continuation")
    for line in lines:
        match = re.match(r"^([A-Za-z]+)\s+(.+)$", line)
        if not match:
            raise LayerPolicyError("Dockerfile instruction is malformed")
        yield match.group(1).upper(), match.group(2).strip()


def validate_generated_dockerfile(text: str, required_parent: str, *, allow_network: bool = False) -> None:
    if len(text.encode("utf-8")) > _MAX_DOCKERFILE_BYTES:
        raise LayerPolicyError("Dockerfile is too large")
    instructions = list(_instructions(text))
    froms = [argument for instruction, argument in instructions if instruction == "FROM"]
    if froms != [required_parent]:
        raise LayerPolicyError("Dockerfile must have exactly one required parent FROM")
    runs = 0
    for instruction, argument in instructions:
        if len(argument.encode("utf-8")) > _MAX_INSTRUCTION_BYTES:
            raise LayerPolicyError("Dockerfile instruction is too large")
        if instruction not in _ALLOWED:
            raise LayerPolicyError(f"Dockerfile instruction {instruction} is not allowed")
        if _FORBIDDEN.search(argument):
            raise LayerPolicyError("Dockerfile contains a forbidden host, remote, privileged, or external-framework reference")
        if not allow_network and re.search(r"(?:^|\s)(?:curl|wget)\b|https?://", argument, re.I):
            raise LayerPolicyError("Dockerfile layer does not permit build-time network access")
        if instruction == "ARG" and re.search(r"(?:secret|token|password|key)", argument, re.I):
            raise LayerPolicyError("Dockerfile ARG must not contain a secret")
        if instruction == "COPY":
            if argument.startswith("--") or "--from" in argument.lower():
                raise LayerPolicyError("Dockerfile COPY stages are not allowed")
            parts = argument.split()
            if len(parts) != 2 or any(part.startswith("/") or ".." in part.split("/") for part in parts[:-1]):
                raise LayerPolicyError("Dockerfile COPY sources must be safe generated-context paths")
        if instruction == "RUN":
            runs += 1
            if runs > _MAX_RUN_STEPS:
                raise LayerPolicyError("Dockerfile has too many RUN steps")


class LayerPolicy:
    def validate_coverage_inputs(self, names) -> None:
        for item in names:
            name, kind = item if isinstance(item, tuple) else (item, "")
            if str(kind).lower().replace("-", "_") == "fuzz_patch" or str(name).lower().endswith(".patch"):
                raise LayerPolicyError("fuzz-only patch is not allowed in clean coverage")
