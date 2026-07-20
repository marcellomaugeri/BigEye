"""Account campaign CPU time against its current clean reachable source set."""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Iterable


_MAX_REACHED_LINES = 100_000


@dataclass(frozen=True, order=True)
class ReachedLine:
    source_path: str
    line_number: int
    function_name: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_path", _source_path(self.source_path))
        if type(self.line_number) is not int or self.line_number < 1:
            raise ValueError("reached line number must be a positive integer")
        if self.function_name is not None and (
            not isinstance(self.function_name, str)
            or not self.function_name.strip()
            or len(self.function_name) > 1_024
        ):
            raise ValueError("reached function name is invalid")


class ExposureAccountant:
    """Persist cumulative observations through the repository's locked watermark."""

    def __init__(self, repository):
        self._repository = repository

    @staticmethod
    def calculate(cpu_delta: float, reached_lines: Iterable[tuple[str, int]]) -> dict[tuple[str, int], float]:
        delta = _cpu_value(cpu_delta, "CPU delta")
        if delta == 0:
            return {}
        normalised = _line_pairs(reached_lines)
        return {line: delta for line in normalised}

    async def apply(
        self,
        campaign_id: int,
        observed_cpu_seconds: float,
        reached_lines: Iterable[ReachedLine],
    ) -> bool:
        if type(campaign_id) is not int or campaign_id <= 0:
            raise ValueError("campaign ID must be a positive integer")
        observed = _cpu_value(observed_cpu_seconds, "observed CPU seconds")
        try:
            lines = tuple(reached_lines)
        except TypeError as error:
            raise ValueError("reached lines must be an iterable") from error
        if len(lines) > _MAX_REACHED_LINES or any(not isinstance(line, ReachedLine) for line in lines):
            raise ValueError("reached lines are invalid or exceed their bound")
        pairs = tuple(sorted({(line.source_path, line.line_number) for line in lines}))
        return await self._repository.apply_exposure_observation(
            campaign_id=campaign_id,
            observed_cpu_seconds=observed,
            reached_lines=pairs,
        )


def _cpu_value(value, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError(f"{label} must be a finite non-negative number")
    return float(value)


def _line_pairs(values: Iterable[tuple[str, int]]) -> tuple[tuple[str, int], ...]:
    try:
        pairs = tuple(values)
    except TypeError as error:
        raise ValueError("reached lines must be an iterable") from error
    if len(pairs) > _MAX_REACHED_LINES:
        raise ValueError("reached lines exceed their bound")
    normalised: set[tuple[str, int]] = set()
    for item in pairs:
        if not isinstance(item, tuple) or len(item) != 2:
            raise ValueError("reached line must contain a path and line number")
        path, number = item
        if type(number) is not int or number < 1:
            raise ValueError("reached line number must be a positive integer")
        normalised.add((_source_path(path), number))
    return tuple(sorted(normalised))


def _source_path(value) -> str:
    if not isinstance(value, str) or not value or len(value) > 4_096:
        raise ValueError("reached source path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", "..", ".git"} for part in path.parts):
        raise ValueError("reached source path must be repository-relative")
    return path.as_posix()

