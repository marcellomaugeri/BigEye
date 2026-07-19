"""Parse AFL++ ``fuzzer_stats`` without making scheduling decisions."""

from __future__ import annotations

from math import isfinite

from backend.fuzzing.engines.contracts import EngineStatistics


class AflStats:
    @staticmethod
    def parse(text: str) -> EngineStatistics:
        values: dict[str, str] = {}
        for line in text.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            if key:
                values[key] = value.strip()

        executions = _integer(values, "execs_done", required=True)
        rate = _number(values, "execs_per_sec", required=True)
        pid = _integer(values, "fuzzer_pid")
        health = "active" if pid > 0 and rate > 0 else "idle"
        return EngineStatistics(
            execution_count=executions,
            execution_rate=rate,
            corpus_count=_integer(values, "corpus_count"),
            corpus_size=_integer(values, "corpus_size"),
            last_new_path=_optional_integer(values, "last_find"),
            crashes=_integer(values, "saved_crashes"),
            timeouts=_integer(values, "saved_hangs"),
            health=health,
        )


def _integer(values: dict[str, str], key: str, required: bool = False) -> int:
    if key not in values:
        if required:
            raise ValueError(f"missing {key}")
        return 0
    try:
        value = int(values[key])
    except ValueError as error:
        raise ValueError(f"{key} must be an integer") from error
    if value < 0:
        raise ValueError(f"{key} must not be negative")
    return value


def _optional_integer(values: dict[str, str], key: str) -> int | None:
    return _integer(values, key) if key in values else None


def _number(values: dict[str, str], key: str, required: bool = False) -> float:
    if key not in values:
        if required:
            raise ValueError(f"missing {key}")
        return 0.0
    try:
        value = float(values[key])
    except ValueError as error:
        raise ValueError(f"{key} must be a number") from error
    if not isfinite(value):
        raise ValueError(f"{key} must be finite")
    if value < 0:
        raise ValueError(f"{key} must not be negative")
    return value
