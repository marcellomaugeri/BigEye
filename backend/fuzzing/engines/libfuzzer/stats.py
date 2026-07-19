"""Parse libFuzzer progress output without campaign policy."""

from __future__ import annotations

import re

from backend.fuzzing.engines.contracts import EngineStatistics


PROGRESS = re.compile(
    r"^#(?P<executions>\d+)\s+(?P<event>\w+).*?"
    r"corp:\s*(?P<corpus>\d+)/(?P<size>\d+)(?P<unit>[kKmMgG]?)[bB]\b.*?"
    r"exec/s:\s*(?P<rate>[0-9]+(?:\.[0-9]+)?)",
)
SIZE_FACTORS = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}


class LibFuzzerStats:
    @staticmethod
    def parse(stderr: str) -> EngineStatistics:
        latest = None
        last_new_path = None
        for line in stderr.splitlines():
            match = PROGRESS.search(line.strip())
            if match is None:
                continue
            latest = match
            if match.group("event") == "NEW":
                last_new_path = int(match.group("executions"))

        timed_out = bool(re.search(r"SUMMARY:\s+libFuzzer:\s+timeout\b", stderr, re.IGNORECASE))
        crashed = not timed_out and bool(re.search(
            r"SUMMARY:\s+(?:AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|ThreadSanitizer)|ERROR:\s+libFuzzer",
            stderr,
            re.IGNORECASE,
        ))
        if crashed:
            health = "crashed"
        elif timed_out:
            health = "timed_out"
        elif latest is None:
            health = "unknown"
        elif float(latest.group("rate")) > 0:
            health = "active"
        else:
            health = "idle"

        if latest is None:
            return EngineStatistics(0, 0.0, 0, 0, last_new_path, int(crashed), int(timed_out), health)
        size = int(latest.group("size")) * SIZE_FACTORS[latest.group("unit").lower()]
        return EngineStatistics(
            execution_count=int(latest.group("executions")),
            execution_rate=float(latest.group("rate")),
            corpus_count=int(latest.group("corpus")),
            corpus_size=size,
            last_new_path=last_new_path,
            crashes=int(crashed),
            timeouts=int(timed_out),
            health=health,
        )
