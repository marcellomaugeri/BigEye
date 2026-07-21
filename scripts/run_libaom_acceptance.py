#!/usr/bin/env python3
"""Observe and record BigEye's exact libaom v3.13.2 acceptance campaign.

The runner submits only the public project intake request. Target selection, generated
assets, build commands, harnesses, corpora, and engine commands remain owned by BigEye.
"""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import sys
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[1]
LIBAOM_REPOSITORY = "https://aomedia.googlesource.com/aom"
LIBAOM_REVISION = "ad44980d7f3c7a2605c25d51ea96946949000841"
LIBAOM_TAG = "v3.13.2"
EXECUTION_SLOT_LIMIT = 4
DEFAULT_BASE_URL = "http://127.0.0.1:8000"
DEFAULT_REPORT_ROOT = ROOT / "workspace" / "acceptance" / "libaom-v3.13.2"
_HASH = frozenset("0123456789abcdef")
_SANITIZER_ENVIRONMENT = frozenset({
    "ASAN_OPTIONS", "UBSAN_OPTIONS", "MSAN_OPTIONS", "TSAN_OPTIONS", "LSAN_OPTIONS",
})


class AcceptanceBlocker(RuntimeError):
    """An actionable reason why the recorded run does not satisfy acceptance."""


def project_submission(repository_token: str | None) -> dict[str, object]:
    """Return the complete and intentionally small public intake request."""
    payload: dict[str, object] = {
        "repository_url": LIBAOM_REPOSITORY,
        "revision": LIBAOM_REVISION,
        "worker_count": EXECUTION_SLOT_LIMIT,
    }
    if repository_token:
        payload["repository_token"] = repository_token
    return payload


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _utc(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(UTC) if parsed.tzinfo is not None else None


def _positive_measurement(value: object) -> bool:
    return (
        isinstance(value, Mapping)
        and type(value.get("covered")) is int
        and type(value.get("total")) is int
        and 0 < value["covered"] <= value["total"]
    )


def _sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HASH for character in value)
    )


def _image_id(value: object) -> bool:
    return isinstance(value, str) and value.startswith("sha256:") and _sha256(value[7:])


def _engine_kind(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    lowered = value.casefold().replace("_", "").replace("-", "")
    if "libfuzzer" in lowered:
        return "libfuzzer"
    if "afl" in lowered:
        return "afl"
    return None


def _healthy(campaign: Mapping[str, object]) -> bool:
    return (
        campaign.get("stopped_at") is None
        and campaign.get("error") is None
        and campaign.get("last_heartbeat_at") is not None
    )


def _exact_corpus(value: object) -> bool:
    return (
        isinstance(value, Mapping)
        and type(value.get("file_count")) is int
        and value["file_count"] > 0
        and type(value.get("total_bytes")) is int
        and value["total_bytes"] >= 0
        and _sha256(value.get("sha256"))
    )


def _baseline_sanitizers_required(campaign: Mapping[str, object]) -> bool:
    purpose = campaign.get("configuration_purpose")
    if not isinstance(purpose, str):
        return False
    normalized = purpose.casefold()
    return any(
        marker in normalized
        for marker in ("baseline", "address", "asan", "undefined", "ubsan")
    )


def _strategy_matches_campaign(
    campaign: Mapping[str, object], container: Mapping[str, object],
) -> bool:
    strategy = container.get("strategy")
    if not isinstance(strategy, Mapping):
        return False
    engine = _engine_kind(campaign.get("engine"))
    if engine is None or engine != _engine_kind(container.get("engine")):
        return False
    expected_instance = "system-level" if engine == "afl" else "component-level"
    if (
        _engine_kind(strategy.get("engine")) != engine
        or strategy.get("instance_type") != expected_instance
        or strategy.get("commit_sha") != LIBAOM_REVISION
        or not _sha256(strategy.get("proposal_identity"))
    ):
        return False
    target = strategy.get("target")
    configuration = strategy.get("configuration")
    coverage = strategy.get("coverage")
    if not all(isinstance(value, Mapping) for value in (target, configuration, coverage)):
        return False
    if (
        target.get("asset_id") != campaign.get("target_asset_id")
        or configuration.get("asset_id") != campaign.get("configuration_asset_id")
        or any(
            not _sha256(value.get("content_sha256"))
            for value in (target, configuration, coverage)
        )
        or type(coverage.get("asset_id")) is not int
        or coverage["asset_id"] <= 0
        or not _image_id(coverage.get("clean_image_id"))
        or not _sha256(coverage.get("clean_content_sha256"))
    ):
        return False
    sanitizers = container.get("sanitizers")
    if (
        not isinstance(sanitizers, list)
        or not sanitizers
        or not all(isinstance(value, str) and value for value in sanitizers)
    ):
        return False
    if _baseline_sanitizers_required(campaign) and not {
        "address", "undefined",
    }.issubset(set(sanitizers)):
        return False
    return _exact_corpus(container.get("corpus"))


def _coverage_matches_strategy(
    evidence: Mapping[str, object],
    campaign: Mapping[str, object],
    container: Mapping[str, object],
) -> bool:
    strategy = container.get("strategy")
    if not isinstance(strategy, Mapping):
        return False
    target = strategy.get("target")
    configuration = strategy.get("configuration")
    coverage = strategy.get("coverage")
    if not all(isinstance(value, Mapping) for value in (target, configuration, coverage)):
        return False
    expected_strategy_id = configuration.get("asset_id") or target.get("asset_id")
    return (
        evidence.get("campaign_id") == campaign.get("id") == container.get("campaign_id")
        and evidence.get("strategy_asset_id") == expected_strategy_id
        and evidence.get("target_asset_id") == target.get("asset_id")
        and evidence.get("configuration_asset_id") == configuration.get("asset_id")
        and evidence.get("clean_image_id") == coverage.get("clean_image_id")
        and _sha256(evidence.get("testcase_sha256"))
        and isinstance(evidence.get("source_path"), str)
        and bool(evidence.get("source_path"))
        and type(evidence.get("line_number")) is int
        and evidence["line_number"] > 0
    )


def _validated_observation(
    project: Mapping[str, object],
    campaigns: list[dict[str, object]],
    coverage: Mapping[str, object] | None,
    containers: list[dict[str, object]],
    coverage_evidence: list[dict[str, object]],
) -> bool:
    """Require clean coverage from the exact strategy that is currently fuzzing."""
    if project.get("commit_sha") != LIBAOM_REVISION or coverage is None:
        return False
    if coverage.get("commit_sha") != LIBAOM_REVISION:
        return False
    summary = coverage.get("summary")
    if not isinstance(summary, Mapping):
        return False
    if not _positive_measurement(summary.get("lines")) or not _positive_measurement(summary.get("branches")):
        return False
    healthy = {
        item.get("id"): item for item in campaigns
        if isinstance(item, Mapping) and _healthy(item)
    }
    active = [
        (healthy[item.get("campaign_id")], item)
        for item in containers
        if item.get("state") == "running"
        and item.get("campaign_id") in healthy
        and item.get("commit_sha") == LIBAOM_REVISION
        and _image_id(item.get("image_id"))
        and isinstance(item.get("command"), list)
        and bool(item.get("command"))
    ]
    if not active or any(
        not _strategy_matches_campaign(campaign, container)
        for campaign, container in active
    ):
        return False
    return any(
        _coverage_matches_strategy(evidence, campaign, container)
        for evidence in coverage_evidence
        if isinstance(evidence, Mapping)
        for campaign, container in active
    )


def _event_payloads(snapshot: Mapping[str, object]) -> list[dict[str, object]]:
    payloads: list[dict[str, object]] = []
    for name in ("activity_events", "debug_events"):
        values = snapshot.get(name)
        if not isinstance(values, list):
            continue
        for event in values:
            if isinstance(event, Mapping) and isinstance(event.get("payload"), Mapping):
                payloads.append(dict(event["payload"]))
    return payloads


def _assets(
    snapshot: Mapping[str, object], containers: list[dict[str, object]],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    page = snapshot.get("campaigns")
    raw_assets = page.get("assets", []) if isinstance(page, Mapping) else []
    metadata = {
        value["id"]: value for value in raw_assets if isinstance(value, Mapping)
        and type(value.get("id")) is int
    } if isinstance(raw_assets, list) else {}
    linked: dict[tuple[str, int], str] = {}
    for container in containers:
        strategy = container.get("strategy")
        if not isinstance(strategy, Mapping):
            continue
        for role in ("target", "configuration", "coverage"):
            asset = strategy.get(role)
            if (
                isinstance(asset, Mapping)
                and type(asset.get("asset_id")) is int
                and _sha256(asset.get("content_sha256"))
            ):
                key = (role, asset["asset_id"])
                previous = linked.get(key)
                if previous is not None and previous != asset["content_sha256"]:
                    raise AcceptanceBlocker("campaign strategies disagree on one asset content hash")
                linked[key] = asset["content_sha256"]
    targets: list[dict[str, object]] = []
    configurations: list[dict[str, object]] = []
    for (role, asset_id), content_hash in sorted(linked.items(), key=lambda item: (item[0][0], item[0][1])):
        value = metadata.get(asset_id, {})
        item = {
            "id": asset_id,
            "role": role,
            "kind": value.get("kind"),
            "name": value.get("name"),
            "parent_id": value.get("parent_id"),
            "content_hash": content_hash,
        }
        if role == "target":
            targets.append(item)
        else:
            configurations.append(item)
    return targets, configurations


def _merged_campaigns(
    snapshot: Mapping[str, object], containers: list[dict[str, object]],
) -> list[dict[str, object]]:
    page = snapshot.get("campaigns")
    raw = page.get("campaigns", []) if isinstance(page, Mapping) else []
    by_campaign = {
        item["campaign_id"]: item for item in containers
        if type(item.get("campaign_id")) is int
    }
    result: list[dict[str, object]] = []
    for value in raw if isinstance(raw, list) else []:
        if not isinstance(value, Mapping) or type(value.get("id")) is not int:
            continue
        item = dict(value)
        docker = by_campaign.get(value["id"])
        if docker is not None:
            item.update({
                "container_id": docker.get("container_id"),
                "container_state": docker.get("state"),
                "image_id": docker.get("image_id"),
                "command": docker.get("command"),
                "sanitizers": docker.get("sanitizers", []),
                "corpus": docker.get("corpus"),
                "strategy": docker.get("strategy"),
            })
        result.append(item)
    return result


def _agent_runs(snapshot: Mapping[str, object]) -> list[dict[str, object]]:
    events = snapshot.get("debug_events")
    result: list[dict[str, object]] = []
    for value in events if isinstance(events, list) else []:
        if not isinstance(value, Mapping) or not isinstance(value.get("payload"), Mapping):
            continue
        payload = value["payload"]
        event_name = payload.get("event")
        if not isinstance(event_name, str) or not (
            event_name.startswith("agent.")
            or event_name.startswith("model.")
            or event_name.startswith("tool.")
        ):
            continue
        result.append({
            "event_id": value.get("id"),
            "created_at": value.get("created_at"),
            **dict(payload),
        })
    return result


def _retries(snapshot: Mapping[str, object]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for payload in _event_payloads(snapshot):
        if any("retry" in str(key).casefold() for key in payload):
            result.append(payload)
    return result


def _watchdog_failures(
    campaigns: list[dict[str, object]], now: datetime, *, grace_seconds: float = 30.0,
) -> list[dict[str, object]]:
    failures: list[dict[str, object]] = []
    for campaign in campaigns:
        if not _healthy(campaign):
            continue
        deadline = _utc(campaign.get("next_review_after"))
        if deadline is not None and (now - deadline).total_seconds() > grace_seconds:
            failures.append({
                "kind": "overdue_manager_wake",
                "campaign_id": campaign.get("id"),
                "deadline": _iso(deadline),
                "observed_at": _iso(now),
                "message": "A persisted campaign review deadline is overdue.",
            })
    return failures


def _observation_failures(snapshot: Mapping[str, object]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    supplied = snapshot.get("failures")
    if isinstance(supplied, list):
        result.extend(dict(value) for value in supplied if isinstance(value, Mapping))
    for payload in _event_payloads(snapshot):
        event = payload.get("event")
        failed = (
            isinstance(event, str)
            and ("error" in event.casefold() or "failed" in event.casefold())
        ) or payload.get("status") == "failed"
        if failed:
            error = payload.get("error")
            message = (
                error.get("message") if isinstance(error, Mapping)
                else error if isinstance(error, str)
                else payload.get("motivation") or event or "recorded failure"
            )
            result.append({"kind": str(event or "recorded_failure"), "message": str(message)[:2_000]})
    project = snapshot.get("project")
    if isinstance(project, Mapping) and project.get("error"):
        result.append({"kind": "project", "message": str(project["error"])})
    page = snapshot.get("campaigns")
    campaigns = page.get("campaigns", []) if isinstance(page, Mapping) else []
    for campaign in campaigns if isinstance(campaigns, list) else []:
        if isinstance(campaign, Mapping) and campaign.get("error"):
            result.append({
                "kind": "campaign", "campaign_id": campaign.get("id"),
                "message": str(campaign["error"]),
            })
    return result


def verify_report(report: Mapping[str, object], required_seconds: int = 3600) -> list[str]:
    """Return concise evidence gaps without substituting missing values with zero."""
    blockers: list[str] = []
    if report.get("repository_url") != LIBAOM_REPOSITORY:
        blockers.append("repository identity is not the upstream libaom repository")
    if report.get("requested_revision") != LIBAOM_REVISION:
        blockers.append("requested revision is not the exact libaom v3.13.2 revision")
    if report.get("resolved_revision") != LIBAOM_REVISION:
        blockers.append("resolved revision is missing or differs from the requested libaom revision")
    elapsed = report.get("elapsed_validated_fuzzing_seconds")
    if (
        isinstance(elapsed, bool)
        or not isinstance(elapsed, (int, float))
        or not math.isfinite(elapsed)
        or elapsed < required_seconds
    ):
        blockers.append(f"validated fuzzing evidence is shorter than {required_seconds} seconds")
    if not report.get("validated_fuzzing_started_at") or not report.get("validated_fuzzing_finished_at"):
        blockers.append("validated fuzzing start or finish evidence is missing")

    campaigns = report.get("campaigns")
    values = campaigns if isinstance(campaigns, list) else []
    healthy = [value for value in values if isinstance(value, Mapping) and _healthy(value)]
    active = [
        value for value in healthy
        if value.get("container_state", value.get("state")) == "running"
    ]
    engine_kinds = {_engine_kind(value.get("engine")) for value in active}
    if "afl" not in engine_kinds:
        blockers.append("a healthy system-level AFL++ campaign is missing")
    if "libfuzzer" not in engine_kinds:
        blockers.append("a healthy component-level libFuzzer campaign is missing")
    baseline_engine_kinds = {
        _engine_kind(value.get("engine"))
        for value in active
        if isinstance(value.get("sanitizers"), list)
        and {"address", "undefined"}.issubset(set(value["sanitizers"]))
    }
    if "afl" not in baseline_engine_kinds:
        blockers.append("system-level AFL++ lacks initial ASan and UBSan evidence")
    if "libfuzzer" not in baseline_engine_kinds:
        blockers.append("component-level libFuzzer lacks initial ASan and UBSan evidence")
    for value in active:
        if (
            not _image_id(value.get("image_id"))
            or not isinstance(value.get("command"), list)
            or not value.get("command")
        ):
            blockers.append(f"campaign {value.get('id')} lacks exact Docker image or command evidence")
        if not _strategy_matches_campaign(
            value,
            {**dict(value), "campaign_id": value.get("id")},
        ):
            blockers.append(
                f"campaign {value.get('id')} lacks exact strategy, sanitizer, or corpus evidence"
            )

    coverage = report.get("coverage")
    coverage = coverage if isinstance(coverage, Mapping) else {}
    if not _positive_measurement(coverage.get("lines")):
        blockers.append("positive exact clean line coverage is missing")
    if not _positive_measurement(coverage.get("branches")):
        blockers.append("positive exact clean branch coverage is missing")
    coverage_evidence = report.get("coverage_evidence")
    witnesses = coverage_evidence if isinstance(coverage_evidence, list) else []
    if not any(
        _coverage_matches_strategy(
            evidence,
            campaign,
            {**dict(campaign), "campaign_id": campaign.get("id")},
        )
        for evidence in witnesses
        if isinstance(evidence, Mapping)
        for campaign in active
    ):
        blockers.append("positive clean coverage is not bound to the same active strategy and campaign")

    limit = report.get("execution_slot_limit")
    maximum = report.get("maximum_active_fuzzing_jobs")
    if limit != EXECUTION_SLOT_LIMIT:
        blockers.append("the recorded execution slot limit is not four")
    if type(maximum) is not int:
        blockers.append("maximum active fuzzing-job evidence is missing")
    elif maximum > EXECUTION_SLOT_LIMIT:
        blockers.append("the four-job execution slot limit was exceeded")
    heavy = report.get("maximum_active_heavy_jobs")
    observation = report.get("heavy_job_observation")
    if heavy is not None:
        blockers.append("compilation occupancy was presented without public read-only evidence")
    if (
        not isinstance(observation, Mapping)
        or observation.get("available") is not False
        or not isinstance(observation.get("reason"), str)
        or "compilation" not in observation["reason"].casefold()
    ):
        blockers.append("the unavailable compilation-lease observation is not explained")

    inventory: dict[tuple[str, int], str] = {}
    for collection_name in ("targets", "configurations"):
        collection = report.get(collection_name)
        if not isinstance(collection, list):
            blockers.append(f"{collection_name} inventory is missing")
            continue
        for item in collection:
            if not isinstance(item, Mapping) or not _sha256(item.get("content_hash")):
                blockers.append(f"one or more {collection_name} lack a durable content hash")
                break
            role = item.get("role")
            asset_id = item.get("id")
            if role in {"target", "configuration", "coverage"} and type(asset_id) is int:
                inventory[(role, asset_id)] = item["content_hash"]
    inventory_matches = True
    for campaign in active:
        strategy = campaign.get("strategy")
        if not isinstance(strategy, Mapping):
            inventory_matches = False
            break
        for role in ("target", "configuration", "coverage"):
            asset = strategy.get(role)
            if (
                not isinstance(asset, Mapping)
                or type(asset.get("asset_id")) is not int
                or inventory.get((role, asset["asset_id"])) != asset.get("content_sha256")
            ):
                inventory_matches = False
                break
        if not inventory_matches:
            break
    if not inventory_matches:
        blockers.append("the strategy asset inventory does not match active campaign identities")
    agent_runs = report.get("agent_runs")
    if not isinstance(agent_runs, list) or not any(
        isinstance(value, Mapping)
        and value.get("agent") == "Campaign manager"
        and value.get("event") == "agent.end"
        for value in agent_runs
    ):
        blockers.append("a completed manager agent run is missing")
    return blockers


def atomic_write_report(root: Path, report: Mapping[str, object]) -> tuple[Path, Path]:
    """Durably preserve one run and atomically replace the latest-report pointer."""
    root = Path(root)
    run_id = report.get("run_id")
    if not isinstance(run_id, str) or not run_id or "/" in run_id or "\\" in run_id:
        raise ValueError("report run_id is invalid")
    run_path = root / run_id / "report.json"
    latest_path = root / "latest-report.json"
    encoded = (json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")
    for destination in (run_path, latest_path):
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = destination.with_name(f".{destination.name}.{secrets.token_hex(8)}.tmp")
        try:
            with temporary.open("xb") as output:
                output.write(encoded)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, destination)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    return run_path, latest_path


class PublicProjectApi:
    """Bounded reads and one public project intake call against the running app."""

    def __init__(self, base_url: str, *, timeout: float = 30.0):
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("base URL must be an http or https URL")
        self._client = httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=timeout)

    async def close(self) -> None:
        await self._client.aclose()

    async def _json(self, method: str, path: str, **kwargs) -> object:
        response = await self._client.request(method, path, **kwargs)
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as error:
            detail = response.text[:500].replace("\n", " ")
            raise AcceptanceBlocker(f"{method} {path} returned {response.status_code}: {detail}") from error
        try:
            return response.json()
        except ValueError as error:
            raise AcceptanceBlocker(f"{method} {path} did not return JSON") from error

    async def list_projects(self) -> list[dict[str, object]]:
        value = await self._json("GET", "/api/projects")
        if not isinstance(value, list):
            raise AcceptanceBlocker("project API returned an invalid collection")
        return [dict(item) for item in value if isinstance(item, Mapping)]

    async def create_project(self, payload: dict[str, object]) -> dict[str, object]:
        value = await self._json("POST", "/api/projects", json=payload)
        if not isinstance(value, Mapping):
            raise AcceptanceBlocker("project API returned an invalid project")
        return dict(value)

    async def _optional(self, path: str) -> object | None:
        response = await self._client.get(path)
        if response.status_code in {404, 409, 422}:
            return None
        try:
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPStatusError, ValueError) as error:
            raise AcceptanceBlocker(f"GET {path} did not return usable evidence") from error

    async def _events(self, project_id: str, stream: str) -> list[dict[str, object]]:
        before = -1
        result: list[dict[str, object]] = []
        for _ in range(100):
            value = await self._json(
                "GET", f"/api/projects/{project_id}/logs/{stream}",
                params={"before": before, "limit": 1000},
            )
            if not isinstance(value, Mapping) or not isinstance(value.get("events"), list):
                raise AcceptanceBlocker(f"{stream} event API returned an invalid page")
            result.extend(dict(item) for item in value["events"] if isinstance(item, Mapping))
            if value.get("has_more") is not True:
                return result
            next_offset = value.get("next_offset")
            if type(next_offset) is not int or next_offset < 0 or next_offset == before:
                raise AcceptanceBlocker(f"{stream} event pagination did not advance")
            before = next_offset
        raise AcceptanceBlocker(f"{stream} event log exceeded the bounded observation window")

    async def _findings(self, project_id: str) -> dict[str, object]:
        summaries: list[dict[str, object]] = []
        cursor: str | None = None
        for _ in range(100):
            parameters = {"limit": 100}
            if cursor is not None:
                parameters["cursor"] = cursor
            page = await self._json("GET", f"/api/projects/{project_id}/findings", params=parameters)
            if not isinstance(page, Mapping) or not isinstance(page.get("items"), list):
                raise AcceptanceBlocker("finding API returned an invalid page")
            summaries.extend(dict(item) for item in page["items"] if isinstance(item, Mapping))
            cursor = page.get("next_cursor") if isinstance(page.get("next_cursor"), str) else None
            if cursor is None:
                break
        details: list[dict[str, object]] = []
        for summary in summaries:
            identifier = summary.get("id")
            if not isinstance(identifier, str):
                continue
            detail = await self._optional(f"/api/projects/{project_id}/findings/{identifier}")
            details.append(dict(detail) if isinstance(detail, Mapping) else summary)
        return {"items": details, "next_cursor": cursor}

    async def _coverage_evidence(
        self, project_id: str, coverage: Mapping[str, object],
    ) -> list[dict[str, object]]:
        """Collect a bounded first-hit witness set through the public traceability API."""
        files = coverage.get("files")
        if not isinstance(files, list):
            return []
        result: list[dict[str, object]] = []
        seen: set[tuple[object, ...]] = set()
        for source in files[:32]:
            if (
                not isinstance(source, Mapping)
                or not isinstance(source.get("path"), str)
                or not source["path"]
                or type(source.get("covered_lines")) is not int
                or source["covered_lines"] <= 0
                or type(source.get("total_lines")) is not int
                or source["total_lines"] <= 0
            ):
                continue
            path = source["path"]
            covered_examined = 0
            last_line = min(source["total_lines"], 20_000)
            for start in range(1, last_line + 1, 500):
                end = min(start + 499, last_line)
                source_page = await self._json(
                    "GET",
                    f"/api/projects/{project_id}/coverage/source",
                    params={"path": path, "start_line": start, "end_line": end},
                )
                lines = source_page.get("lines") if isinstance(source_page, Mapping) else None
                if not isinstance(lines, list):
                    raise AcceptanceBlocker("source coverage API returned an invalid page")
                for line in lines:
                    if (
                        not isinstance(line, Mapping)
                        or line.get("covered") is not True
                        or type(line.get("strategy_count")) is not int
                        or line["strategy_count"] <= 0
                        or type(line.get("number")) is not int
                        or line["number"] <= 0
                    ):
                        continue
                    line_number = line["number"]
                    evidence_page = await self._json(
                        "GET",
                        f"/api/projects/{project_id}/coverage/lines/{line_number}",
                        params={"path": path, "limit": 500, "offset": 0},
                    )
                    evidence = (
                        evidence_page.get("evidence")
                        if isinstance(evidence_page, Mapping) else None
                    )
                    if not isinstance(evidence, list):
                        raise AcceptanceBlocker("line evidence API returned an invalid page")
                    for item in evidence:
                        if not isinstance(item, Mapping):
                            continue
                        witness = {
                            **dict(item),
                            "source_path": path,
                            "line_number": line_number,
                        }
                        identity = (
                            witness.get("campaign_id"),
                            witness.get("strategy_asset_id"),
                            witness.get("testcase_sha256"),
                            path,
                            line_number,
                        )
                        if identity not in seen:
                            seen.add(identity)
                            result.append(witness)
                    covered_examined += 1
                    if len(result) >= 256 or covered_examined >= 8:
                        break
                if len(result) >= 256 or covered_examined >= 8:
                    break
            if len(result) >= 256:
                break
        return result

    async def observe(self, project_id: str) -> dict[str, object]:
        project = await self._json("GET", f"/api/projects/{project_id}")
        campaigns, coverage, findings, activity, debug = await asyncio.gather(
            self._optional(f"/api/projects/{project_id}/campaigns"),
            self._optional(f"/api/projects/{project_id}/coverage/tree"),
            self._findings(project_id),
            self._events(project_id, "activity"),
            self._events(project_id, "debug"),
        )
        if not isinstance(project, Mapping):
            raise AcceptanceBlocker("project API returned invalid project evidence")
        coverage_evidence = (
            await self._coverage_evidence(project_id, coverage)
            if isinstance(coverage, Mapping) else []
        )
        return {
            "project": dict(project),
            "campaigns": dict(campaigns) if isinstance(campaigns, Mapping) else {"campaigns": [], "assets": []},
            "coverage": dict(coverage) if isinstance(coverage, Mapping) else None,
            "coverage_evidence": coverage_evidence,
            "findings": findings,
            "activity_events": activity,
            "debug_events": debug,
            "failures": [],
        }


class DockerCampaignObserver:
    """Read exact BigEye-owned container identities without controlling them."""

    def __init__(self, client=None):
        self._client = client

    def _docker(self):
        if self._client is None:
            import docker

            self._client = docker.from_env()
        return self._client

    async def observe(self, project_id: int, commit_sha: str) -> list[dict[str, object]]:
        return await asyncio.to_thread(self._observe, project_id, commit_sha)

    def _observe(self, project_id: int, commit_sha: str) -> list[dict[str, object]]:
        filters = {
            "label": [
                "com.bigeye.managed=fuzz-campaign",
                f"com.bigeye.project-id={project_id}",
                f"com.bigeye.commit-sha={commit_sha}",
            ],
        }
        containers = self._docker().containers.list(all=True, filters=filters)
        return [self._container(container, project_id, commit_sha) for container in containers]

    @staticmethod
    def _container(container, project_id: int, commit_sha: str) -> dict[str, object]:
        container.reload()
        attributes = container.attrs
        config = attributes.get("Config") or {}
        labels = config.get("Labels") or {}
        if (
            labels.get("com.bigeye.managed") != "fuzz-campaign"
            or labels.get("com.bigeye.project-id") != str(project_id)
            or labels.get("com.bigeye.commit-sha") != commit_sha
        ):
            raise AcceptanceBlocker(f"Docker container {container.id[:12]} has contradictory identity labels")
        try:
            campaign_id = int(labels["com.bigeye.campaign-id"])
        except (KeyError, TypeError, ValueError) as error:
            raise AcceptanceBlocker(f"Docker container {container.id[:12]} lacks a campaign identity") from error
        image_id = attributes.get("Image") or labels.get("com.bigeye.image-id")
        labelled_image = labels.get("com.bigeye.image-id")
        if not _image_id(image_id) or labelled_image != image_id:
            raise AcceptanceBlocker(f"Docker container {container.id[:12]} lacks an exact image identity")
        command = [
            *([config["Entrypoint"]] if isinstance(config.get("Entrypoint"), str) else (config.get("Entrypoint") or [])),
            *([config["Cmd"]] if isinstance(config.get("Cmd"), str) else (config.get("Cmd") or [])),
        ]
        environment = {}
        for item in config.get("Env") or []:
            key, separator, value = item.partition("=")
            if separator and key in _SANITIZER_ENVIRONMENT:
                environment[key] = value
        mounts = attributes.get("Mounts") or []
        config_root = next(
            (
                Path(item["Source"]) for item in mounts
                if item.get("Type") == "bind" and item.get("Destination") == "/campaign/config"
                and isinstance(item.get("Source"), str)
            ),
            None,
        )
        corpus_root = next(
            (
                Path(item["Source"]) for item in mounts
                if item.get("Type") == "bind" and item.get("Destination") == "/campaign/corpus"
                and isinstance(item.get("Source"), str)
            ),
            None,
        )
        strategy = _strategy_identity(
            config_root, project_id, campaign_id, commit_sha, labels.get("com.bigeye.engine"),
        )
        sanitizers = _sanitizers(environment) | _configured_sanitizers(config_root)
        return {
            "campaign_id": campaign_id,
            "container_id": container.id,
            "state": (attributes.get("State") or {}).get("Status"),
            "image_id": image_id,
            "command": [str(value) for value in command],
            "engine": labels.get("com.bigeye.engine"),
            "commit_sha": commit_sha,
            "project_id": project_id,
            "sanitizers": sorted(sanitizers),
            "sanitizer_environment": environment,
            "corpus": _corpus_identity(corpus_root),
            "strategy": strategy,
        }


def _sanitizers(environment: Mapping[str, str]) -> set[str]:
    names = {
        "ASAN_OPTIONS": "address", "UBSAN_OPTIONS": "undefined", "MSAN_OPTIONS": "memory",
        "TSAN_OPTIONS": "thread", "LSAN_OPTIONS": "leak",
    }
    return {name for key, name in names.items() if key in environment}


def _config_document(root: Path | None, name: str) -> dict[str, object]:
    if root is None or root.is_symlink() or not root.is_dir():
        raise AcceptanceBlocker("a running campaign lacks its Docker-owned configuration mount")
    path = root / name
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024:
        raise AcceptanceBlocker(f"campaign configuration {name} is missing or invalid")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcceptanceBlocker(f"campaign configuration {name} is not valid JSON") from error
    if not isinstance(value, dict):
        raise AcceptanceBlocker(f"campaign configuration {name} is not a JSON object")
    return value


def _strategy_identity(
    root: Path | None,
    project_id: int,
    campaign_id: int,
    commit_sha: str,
    engine: object,
) -> dict[str, object]:
    del project_id, campaign_id
    value = _config_document(root, "strategy.json")
    engine_kind = _engine_kind(engine)
    expected_instance = (
        "system-level" if engine_kind == "afl"
        else "component-level" if engine_kind == "libfuzzer"
        else None
    )
    if (
        expected_instance is None
        or _engine_kind(value.get("engine")) != engine_kind
        or value.get("instance_type") != expected_instance
    ):
        raise AcceptanceBlocker("campaign engine and instance type are contradictory")
    if (
        value.get("commit_sha") != commit_sha
        or not _sha256(value.get("proposal_identity"))
        or not isinstance(value.get("argv"), list)
        or not all(isinstance(item, str) and item for item in value["argv"])
        or not isinstance(value.get("seed_set"), list)
        or not all(_sha256(item) for item in value["seed_set"])
    ):
        raise AcceptanceBlocker("campaign strategy identity is incomplete or contradictory")
    for role in ("target", "configuration", "coverage"):
        asset = value.get(role)
        if (
            not isinstance(asset, Mapping)
            or type(asset.get("asset_id")) is not int
            or asset["asset_id"] <= 0
            or not _sha256(asset.get("content_sha256"))
        ):
            raise AcceptanceBlocker(f"campaign strategy {role} identity is incomplete")
    coverage = value["coverage"]
    if not _image_id(coverage.get("clean_image_id")) or not _sha256(coverage.get("clean_content_sha256")):
        raise AcceptanceBlocker("campaign clean coverage image identity is incomplete")
    return value


def _configured_sanitizers(root: Path | None) -> set[str]:
    value = _config_document(root, "sanitizer-intent.json")
    applied = value.get("applied_primary")
    allowed = {"address", "undefined", "memory", "thread", "leak"}
    if not isinstance(applied, list) or not applied or any(item not in allowed for item in applied):
        raise AcceptanceBlocker("campaign sanitizer intent is incomplete")
    return set(applied)


def _corpus_identity(root: Path | None) -> dict[str, object] | None:
    if root is None or root.is_symlink() or not root.is_dir():
        return None
    files = sorted(
        value for value in root.rglob("*")
        if value.is_file() and not value.is_symlink()
    )
    combined = hashlib.sha256()
    total_bytes = 0
    for path in files:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        content = path.read_bytes()
        combined.update(len(relative).to_bytes(8, "big"))
        combined.update(relative)
        combined.update(len(content).to_bytes(8, "big"))
        combined.update(content)
        total_bytes += len(content)
    return {"file_count": len(files), "total_bytes": total_bytes, "sha256": combined.hexdigest()}


class AcceptanceRunner:
    """Resumable observer for one exact public libaom project."""

    def __init__(
        self,
        api,
        docker_observer,
        report_root: Path,
        *,
        repository_token: str | None = None,
        now: Callable[[], datetime] | None = None,
        sleeper: Callable[[float], Awaitable[None]] = asyncio.sleep,
        poll_seconds: float = 5.0,
        start_timeout_seconds: float = 45 * 60,
    ):
        if poll_seconds <= 0 or start_timeout_seconds <= 0:
            raise ValueError("poll and startup timeouts must be positive")
        self._api = api
        self._docker = docker_observer
        self._root = Path(report_root)
        self._repository_token = repository_token
        self._now = now or (lambda: datetime.now(UTC))
        self._sleep = sleeper
        self._poll_seconds = float(poll_seconds)
        self._start_timeout_seconds = float(start_timeout_seconds)
        self._run_id = f"{self._now().strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(4)}"

    async def ensure_project(self) -> dict[str, object]:
        projects = await self._api.list_projects()
        exact = [
            project for project in projects
            if project.get("repository_url") == LIBAOM_REPOSITORY
            and project.get("requested_revision") == LIBAOM_REVISION
            and project.get("error") is None
        ]
        resolved = [project for project in exact if project.get("commit_sha") == LIBAOM_REVISION]
        pending = [project for project in exact if project.get("commit_sha") is None]
        candidates = resolved or pending
        if candidates:
            return max(candidates, key=lambda value: int(str(value.get("id", "0"))))
        return await self._api.create_project(project_submission(self._repository_token))

    async def run(self, validated_seconds: int) -> dict[str, object]:
        if isinstance(validated_seconds, bool) or not isinstance(validated_seconds, int) or validated_seconds <= 0:
            raise ValueError("validated seconds must be a positive integer")
        project = await self.ensure_project()
        project_id = str(project.get("id", ""))
        if not project_id.isascii() or not project_id.isdecimal() or int(project_id) <= 0:
            raise AcceptanceBlocker("project API did not return a positive project ID")
        report = self._resume_report(project, validated_seconds) or self._empty_report(project)
        self._run_id = str(report["run_id"])
        observation_started = self._now()
        previous_observation: datetime | None = None
        previous_valid = False
        validated_started = _utc(report.get("validated_fuzzing_started_at"))
        prior_elapsed = report.get("elapsed_validated_fuzzing_seconds")
        accumulated = float(prior_elapsed) if isinstance(prior_elapsed, (int, float)) else 0.0
        prior_active = report.get("maximum_active_fuzzing_jobs")
        prior_candidates = report.get("maximum_healthy_candidates")
        maximum_active = prior_active if type(prior_active) is int else 0
        maximum_candidates = prior_candidates if type(prior_candidates) is int else 0

        while accumulated < validated_seconds:
            observed_at = self._now()
            snapshot = await self._api.observe(project_id)
            current_project = snapshot.get("project")
            if not isinstance(current_project, Mapping):
                raise AcceptanceBlocker("project observation is missing")
            if current_project.get("error"):
                raise AcceptanceBlocker(f"project failed: {current_project['error']}")
            commit = current_project.get("commit_sha")
            containers = (
                await self._docker.observe(int(project_id), commit)
                if commit == LIBAOM_REVISION else []
            )
            page = snapshot.get("campaigns")
            campaign_values = page.get("campaigns", []) if isinstance(page, Mapping) else []
            campaigns = [dict(value) for value in campaign_values if isinstance(value, Mapping)]
            coverage = snapshot.get("coverage")
            valid = _validated_observation(
                current_project,
                campaigns,
                coverage if isinstance(coverage, Mapping) else None,
                containers,
                [
                    dict(value) for value in snapshot.get("coverage_evidence", [])
                    if isinstance(value, Mapping)
                ] if isinstance(snapshot.get("coverage_evidence"), list) else [],
            )
            if valid and validated_started is None:
                validated_started = observed_at
            if valid and previous_valid and previous_observation is not None:
                accumulated += max((observed_at - previous_observation).total_seconds(), 0.0)
            previous_observation = observed_at
            previous_valid = valid

            healthy_ids = {item.get("id") for item in campaigns if _healthy(item)}
            active = sum(
                item.get("state") == "running" and item.get("campaign_id") in healthy_ids
                for item in containers
            )
            maximum_active = max(maximum_active, active)
            maximum_candidates = max(maximum_candidates, len(healthy_ids))
            report = self._report(
                report,
                snapshot,
                containers,
                current_project,
                validated_started,
                observed_at if accumulated >= validated_seconds else None,
                accumulated,
                maximum_active,
                maximum_candidates,
            )
            atomic_write_report(self._root, report)
            if accumulated >= validated_seconds:
                break
            if validated_started is None and (
                observed_at - observation_started
            ).total_seconds() >= self._start_timeout_seconds:
                message = "no active fuzzer reached exact libaom code before the startup watchdog expired"
                report["failures"].append({"kind": "startup_watchdog", "message": message})
                atomic_write_report(self._root, report)
                raise AcceptanceBlocker(message)
            await self._sleep(self._poll_seconds)

        blockers = verify_report(report, validated_seconds)
        if blockers:
            report["failures"].extend(
                {"kind": "acceptance_blocker", "message": message} for message in blockers
            )
            atomic_write_report(self._root, report)
            raise AcceptanceBlocker("; ".join(blockers))
        atomic_write_report(self._root, report)
        return report

    def _resume_report(
        self, project: Mapping[str, object], validated_seconds: int,
    ) -> dict[str, object] | None:
        """Resume only an incomplete, exact-identity report; downtime is never counted."""
        path = self._root / "latest-report.json"
        if path.is_symlink() or not path.is_file():
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            return None
        if not isinstance(value, dict):
            return None
        elapsed = value.get("elapsed_validated_fuzzing_seconds")
        if (
            value.get("repository_url") != LIBAOM_REPOSITORY
            or value.get("requested_revision") != LIBAOM_REVISION
            or value.get("resolved_revision") != LIBAOM_REVISION
            or str(value.get("project_id")) != str(project.get("id"))
            or value.get("validated_fuzzing_finished_at") is not None
            or isinstance(elapsed, bool)
            or not isinstance(elapsed, (int, float))
            or not math.isfinite(elapsed)
            or not 0 <= elapsed < validated_seconds
            or not isinstance(value.get("run_id"), str)
            or _utc(value.get("validated_fuzzing_started_at")) is None
            or value.get("maximum_active_heavy_jobs") is not None
            or type(value.get("maximum_active_fuzzing_jobs")) is not int
            or value["maximum_active_fuzzing_jobs"] < 0
            or not isinstance(value.get("coverage_evidence"), list)
            or not value["coverage_evidence"]
            or not isinstance(value.get("heavy_job_observation"), Mapping)
            or value["heavy_job_observation"].get("available") is not False
        ):
            return None
        return value

    def _empty_report(self, project: Mapping[str, object]) -> dict[str, object]:
        return {
            "run_id": self._run_id,
            "tag": LIBAOM_TAG,
            "repository_url": LIBAOM_REPOSITORY,
            "requested_revision": LIBAOM_REVISION,
            "resolved_revision": project.get("commit_sha"),
            "project_id": project.get("id"),
            "validated_fuzzing_started_at": None,
            "validated_fuzzing_finished_at": None,
            "elapsed_validated_fuzzing_seconds": None,
            "execution_slot_limit": EXECUTION_SLOT_LIMIT,
            "maximum_active_heavy_jobs": None,
            "heavy_job_observation": {
                "available": False,
                "reason": (
                    "compilation leases are process-local and have no public read-only "
                    "API or Docker-owned labelled identity"
                ),
            },
            "maximum_active_fuzzing_jobs": 0,
            "maximum_healthy_candidates": 0,
            "targets": [],
            "configurations": [],
            "campaigns": [],
            "coverage": {"lines": None, "functions": None, "branches": None},
            "coverage_evidence": [],
            "corpus": {"campaigns": {}},
            "findings": [],
            "agent_runs": [],
            "retries": [],
            "failures": [],
        }

    def _report(
        self,
        previous: dict[str, object],
        snapshot: Mapping[str, object],
        containers: list[dict[str, object]],
        project: Mapping[str, object],
        started_at: datetime | None,
        finished_at: datetime | None,
        accumulated: float,
        maximum_active: int,
        maximum_candidates: int,
    ) -> dict[str, object]:
        targets, configurations = _assets(snapshot, containers)
        campaigns = _merged_campaigns(snapshot, containers)
        coverage_page = snapshot.get("coverage")
        coverage_summary = (
            coverage_page.get("summary")
            if isinstance(coverage_page, Mapping) and isinstance(coverage_page.get("summary"), Mapping)
            else {"lines": None, "functions": None, "branches": None}
        )
        corpus = {
            "campaigns": {
                str(item["campaign_id"]): item["corpus"]
                for item in containers
                if type(item.get("campaign_id")) is int and isinstance(item.get("corpus"), Mapping)
            },
        }
        findings_page = snapshot.get("findings")
        findings = findings_page.get("items", []) if isinstance(findings_page, Mapping) else []
        failures = [
            *_observation_failures(snapshot),
            *_watchdog_failures(campaigns, self._now()),
        ]
        return {
            **previous,
            "resolved_revision": project.get("commit_sha"),
            "validated_fuzzing_started_at": _iso(started_at) if started_at is not None else None,
            "validated_fuzzing_finished_at": _iso(finished_at) if finished_at is not None else None,
            "elapsed_validated_fuzzing_seconds": int(accumulated),
            "maximum_active_heavy_jobs": None,
            "heavy_job_observation": {
                "available": False,
                "reason": (
                    "compilation leases are process-local and have no public read-only "
                    "API or Docker-owned labelled identity"
                ),
            },
            "maximum_active_fuzzing_jobs": maximum_active,
            "maximum_healthy_candidates": maximum_candidates,
            "targets": targets,
            "configurations": configurations,
            "campaigns": campaigns,
            "coverage": dict(coverage_summary),
            "coverage_evidence": [
                dict(value) for value in snapshot.get("coverage_evidence", [])
                if isinstance(value, Mapping)
            ] if isinstance(snapshot.get("coverage_evidence"), list) else [],
            "corpus": corpus,
            "findings": [dict(value) for value in findings if isinstance(value, Mapping)],
            "agent_runs": _agent_runs(snapshot),
            "retries": _retries(snapshot),
            "failures": failures,
        }


def _arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--verify-report", type=Path,
        help="Verify one existing report instead of observing a campaign.",
    )
    parser.add_argument(
        "--validated-seconds", type=int, choices=(120, 3600), default=3600,
        help="Required accumulated seconds with validated real fuzzing evidence.",
    )
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--report-root", type=Path, default=DEFAULT_REPORT_ROOT)
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    return parser.parse_args(argv)


async def _observe(arguments: argparse.Namespace) -> dict[str, object]:
    load_dotenv(ROOT / ".env", override=False)
    api = PublicProjectApi(arguments.base_url)
    try:
        runner = AcceptanceRunner(
            api,
            DockerCampaignObserver(),
            arguments.report_root,
            repository_token=os.environ.get("BIGEYE_LIBAOM_REPOSITORY_TOKEN") or None,
            poll_seconds=arguments.poll_seconds,
        )
        return await runner.run(arguments.validated_seconds)
    finally:
        await api.close()


def main(argv: list[str] | None = None) -> int:
    arguments = _arguments(list(sys.argv[1:] if argv is None else argv))
    try:
        if arguments.verify_report is not None:
            report = json.loads(arguments.verify_report.read_text(encoding="utf-8"))
            blockers = verify_report(report, arguments.validated_seconds)
            if blockers:
                raise AcceptanceBlocker("; ".join(blockers))
            print(f"Verified libaom acceptance report: {arguments.verify_report}")
            return 0
        report = asyncio.run(_observe(arguments))
        print(
            "Recorded validated libaom fuzzing: "
            f"{report['elapsed_validated_fuzzing_seconds']} seconds, "
            f"project {report['project_id']}."
        )
        return 0
    except (AcceptanceBlocker, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"libaom acceptance blocked: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
