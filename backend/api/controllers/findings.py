"""Project-scoped access to replayed findings and minimal reproducers."""

from __future__ import annotations

import base64
import json
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, Query, Request, Response

from backend.api.views.finding import (
    FindingDetailResponse,
    FindingEvidenceEventResponse,
    FindingPageResponse,
    FindingResponse,
)


router = APIRouter()
_MAX_REPRODUCER_BYTES = 16 * 1024 * 1024
PositiveId = Annotated[int, Path(ge=1)]
PageLimit = Annotated[int, Query(ge=1, le=100)]
Cursor = Annotated[str | None, Query(max_length=512)]


async def _finding(project_id: PositiveId, finding_id: PositiveId, request: Request):
    finding = await request.app.state.services.findings.get(finding_id)
    if finding is None or finding.project_id != project_id:
        raise HTTPException(status_code=404, detail="finding not found")
    return finding


def _encode_cursor(project_id: int, finding) -> str:
    payload = json.dumps(
        {
            "project_id": project_id, "priority_rank": finding.priority_rank,
            "created_at": finding.created_at.isoformat(), "id": finding.id,
        },
        ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ).encode("ascii")
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


def _decode_cursor(value: str | None, project_id: int) -> tuple[int | None, datetime, int] | None:
    if value is None:
        return None
    try:
        padding = "=" * (-len(value) % 4)
        payload = base64.b64decode(value + padding, altchars=b"-_", validate=True)
        decoded = json.loads(payload)
        if not isinstance(decoded, dict) or set(decoded) != {"project_id", "priority_rank", "created_at", "id"}:
            raise ValueError
        if decoded["project_id"] != project_id:
            raise ValueError
        created_at = datetime.fromisoformat(decoded["created_at"])
        priority_rank = decoded["priority_rank"]
        finding_id = decoded["id"]
        if (
            (priority_rank is not None and (
                isinstance(priority_rank, bool) or not isinstance(priority_rank, int) or priority_rank <= 0
            ))
            or created_at.tzinfo is None
            or isinstance(finding_id, bool) or not isinstance(finding_id, int) or finding_id <= 0
        ):
            raise ValueError
        return priority_rank, created_at, finding_id
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HTTPException(status_code=422, detail="invalid findings cursor") from error


@router.get("/projects/{project_id}/findings", response_model=FindingPageResponse)
async def list_findings(
    project_id: PositiveId, request: Request, limit: PageLimit = 50, cursor: Cursor = None,
):
    before = _decode_cursor(cursor, project_id)
    findings, has_more = await request.app.state.services.findings.list_page(project_id, limit, before)
    return FindingPageResponse(
        items=[FindingResponse.from_model(finding) for finding in findings],
        next_cursor=_encode_cursor(project_id, findings[-1]) if has_more and findings else None,
    )


@router.get("/projects/{project_id}/findings/{finding_id}", response_model=FindingDetailResponse)
async def get_finding(project_id: PositiveId, finding_id: PositiveId, request: Request):
    finding = await _finding(project_id, finding_id, request)
    try:
        evidence = request.app.state.services.finding_artifacts.detail(finding)
        detail = FindingDetailResponse.from_model_and_evidence(finding, evidence)
        located = await request.app.state.services.observability.locate_evidence(
            project_id, detail.evidence_ids,
        )
        evidence_events = [
            FindingEvidenceEventResponse(
                evidence_id=evidence_id, stream=located[evidence_id].stream,
                event_id=located[evidence_id].id,
            )
            for evidence_id in detail.evidence_ids if evidence_id in located
        ]
        response = detail.model_dump()
        response["evidence_events"] = evidence_events
        return FindingDetailResponse(**response)
    except (OSError, ValueError) as error:
        raise HTTPException(status_code=409, detail="finding evidence is unavailable") from error


@router.get("/projects/{project_id}/findings/{finding_id}/reproducer")
async def get_reproducer(project_id: PositiveId, finding_id: PositiveId, request: Request):
    finding = await _finding(project_id, finding_id, request)
    try:
        content = request.app.state.services.finding_artifacts.read_reproducer(
            finding, _MAX_REPRODUCER_BYTES,
        )
    except (OSError, ValueError) as error:
        raise HTTPException(status_code=409, detail="finding reproducer is unavailable") from error
    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="bigeye-finding-{finding.id}.bin"'},
    )
