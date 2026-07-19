"""Project-scoped access to replayed findings and minimal reproducers."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, Request, Response

from backend.api.views.finding import FindingDetailResponse, FindingResponse


router = APIRouter()
_MAX_REPRODUCER_BYTES = 16 * 1024 * 1024
PositiveId = Annotated[int, Path(ge=1)]


async def _finding(project_id: PositiveId, finding_id: PositiveId, request: Request):
    finding = await request.app.state.services.findings.get(finding_id)
    if finding is None or finding.project_id != project_id:
        raise HTTPException(status_code=404, detail="finding not found")
    return finding


@router.get("/projects/{project_id}/findings", response_model=list[FindingResponse])
async def list_findings(project_id: PositiveId, request: Request):
    findings = await request.app.state.services.findings.list_for_project(project_id)
    return [FindingResponse.from_model(finding) for finding in findings]


@router.get("/projects/{project_id}/findings/{finding_id}", response_model=FindingDetailResponse)
async def get_finding(project_id: PositiveId, finding_id: PositiveId, request: Request):
    finding = await _finding(project_id, finding_id, request)
    try:
        evidence = request.app.state.services.finding_artifacts.detail(finding)
        return FindingDetailResponse.from_model_and_evidence(finding, evidence)
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
