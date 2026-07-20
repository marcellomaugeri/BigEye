"""Thin HTTP handling for source traceability queries."""

from fastapi import APIRouter, HTTPException, Query, Request

from backend.api.views.coverage import (
    CoverageTreeResponse,
    FunctionCoveragePageResponse,
    LineEvidencePageResponse,
    SourceFileResponse,
)
from backend.fuzzing.coverage.llvm_coverage import CoverageIntegrityError


router = APIRouter()


def _coverage(request: Request):
    service = getattr(request.app.state.services, "coverage", None)
    if service is None:
        raise HTTPException(status_code=409, detail="coverage is not ready")
    return service


def _translate(error):
    if isinstance(error, KeyError):
        raise HTTPException(status_code=404, detail="coverage not found") from error
    raise HTTPException(status_code=422, detail="invalid source path or range") from error


@router.get("/projects/{project_id}/coverage/tree", response_model=CoverageTreeResponse)
async def project_tree(
    project_id: int,
    request: Request,
    limit: int = Query(default=1_000, ge=1, le=1_000),
    offset: int = Query(default=0, ge=0, le=10_000_000),
):
    try:
        return await _coverage(request).project_tree(project_id, limit=limit, offset=offset)
    except (ValueError, KeyError, CoverageIntegrityError) as error:
        _translate(error)

@router.get("/projects/{project_id}/coverage/source", response_model=SourceFileResponse)
async def source_file(
    project_id: int,
    request: Request,
    path: str = Query(min_length=1, max_length=4096),
    start_line: int = Query(default=1, ge=1),
    end_line: int = Query(default=200, ge=1),
):
    if end_line < start_line or end_line - start_line + 1 > 500:
        raise HTTPException(status_code=422, detail="invalid source path or range")
    try:
        return await _coverage(request).source_file(project_id, path, start_line, end_line)
    except (ValueError, KeyError, CoverageIntegrityError) as error:
        _translate(error)


@router.get("/projects/{project_id}/coverage/functions", response_model=FunctionCoveragePageResponse)
async def functions(
    project_id: int,
    request: Request,
    path: str = Query(min_length=1, max_length=4096),
    limit: int = Query(default=1_000, ge=1, le=1_000),
    offset: int = Query(default=0, ge=0, le=10_000_000),
):
    try:
        return await _coverage(request).function_summaries(project_id, path, limit=limit, offset=offset)
    except (ValueError, KeyError, CoverageIntegrityError) as error:
        _translate(error)


@router.get("/projects/{project_id}/coverage/lines/{line_number}", response_model=LineEvidencePageResponse)
async def line_evidence(
    project_id: int,
    line_number: int,
    request: Request,
    path: str = Query(min_length=1, max_length=4096),
    limit: int = Query(default=500, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=10_000_000),
):
    try:
        return await _coverage(request).line_evidence(
            project_id, path, line_number, limit=limit, offset=offset
        )
    except (ValueError, KeyError, CoverageIntegrityError) as error:
        _translate(error)
