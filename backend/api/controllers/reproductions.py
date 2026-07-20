"""HTTP boundary for exact read-only finding reproduction."""

from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, Request, status
from fastapi.responses import StreamingResponse

from backend.api.views.reproduction import ReproductionResponse
from backend.services.findings.reproduce_finding import FindingNotFound, FindingNotReproducible


router = APIRouter()
PositiveId = Annotated[int, Path(ge=1)]
RunId = Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")]


@router.post(
    "/projects/{project_id}/findings/{finding_id}/reproductions",
    response_model=ReproductionResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def start_reproduction(project_id: PositiveId, finding_id: PositiveId, request: Request):
    try:
        run = await request.app.state.services.reproductions.start(project_id, finding_id)
    except FindingNotFound as error:
        raise HTTPException(status_code=404, detail="finding not found") from error
    except (FindingNotReproducible, OSError, ValueError) as error:
        raise HTTPException(status_code=409, detail="finding reproduction is unavailable") from error
    return ReproductionResponse.from_run(run)


@router.get(
    "/projects/{project_id}/findings/{finding_id}/reproductions/{run_id}/events",
)
async def stream_reproduction(
    project_id: PositiveId, finding_id: PositiveId, run_id: RunId, request: Request,
):
    try:
        stream = request.app.state.services.reproductions.stream(project_id, finding_id, run_id)
        first = await anext(stream)
    except (LookupError, OSError, ValueError) as error:
        raise HTTPException(status_code=404, detail="reproduction run not found") from error

    async def events():
        try:
            yield _sse(first)
            async for event in stream:
                yield _sse(event)
        finally:
            await stream.aclose()

    return StreamingResponse(
        events(), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _sse(record: dict) -> str:
    if "comment" in record:
        return f": {record['comment']}\n\n"
    data = json.dumps(record["data"], ensure_ascii=False, separators=(",", ":"))
    return f"event: {record['event']}\ndata: {data}\n\n"
