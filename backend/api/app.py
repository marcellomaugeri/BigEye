"""FastAPI application and pool lifecycle."""

from contextlib import asynccontextmanager
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.api.controllers import campaigns, coverage, events, findings, projects, reproductions, settings, tasks
from backend.api.dependencies import build_services
from backend.database.connection import create_pool


_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_FRONTEND_UNAVAILABLE = "Frontend build is unavailable. Run npm --prefix frontend run build."


def _verified_frontend_build(frontend_dist: Path) -> tuple[Path, Path] | None:
    """Accept only a real Vite index and assets directory, never symlink substitutes."""
    root = Path(os.path.abspath(frontend_dist))
    index = root / "index.html"
    assets = root / "assets"
    if (
        root.is_symlink() or not root.is_dir()
        or index.is_symlink() or not index.is_file()
        or assets.is_symlink() or not assets.is_dir()
    ):
        return None
    return index, assets


def create_app(
    services=None,
    workspace: Path | None = None,
    frontend_dist: Path | None = None,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        pool = None
        if services is not None:
            app.state.services = services
        else:
            pool = await create_pool()
            app.state.services = build_services(pool, workspace or Path("workspace"))
        try:
            await app.state.services.recovery.recover()
            yield
        finally:
            close = getattr(app.state.services, "close", None)
            if close is not None:
                await close()
            if pool is not None:
                await pool.close()

    app = FastAPI(lifespan=lifespan)
    app.include_router(projects.router, prefix="/api")
    app.include_router(events.router, prefix="/api")
    app.include_router(tasks.router, prefix="/api")
    app.include_router(settings.router, prefix="/api")
    app.include_router(campaigns.router, prefix="/api")
    app.include_router(coverage.router, prefix="/api")
    app.include_router(findings.router, prefix="/api")
    app.include_router(reproductions.router, prefix="/api")
    build = _verified_frontend_build(frontend_dist or _PROJECT_ROOT / "frontend" / "dist")
    if build is not None:
        index, assets = build
        app.mount("/assets", StaticFiles(directory=assets), name="frontend-assets")
    else:
        index = None

    @app.get("/{path:path}", include_in_schema=False)
    async def frontend(path: str):
        if path == "api" or path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Not Found")
        if index is None:
            raise HTTPException(status_code=503, detail=_FRONTEND_UNAVAILABLE)
        return FileResponse(index, media_type="text/html")

    return app


app = create_app()
