"""FastAPI application and pool lifecycle."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from backend.api.controllers import projects, settings, tasks
from backend.api.dependencies import build_services
from backend.database.connection import create_pool


def create_app(services=None, workspace: Path | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if services is not None:
            app.state.services = services
            yield
            return
        pool = await create_pool()
        app.state.services = build_services(pool, workspace or Path("workspace"))
        await app.state.services.recovery.recover()
        try:
            yield
        finally:
            await pool.close()

    app = FastAPI(lifespan=lifespan)
    app.include_router(projects.router, prefix="/api")
    app.include_router(tasks.router, prefix="/api")
    app.include_router(settings.router, prefix="/api")
    return app


app = create_app()
