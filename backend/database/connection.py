"""Host-side PostgreSQL connection setup."""

import os

import asyncpg


def database_url() -> str:
    """Return the configured development database URL."""
    configured_url = os.environ.get("DATABASE_URL")
    if configured_url:
        return configured_url

    user = os.environ.get("POSTGRES_USER", "bigeye")
    password = os.environ.get("POSTGRES_PASSWORD", "bigeye")
    port = os.environ.get("BIGEYE_POSTGRES_PORT", "5433")
    database = os.environ.get("POSTGRES_DB", "bigeye")
    return f"postgresql://{user}:{password}@127.0.0.1:{port}/{database}"


async def create_pool() -> asyncpg.Pool:
    """Create a pool for the host-run FastAPI service."""
    return await asyncpg.create_pool(database_url())
