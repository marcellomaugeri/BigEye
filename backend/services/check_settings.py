"""Truthful environment availability checks without secret disclosure."""

import os


def docker_available() -> bool:
    """Ask the local Docker daemon directly, without exposing its details."""
    try:
        import docker

        docker.from_env().ping()
        return True
    except Exception:
        return False


class SettingsService:
    def __init__(self, pool=None, docker_check=None, toolchain_check=None):
        self._pool = pool
        self._docker_check = docker_check or docker_available
        self._toolchain_check = toolchain_check or (lambda: False)

    async def check(self) -> dict[str, bool]:
        database = False
        if self._pool is not None:
            try:
                database = (await self._pool.fetchval("SELECT 1")) == 1
            except Exception:
                database = False
        return {
            "database": database,
            "docker": bool(self._docker_check()),
            "openai_api_key_present": bool(os.environ.get("OPENAI_API_KEY")),
            "toolchain": bool(self._toolchain_check()),
        }
