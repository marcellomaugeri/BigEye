"""Create a healthy Docker SDK client without hiding programming errors."""

import docker


DOCKER_REQUEST_TIMEOUT_SECONDS = 30


class DockerUnavailable(RuntimeError):
    """Raised when the Docker daemon cannot be reached."""


class DockerClient:
    def __init__(self, docker_module=docker):
        self._docker = docker_module

    def connect(self):
        client = None
        try:
            client = self._docker.from_env(timeout=DOCKER_REQUEST_TIMEOUT_SECONDS)
            client.ping()
        except self._docker.errors.DockerException as error:
            self._close(client)
            raise DockerUnavailable("Docker is unavailable") from error
        except BaseException:
            self._close(client)
            raise
        return client

    @staticmethod
    def _close(client) -> None:
        close = getattr(client, "close", None)
        if close is not None:
            try:
                close()
            except Exception:
                pass
