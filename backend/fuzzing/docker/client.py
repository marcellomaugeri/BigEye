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
            close = getattr(client, "close", None)
            if close is not None:
                close()
            raise DockerUnavailable("Docker is unavailable") from error
        return client
