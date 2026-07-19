"""Create a healthy Docker SDK client without hiding programming errors."""

import docker


class DockerUnavailable(RuntimeError):
    """Raised when the Docker daemon cannot be reached."""


class DockerClient:
    def __init__(self, docker_module=docker):
        self._docker = docker_module

    def connect(self):
        try:
            client = self._docker.from_env()
            client.ping()
        except self._docker.errors.DockerException as error:
            raise DockerUnavailable("Docker is unavailable") from error
        return client
