"""Inspect only the image facts required by the maintained toolchain."""

from dataclasses import dataclass

import docker


class MissingImage(RuntimeError):
    """Raised when an expected tag does not exist."""


class UnsupportedImagePlatform(RuntimeError):
    """Raised for images other than the required linux/amd64 platform."""


@dataclass(frozen=True)
class ImageInfo:
    image_id: str
    os: str
    architecture: str


class ImageInspector:
    def __init__(self, client):
        self._client = client
        self._errors = getattr(client, "errors", docker.errors)

    def inspect(self, tag: str) -> ImageInfo:
        try:
            data = self._client.api.inspect_image(tag)
        except self._errors.ImageNotFound as error:
            raise MissingImage(f"Docker image is missing: {tag}") from error
        info = ImageInfo(str(data["Id"]), str(data["Os"]), str(data["Architecture"]))
        if (info.os, info.architecture) != ("linux", "amd64"):
            raise UnsupportedImagePlatform(f"image {tag} must be linux/amd64, got {info.os}/{info.architecture}")
        return info
