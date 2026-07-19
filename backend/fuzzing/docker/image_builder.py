"""Build maintained images through Docker's low-level Engine API."""

from pathlib import Path


PLATFORM = "linux/amd64"


class ImageBuildFailed(RuntimeError):
    """Raised when Docker reports, or truncates, an image build."""


class ImageBuilder:
    def __init__(self, client):
        self._client = client

    def build(self, dockerfile: Path, tag: str, sink) -> str:
        dockerfile = Path(dockerfile)
        if dockerfile.name != "Dockerfile" or not dockerfile.is_file():
            raise ValueError("dockerfile must be an existing Dockerfile")
        stream = self._client.api.build(
            path=str(dockerfile.parent), dockerfile=dockerfile.name, tag=tag,
            platform=PLATFORM, decode=True, rm=True,
        )
        image_id = None
        for entry in stream:
            if not isinstance(entry, dict):
                raise ImageBuildFailed("Docker build stream contained an invalid entry")
            text = entry.get("stream")
            if text:
                sink(text)
            error = entry.get("error") or entry.get("errorDetail", {}).get("message")
            if error:
                message = str(error)
                sink(message if message.endswith("\n") else f"{message}\n")
                raise ImageBuildFailed(message)
            auxiliary = entry.get("aux") or {}
            if auxiliary.get("ID"):
                image_id = str(auxiliary["ID"])
        if image_id is None:
            raise ImageBuildFailed("Docker build stream ended without an image ID")
        return image_id
