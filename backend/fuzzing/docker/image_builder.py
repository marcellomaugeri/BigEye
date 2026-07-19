"""Build maintained images through Docker's low-level Engine API."""

from pathlib import Path


PLATFORM = "linux/amd64"
IMAGE_BUILD_LOG_MAX_BYTES = 5 * 1024 * 1024


class ImageBuildFailed(RuntimeError):
    """Raised when Docker reports, or truncates, an image build."""


class ImageBuildCancelled(ImageBuildFailed):
    """Raised when a caller cancels a build at an event boundary."""


class ImageBuildLogLimitExceeded(ImageBuildFailed):
    """Raised before build output would exceed the retained log budget."""


class ImageBuilder:
    def __init__(self, client):
        self._client = client

    def build(self, dockerfile: Path, tag: str, sink, cancellation_signal=None) -> str:
        dockerfile = Path(dockerfile)
        if dockerfile.name != "Dockerfile" or not dockerfile.is_file():
            raise ValueError("dockerfile must be an existing Dockerfile")
        stream = self._client.api.build(
            path=str(dockerfile.parent), dockerfile=dockerfile.name, tag=tag,
            platform=PLATFORM, decode=True, rm=True,
        )
        emitted = 0
        def emit(text: str) -> None:
            nonlocal emitted
            encoded = text.encode("utf-8")
            if emitted + len(encoded) > IMAGE_BUILD_LOG_MAX_BYTES:
                raise ImageBuildLogLimitExceeded("image build log exceeded its byte limit")
            emitted += len(encoded)
            sink(text)
        try:
            for entry in stream:
                if cancellation_signal is not None and cancellation_signal.is_set():
                    raise ImageBuildCancelled("image build cancelled")
                if not isinstance(entry, dict):
                    raise ImageBuildFailed("Docker build stream contained an invalid entry")
                text = entry.get("stream")
                if text:
                    emit(text)
                detail = entry.get("errorDetail") or {}
                error = entry.get("error") or (detail.get("message") if isinstance(detail, dict) else detail)
                if error:
                    message = str(error)
                    emit(message if message.endswith("\n") else f"{message}\n")
                    raise ImageBuildFailed(message)
                status = entry.get("status")
                identifier = entry.get("id")
                progress = entry.get("progress")
                if status or identifier or progress:
                    prefix = f"{identifier}: " if identifier else ""
                    rendered = f"{prefix}{status or ''}{(' ' + progress) if progress else ''}".strip()
                    emit(f"{rendered}\n")
        except BaseException:
            close = getattr(stream, "close", None)
            if close is not None:
                close()
            raise
        try:
            image_id = self._client.api.inspect_image(tag)["Id"]
        except Exception as error:
            raise ImageBuildFailed(f"built image {tag} could not be inspected: {error}") from error
        if not image_id:
            raise ImageBuildFailed(f"built image {tag} could not be inspected: no image ID")
        return str(image_id)
