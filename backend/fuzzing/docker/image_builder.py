"""Build maintained images through Docker's low-level Engine API."""

from pathlib import Path

from backend.fuzzing.docker.client import DOCKER_REQUEST_TIMEOUT_SECONDS


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

    def build(self, dockerfile: Path, tag: str, sink, cancellation_signal=None, network_mode: str | None = None) -> str:
        dockerfile = Path(dockerfile)
        if dockerfile.name != "Dockerfile" or not dockerfile.is_file():
            raise ValueError("dockerfile must be an existing Dockerfile")
        kwargs = {
            "path": str(dockerfile.parent), "dockerfile": dockerfile.name, "tag": tag,
            "platform": PLATFORM, "decode": True, "rm": True, "timeout": DOCKER_REQUEST_TIMEOUT_SECONDS,
        }
        if network_mode is not None:
            kwargs["network_mode"] = network_mode
        stream = self._client.api.build(**kwargs)
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

    def inspect_matching(self, tag: str, labels: dict[str, str]) -> str | None:
        """Return an existing linux/amd64 image only when every layer label matches."""
        try:
            image = self._client.api.inspect_image(tag)
        except Exception:
            return None
        if image.get("Os") != "linux" or image.get("Architecture") != "amd64":
            return None
        actual = image.get("Config", {}).get("Labels", {})
        if not isinstance(actual, dict) or any(actual.get(key) != value for key, value in labels.items()):
            return None
        image_id = image.get("Id")
        return str(image_id) if image_id else None

    def verify_parent(self, tag: str, labels: dict[str, str], expected_image_id: str) -> bool:
        """Verify the manifest labels still name the inspected linux/amd64 parent image."""
        return self.inspect_matching(tag, labels) == expected_image_id
