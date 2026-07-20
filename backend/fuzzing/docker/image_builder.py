"""Build maintained images through Docker's low-level Engine API."""

from dataclasses import dataclass
from pathlib import Path
import re
import threading

from backend.fuzzing.docker.client import DOCKER_REQUEST_TIMEOUT_SECONDS


PLATFORM = "linux/amd64"
IMAGE_BUILD_LOG_MAX_BYTES = 5 * 1024 * 1024
IMAGE_BUILD_DETAIL_MAX_CHARS = 32 * 1024


def _bounded_text(value, default: str = "") -> str:
    if value is None:
        return default
    return str(value)[:IMAGE_BUILD_DETAIL_MAX_CHARS]


@dataclass(frozen=True)
class ImageBuildFailureDetail:
    """Bounded Docker stream facts retained for repair and diagnostics."""

    stream_type: str
    phase: str
    message: str
    code: str | int | None = None
    exit_code: int | None = None
    source: str | None = None
    instruction: str | None = None

    def __post_init__(self) -> None:
        for name in ("stream_type", "phase", "message"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or len(value) > IMAGE_BUILD_DETAIL_MAX_CHARS:
                raise ValueError(f"image build failure {name} is invalid")
        for name in ("source", "instruction"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or len(value) > IMAGE_BUILD_DETAIL_MAX_CHARS):
                raise ValueError(f"image build failure {name} is invalid")
        if self.code is not None and not isinstance(self.code, (str, int)):
            raise ValueError("image build failure code is invalid")
        if self.exit_code is not None and type(self.exit_code) is not int:
            raise ValueError("image build failure exit code is invalid")


class ImageBuildFailed(RuntimeError):
    """Raised when Docker reports, or truncates, an image build."""

    def __init__(self, message: str, detail: ImageBuildFailureDetail | None = None):
        super().__init__(message)
        self.detail = detail


class ImageCompilationFailed(ImageBuildFailed):
    """Docker completed a build step and reported a deterministic command failure."""


class ImageBuildCancelled(ImageBuildFailed):
    """Raised when a caller cancels a build at an event boundary."""


class ImageBuildLogLimitExceeded(ImageBuildFailed):
    """Raised before build output would exceed the retained log budget."""


class BuildCancellationSignal:
    """A thread-safe event that can immediately close registered build streams."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._guard = threading.Lock()
        self._callbacks = set()

    def is_set(self) -> bool:
        return self._event.is_set()

    def wait(self, timeout: float | None = None) -> bool:
        return self._event.wait(timeout)

    def set(self) -> None:
        with self._guard:
            self._event.set()
            callbacks = tuple(self._callbacks)
            self._callbacks.clear()
        for callback in callbacks:
            try:
                callback()
            except Exception:
                pass

    def add_callback(self, callback) -> None:
        with self._guard:
            if not self._event.is_set():
                self._callbacks.add(callback)
                return
        callback()

    def remove_callback(self, callback) -> None:
        with self._guard:
            self._callbacks.discard(callback)


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
        if cancellation_signal is not None and cancellation_signal.is_set():
            raise ImageBuildCancelled("image build cancelled before it started")
        try:
            stream = self._client.api.build(**kwargs)
        except Exception as error:
            message = _bounded_text(error, "Docker image build request failed")
            detail = ImageBuildFailureDetail("request", "engine", message)
            raise ImageBuildFailed(f"Docker image build request failed: {message}", detail) from error
        close = getattr(stream, "close", None)

        def close_stream() -> None:
            if close is not None:
                try:
                    close()
                except Exception:
                    pass

        register = getattr(cancellation_signal, "add_callback", None)
        unregister = getattr(cancellation_signal, "remove_callback", None)
        if register is not None:
            register(close_stream)
        if cancellation_signal is not None and cancellation_signal.is_set():
            close_stream()
            raise ImageBuildCancelled("image build cancelled before streaming")
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
                    failure_detail, deterministic = self._classify_failure(entry, message)
                    if deterministic:
                        raise ImageCompilationFailed(failure_detail.message, failure_detail)
                    raise ImageBuildFailed(failure_detail.message, failure_detail)
                status = entry.get("status")
                identifier = entry.get("id")
                progress = entry.get("progress")
                if status or identifier or progress:
                    prefix = f"{identifier}: " if identifier else ""
                    rendered = f"{prefix}{status or ''}{(' ' + progress) if progress else ''}".strip()
                    emit(f"{rendered}\n")
        except ImageBuildFailed:
            close_stream()
            raise
        except Exception as error:
            close_stream()
            message = _bounded_text(error, "Docker build stream failed")
            detail = ImageBuildFailureDetail("stream", "engine", message)
            raise ImageBuildFailed(f"Docker build stream failed: {message}", detail) from error
        except BaseException:
            close_stream()
            raise
        finally:
            if unregister is not None:
                unregister(close_stream)
        if cancellation_signal is not None and cancellation_signal.is_set():
            close_stream()
            raise ImageBuildCancelled("image build cancelled before inspection")
        try:
            image_id = self._client.api.inspect_image(tag)["Id"]
        except Exception as error:
            raise ImageBuildFailed(f"built image {tag} could not be inspected: {error}") from error
        if not image_id:
            raise ImageBuildFailed(f"built image {tag} could not be inspected: no image ID")
        return str(image_id)

    @classmethod
    def _classify_failure(cls, entry: dict, message: str) -> tuple[ImageBuildFailureDetail, bool]:
        raw_detail = entry.get("errorDetail")
        detail = raw_detail if isinstance(raw_detail, dict) else {}
        stream_type = _bounded_text(entry.get("type") or detail.get("type"), "error")
        raw_phase = entry.get("phase") or detail.get("phase")
        source = _bounded_text(entry.get("source") or detail.get("source")) or None
        instruction = _bounded_text(entry.get("instruction") or detail.get("instruction")) or None
        code = detail.get("code")
        if not isinstance(code, (str, int)):
            code = None
        exit_code = cls._integer(detail.get("exitCode", detail.get("exit_code")))
        bounded_message = _bounded_text(message, "Docker build failed")
        fatal_phase = cls._fatal_phase(raw_phase, code, bounded_message)
        phase, fallback_exit, fallback_instruction = cls._deterministic_phase(
            raw_phase, stream_type, bounded_message,
        )
        if exit_code is None:
            exit_code = fallback_exit
        if instruction is None:
            instruction = fallback_instruction
        deterministic = fatal_phase is None and (
            (exit_code is not None and exit_code != 0)
            or phase in {"dockerfile-frontend", "generated-build-config"}
        )
        if fatal_phase is not None:
            phase = fatal_phase
        elif raw_phase is not None and phase == "engine":
            phase = _bounded_text(raw_phase, "engine")
        return ImageBuildFailureDetail(
            stream_type=stream_type,
            phase=phase,
            message=bounded_message,
            code=code,
            exit_code=exit_code,
            source=source,
            instruction=instruction,
        ), deterministic

    @staticmethod
    def _integer(value) -> int | None:
        if type(value) is int:
            return value
        if isinstance(value, str) and re.fullmatch(r"-?[0-9]+", value):
            return int(value)
        return None

    @staticmethod
    def _fatal_phase(raw_phase, code, message: str) -> str | None:
        phase = str(raw_phase or "").casefold()
        if phase in {"engine", "daemon", "registry", "network", "resource", "cancelled", "canceled"}:
            return "cancelled" if phase in {"cancelled", "canceled"} else phase
        if type(code) is int and code >= 400:
            return "engine"
        lowered = message.casefold()
        categories = (
            ("engine", (
            "cannot connect to the docker daemon",
            "error during connect",
            "connection refused",
            "connection reset",
            )),
            ("network", (
            "network is unreachable",
            "temporary failure in name resolution",
            "tls handshake timeout",
            "i/o timeout",
            )),
            ("registry", (
            "failed to resolve source metadata",
            "pull access denied",
            "unauthorized:",
            "manifest unknown",
            )),
            ("resource", (
            "no space left on device",
            "out of memory",
            "resource exhausted",
            )),
            ("cancelled", (
            "context canceled",
            "context cancelled",
            "build cancelled",
            "build canceled",
            )),
        )
        for category, markers in categories:
            if any(marker in lowered for marker in markers):
                return category
        return None

    @classmethod
    def _deterministic_phase(
        cls, raw_phase, stream_type: str, message: str,
    ) -> tuple[str, int | None, str | None]:
        phase = str(raw_phase or "").casefold()
        stream_kind = stream_type.casefold()
        if phase in {"dockerfile", "dockerfile-frontend", "frontend", "parser"} or stream_kind in {
            "dockerfile", "dockerfile-frontend", "frontend",
        }:
            return "dockerfile-frontend", None, cls._instruction(message)
        if phase in {"generated-build-config", "build-context", "configuration"}:
            return "generated-build-config", None, cls._instruction(message)
        if phase in {"build-command", "executor", "command", "run"}:
            return "build-command", cls._exit_code(message), cls._instruction(message)

        frontend_patterns = (
            r"(?i)(?:failed to solve:\s*)?dockerfile parse error on line \d+:",
            r"(?i)failed to solve with frontend dockerfile(?:\.v\d+)?:",
            r"(?i)failed to (?:read|parse) dockerfile:",
            r"(?i)(?:^|:\s*)unknown instruction:\s*[A-Z][A-Z0-9_-]*",
        )
        if any(re.search(pattern, message) for pattern in frontend_patterns):
            return "dockerfile-frontend", None, cls._instruction(message)

        generated_config_patterns = (
            r"(?i)COPY failed: .*not found in build context",
            r"(?i)failed to (?:compute cache key|calculate checksum).*not found",
        )
        if any(re.search(pattern, message) for pattern in generated_config_patterns):
            return "generated-build-config", None, cls._instruction(message)

        exit_code = cls._exit_code(message)
        if exit_code is not None:
            return "build-command", exit_code, cls._instruction(message)
        return "engine", None, cls._instruction(message)

    @staticmethod
    def _exit_code(message: str) -> int | None:
        match = re.search(
            r"(?i)(?:returned (?:a )?non-zero code|did not complete successfully:\s*exit code):\s*(-?[0-9]+)",
            message,
        )
        return int(match.group(1)) if match else None

    @staticmethod
    def _instruction(message: str) -> str | None:
        match = re.search(r"(?i)unknown instruction:\s*([A-Z][A-Z0-9_-]*)", message)
        return match.group(1).upper() if match else None

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
