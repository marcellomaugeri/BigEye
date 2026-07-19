"""Build or safely reuse BigEye's maintained LLVM image."""

from hashlib import sha256
import inspect
from pathlib import Path
import threading

from backend.fuzzing.docker.image_inspector import MissingImage


PLATFORM = "linux/amd64"
LLVM_VERSION = "18"
AFL_VERSION = "v4.40c"


class ToolchainBuilder:
    _tag_locks: dict[str, threading.Lock] = {}
    _tag_locks_guard = threading.Lock()
    def __init__(self, dockerfile: Path, image_builder, inspector):
        self._dockerfile = Path(dockerfile)
        self._image_builder = image_builder
        self._inspector = inspector

    def tag(self) -> str:
        identity = b"\0".join(
            (
                b"bigeye-toolchain-v1",
                PLATFORM.encode(),
                LLVM_VERSION.encode(),
                AFL_VERSION.encode(),
                self._dockerfile.read_bytes(),
            )
        )
        digest = sha256(identity).hexdigest()[:20]
        return f"bigeye-toolchain:{digest}"

    def ensure(self, sink, cancellation_signal=None):
        tag = self.tag()
        try:
            return self._inspector.inspect(tag)
        except MissingImage:
            with self._lock_for(tag):
                try:
                    return self._inspector.inspect(tag)
                except MissingImage:
                    build = self._image_builder.build
                    if "cancellation_signal" in inspect.signature(build).parameters:
                        build(self._dockerfile, tag, sink, cancellation_signal=cancellation_signal)
                    else:
                        build(self._dockerfile, tag, sink)
                    return self._inspector.inspect(tag)

    @classmethod
    def _lock_for(cls, tag: str) -> threading.Lock:
        with cls._tag_locks_guard:
            return cls._tag_locks.setdefault(tag, threading.Lock())
