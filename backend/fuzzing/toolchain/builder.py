"""Build or safely reuse BigEye's maintained LLVM image."""

from hashlib import sha256
from pathlib import Path

from backend.fuzzing.docker.image_inspector import MissingImage


class ToolchainBuilder:
    def __init__(self, dockerfile: Path, image_builder, inspector):
        self._dockerfile = Path(dockerfile)
        self._image_builder = image_builder
        self._inspector = inspector

    def tag(self) -> str:
        digest = sha256(b"bigeye-llvm-v1\0linux/amd64\0" + self._dockerfile.read_bytes()).hexdigest()[:20]
        return f"bigeye-llvm:{digest}"

    def ensure(self, sink):
        tag = self.tag()
        try:
            return self._inspector.inspect(tag)
        except MissingImage:
            self._image_builder.build(self._dockerfile, tag, sink)
            return self._inspector.inspect(tag)
