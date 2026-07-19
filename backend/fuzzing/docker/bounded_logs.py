"""Persist a bounded tail of final container logs without blocking shutdown."""

from __future__ import annotations

import os
import queue
import threading
import time


BYTE_MARKER = b"\n[BigEye final log truncated: byte limit reached]\n"
TIME_MARKER = b"\n[BigEye final log truncated: time limit reached]\n"
ERROR_MARKER = b"\n[BigEye final log truncated: collection failed]\n"


def persist_bounded_logs(container, descriptor: int, byte_limit: int, time_limit: float) -> None:
    messages: queue.Queue[tuple[str, object]] = queue.Queue(maxsize=16)
    cancelled = threading.Event()
    stream_holder: dict[str, object] = {}

    def publish(kind: str, value: object) -> None:
        while not cancelled.is_set():
            try:
                messages.put((kind, value), timeout=0.01)
                return
            except queue.Full:
                continue

    def read_logs() -> None:
        try:
            stream = container.logs(stream=True, follow=False, stdout=True, stderr=True)
            stream_holder["stream"] = stream
            for chunk in stream:
                if cancelled.is_set():
                    break
                publish("chunk", chunk)
            publish("done", None)
        except BaseException:
            publish("error", None)

    worker = threading.Thread(target=read_logs, name="bigeye-final-logs", daemon=True)
    worker.start()
    deadline = time.monotonic() + time_limit
    written = 0
    marker = None
    try:
        while True:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                marker = TIME_MARKER
                break
            try:
                kind, value = messages.get(timeout=remaining_time)
            except queue.Empty:
                marker = TIME_MARKER
                break
            if kind == "done":
                break
            if kind == "error":
                marker = ERROR_MARKER
                break
            data = value if isinstance(value, bytes) else str(value).encode("utf-8", errors="replace")
            available = byte_limit - written
            if len(data) > available:
                if available > 0:
                    _write_all(descriptor, data[:available])
                marker = BYTE_MARKER
                break
            _write_all(descriptor, data)
            written += len(data)
        if marker is not None:
            _write_all(descriptor, marker)
        os.fsync(descriptor)
    finally:
        cancelled.set()
        stream = stream_holder.get("stream")
        close = getattr(stream, "close", None)
        if close is not None:
            try:
                close()
            except (RuntimeError, ValueError):
                pass
        worker.join(timeout=min(0.02, time_limit))


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("failed to persist final container logs")
        view = view[written:]
