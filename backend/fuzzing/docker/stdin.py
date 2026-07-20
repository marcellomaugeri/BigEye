"""Feed one bounded byte sequence to an attached Docker stdin socket."""

import socket


MAX_STDIN_BYTES = 16 * 1024 * 1024


def send_exact_stdin(attached, content: bytes, timeout_seconds: float) -> None:
    if not isinstance(content, bytes) or len(content) > MAX_STDIN_BYTES:
        raise ValueError("container stdin exceeds its byte bound")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or timeout_seconds <= 0
    ):
        raise ValueError("container stdin timeout must be positive")
    raw = getattr(attached, "_sock", attached)
    settimeout = getattr(raw, "settimeout", None)
    if settimeout is not None:
        settimeout(timeout_seconds)
    raw.sendall(content)
    raw.shutdown(socket.SHUT_WR)
