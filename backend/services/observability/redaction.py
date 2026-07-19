"""Remove known credentials before observability payloads are persisted."""

from collections.abc import Mapping


REDACTED = "[REDACTED]"
_SECRET_KEYS = frozenset({
    "authorization", "proxy_authorization", "repository_token", "access_token", "refresh_token",
    "token", "api_key", "apikey", "password", "passwd", "secret", "client_secret",
    "private_key", "credential", "credentials",
})


def _is_secret_key(key: object) -> bool:
    if not isinstance(key, str):
        return False
    normalized = key.lower().replace("-", "_")
    return normalized in _SECRET_KEYS or normalized.endswith("_token") or normalized.endswith("_secret")


def redact(value):
    """Return a recursively redacted, JSON-compatible payload value."""
    if isinstance(value, Mapping):
        return {
            key: REDACTED if _is_secret_key(key) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    return value
