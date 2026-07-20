"""Remove known credentials before observability payloads are persisted."""

from collections.abc import Mapping
import re
from urllib.parse import urlsplit


REDACTED = "[REDACTED]"
_SECRET_KEYS = frozenset({
    "authorization", "proxy_authorization", "repository_token", "access_token", "refresh_token",
    "token", "api_key", "apikey", "password", "passwd", "secret", "client_secret",
    "private_key", "credential", "credentials",
})
_BEARER_CREDENTIAL = re.compile(r"\bbearer\s+\S+", re.IGNORECASE)
_PRIVATE_KEY_MATERIAL = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----", re.IGNORECASE,
)


def is_secret_key(key: object) -> bool:
    if not isinstance(key, str):
        return False
    normalized = key.lower().replace("-", "_")
    return (
        normalized in _SECRET_KEYS
        or normalized.endswith((
            "_token", "_secret", "_password", "_credential", "_credentials",
            "_key", "_key_id", "_pat",
        ))
    )


def is_secret_value(value: object) -> bool:
    if not isinstance(value, str):
        return False
    candidate = value.strip()
    if _BEARER_CREDENTIAL.search(candidate) or _PRIVATE_KEY_MATERIAL.search(candidate):
        return True
    try:
        parsed = urlsplit(candidate)
        if not parsed.scheme or not parsed.netloc:
            return False
        return parsed.username is not None or parsed.password is not None
    except ValueError:
        return "://" in candidate and "@" in candidate


def redact_environment(value):
    """Redact credential-shaped environment entries without changing the source mapping."""
    if not isinstance(value, Mapping):
        return value
    return {
        key: REDACTED if is_secret_key(key) or is_secret_value(item) else item
        for key, item in value.items()
    }


def redact(value):
    """Return a recursively redacted, JSON-compatible payload value."""
    if isinstance(value, Mapping):
        return {
            key: REDACTED if is_secret_key(key) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if is_secret_value(value):
        return REDACTED
    return value
