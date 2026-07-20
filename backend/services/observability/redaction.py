"""Remove known credentials before observability payloads are persisted."""

from base64 import b64decode
from binascii import Error as Base64Error
from collections.abc import Mapping
import re
from urllib.parse import parse_qsl, urlsplit


REDACTED = "[REDACTED]"
_SECRET_KEYS = frozenset({
    "authorization", "proxy_authorization", "repository_token", "access_token", "refresh_token",
    "token", "api_key", "apikey", "password", "passwd", "secret", "client_secret",
    "private_key", "credential", "credentials",
})
_BEARER_CREDENTIAL = re.compile(r"\bbearer\s+\S+", re.IGNORECASE)
_BASIC_CREDENTIAL = re.compile(
    r"\bbasic[ \t]+([A-Za-z0-9+/]+={0,2})(?![A-Za-z0-9+/=])", re.IGNORECASE,
)
_PRIVATE_KEY_MATERIAL = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----", re.IGNORECASE,
)
_MAX_REPLAY_VALUE_CHARS = 4_096
_MAX_DECODED_QUERY_VALUES = 4_096


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
    pending = [value]
    inspected = 0
    while pending:
        inspected += 1
        if inspected > _MAX_DECODED_QUERY_VALUES:
            break
        candidate = pending.pop().strip()
        if (
            _BEARER_CREDENTIAL.search(candidate)
            or _PRIVATE_KEY_MATERIAL.search(candidate)
            or _has_basic_credential(candidate)
        ):
            return True
        try:
            parsed = urlsplit(candidate)
        except ValueError:
            if "://" in candidate and "@" in candidate:
                return True
            continue
        if not parsed.scheme or not parsed.netloc:
            continue
        if parsed.username is not None or parsed.password is not None:
            return True
        try:
            query = parse_qsl(
                parsed.query[:_MAX_REPLAY_VALUE_CHARS],
                keep_blank_values=True,
            )
        except ValueError:
            continue
        for key, item in query:
            if is_secret_key(key):
                return True
            if item:
                if inspected + len(pending) >= _MAX_DECODED_QUERY_VALUES:
                    continue
                pending.append(item)
    return False


def _has_basic_credential(value: str) -> bool:
    for match in _BASIC_CREDENTIAL.finditer(value):
        encoded = match.group(1)
        if len(encoded) > _MAX_REPLAY_VALUE_CHARS:
            return True
        try:
            decoded = b64decode(encoded, validate=True)
        except (Base64Error, ValueError):
            continue
        if b":" in decoded:
            return True
    return False


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
