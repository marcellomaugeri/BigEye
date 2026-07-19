"""Durable, redacted project observability tests."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException


def run(awaitable):
    return asyncio.run(awaitable)


def test_event_id_is_the_durable_jsonl_byte_offset(tmp_path: Path) -> None:
    from backend.services.observability.event_store import ProjectEventStore

    store = ProjectEventStore(tmp_path)
    first = run(store.append(7, "activity", {"message": "one"}))
    second = run(store.append(7, "activity", {"message": "two"}))

    assert first.id == 0
    assert second.id > first.id
    assert [event.payload["message"] for event in run(store.read(7, "activity", first.id, 20))] == ["two"]


def test_redaction_removes_tokens_and_authorization_headers() -> None:
    from backend.services.observability.redaction import redact

    value = redact({"Authorization": "Bearer secret", "repository_token": "secret", "safe": "value"})

    assert value == {"Authorization": "[REDACTED]", "repository_token": "[REDACTED]", "safe": "value"}


def test_redaction_recurses_before_durable_serialization(tmp_path: Path) -> None:
    from backend.services.observability.event_store import ProjectEventStore

    event = run(ProjectEventStore(tmp_path).append(7, "debug", {
        "headers": {"authorization": "Bearer secret"}, "items": [{"api_key": "secret"}],
    }))

    assert event.payload == {
        "headers": {"authorization": "[REDACTED]"}, "items": [{"api_key": "[REDACTED]"}],
    }


def test_redaction_normalizes_nested_key_separators_and_case() -> None:
    from backend.services.observability.redaction import redact

    value = redact({
        "OPENAI_API_KEY": "openai", "X-Api-Key": "header", "AWS_SECRET_ACCESS_KEY": "aws",
        "nested": [{"Authorization": "Bearer secret", "repository_token": "token"}],
        "credentials": {"password": "password", "credential": "credential"},
        "safe_key": "visible", "monkey": "visible", "secretary": "visible",
    })

    assert value == {
        "OPENAI_API_KEY": "[REDACTED]", "X-Api-Key": "[REDACTED]", "AWS_SECRET_ACCESS_KEY": "[REDACTED]",
        "nested": [{"Authorization": "[REDACTED]", "repository_token": "[REDACTED]"}],
        "credentials": "[REDACTED]", "safe_key": "visible", "monkey": "visible", "secretary": "visible",
    }


def test_activity_and_debug_are_separate_from_internal_events_stream(tmp_path: Path) -> None:
    from backend.services.observability.event_store import ProjectEventStore

    store = ProjectEventStore(tmp_path)
    run(store.append(7, "activity", {"message": "created"}))
    run(store.append(7, "debug", {"message": "details"}))

    assert [event.payload["message"] for event in run(store.read(7, "activity", -1, 20))] == ["created"]
    assert [event.payload["message"] for event in run(store.read(7, "debug", -1, 20))] == ["details"]
    assert [event.payload["name"] for event in run(store.read(7, "events", -1, 20))] == ["activity", "debug"]


@pytest.mark.parametrize("stream", ["events.jsonl", "../debug", "unknown", "Activity"])
def test_store_rejects_invalid_stream_names(tmp_path: Path, stream: str) -> None:
    from backend.services.observability.event_store import ProjectEventStore

    with pytest.raises(ValueError, match="stream"):
        run(ProjectEventStore(tmp_path).append(7, stream, {"message": "no"}))


def test_event_stream_replays_only_events_after_last_id(tmp_path: Path) -> None:
    from backend.services.observability.event_store import ProjectEventStore
    from backend.services.observability.event_stream import ProjectEventStream

    store = ProjectEventStore(tmp_path)
    run(store.append(7, "activity", {"message": "first"}))
    run(store.append(7, "debug", {"message": "second"}))
    first, second = run(store.read(7, "events", -1, 20))
    events = ProjectEventStream(store)

    async def replay():
        stream = events.stream(7, first.id)
        try:
            return await anext(stream)
        finally:
            await stream.aclose()

    assert f"id: {second.id}" in run(replay())
    assert "event: debug" in run(replay())
    assert "second" not in run(replay())


def test_event_stream_waits_for_new_durable_invalidation(tmp_path: Path) -> None:
    from backend.services.observability.event_store import ProjectEventStore
    from backend.services.observability.event_stream import ProjectEventStream

    store = ProjectEventStore(tmp_path)
    events = ProjectEventStream(store)

    async def receive():
        stream = events.stream(7, -1)
        waiting = asyncio.create_task(anext(stream))
        await asyncio.sleep(0)
        await store.append(7, "activity", {"message": "created"})
        try:
            return await asyncio.wait_for(waiting, 1)
        finally:
            await stream.aclose()

    assert "event: activity" in run(receive())


def test_event_log_read_stays_bounded_and_at_record_boundaries(tmp_path: Path, monkeypatch) -> None:
    from backend.services.observability import event_store
    from backend.services.observability.event_store import ProjectEventStore

    monkeypatch.setattr(event_store, "EVENT_RESPONSE_MAX_BYTES", 500)
    store = ProjectEventStore(tmp_path)
    first = run(store.append(7, "activity", {"message": "a" * 100}))
    second = run(store.append(7, "activity", {"message": "b" * 100}))
    third = run(store.append(7, "activity", {"message": "c" * 100}))

    page = run(store.read(7, "activity", -1, 20))
    assert [event.id for event in page] == [first.id, second.id]
    assert [event.id for event in run(store.read(7, "activity", page[-1].id, 20))] == [third.id]


def test_oversized_newline_free_record_is_rejected_without_an_unbounded_read(tmp_path: Path, monkeypatch) -> None:
    from backend.services.observability import event_store
    from backend.services.observability.event_store import CorruptEventLog, ProjectEventStore

    monkeypatch.setattr(event_store, "EVENT_RECORD_MAX_BYTES", 32)
    path = tmp_path / "projects/7/logs"
    path.mkdir(parents=True)
    (path / "activity.jsonl").write_bytes(b"x" * 33)
    original = event_store.os.fdopen

    class BoundedFile:
        def __init__(self, file): self._file = file
        def __enter__(self): return self
        def __exit__(self, *args): return self._file.close()
        def readline(self, size=-1):
            assert size != -1
            return self._file.readline(size)
        def __getattr__(self, name): return getattr(self._file, name)

    monkeypatch.setattr(event_store.os, "fdopen", lambda *args, **kwargs: BoundedFile(original(*args, **kwargs)))
    with pytest.raises(CorruptEventLog, match="corrupt"):
        run(ProjectEventStore(tmp_path).read(7, "activity", -1, 20))


def test_mid_record_cursor_is_rejected_instead_of_discarding_data(tmp_path: Path) -> None:
    from backend.services.observability.event_store import InvalidEventCursor, ProjectEventStore

    store = ProjectEventStore(tmp_path)
    first = run(store.append(7, "activity", {"message": "one"}))
    run(store.append(7, "activity", {"message": "two"}))

    with pytest.raises(InvalidEventCursor, match="cursor"):
        run(store.read(7, "activity", first.id + 1, 20))
    assert run(store.read(7, "activity", -1, 20))[0].id == first.id
    assert run(store.read(7, "activity", first.id, 20))[0].payload["message"] == "two"


def test_empty_event_log_accepts_only_initial_or_exact_eof_cursor(tmp_path: Path) -> None:
    from backend.services.observability.event_store import InvalidEventCursor, ProjectEventStore

    store = ProjectEventStore(tmp_path)

    assert run(store.read(7, "events", -1, 20)) == []
    assert run(store.read(7, "events", 0, 20)) == []
    with pytest.raises(InvalidEventCursor, match="cursor"):
        run(store.read(7, "events", 1, 20))


def test_nonempty_event_log_rejects_cursor_beyond_exact_eof(tmp_path: Path) -> None:
    from backend.services.observability.event_store import InvalidEventCursor, ProjectEventStore

    store = ProjectEventStore(tmp_path)
    run(store.append(7, "events", {"name": "project"}))
    size = store.path_for(7, "events").stat().st_size

    assert run(store.read(7, "events", size, 20)) == []
    with pytest.raises(InvalidEventCursor, match="cursor"):
        run(store.read(7, "events", size + 1, 20))


def test_cursor_boundary_validation_reads_constant_bytes_not_prior_records(tmp_path: Path, monkeypatch) -> None:
    from backend.services.observability import event_store
    from backend.services.observability.event_store import ProjectEventStore

    store = ProjectEventStore(tmp_path)
    records = [run(store.append(7, "activity", {"message": str(number)})) for number in range(80)]
    calls = []
    original = event_store.os.fdopen

    class CountingFile:
        def __init__(self, file): self._file = file
        def __enter__(self): return self
        def __exit__(self, *args): return self._file.close()
        def read(self, size=-1):
            calls.append(("read", size))
            return self._file.read(size)
        def readline(self, size=-1):
            calls.append(("readline", size))
            return self._file.readline(size)
        def __getattr__(self, name): return getattr(self._file, name)

    monkeypatch.setattr(event_store.os, "fdopen", lambda *args, **kwargs: CountingFile(original(*args, **kwargs)))
    assert run(store.read(7, "activity", records[-1].id, 20)) == []
    assert calls.count(("read", 1)) == 1
    assert sum(1 for name, _ in calls if name == "readline") <= 2


def test_activity_and_debug_query_routes_exclude_internal_events(tmp_path: Path) -> None:
    from backend.api.controllers.events import get_project_log
    from backend.services.observability.event_store import ProjectEventStore

    store = ProjectEventStore(tmp_path)
    run(store.append(7, "activity", {"repository_token": "secret", "message": "created"}))
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(services=SimpleNamespace(
        projects=SimpleNamespace(get=AsyncMock(return_value=object())), observability=store,
    ))))
    activity = run(get_project_log(7, "activity", request, -1, 100))

    with pytest.raises(HTTPException) as error:
        run(get_project_log(7, "events", request, -1, 100))

    assert activity.events[0].payload["repository_token"] == "[REDACTED]"
    assert error.value.status_code == 422


def test_sse_rejects_an_invalid_last_event_id() -> None:
    from backend.api.controllers.projects import project_events

    request = SimpleNamespace(
        headers={"last-event-id": "not-an-offset"},
        app=SimpleNamespace(state=SimpleNamespace(services=SimpleNamespace(
            projects=SimpleNamespace(get=AsyncMock(return_value=object())), events=object(),
        ))),
    )

    with pytest.raises(HTTPException) as error:
        run(project_events(7, request))
    assert error.value.status_code == 422


def test_sse_rejects_a_mid_record_last_event_id(tmp_path: Path) -> None:
    from backend.api.controllers.projects import project_events
    from backend.services.observability.event_store import ProjectEventStore
    from backend.services.observability.event_stream import ProjectEventStream

    store = ProjectEventStore(tmp_path)
    first = run(store.append(7, "activity", {"message": "one"}))
    event_id = run(store.read(7, "events", -1, 1))[0].id
    request = SimpleNamespace(
        headers={"last-event-id": str(event_id + 1)},
        app=SimpleNamespace(state=SimpleNamespace(services=SimpleNamespace(
            projects=SimpleNamespace(get=AsyncMock(return_value=object())), events=ProjectEventStream(store), observability=store,
        ))),
    )

    with pytest.raises(HTTPException) as error:
        run(project_events(7, request))
    assert first.id == 0
    assert error.value.status_code == 422
