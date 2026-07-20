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


def test_exact_public_event_read_uses_the_durable_record_offset(tmp_path: Path) -> None:
    from backend.services.observability.event_store import ProjectEventStore

    store = ProjectEventStore(tmp_path)
    run(store.append(7, "debug", {"evidence_id": "replay:old"}))
    retained = run(store.append(7, "debug", {"evidence_id": "replay:clean"}))

    exact = run(store.read_exact(7, "debug", retained.id))

    assert exact == retained


def test_exact_event_read_rejects_non_boundary_wrong_stream_and_missing_offsets(tmp_path: Path) -> None:
    from backend.services.observability.event_store import InvalidEventCursor, ProjectEventStore

    store = ProjectEventStore(tmp_path)
    retained = run(store.append(7, "activity", {"evidence_id": "coverage:parser:42"}))

    with pytest.raises(InvalidEventCursor):
        run(store.read_exact(7, "activity", retained.id + 1))
    with pytest.raises(ValueError, match="public"):
        run(store.read_exact(7, "events", retained.id))
    with pytest.raises(KeyError):
        run(store.read_exact(8, "activity", retained.id))


def test_evidence_lookup_returns_only_exact_retained_public_records(tmp_path: Path) -> None:
    from backend.services.observability.event_store import ProjectEventStore

    store = ProjectEventStore(tmp_path)
    activity = run(store.append(7, "activity", {
        "evidence_ids": ["coverage:parser:42", "shared:evidence"],
    }))
    debug = run(store.append(7, "debug", {
        "outcomes": [{"evidence_id": "replay:clean"}, {"evidence_id": "shared:evidence"}],
    }))

    located = run(store.locate_evidence(7, [
        "coverage:parser:42", "replay:clean", "shared:evidence", "not-retained",
    ]))

    assert located["coverage:parser:42"] == activity
    assert located["replay:clean"] == debug
    assert located["shared:evidence"] == debug
    assert "not-retained" not in located


def test_evidence_lookup_pages_to_an_old_retained_record_without_a_total_scan_cutoff(
    tmp_path: Path, monkeypatch,
) -> None:
    from backend.services.observability import event_store
    from backend.services.observability.event_store import ProjectEventStore

    monkeypatch.setattr(event_store.os, "fsync", lambda _descriptor: None)
    store = ProjectEventStore(tmp_path)
    retained = store.append_sync(7, "activity", {"evidence_id": "old:retained"})
    for index in range(1_001):
        store.append_sync(7, "activity", {"evidence_id": f"newer:{index}"})

    located = run(store.locate_evidence(7, ["old:retained"]))

    assert located["old:retained"] == retained


def test_evidence_lookup_prefers_the_scalar_owner_over_a_newer_reference(tmp_path: Path) -> None:
    from backend.services.observability.event_store import ProjectEventStore

    store = ProjectEventStore(tmp_path)
    owner = run(store.append(7, "debug", {"evidence_id": "replay:owned"}))
    run(store.append(7, "activity", {"evidence_ids": ["replay:owned"]}))
    run(store.append(7, "debug", {"outcomes": [{"evidence_id": "replay:owned"}]}))

    located = run(store.locate_evidence(7, ["replay:owned"]))

    assert located["replay:owned"] == owner


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
        "safe_key": "credential-shaped", "monkey": "visible", "secretary": "visible",
    })

    assert value == {
        "OPENAI_API_KEY": "[REDACTED]", "X-Api-Key": "[REDACTED]", "AWS_SECRET_ACCESS_KEY": "[REDACTED]",
        "nested": [{"Authorization": "[REDACTED]", "repository_token": "[REDACTED]"}],
        "credentials": "[REDACTED]", "safe_key": "[REDACTED]", "monkey": "visible", "secretary": "visible",
    }


def test_redaction_removes_credential_shaped_names_and_values() -> None:
    from backend.services.observability.redaction import redact

    value = redact({
        "GITHUB_PAT": "github-secret",
        "AWS_ACCESS_KEY_ID": "aws-secret",
        "DATABASE_URL": "postgresql://user:password@db/bigeye",
        "authentication": "Bearer bearer-secret",
        "signing_material": "-----BEGIN PRIVATE KEY-----\nprivate-secret",
        "BIGEYE_MODE": "encrypted",
        "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=1",
    })

    assert value == {
        "GITHUB_PAT": "[REDACTED]",
        "AWS_ACCESS_KEY_ID": "[REDACTED]",
        "DATABASE_URL": "[REDACTED]",
        "authentication": "[REDACTED]",
        "signing_material": "[REDACTED]",
        "BIGEYE_MODE": "encrypted",
        "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=1",
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


def test_event_stream_replays_preexisting_backlog_beyond_one_page_without_new_append(tmp_path: Path) -> None:
    from backend.services.observability.event_store import ProjectEventStore
    from backend.services.observability.event_stream import ProjectEventStream

    store = ProjectEventStore(tmp_path)
    durable = [store.append_sync(7, "events", {"name": "project"}) for _ in range(1001)]
    events = ProjectEventStream(store)

    async def replay():
        stream = events.stream(7, -1)
        try:
            frames = [await anext(stream) for _ in range(1001)]
            return frames[-1]
        finally:
            await stream.aclose()

    last = run(asyncio.wait_for(replay(), 2))
    assert f"id: {durable[-1].id}" in last


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


def test_existing_empty_events_file_does_not_advance_initial_sse_cursor(tmp_path: Path) -> None:
    from backend.services.observability.event_store import ProjectEventStore
    from backend.services.observability.event_stream import ProjectEventStream

    path = tmp_path / "projects/7/logs"
    path.mkdir(parents=True)
    (path / "events.jsonl").write_bytes(b"")
    store = ProjectEventStore(tmp_path)
    events = ProjectEventStream(store)

    async def receive():
        stream = events.stream(7, -1)
        waiting = asyncio.create_task(anext(stream))
        await asyncio.sleep(0)
        await store.append(7, "activity", {"message": "first"})
        try:
            return await asyncio.wait_for(waiting, 1)
        finally:
            await stream.aclose()

    assert "event: activity" in run(receive())


@pytest.mark.parametrize("stream", ["activity", "debug"])
def test_page_cursor_at_eof_still_receives_a_later_append(tmp_path: Path, stream: str) -> None:
    from backend.services.observability.event_store import ProjectEventStore

    store = ProjectEventStore(tmp_path)
    first = run(store.append(7, stream, {"message": "first"}))
    page = run(store.read(7, stream, -1, 20))
    second = run(store.append(7, stream, {"message": "second"}))

    assert page.next_offset == first.id
    later = run(store.read(7, stream, page.next_offset, 20))
    assert [event.id for event in later] == [second.id]
    assert [event.payload["message"] for event in later] == ["second"]


def test_public_event_pages_are_newest_first_and_page_towards_older_records(tmp_path: Path) -> None:
    from backend.services.observability.event_store import ProjectEventStore

    store = ProjectEventStore(tmp_path)
    first = run(store.append(7, "activity", {"message": "first"}))
    second = run(store.append(7, "activity", {"message": "second"}))
    third = run(store.append(7, "activity", {"message": "third"}))

    newest = run(store.read_latest(7, "activity", -1, 2))
    older = run(store.read_latest(7, "activity", newest.next_offset, 2))

    assert [event.id for event in newest] == [third.id, second.id]
    assert newest.has_more is True
    assert newest.next_offset == second.id
    assert [event.id for event in older] == [first.id]
    assert older.has_more is False
    assert older.next_offset == 0


def test_public_event_page_refresh_restarts_at_the_newest_record(tmp_path: Path) -> None:
    from backend.services.observability.event_store import ProjectEventStore

    store = ProjectEventStore(tmp_path)
    run(store.append(7, "debug", {"message": "first"}))
    initial = run(store.read_latest(7, "debug", -1, 100))
    latest = run(store.append(7, "debug", {"message": "latest"}))

    refreshed = run(store.read_latest(7, "debug", -1, 100))

    assert [event.id for event in initial] != [event.id for event in refreshed]
    assert refreshed[0].id == latest.id


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


@pytest.mark.parametrize("raw", [
    b"{not-json}\n",
    b'{"id":0,"created_at":"not-a-time","stream":"activity","payload":{}}\n',
    b'{"id":0}\n',
    b'{"id":0,"created_at":"2026-07-19T00:00:00+00:00","stream":"debug","payload":{}}\n',
])
def test_every_examined_record_charges_the_bounded_scan_budget(tmp_path: Path, monkeypatch, raw: bytes) -> None:
    from backend.services.observability import event_store
    from backend.services.observability.event_store import ProjectEventStore

    valid = b'{"id":0,"created_at":"2026-07-19T00:00:00+00:00","stream":"activity","payload":{"message":"ok"}}\n'
    monkeypatch.setattr(event_store, "EVENT_RESPONSE_MAX_BYTES", max(len(raw) * 2, len(raw) + len(valid)))
    path = tmp_path / "projects/7/logs"
    path.mkdir(parents=True)
    (path / "activity.jsonl").write_bytes(raw * 3 + valid)

    store = ProjectEventStore(tmp_path)
    page = run(store.read(7, "activity", -1, 20))

    assert page == []
    assert page.next_offset in {len(raw), len(raw) * 2}
    for _ in range(3):
        page = run(store.read(7, "activity", page.next_offset, 20))
        if page:
            break
    assert [event.payload for event in page] == [{"message": "ok"}]


def test_valid_record_after_a_wrong_stream_record_is_still_returned(tmp_path: Path) -> None:
    from backend.services.observability.event_store import ProjectEventStore

    wrong = b'{"id":0,"created_at":"2026-07-19T00:00:00+00:00","stream":"debug","payload":{}}\n'
    valid = b'{"id":90,"created_at":"2026-07-19T00:00:00+00:00","stream":"activity","payload":{"message":"ok"}}\n'
    path = tmp_path / "projects/7/logs"
    path.mkdir(parents=True)
    (path / "activity.jsonl").write_bytes(wrong + valid)

    records = run(ProjectEventStore(tmp_path).read(7, "activity", -1, 20))

    assert [event.payload for event in records] == [{"message": "ok"}]


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
    assert activity.has_more is False
    assert error.value.status_code == 422


def test_exact_public_event_route_returns_the_requested_retained_record(tmp_path: Path) -> None:
    from backend.api.controllers.events import get_project_event
    from backend.services.observability.event_store import ProjectEventStore

    store = ProjectEventStore(tmp_path)
    retained = run(store.append(7, "debug", {"evidence_id": "replay:clean"}))
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(services=SimpleNamespace(
        projects=SimpleNamespace(get=AsyncMock(return_value=object())), observability=store,
    ))))

    response = run(get_project_event(7, "debug", retained.id, request))

    assert response.id == retained.id
    assert response.stream == "debug"
    assert response.payload == {"evidence_id": "replay:clean"}


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
