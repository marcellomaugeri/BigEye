"""Resumable SSE rendering of durable project invalidations."""

import asyncio
import threading

from backend.services.observability.event_store import CorruptEventLog, InvalidEventCursor


class ProjectEventStream:
    def __init__(self, store):
        self._store = store
        self._signals: dict[int, set[tuple[asyncio.AbstractEventLoop, asyncio.Event]]] = {}
        self._signals_lock = threading.Lock()
        store.subscribe(self._notify)

    def _subscribe(self, project_id: int) -> asyncio.Event:
        signal = asyncio.Event()
        with self._signals_lock:
            self._signals.setdefault(project_id, set()).add((asyncio.get_running_loop(), signal))
        return signal

    def _unsubscribe(self, project_id: int, signal: asyncio.Event) -> None:
        with self._signals_lock:
            signals = self._signals.get(project_id)
            if signals is None:
                return
            signals = {(loop, item) for loop, item in signals if item is not signal}
            if signals:
                self._signals[project_id] = signals
            else:
                self._signals.pop(project_id, None)

    def _notify(self, project_id: int) -> None:
        with self._signals_lock:
            signals = tuple(self._signals.get(project_id, ()))
        for loop, signal in signals:
            if not loop.is_closed():
                loop.call_soon_threadsafe(signal.set)

    async def stream(self, project_id: int, after: int = -1):
        signal = self._subscribe(project_id)
        cursor = after
        try:
            while True:
                try:
                    events = await self._store.read(project_id, "events", cursor, 1000)
                except (CorruptEventLog, InvalidEventCursor):
                    return
                emitted = False
                for event in events:
                    cursor = event.id
                    emitted = True
                    yield self.frame(event)
                if emitted:
                    continue
                if events.next_offset != cursor:
                    cursor = events.next_offset
                    continue
                await signal.wait()
                signal.clear()
        finally:
            self._unsubscribe(project_id, signal)

    @staticmethod
    def frame(event) -> str:
        return f"id: {event.id}\nevent: {event.payload['name']}\ndata: invalidated\n\n"
