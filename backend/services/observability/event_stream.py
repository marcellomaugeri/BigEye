"""Resumable SSE rendering of durable project invalidations."""

import asyncio


class ProjectEventStream:
    def __init__(self, store):
        self._store = store
        self._signals: dict[int, set[asyncio.Event]] = {}
        store.subscribe(self._notify)

    def _subscribe(self, project_id: int) -> asyncio.Event:
        signal = asyncio.Event()
        self._signals.setdefault(project_id, set()).add(signal)
        return signal

    def _unsubscribe(self, project_id: int, signal: asyncio.Event) -> None:
        signals = self._signals.get(project_id)
        if signals is None:
            return
        signals.discard(signal)
        if not signals:
            self._signals.pop(project_id, None)

    def _notify(self, project_id: int) -> None:
        for signal in tuple(self._signals.get(project_id, ())):
            signal.set()

    async def stream(self, project_id: int, after: int = -1):
        signal = self._subscribe(project_id)
        cursor = after
        try:
            while True:
                events = await self._store.read(project_id, "events", cursor, 1000)
                for event in events:
                    cursor = event.id
                    yield self.frame(event)
                await signal.wait()
                signal.clear()
        finally:
            self._unsubscribe(project_id, signal)

    @staticmethod
    def frame(event) -> str:
        return f"id: {event.id}\nevent: {event.payload['name']}\ndata: invalidated\n\n"
