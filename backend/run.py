"""Start BigEye's host API and production frontend on loopback."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from threading import Event, Thread
from time import monotonic, sleep
import webbrowser

import uvicorn


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("port must be an integer") from error
    if not 1 <= port <= 65_535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run BigEye on the local host.")
    parser.add_argument("--port", type=_port, default=8000, help="loopback port (default: 8000)")
    parser.add_argument(
        "--no-browser", action="store_true",
        help="do not open the product URL; suitable for Linux servers and CI",
    )
    return parser


def wait_for(predicate: Callable[[], bool], timeout: float) -> bool:
    """Wait briefly for a local state transition without busy-spinning."""
    deadline = monotonic() + timeout
    while monotonic() < deadline:
        if predicate():
            return True
        sleep(0.01)
    return predicate()


def _open_after_readiness(server, url: str, stopped: Event) -> None:
    while not stopped.wait(0.05):
        if server.started:
            webbrowser.open(url)
            return


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    url = f"http://127.0.0.1:{arguments.port}/"
    config = uvicorn.Config(
        "backend.api.app:app",
        host="127.0.0.1",
        port=arguments.port,
        reload=False,
    )
    server = uvicorn.Server(config)
    stopped = Event()
    opener = None
    if not arguments.no_browser:
        opener = Thread(
            target=_open_after_readiness,
            args=(server, url, stopped),
            name="bigeye-browser-opener",
            daemon=True,
        )
        opener.start()
    try:
        try:
            server.run()
        except KeyboardInterrupt:
            pass
    finally:
        stopped.set()
        if opener is not None:
            opener.join(timeout=1.0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
