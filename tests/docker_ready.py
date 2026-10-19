"""Readiness of a server behind a Docker published port.

Docker's userland proxy accepts a connection on the host port before the
process in the container listens, then closes it at once when it cannot reach
the backend. So "connect() succeeded" proves nothing: right after the Gurux
simulator prints its start banner, the first one or two connections (about
0.1 to 0.4 s, longer under load) are closed with EOF while later ones are held
(measured 2026-10-17). A test that connects in that window sees a reset.

:func:`wait_listening` therefore waits until a connection stays open: the
server is listening once the proxy keeps the connection for ``hold`` seconds
(or the server sends something), instead of dropping it.
"""

from __future__ import annotations

import socket
import time

import pytest

__all__ = ["listening", "wait_listening"]


def listening(port: int, host: str = "127.0.0.1", hold: float = 0.3) -> bool:
    """True when a connection to ``host:port`` is kept open, not dropped."""
    try:
        conn = socket.create_connection((host, port), timeout=2)
    except OSError:
        return False
    try:
        conn.settimeout(hold)
        try:
            return conn.recv(1) != b""  # data: the server talks, so it listens
        except TimeoutError:
            return True  # held open: the backend accepted it
        except OSError:
            return False  # reset by the proxy
    finally:
        conn.close()


def wait_listening(port: int, what: str = "server", timeout: float = 60.0) -> None:
    """Block until :func:`listening` holds twice in a row, else fail the test."""
    deadline = time.monotonic() + timeout
    held = 0
    while time.monotonic() < deadline:
        held = held + 1 if listening(port) else 0
        if held >= 2:
            return
        time.sleep(0.1)
    pytest.fail(f"{what} on port {port} never kept a connection open")
