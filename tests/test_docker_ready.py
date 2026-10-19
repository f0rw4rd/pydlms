"""The readiness probe tells a held connection from one closed at once."""

from __future__ import annotations

import socket
import threading

from tests.docker_ready import listening


def _server(hold: bool) -> tuple[socket.socket, threading.Event, threading.Thread]:
    srv = socket.create_server(("127.0.0.1", 0))
    stop = threading.Event()

    def run() -> None:
        srv.settimeout(0.1)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except TimeoutError:
                continue
            if hold:
                stop.wait(1.0)
            conn.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return srv, stop, thread


def _shutdown(srv: socket.socket, stop: threading.Event, thread: threading.Thread) -> None:
    # Join before closing: closing the socket under a blocked accept()
    # raises in the thread, and pytest reports it against a later test.
    stop.set()
    thread.join()
    srv.close()


def test_held_connection_is_listening():
    srv, stop, thread = _server(hold=True)
    try:
        assert listening(srv.getsockname()[1], hold=0.2)
    finally:
        _shutdown(srv, stop, thread)


def test_connection_closed_at_once_is_not_listening():
    # What Docker's proxy does before the container's server listens.
    srv, stop, thread = _server(hold=False)
    try:
        assert not listening(srv.getsockname()[1], hold=0.5)
    finally:
        _shutdown(srv, stop, thread)


def test_refused_port_is_not_listening():
    srv = socket.create_server(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.close()
    assert not listening(port)
