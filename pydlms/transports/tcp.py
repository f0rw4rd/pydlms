"""TCP and UDP transports (blocking sockets)."""

from __future__ import annotations

import select
import socket

from pydlms.debug import get_logger
from pydlms.exceptions import TransportError
from pydlms.transports.base import Transport

__all__ = ["TcpTransport", "UdpTransport"]

log = get_logger("transport")


class TcpTransport(Transport):
    """A TCP client connection (default DLMS port 4059)."""

    def __init__(
        self, host: str, port: int = 4059, timeout: float = 10.0, connect_timeout: float = 10.0
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self._sock: socket.socket | None = None

    @property
    def description(self) -> str:
        return f"tcp://{self.host}:{self.port}"

    def open(self) -> None:
        if self._sock is not None:
            return
        log.debug("connecting to %s", self.description)
        try:
            sock = socket.create_connection((self.host, self.port), self.connect_timeout)
        except OSError as exc:
            raise TransportError(f"cannot connect to {self.description}: {exc}") from exc
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._sock = sock
        log.info("connected to %s", self.description)

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None
                log.debug("closed %s", self.description)

    def _require(self) -> socket.socket:
        if self._sock is None:
            raise TransportError(f"{self.description} is not open")
        return self._sock

    def _write(self, data: bytes) -> None:
        try:
            self._require().sendall(data)
        except OSError as exc:
            raise TransportError(f"send to {self.description} failed: {exc}") from exc

    def _read(self, max_bytes: int, timeout: float) -> bytes:
        sock = self._require()
        ready, _, _ = select.select([sock], [], [], max(timeout, 0))
        if not ready:
            return b""
        try:
            data = sock.recv(max_bytes)
        except OSError as exc:
            raise TransportError(f"receive from {self.description} failed: {exc}") from exc
        if not data:
            raise TransportError(f"{self.description} closed the connection")
        return data


class UdpTransport(Transport):
    """A connected UDP socket; each datagram carries one wrapper PDU."""

    def __init__(self, host: str, port: int = 4059, timeout: float = 10.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock: socket.socket | None = None
        self._buffer = bytearray()

    @property
    def description(self) -> str:
        return f"udp://{self.host}:{self.port}"

    def open(self) -> None:
        if self._sock is None:
            family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.connect((self.host, self.port))
            self._sock = sock

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def _write(self, data: bytes) -> None:
        if self._sock is None:
            raise TransportError(f"{self.description} is not open")
        self._sock.send(data)

    def recv_datagram(self, timeout: float | None = None) -> bytes:
        """Receive one whole datagram (what is left of a partly read one
        first), keeping the boundary the wrapper length is checked against."""
        if self._buffer:
            data = bytes(self._buffer)
            self._buffer.clear()
            return data
        return self.recv(65535, timeout)

    def _read(self, max_bytes: int, timeout: float) -> bytes:
        if not self._buffer:
            if self._sock is None:
                raise TransportError(f"{self.description} is not open")
            ready, _, _ = select.select([self._sock], [], [], max(timeout, 0))
            if not ready:
                return b""
            try:
                self._buffer += self._sock.recv(65535)
            except OSError as exc:
                raise TransportError(f"receive from {self.description} failed: {exc}") from exc
        chunk = bytes(self._buffer[:max_bytes])
        del self._buffer[:max_bytes]
        return chunk
