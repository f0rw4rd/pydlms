"""Transport interface: a byte stream with timeouts.

Framing layers (HDLC, the TCP/UDP wrapper, M-Bus) sit on top of a
:class:`Transport`. A transport only moves octets; it knows nothing about
frames. Every transport logs TX/RX hexdumps at :data:`pydlms.debug.TRACE` on
the ``pydlms.transport`` logger and feeds an optional
:class:`~pydlms.debug.FrameRecorder`.
"""

from __future__ import annotations

import abc
import time

from pydlms.debug import TRACE, FrameRecorder, get_logger, hexdump
from pydlms.exceptions import DlmsTimeoutError

__all__ = ["Transport", "LoopbackTransport"]

log = get_logger("transport")


class Transport(abc.ABC):
    """Abstract byte-stream transport."""

    #: Default receive timeout in seconds.
    timeout: float = 10.0
    recorder: FrameRecorder | None = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()

    @abc.abstractmethod
    def open(self) -> None: ...

    @abc.abstractmethod
    def close(self) -> None: ...

    @abc.abstractmethod
    def _write(self, data: bytes) -> None: ...

    @abc.abstractmethod
    def _read(self, max_bytes: int, timeout: float) -> bytes:
        """Return 1..max_bytes octets, or ``b""`` if the timeout elapsed."""

    @property
    def description(self) -> str:
        return type(self).__name__

    def send(self, data: bytes) -> None:
        if log.isEnabledFor(TRACE):
            log.log(TRACE, "TX %d bytes via %s\n%s", len(data), self.description, hexdump(data))
        if self.recorder is not None:
            self.recorder.record("TX", data)
        self._write(bytes(data))

    def recv(self, max_bytes: int = 4096, timeout: float | None = None) -> bytes:
        """Receive at least one octet or raise :class:`DlmsTimeoutError`."""
        timeout = self.timeout if timeout is None else timeout
        data = self._read(max_bytes, timeout)
        if not data:
            raise DlmsTimeoutError(f"no data from {self.description} within {timeout:.1f}s")
        if log.isEnabledFor(TRACE):
            log.log(TRACE, "RX %d bytes via %s\n%s", len(data), self.description, hexdump(data))
        if self.recorder is not None:
            self.recorder.record("RX", data)
        return data

    def recv_exact(self, n: int, timeout: float | None = None) -> bytes:
        """Receive exactly ``n`` octets within an overall ``timeout``."""
        timeout = self.timeout if timeout is None else timeout
        deadline = time.monotonic() + timeout
        out = bytearray()
        while len(out) < n:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DlmsTimeoutError(
                    f"{self.description}: got {len(out)} of {n} octets within {timeout:.1f}s"
                )
            try:
                out += self.recv(n - len(out), remaining)
            except DlmsTimeoutError:
                raise DlmsTimeoutError(
                    f"{self.description}: got {len(out)} of {n} octets within {timeout:.1f}s"
                ) from None
        return bytes(out)


class LoopbackTransport(Transport):
    """In-memory transport for tests and offline replay.

    ``responder`` is called with every sent buffer and returns the bytes the
    "meter" answers with (or ``b""``). Bytes queued with :meth:`inject` are
    delivered before any responder output.
    """

    def __init__(self, responder=None, timeout: float = 0.5) -> None:
        self.responder = responder
        self.timeout = timeout
        self._rx = bytearray()
        self.sent: list[bytes] = []
        self.is_open = False

    def open(self) -> None:
        self.is_open = True

    def close(self) -> None:
        self.is_open = False

    def inject(self, data: bytes) -> None:
        self._rx += data

    def _write(self, data: bytes) -> None:
        self.sent.append(data)
        if self.responder is not None:
            answer = self.responder(data)
            if answer:
                self._rx += answer

    def _read(self, max_bytes: int, timeout: float) -> bytes:
        if not self._rx:
            return b""
        chunk = bytes(self._rx[:max_bytes])
        del self._rx[:max_bytes]
        return chunk
