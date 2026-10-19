"""The APDU link interface every framing layer implements.

An :class:`ApduLink` moves whole xDLMS/ACSE APDUs: it hides HDLC sequencing
and segmentation, wrapper headers or M-Bus reassembly from the association
layer above it.
"""

from __future__ import annotations

import abc
from collections import deque
from dataclasses import dataclass
from typing import Any

from pydlms.debug import get_logger, hexstr
from pydlms.exceptions import ProtocolError

__all__ = ["ApduLink", "QueuedPush", "MAX_QUEUED_PUSHES"]

log = get_logger("link")

#: Library limit on pushes held back while a response is awaited; when it is
#: reached the oldest push is dropped (and counted in ``dropped_pushes``).
MAX_QUEUED_PUSHES = 32


@dataclass(frozen=True)
class QueuedPush:
    """An unsolicited APDU held for :meth:`ApduLink.receive_push`.

    ``apdu`` is what the link received, unless the association already
    deciphered it while waiting for a response: then ``apdu`` is the
    plaintext and ``unwrapped`` the :class:`~pydlms.security.ciphering.CipheredApdu`
    with its system title, invocation counter and authentication verdict.
    Such a push must not be deciphered again: the inbound invocation counter
    has already advanced past it. ``checked`` marks a push the association
    has already put through its security checks (plaintext pushes included).
    """

    apdu: bytes
    unwrapped: Any = None
    checked: bool = False

    def __repr__(self) -> str:
        state = (
            "deciphered"
            if self.unwrapped is not None
            else ("checked" if self.checked else "as received")
        )
        return f"QueuedPush({hexstr(self.apdu, 16)}, {state})"


class ApduLink(abc.ABC):
    """Abstract request/response + push link for APDUs."""

    #: Largest APDU the peer accepts in one link-layer unit, when known.
    max_apdu: int | None = None
    #: Client SAP used by the link (wrapper wPort / HDLC client address).
    client_sap: int = 16

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.disconnect()

    @abc.abstractmethod
    def connect(self) -> None:
        """Open the transport and set up the link (e.g. HDLC SNRM/UA)."""

    @abc.abstractmethod
    def disconnect(self) -> None:
        """Tear the link down (e.g. HDLC DISC) and close the transport."""

    @abc.abstractmethod
    def send_apdu(self, apdu: bytes) -> None: ...

    @abc.abstractmethod
    def receive_apdu(self, timeout: float | None = None) -> bytes: ...

    # -- pushes ------------------------------------------------------------------
    def push_queue(self) -> deque[QueuedPush]:
        """The queue of pushes held back during requests (created on first use,
        so subclasses need not call an ``__init__`` here)."""
        queue = self.__dict__.get("_pushes")
        if queue is None:
            queue = self.__dict__["_pushes"] = deque(maxlen=MAX_QUEUED_PUSHES)
        return queue

    @property
    def dropped_pushes(self) -> int:
        """Pushes dropped because the queue was full."""
        return self.__dict__.get("_dropped_pushes", 0)

    def queue_push(self, apdu: bytes, unwrapped: Any = None, checked: bool = False) -> None:
        """Hold an unsolicited APDU that arrived while a response was awaited.

        ``unwrapped`` is the deciphering result when ``apdu`` is the
        plaintext of a ciphered push, ``checked`` that the association
        checked it (see :class:`QueuedPush`). A full queue drops its oldest
        push.
        """
        queue = self.push_queue()
        if len(queue) == queue.maxlen:
            self.__dict__["_dropped_pushes"] = self.dropped_pushes + 1
            log.warning("push queue full (%d); dropping the oldest push", len(queue))
        log.debug("queued a %d-octet push received while awaiting a response", len(apdu))
        queue.append(QueuedPush(bytes(apdu), unwrapped, checked or unwrapped is not None))

    def clear_pushes(self) -> None:
        self.push_queue().clear()

    def receive_queued_push(self, timeout: float | None = None) -> QueuedPush:
        """Return the next push: a queued one first, else the next one the
        link receives (:meth:`_receive_unsolicited`)."""
        queue = self.push_queue()
        if queue:
            return queue.popleft()
        return QueuedPush(self._receive_unsolicited(timeout))

    def receive_push(self, timeout: float | None = None) -> bytes:
        """Return the next unsolicited APDU (push, event notification).

        Pushes queued during a request come first. A push the association
        deciphered comes back as plaintext; use :meth:`receive_queued_push`
        to keep its security verdict.
        """
        return self.receive_queued_push(timeout).apdu

    def _receive_unsolicited(self, timeout: float | None) -> bytes:
        """Wait for a push on the link. Links that can tell pushes from
        responses (HDLC UI frames, wrapper push wPorts) override this; the
        default is :meth:`receive_apdu`."""
        return self.receive_apdu(timeout)

    def send_unconfirmed(self, apdu: bytes, broadcast: bool = False) -> None:
        """Send an APDU no answer is expected for (an unconfirmed service).

        Nothing is read and no response is awaited. ``broadcast`` sends to
        every server on the link (the all-station address); links without
        one raise :class:`~pydlms.exceptions.ProtocolError`. Links with a
        dedicated frame for it (HDLC UI, a broadcast wPort) override this;
        the default is :meth:`send_apdu`.
        """
        if broadcast:
            raise ProtocolError(f"{type(self).__name__} has no broadcast address")
        self.send_apdu(apdu)

    def request(self, apdu: bytes, timeout: float | None = None) -> bytes:
        """Send ``apdu`` and return the next APDU the peer sends."""
        self.send_apdu(apdu)
        return self.receive_apdu(timeout)
