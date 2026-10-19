"""DLMS/COSEM TCP-UDP wrapper (IEC 62056-47 / 62056-9-7).

Every APDU is prefixed with an 8-octet header, all big-endian::

    version(0x0001) | source wPort(2) | destination wPort(2) | length(2)

followed by ``length`` APDU octets. wPorts are the DLMS SAPs of the client
and of the server logical device; the reserved values are the ``WPORT_*``
constants below. Over TCP the header is how a receiver re-assembles an APDU
split across reads.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from dataclasses import dataclass

import construct
from construct import Bytes, Const, Int16ub, Struct, this

from pydlms.debug import TRACE, get_logger, hexstr
from pydlms.exceptions import DlmsTimeoutError, FramingError
from pydlms.link import ApduLink
from pydlms.transports.base import Transport

__all__ = [
    "WRAPPER_VERSION",
    "WPORT_MANAGEMENT_CLIENT",
    "WPORT_PUBLIC_CLIENT",
    "WPORT_MANAGEMENT_LOGICAL_DEVICE",
    "WPORT_BROADCAST",
    "WrapperHeader",
    "WrapperFrame",
    "WrapperPdu",
    "encode_wrapper",
    "decode_wrapper",
    "WrapperLink",
]

log = get_logger("wrapper")

WRAPPER_VERSION = 0x0001
HEADER_SIZE = 8

# Reserved wPort numbers, IEC 62056-47:2006 "reserved wrapper port numbers"
# table (carried over unchanged into IEC 62056-9-7 and the Green Book's
# TCP-UDP transport layer clause). Client side and server side are separate
# number spaces, which is why 0x0001 appears twice.
#: Client management process (client side).
WPORT_MANAGEMENT_CLIENT = 0x0001
#: Public client (client side); every logical device must accept it.
WPORT_PUBLIC_CLIENT = 0x0010
#: Management logical device (server side).
WPORT_MANAGEMENT_LOGICAL_DEVICE = 0x0001
#: All-station / broadcast (server side).
WPORT_BROADCAST = 0x007F

#: construct definition of a complete wrapper PDU.
WrapperFrame = Struct(
    "version" / Const(WRAPPER_VERSION, Int16ub),
    "source" / Int16ub,
    "destination" / Int16ub,
    "length" / construct.Rebuild(Int16ub, construct.len_(this.apdu)),
    "apdu" / Bytes(this.length),
)


#: The 8-octet header without the version check, so a WPDU of another
#: version can still be skipped by its length.
_AnyVersionHeader = Struct(
    "version" / Int16ub,
    "source" / Int16ub,
    "destination" / Int16ub,
    "length" / Int16ub,
)


@dataclass(frozen=True)
class WrapperHeader:
    source: int
    destination: int
    length: int


@dataclass(frozen=True)
class WrapperPdu:
    source: int
    destination: int
    apdu: bytes


def encode_wrapper(source: int, destination: int, apdu: bytes) -> bytes:
    if len(apdu) > 0xFFFF:
        raise ValueError(f"APDU of {len(apdu)} octets exceeds the 16-bit wrapper length")
    return WrapperFrame.build({"source": source, "destination": destination, "apdu": apdu})


def decode_header(data: bytes) -> WrapperHeader:
    if len(data) < HEADER_SIZE:
        raise FramingError(f"wrapper header needs 8 octets, got {len(data)}")
    version = int.from_bytes(data[0:2], "big")
    if version != WRAPPER_VERSION:
        raise FramingError(f"wrapper version 0x{version:04X} is not 0x0001")
    return WrapperHeader(
        int.from_bytes(data[2:4], "big"),
        int.from_bytes(data[4:6], "big"),
        int.from_bytes(data[6:8], "big"),
    )


def decode_wrapper(data: bytes) -> WrapperPdu:
    """Decode exactly one wrapper PDU; trailing or missing octets are errors."""
    header = decode_header(data)
    if len(data) != HEADER_SIZE + header.length:
        raise FramingError(
            f"wrapper length field says {header.length}, payload has {len(data) - HEADER_SIZE}"
        )
    return WrapperPdu(header.source, header.destination, bytes(data[HEADER_SIZE:]))


class WrapperLink(ApduLink):
    """Wrapper framing over a stream (TCP) or datagram (UDP) transport."""

    def __init__(
        self,
        transport: Transport,
        client_wport: int = WPORT_PUBLIC_CLIENT,
        server_wport: int = WPORT_MANAGEMENT_LOGICAL_DEVICE,
        timeout: float = 10.0,
        check_ports: bool = True,
        push_wports: Iterable[int] = (),
    ) -> None:
        self.transport = transport
        self.client_wport = client_wport
        self.server_wport = server_wport
        self.timeout = timeout
        #: Accept only WPDUs from ``server_wport`` to ``client_wport``.
        self.check_ports = check_ports
        #: WPDUs skipped for a wrong version, wPort or datagram length.
        self.discarded = 0
        #: Client wPorts the meter pushes to besides ``client_wport`` (with
        #: ``check_ports``). WPDUs to them are pushes: held for
        #: :meth:`receive_push` while a response is awaited, and returned by
        #: ``receive_push``.
        self.push_wports = frozenset(push_wports)
        #: WPDUs to a push wPort queued while a response was awaited.
        self.queued_pushes = 0

    @property
    def client_sap(self) -> int:
        return self.client_wport

    @client_sap.setter
    def client_sap(self, sap: int) -> None:
        self.client_wport = sap

    def connect(self) -> None:
        self.transport.open()

    def disconnect(self) -> None:
        self.transport.close()

    def send_apdu(self, apdu: bytes) -> None:
        log.debug("wrapper TX %d->%d len=%d", self.client_wport, self.server_wport, len(apdu))
        self.transport.send(encode_wrapper(self.client_wport, self.server_wport, apdu))

    def send_unconfirmed(self, apdu: bytes, broadcast: bool = False) -> None:
        """Send an unconfirmed APDU to the server's wPort, or with
        ``broadcast`` to the all-station wPort :data:`WPORT_BROADCAST`.
        Nothing is read."""
        destination = WPORT_BROADCAST if broadcast else self.server_wport
        log.debug("wrapper TX unconfirmed %d->%d len=%d", self.client_wport, destination, len(apdu))
        self.transport.send(encode_wrapper(self.client_wport, destination, apdu))

    def _read_wpdu(self, deadline: float, timeout: float) -> tuple[construct.Container, bytes]:
        """Read one WPDU: from the stream by its length field, or one whole
        datagram when the transport keeps datagram boundaries (UDP)."""
        remaining = deadline - time.monotonic()
        recv_datagram = getattr(self.transport, "recv_datagram", None)
        try:
            if recv_datagram is not None:
                datagram = recv_datagram(max(remaining, 0))
                if len(datagram) < HEADER_SIZE:
                    return construct.Container(version=None), datagram
                header = _AnyVersionHeader.parse(datagram[:HEADER_SIZE])
                return header, bytes(datagram[HEADER_SIZE:])
            header = _AnyVersionHeader.parse(self.transport.recv_exact(HEADER_SIZE, remaining))
            remaining = deadline - time.monotonic()
            apdu = self.transport.recv_exact(header.length, remaining) if header.length else b""
        except DlmsTimeoutError:
            raise DlmsTimeoutError(f"no wrapper PDU within {timeout:.1f}s") from None
        return header, apdu

    def _discard(self, reason: str, header, apdu: bytes) -> None:
        self.discarded += 1
        log.debug("discarding wrapper PDU (%s): %s", reason, hexstr(apdu, 32))

    def receive_apdu(self, timeout: float | None = None) -> bytes:
        """Return the next APDU from the server to us.

        A WPDU of another version is skipped by its length; with
        ``check_ports``, one from another source wPort or to another
        destination wPort (another client) is skipped too. Skipped WPDUs are
        counted in :attr:`discarded` and the wait continues until
        ``timeout``. A WPDU to one of :attr:`push_wports` is queued for
        :meth:`receive_push` (counted in :attr:`queued_pushes`). Over a
        datagram transport the wrapper length must match the datagram
        (IEC 62056-4-7, via cB-Sigma).
        """
        return self._receive(timeout, push=False)

    def _receive_unsolicited(self, timeout: float | None) -> bytes:
        """The next APDU to us or to one of :attr:`push_wports`."""
        return self._receive(timeout, push=True)

    def _receive(self, timeout: float | None, push: bool) -> bytes:
        timeout = self.timeout if timeout is None else timeout
        deadline = time.monotonic() + timeout
        while True:
            if time.monotonic() >= deadline:
                raise DlmsTimeoutError(f"no wrapper PDU within {timeout:.1f}s")
            header, apdu = self._read_wpdu(deadline, timeout)
            if header.version is None:
                self._discard("datagram shorter than the header", header, apdu)
                continue
            if header.version != WRAPPER_VERSION:
                self._discard(f"version 0x{header.version:04X}", header, apdu)
                continue
            if len(apdu) != header.length:
                self._discard(
                    f"length field {header.length}, datagram carries {len(apdu)}", header, apdu
                )
                continue
            log.debug("wrapper RX %d->%d len=%d", header.source, header.destination, header.length)
            log.log(TRACE, "wrapper RX apdu %s", hexstr(apdu))
            if self.check_ports:
                if header.destination != self.client_wport and header.destination in (
                    self.push_wports
                ):
                    # The meter's logical devices may push from any wPort.
                    if push:
                        return apdu
                    log.debug(
                        "queueing a push from wPort %d to wPort %d",
                        header.source,
                        header.destination,
                    )
                    self.queued_pushes += 1
                    self.queue_push(apdu)
                    continue
                if header.destination != self.client_wport:
                    self._discard(
                        f"to wPort {header.destination}, we are {self.client_wport}", header, apdu
                    )
                    continue
                if header.source != self.server_wport and self.server_wport != WPORT_BROADCAST:
                    self._discard(
                        f"from wPort {header.source}, we talk to {self.server_wport}", header, apdu
                    )
                    continue
            return apdu
