"""Wired M-Bus request/response link for DLMS (EN 13757-2 link layer).

A DLMS client talking to a meter on a wired M-Bus is the M-Bus master; the
meter is the slave. Every exchange is started by the master::

    SND_NKE   10 40 A CS 16                     -> E5      link reset
    SND_UD    68 L L 68 53|73 A CI ... CS 16    -> E5      one DLMS segment
    REQ_UD2   10 5B|7B A CS 16                  -> RSP_UD  poll for data
    RSP_UD    68 L L 68 08|18|28|38 A CI ... CS 16

``CS`` is the sum of C and A (short frame) or of C through the last data
octet (long frame) modulo 256. In the master's C field bit 5 is the frame
count bit FCB and bit 4 the FCV bit that makes it valid; in the slave's C
field the same bits are ACD and DFC. After SND_NKE the next SND_UD and the
next REQ_UD2 both carry FCB=1; each FCB is toggled after a successful
exchange of its kind and kept on a repetition, so the slave can tell a
repeated telegram from the next one. A missing or corrupt answer is
repeated up to two times (three attempts), then an idle time of 33 bit
periods follows.

The DLMS APDU travels in the long frames' user data, split into segments
with CI 0x00..0x1F (sequence number in the low nibble, 0x10 = last) or in
one frame behind an M-Bus data header (CI 0x60/0x61 down, 0x7C/0x7D up),
always with STSAP and DTSAP first (:mod:`pydlms.mbus`).

Sources: the M-Bus Usergroup "The M-Bus: A
Documentation" Rev. 4.8 (5.2 telegram formats, 5.3 C field and Table 1, 5.4
communication process and timing, 5.5 FCB/FCV, 7.1 selection), OMS Vol. 2
Issue 5.0.1 (3.1.2 addresses, 5.1, 5.2.4 Tables 15/16) and IEC 62056-7-3:2017
(Figure 2, 5.4). The segment sequence rolls over from 15 to 0 while
segments remain (Vorarlberg Netz / Honeywell "KSMWest H1 interface", 2018,
p. 6; single source). How a DLMS master polls for a response that is not
yet ready is not in a public source; the behaviour chosen here is marked
*unverified*.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

import construct
from construct import Byte, Bytes, Checksum, Const, Int8ub, RawCopy, Struct, this

from pydlms.debug import TRACE, get_logger, hexstr
from pydlms.exceptions import ChecksumError, DlmsTimeoutError, FramingError, ProtocolError
from pydlms.link import ApduLink
from pydlms.mbus import (
    CI_FINAL,
    HEADER_CI,
    START_LONG,
    START_SHORT,
    STOP,
    MbusFrame,
    decode_mbus_frame,
    encode_mbus_frame,
)
from pydlms.transports.base import Transport

__all__ = [
    "MbusLink",
    "MbusLinkFrame",
    "MbusShortFrame",
    "MbusRawLongFrame",
    "encode_short_frame",
    "encode_long_frame",
    "decode_link_frame",
    "encode_selection",
    "reply_timeout_for",
    "control_name",
    "starts_with_mbus_telegram",
    "MAX_SEGMENTS",
    "MAX_SEGMENT_DATA",
    "MBUS_MAX_APDU",
]

log = get_logger("mbus")

SINGLE_ACK = 0xE5

# C field, M-Bus documentation 4.8 5.3 Fig. 14 and Table 1; OMS Vol. 2 Tables 15/16.
C_SND_NKE = 0x40
C_SND_UD = 0x53  # FCV set; | C_FCB -> 0x73
C_REQ_UD1 = 0x5A
C_REQ_UD2 = 0x5B  # FCV set; | C_FCB -> 0x7B
C_RSP_UD = 0x08  # | ACD 0x20 | DFC 0x10
C_FCB = 0x20
C_FCV = 0x10
C_ACD = 0x20
C_DFC = 0x10
C_PRM = 0x40  # direction: 1 = calling (master to slave)
FUNCTION_MASK = 0x0F
FUNCTION_RSP_UD = 0x08
FUNCTION_NACK = 0x01  # OMS Vol. 2 Table 16 (01h/11h/21h/31h)

# A field, M-Bus documentation 4.8 5.3; OMS Vol. 2 3.1.2.1.
ADDRESS_MAX_PRIMARY = 250
ADDRESS_NETWORK_LAYER = 0xFD  # 253: the slave selected by secondary address
ADDRESS_TEST = 0xFE  # 254: every slave answers (point to point only)
ADDRESS_BROADCAST = 0xFF  # 255: no slave answers

CI_SELECT = 0x52  # selection by secondary address, mode 1 (doc 4.8 7.1 Fig. 29)

#: Octets of user data after CI in one long frame (L <= 255 = C + A + CI + data).
MAX_LONG_DATA = 252
#: DLMS octets per segment: the long frame's data less STSAP and DTSAP.
MAX_SEGMENT_DATA = 250
#: Sequence numbers in the CI's four bits (0..15). The sequence rolls over
#: after 15 (KSMWest H1 p. 6), so this is not a limit on the segments of an
#: APDU; it sizes the default APDU cap (16 full segments, 4000 octets).
MAX_SEGMENTS = 16
MBUS_MAX_APDU = MAX_SEGMENTS * MAX_SEGMENT_DATA

#: Bits per character on the line: start, 8 data, even parity, stop (doc 4.8 5.1).
BITS_PER_CHAR = 11
#: Idle time after the last failed repetition (doc 4.8 5.4).
IDLE_BITS = 33
#: Added to the specified reply time-out on a serial line: USB adapters and
#: level converters buffer and deliver late (library choice, not from a source).
CONVERTER_MARGIN = 0.25
#: Reply time-out when the transport has no baud rate (TCP gateway).
GATEWAY_REPLY_TIMEOUT = 2.0


def _checksum(data: bytes) -> int:
    return sum(data) & 0xFF


def reply_timeout_for(baudrate: int) -> float:
    """The master's time limit for a reply: 330 bit periods + 50 ms
    (M-Bus documentation 4.8 5.4; the slave answers after 11 to 330 bit
    periods + 50 ms)."""
    return 330 / baudrate + 0.05


#: Short frame ``10 C A CS 16`` (doc 4.8 5.2 Fig. 13); CS = C + A.
MbusShortFrame = Struct(
    Const(b"\x10"),
    "body" / RawCopy(Struct("control" / Byte, "address" / Byte)),
    "checksum" / Checksum(Byte, _checksum, this.body.data),
    Const(b"\x16"),
)

#: Long or control frame with any CI (doc 4.8 5.2): L counts C, A, CI and
#: the user data; CS sums the same octets. :data:`pydlms.mbus.MbusLongFrame`
#: is the DLMS view of the same frame (SAPs and data header parsed).
MbusRawLongFrame = Struct(
    Const(b"\x68"),
    "length" / construct.Rebuild(Int8ub, lambda ctx: 3 + len(ctx.body["value"]["data"])),
    "length2" / construct.Rebuild(Int8ub, this.length),
    Const(b"\x68"),
    "body"
    / RawCopy(
        Struct(
            "control" / Byte,
            "address" / Byte,
            "ci" / Byte,
            "data" / Bytes(lambda ctx: ctx._.length - 3),
        )
    ),
    "checksum" / Checksum(Byte, _checksum, this.body.data),
    Const(b"\x16"),
)


@dataclass(frozen=True)
class MbusLinkFrame:
    """One link-layer telegram: ``kind`` is ``"ack"`` (single character
    E5), ``"short"`` or ``"long"``; ``ci`` and ``data`` exist for long
    frames only. ``raw`` is the telegram as received."""

    kind: str
    raw: bytes
    control: int | None = None
    address: int | None = None
    ci: int | None = None
    data: bytes = b""

    @property
    def from_master(self) -> bool:
        return self.control is not None and bool(self.control & C_PRM)

    @property
    def function(self) -> int | None:
        return None if self.control is None else self.control & FUNCTION_MASK

    @property
    def is_rsp_ud(self) -> bool:
        return self.kind == "long" and not self.from_master and self.function == FUNCTION_RSP_UD

    @property
    def is_nack(self) -> bool:
        return (
            self.kind in ("short", "long")
            and not self.from_master
            and self.function == FUNCTION_NACK
        )

    @property
    def is_dlms(self) -> bool:
        return (
            self.kind == "long"
            and self.ci is not None
            and (self.ci <= 0x1F or self.ci in HEADER_CI)
        )

    def describe(self) -> str:
        if self.kind == "ack":
            return "E5"
        text = f"{self.kind} frame C=0x{self.control:02X} A={self.address}"
        if self.kind == "long":
            text += f" CI=0x{self.ci:02X} {len(self.data)} octets"
        return text


def control_name(control: int) -> str:
    """The message type of a C field with its FCB or ACD/DFC bits, e.g.
    ``REQ_UD2 FCB=1`` (doc 4.8 Table 1; NACK from OMS Vol. 2 Table 16)."""
    function = control & FUNCTION_MASK
    if control & C_PRM:
        names = {0x0: "SND_NKE", 0x3: "SND_UD", 0xA: "REQ_UD1", 0xB: "REQ_UD2"}
        name = names.get(function, f"function 0x{function:X}")
        if function == 0x0:
            return name
        if not control & C_FCV:
            return f"{name} FCV=0"
        return f"{name} FCB={int(bool(control & C_FCB))}"
    names = {FUNCTION_RSP_UD: "RSP_UD", 0x0: "ACK", FUNCTION_NACK: "NACK"}
    name = names.get(function, f"function 0x{function:X}")
    return f"{name} ACD={int(bool(control & C_ACD))} DFC={int(bool(control & C_DFC))}"


def starts_with_mbus_telegram(data: bytes) -> bool:
    """True when ``data`` is or starts with a single character E5 or a
    short frame with a valid checksum (the telegrams of a polled M-Bus
    session besides long frames)."""
    if data[:1] == bytes([SINGLE_ACK]):
        return len(data) == 1 or data[1] in (SINGLE_ACK, START_SHORT, START_LONG)
    return (
        len(data) >= 5
        and data[0] == START_SHORT
        and data[4] == STOP
        and data[3] == _checksum(data[1:3])
    )


def encode_short_frame(control: int, address: int) -> bytes:
    """``10 C A CS 16``."""
    return MbusShortFrame.build({"body": {"value": {"control": control, "address": address}}})


def encode_long_frame(control: int, address: int, ci: int, data: bytes = b"") -> bytes:
    """A long frame with any CI (a control frame when ``data`` is empty)."""
    if len(data) > MAX_LONG_DATA:
        raise ValueError(f"M-Bus long frame data of {len(data)} octets exceeds L=255")
    return MbusRawLongFrame.build(
        {"body": {"value": {"control": control, "address": address, "ci": ci, "data": data}}}
    )


def decode_link_frame(raw: bytes) -> MbusLinkFrame:
    """Decode one complete telegram (E5, short or long frame) and verify it."""
    if raw == bytes([SINGLE_ACK]):
        return MbusLinkFrame("ack", raw)
    if raw[:1] == bytes([START_SHORT]):
        if len(raw) != 5:
            raise FramingError(f"M-Bus short frame must be 5 octets, got {len(raw)}")
        if raw[4] != STOP:
            raise FramingError("M-Bus short frame does not end with 0x16")
        try:
            parsed = MbusShortFrame.parse(raw)
        except construct.ChecksumError:
            raise ChecksumError(
                f"M-Bus short frame checksum 0x{raw[3]:02X}, computed 0x{_checksum(raw[1:3]):02X}"
            ) from None
        body = parsed.body.value
        return MbusLinkFrame("short", bytes(raw), body.control, body.address)
    if raw[:1] == bytes([START_LONG]):
        if len(raw) < 9:
            raise FramingError(f"M-Bus long frame too short ({len(raw)} octets)")
        if raw[3] != START_LONG or raw[1] != raw[2]:
            raise FramingError("M-Bus long frame must start with 68 L L 68")
        if raw[1] < 3:
            raise FramingError(f"M-Bus L={raw[1]} leaves no room for C, A and CI")
        if len(raw) != raw[1] + 6:
            raise FramingError(f"M-Bus L={raw[1]} implies {raw[1] + 6} octets, got {len(raw)}")
        if raw[-1] != STOP:
            raise FramingError("M-Bus frame does not end with 0x16")
        try:
            parsed = MbusRawLongFrame.parse(raw)
        except construct.ChecksumError:
            body = raw[4:-2]
            raise ChecksumError(
                f"M-Bus checksum 0x{raw[-2]:02X}, computed 0x{_checksum(body):02X}"
            ) from None
        except construct.ConstructError as exc:  # pragma: no cover - checked above
            raise FramingError(f"malformed M-Bus long frame: {exc}") from exc
        body = parsed.body.value
        return MbusLinkFrame(
            "long", bytes(raw), body.control, body.address, body.ci, bytes(body.data)
        )
    raise FramingError(f"not an M-Bus telegram: {hexstr(raw, 16)}")


def _secondary_octets(secondary: str | bytes) -> bytes:
    """The eight octets of a secondary address as sent in the selection.

    ``bytes`` are taken as they go on the line. A string uses the libmbus
    notation of 16 hex digits ``IIIIIIIIMMMMVVDD``: identification number
    (8 BCD digits, ``F`` = wildcard digit), then manufacturer (two octets in
    line order), version and device type / medium (``FF`` = wildcard).
    The identification goes on the line least significant byte first.
    """
    if isinstance(secondary, bytes):
        if len(secondary) != 8:
            raise ValueError("a secondary address is 8 octets")
        return secondary
    text = secondary.replace(" ", "")
    if len(text) != 16:
        raise ValueError(f"secondary address {secondary!r} must have 16 hex digits")
    ident = text[:8]
    if any(c not in "0123456789Ff" for c in ident):
        raise ValueError(f"identification {ident!r} must be BCD digits or F wildcards")
    try:
        rest = bytes.fromhex(text[8:])
    except ValueError:
        raise ValueError(f"secondary address {secondary!r} is not hex") from None
    return bytes.fromhex(ident)[::-1] + rest


def encode_selection(secondary: str | bytes, control: int = C_SND_UD) -> bytes:
    """SND_UD to address 253 with CI 0x52 and the secondary address (doc 4.8 7.1 Fig. 29)."""
    return encode_long_frame(
        control, ADDRESS_NETWORK_LAYER, CI_SELECT, _secondary_octets(secondary)
    )


_INVALID = MbusLinkFrame("invalid", b"")


class MbusLink(ApduLink):
    """DLMS over a wired M-Bus, the client being the M-Bus master.

    ``transport`` is a serial line (2400 baud 8E1 is the usual M-Bus
    setting) or a TCP connection to an M-Bus gateway. ``primary_address``
    is the meter's A field: 0 (unconfigured) to 250, or 254 (test address,
    point to point only). With ``secondary_address`` the meter is selected
    by its secondary address instead and addressed as 253.

    ``client_sap`` / ``server_sap`` are the STSAP / DTSAP of the M-Bus
    wrapper (IEC 62056-7-3 5.4.2), e.g. 16 (public client) and 1
    (management logical device).

    Timing: ``reply_timeout`` is how long to wait for the first octet of an
    answer; by default 330 bit periods + 50 ms (M-Bus documentation 4.8
    5.4) plus :data:`CONVERTER_MARGIN` on a serial line, and
    :data:`GATEWAY_REPLY_TIMEOUT` over TCP. ``retries`` repetitions follow
    a missing or corrupt answer (default 2: three attempts). ``timeout`` is
    the overall time :meth:`receive_apdu` polls for a DLMS response;
    ``poll_interval`` the pause after the meter answered that it has
    nothing yet, ``max_polls`` a bound on REQ_UD2 per APDU.

    ``clock`` and ``sleep`` replace :func:`time.monotonic` and
    :func:`time.sleep` for every deadline and pause.
    """

    def __init__(
        self,
        transport: Transport,
        primary_address: int = 0,
        client_sap: int = 16,
        server_sap: int = 1,
        timeout: float = 10.0,
        reply_timeout: float | None = None,
        retries: int = 2,
        secondary_address: str | bytes | None = None,
        max_segment: int = MAX_SEGMENT_DATA,
        max_apdu_size: int | None = None,
        poll_interval: float = 0.05,
        max_polls: int = 512,
        clock: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        if secondary_address is not None:
            self.secondary = _secondary_octets(secondary_address)
            primary_address = ADDRESS_NETWORK_LAYER
        else:
            self.secondary = None
            if not (0 <= primary_address <= ADDRESS_MAX_PRIMARY or primary_address == ADDRESS_TEST):
                raise ValueError(
                    f"M-Bus primary address {primary_address} outside 0..250 (or 254, the "
                    "test address); use secondary_address for 253"
                )
        for name, sap in (("client_sap", client_sap), ("server_sap", server_sap)):
            if not 0 <= sap <= 0xFF:
                raise ValueError(f"{name} {sap} outside 0..255 (one octet on M-Bus)")
        if not 1 <= max_segment <= MAX_SEGMENT_DATA:
            raise ValueError(f"max_segment must be 1..{MAX_SEGMENT_DATA}")
        if retries < 0:
            raise ValueError("retries must be >= 0")
        if max_polls < 1:
            raise ValueError("max_polls must be >= 1")
        self.transport = transport
        self.address = primary_address
        self._client_sap = client_sap
        self.server_sap = server_sap
        self.timeout = timeout
        baudrate = getattr(transport, "baudrate", None)
        if reply_timeout is None:
            if baudrate:
                reply_timeout = reply_timeout_for(baudrate) + CONVERTER_MARGIN
            else:
                reply_timeout = GATEWAY_REPLY_TIMEOUT
        self.reply_timeout = reply_timeout
        self.retries = retries
        self.max_segment = max_segment
        self.max_apdu_size = max_apdu_size or MAX_SEGMENTS * max_segment
        self.poll_interval = poll_interval
        self.max_polls = max_polls
        self.clock = clock
        self.sleep = sleep
        #: Next FCB of SND_UD and of REQ_UD2 (doc 4.8 5.5.2: set after SND_NKE).
        self.fcb_send = True
        self.fcb_request = True
        #: Telegrams repeated because the answer was missing or corrupt.
        self.repetitions = 0
        #: RSP_UD frames dropped: wrong address or SAPs, duplicate segment.
        self.discarded = 0
        #: Slave's ACD / DFC bits of the last RSP_UD.
        self.access_demand = False
        self.data_flow_control = False
        #: Octets found waiting before a telegram was sent, and dropped.
        self.stale_octets = 0
        self._last_sent = b""

    # -- ApduLink -------------------------------------------------------------------
    @property
    def client_sap(self) -> int:
        return self._client_sap

    @client_sap.setter
    def client_sap(self, sap: int) -> None:
        if not 0 <= sap <= 0xFF:
            raise ValueError(f"client SAP {sap} outside 0..255 (one octet on M-Bus)")
        self._client_sap = sap

    def connect(self) -> None:
        self.transport.open()
        if self.secondary is not None:
            self.select()
        else:
            self.reset()

    def disconnect(self) -> None:
        self.transport.close()

    # -- time -----------------------------------------------------------------------
    def _now(self) -> float:
        return (self.clock or time.monotonic)()

    def _pause(self, seconds: float) -> None:
        if seconds > 0:
            (self.sleep or time.sleep)(seconds)

    def _char_time(self) -> float:
        baudrate = getattr(self.transport, "baudrate", None)
        return BITS_PER_CHAR / baudrate if baudrate else 0.0

    def _idle(self) -> None:
        """The idle time of 33 bit periods after the last failed attempt."""
        baudrate = getattr(self.transport, "baudrate", None)
        if baudrate:
            self._pause(IDLE_BITS / baudrate)

    # -- telegram I/O ---------------------------------------------------------------
    def _send(self, raw: bytes) -> None:
        self._discard_pending()
        log.log(TRACE, "M-Bus TX %s", hexstr(raw, 32))
        self._last_sent = raw
        self.transport.send(raw)

    def _discard_pending(self) -> None:
        """Drop octets already received: the master speaks first, so
        anything waiting is a late or extra answer to an earlier telegram
        (a second E5, a collision) and must not be taken for the next one."""
        dropped = 0
        while dropped < 0x10000:
            try:
                dropped += len(self.transport.recv(4096, 0))
            except DlmsTimeoutError:
                break
        if dropped:
            log.debug("M-Bus: discarded %d stale octets before sending", dropped)
            self.stale_octets += dropped

    def _recv(self, count: int, deadline: float) -> bytes:
        out = bytearray()
        while len(out) < count:
            remaining = deadline - self._now()
            if remaining <= 0:
                raise DlmsTimeoutError(f"M-Bus telegram incomplete ({len(out)} of {count} octets)")
            out += self.transport.recv(count - len(out), remaining)
        return bytes(out)

    def _drain(self) -> None:
        """Discard the rest of a corrupt answer: read until the line is quiet."""
        quiet = max(self._char_time() * IDLE_BITS / BITS_PER_CHAR, 0.02)
        dropped = 0
        while dropped < 0x10000:
            try:
                dropped += len(self.transport.recv(4096, quiet))
            except DlmsTimeoutError:
                break
        if dropped:
            log.debug("M-Bus: discarded %d octets after a corrupt answer", dropped)

    def _read_telegram(self, deadline: float) -> MbusLinkFrame | None:
        """One telegram; ``None`` when nothing arrived before ``deadline``,
        :data:`_INVALID` for a corrupt or truncated one."""
        try:
            first = self._recv(1, deadline)
        except DlmsTimeoutError:
            return None
        if first[0] == SINGLE_ACK:
            return MbusLinkFrame("ack", first)
        # The rest of the telegram is on the line without pauses (doc 4.8
        # 5.1); allow its transmission time on top of the reply time-out.
        body_deadline = self._now() + self.reply_timeout + (MAX_LONG_DATA + 9) * self._char_time()
        try:
            if first[0] == START_SHORT:
                raw = first + self._recv(4, body_deadline)
            elif first[0] == START_LONG:
                head = self._recv(3, body_deadline)
                if head[0] != head[1] or head[2] != START_LONG:
                    raise FramingError(f"bad long frame start {hexstr(first + head)}")
                raw = first + head + self._recv(head[0] + 2, body_deadline)
            else:
                raise FramingError(f"unexpected octet 0x{first[0]:02X}")
            frame = decode_link_frame(raw)
        except (DlmsTimeoutError, FramingError) as exc:
            log.debug("M-Bus: corrupt answer (%s)", exc)
            self._drain()
            return _INVALID
        log.log(TRACE, "M-Bus RX %s", hexstr(frame.raw, 32))
        return frame

    def _read_reply(self) -> MbusLinkFrame | None:
        """The slave's answer to the telegram just sent; an echo of it (some
        level converters echo the master) is skipped."""
        deadline = self._now() + self.reply_timeout
        while True:
            frame = self._read_telegram(deadline)
            if frame is not None and frame.raw == self._last_sent and frame.from_master:
                log.debug("M-Bus: skipping the echo of our own telegram")
                continue
            return frame

    def _address_ok(self, frame: MbusLinkFrame) -> bool:
        # The slave answers with its own primary address, also when called
        # by 253 or 254 (OMS Vol. 2 3.1.2.1; doc 4.8 5.5.2 5.)).
        return self.address in (ADDRESS_NETWORK_LAYER, ADDRESS_TEST) or (
            frame.address == self.address
        )

    def _exchange(self, build: Callable[[], bytes], what: str) -> MbusLinkFrame:
        """Send a telegram that the slave acknowledges with E5, repeating it
        unchanged (same FCB) on a missing or corrupt answer."""
        raw = build()
        problems: list[str] = []
        for attempt in range(self.retries + 1):
            if attempt:
                self.repetitions += 1
                log.debug("M-Bus: repeating %s (attempt %d)", what, attempt + 1)
            self._send(raw)
            reply = self._read_reply()
            if reply is None:
                problems.append("no answer")
            elif reply is _INVALID:
                problems.append("corrupt answer")
            elif reply.is_nack:
                raise ProtocolError(f"M-Bus {what}: slave answered NACK ({reply.describe()})")
            elif reply.kind == "ack":
                return reply
            else:
                problems.append(f"unexpected {reply.describe()}")
        self._idle()
        error = DlmsTimeoutError if set(problems) == {"no answer"} else ProtocolError
        raise error(
            f"M-Bus {what} to address {self.address}: no E5 after "
            f"{self.retries + 1} attempts ({', '.join(problems)})"
        )

    # -- link-level services --------------------------------------------------------
    def reset(self) -> None:
        """SND_NKE to the meter; expects E5. Both FCBs start over at 1."""
        self._exchange(lambda: encode_short_frame(C_SND_NKE, self.address), "SND_NKE")
        self.fcb_send = self.fcb_request = True
        log.debug("M-Bus link to address %d reset", self.address)

    def select(self) -> None:
        """Select the meter by its secondary address (doc 4.8 7.1): SND_NKE
        to 253 deselects every slave (answers are not awaited, several
        slaves may answer at once), then the selection SND_UD CI 0x52 must
        be acknowledged with E5. Both FCBs start over at 1 (doc 4.8 7.2)."""
        if self.secondary is None:
            raise ProtocolError("no secondary address to select")
        self._send(encode_short_frame(C_SND_NKE, ADDRESS_NETWORK_LAYER))
        if self._read_reply() is not None:
            self._drain()  # every selected slave may answer
        self._exchange(lambda: encode_selection(self.secondary), "selection")
        self.fcb_send = self.fcb_request = True
        log.debug("M-Bus slave %s selected", self.secondary.hex())

    def _request_control(self) -> int:
        return C_REQ_UD2 | (C_FCB if self.fcb_request else 0)

    def _poll(self) -> MbusLinkFrame | None:
        """One REQ_UD2 with the current FCB; toggles the FCB after a valid
        RSP_UD from our slave. Returns ``None`` / :data:`_INVALID` for a
        missing / corrupt answer (the caller repeats with the same FCB)."""
        self._send(encode_short_frame(self._request_control(), self.address))
        reply = self._read_reply()
        if reply is None or reply is _INVALID:
            return reply
        if reply.is_nack:
            raise ProtocolError(f"M-Bus REQ_UD2: slave answered NACK ({reply.describe()})")
        if reply.is_rsp_ud:
            if not self._address_ok(reply):
                log.warning(
                    "M-Bus: RSP_UD from address %d, we poll %d; discarded",
                    reply.address,
                    self.address,
                )
                self.discarded += 1
                return _INVALID
            self.fcb_request = not self.fcb_request
            self.access_demand = bool(reply.control & C_ACD)
            self.data_flow_control = bool(reply.control & C_DFC)
            if self.access_demand:
                log.debug("M-Bus: slave sets ACD (class 1 data waiting)")
        return reply

    def request_user_data(self) -> MbusLinkFrame:
        """REQ_UD2 -> RSP_UD with FCB handling, repeated (same FCB) up to
        ``retries`` times; returns the slave's answer (an RSP_UD, or E5 from
        a slave that answers so)."""
        problems: list[str] = []
        for attempt in range(self.retries + 1):
            if attempt:
                self.repetitions += 1
            reply = self._poll()
            if reply is None:
                problems.append("no answer")
            elif reply is _INVALID:
                problems.append("corrupt answer")
            elif reply.is_rsp_ud or reply.kind == "ack":
                return reply
            else:
                problems.append(f"unexpected {reply.describe()}")
        self._idle()
        error = DlmsTimeoutError if set(problems) == {"no answer"} else ProtocolError
        raise error(
            f"M-Bus REQ_UD2 to address {self.address}: no RSP_UD after "
            f"{self.retries + 1} attempts ({', '.join(problems)})"
        )

    # -- DLMS -----------------------------------------------------------------------
    def _segments(self, apdu: bytes) -> list[tuple[int, bytes]]:
        if len(apdu) > self.max_apdu_size:
            raise ProtocolError(
                f"APDU of {len(apdu)} octets exceeds the M-Bus limit of {self.max_apdu_size}"
            )
        size = self.max_segment
        chunks = [apdu[i : i + size] for i in range(0, len(apdu), size)] or [b""]
        last = len(chunks) - 1
        # The 4-bit sequence rolls over from 15 to 0 (KSMWest H1 p. 6).
        return [
            ((seq & 0x0F) | (CI_FINAL if seq == last else 0), c) for seq, c in enumerate(chunks)
        ]

    def send_apdu(self, apdu: bytes) -> None:
        """Send ``apdu`` as SND_UD segments (CI 0x00..0x1F), each acknowledged
        with E5 before the next; the FCB toggles after every acknowledged
        segment."""
        log.debug(
            "M-Bus TX APDU %d octets SAP %d->%d to address %d",
            len(apdu),
            self.client_sap,
            self.server_sap,
            self.address,
        )
        for ci, chunk in self._segments(apdu):
            control = C_SND_UD | (C_FCB if self.fcb_send else 0)
            raw = encode_mbus_frame(
                MbusFrame(control, self.address, ci, self.client_sap, self.server_sap, chunk)
            )
            self._exchange(lambda raw=raw: raw, f"SND_UD CI 0x{ci:02X}")
            self.fcb_send = not self.fcb_send

    def receive_apdu(self, timeout: float | None = None) -> bytes:
        """Poll with REQ_UD2 until RSP_UD frames complete a DLMS APDU.

        A missing or corrupt answer is repeated with the same FCB, at most
        ``retries`` times in a row. An E5 or an RSP_UD without a DLMS CI
        means the meter has nothing yet (*unverified*: no public source
        says how a DLMS slave answers before its response is ready); the
        master polls again after ``poll_interval`` until ``timeout``.
        Segments must arrive in sequence; a repeated last segment is
        dropped. M-Bus-layer encryption raises :class:`FramingError`.
        """
        timeout = self.timeout if timeout is None else timeout
        deadline = self._now() + timeout
        segments: list[bytes] = []
        size = 0
        failures = 0
        for _poll in range(self.max_polls):
            if self._now() >= deadline:
                raise DlmsTimeoutError(
                    f"no complete DLMS APDU from M-Bus address {self.address} within "
                    f"{timeout:.1f}s ({len(segments)} segment(s) received)"
                )
            if failures:
                self.repetitions += 1
            reply = self._poll()
            if reply is not None and reply is not _INVALID and reply.kind != "ack":
                if not reply.is_rsp_ud:
                    log.debug("M-Bus: unexpected %s to REQ_UD2", reply.describe())
                    reply = _INVALID
            if reply is None or reply is _INVALID:
                failures += 1
                if failures > self.retries:
                    self._idle()
                    error = DlmsTimeoutError if reply is None else ProtocolError
                    raise error(
                        f"M-Bus REQ_UD2 to address {self.address}: "
                        f"{'no answer' if reply is None else 'corrupt answer'} "
                        f"after {failures} attempts"
                    )
                continue
            failures = 0
            if not reply.is_dlms:
                log.debug("M-Bus: %s, no DLMS data yet; polling again", reply.describe())
                self._pause(min(self.poll_interval, max(deadline - self._now(), 0)))
                continue
            frame = decode_mbus_frame(reply.raw)  # refuses M-Bus-layer encryption
            if frame.stsap != self.server_sap or frame.dtsap != self.client_sap:
                log.warning(
                    "M-Bus: DLMS segment SAP %d->%d, expected %d->%d; discarded",
                    frame.stsap,
                    frame.dtsap,
                    self.server_sap,
                    self.client_sap,
                )
                self.discarded += 1
                continue
            if frame.header is not None:
                if frame.header.direction != "up":
                    raise ProtocolError(f"M-Bus slave sent the downlink CI 0x{frame.ci:02X}")
                if segments:
                    raise ProtocolError(
                        f"M-Bus CI 0x{frame.ci:02X} frame after {len(segments)} segment(s)"
                    )
                log.debug("M-Bus RX APDU %d octets (CI 0x%02X)", len(frame.data), frame.ci)
                return frame.data
            expected = len(segments) & 0x0F  # rolls over after 15
            if frame.sequence != expected:
                repeated = (len(segments) - 1) & 0x0F
                if segments and frame.sequence == repeated and frame.data == segments[-1]:
                    log.debug("M-Bus: segment %d repeated; dropped", frame.sequence)
                    self.discarded += 1
                    continue
                raise ProtocolError(
                    f"M-Bus segment {frame.sequence} out of order (expected {expected})"
                )
            size += len(frame.data)
            if size > self.max_apdu_size:
                raise ProtocolError(f"M-Bus APDU exceeds {self.max_apdu_size} octets")
            segments.append(frame.data)
            if frame.final:
                apdu = b"".join(segments)
                log.debug("M-Bus RX APDU %d octets in %d segment(s)", len(apdu), len(segments))
                return apdu
        raise ProtocolError(f"M-Bus: no complete DLMS APDU after {self.max_polls} polls")
