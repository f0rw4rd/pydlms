"""HDLC connection-mode state machine (IEC 62056-46).

:class:`HdlcLink` turns a byte-stream :class:`~pydlms.transports.base.Transport`
into an :class:`~pydlms.link.ApduLink`:

* ``connect``: SNRM with the proposed parameters, UA with the negotiated ones
  (maximum information field lengths and window sizes, see
  :class:`HdlcParameters`), each optionally followed by a user data subfield
  (``snrm_user_data`` / ``ua_user_data``, see :func:`parameter_field`).
  Frames left from an earlier session or SNRM attempt are discarded.
* ``send_apdu``: prefixes the LLC header, splits into I-frames no larger than
  the negotiated transmit length with the segmentation bit on all but the last,
  and sends them in windows of ``negotiated.window_tx`` frames (opt-in via
  ``HdlcParameters(window_tx=N)``; the default 1 waits for an RR after every
  segment). P=1 goes only on the last frame of a window; the link then waits
  for the RR/RNR/REJ with F=1 acknowledging it. The final segment is
  acknowledged by the response's N(R).
* ``receive_apdu``: collects I-frames, checks N(S) against V(R) and N(R)
  against V(S), polls the next segment with RR while the segmentation bit is
  set, and strips the LLC header. A repeated I-frame (our RR was lost) is
  discarded and acknowledged again.
* Loss recovery (per ISO 4335:1984, adopted as IS 11418 (Part 2):1986,
  8.2.4: after the time-out the primary "should enquire status with a
  supervisory frame", and 8.2.1: a frame with F=1 starts retransmission
  from the oldest unacknowledged I frame; the IEC 62056-46 clause number
  6.4.4.9.1 is via cB-Sigma, *unverified*): when an answer or a window
  acknowledgement does not arrive, the link polls with RR (P=1), never
  resending blindly. An answer with F=1 (or a REJ) whose N(R) leaves frames
  unacknowledged makes the link resend every unacknowledged frame from N(R)
  (go-back-N), at most ``retries`` times without progress.
* Only frames from the configured server are taken. UI frames (pushes) that
  arrive while a response is awaited are queued for ``receive_push``; a link
  that is not connected returns them from ``receive_apdu`` too. A push sent
  in I-frames is returned like a response; the association recognises it and
  hands it to :meth:`HdlcLink.queue_push`, which polls for the response that
  is still due.
* REJ resends from N(R); SREJ for one of our outstanding I-frames resends
  just that frame and acknowledges the frames before it (ISO 4335:1984
  7.2.4 and 8.2.3, as IS 11418 (Part 2)); an SREJ for any other frame is a
  protocol error. Neither is in the class IEC 62056-53:2006 annex B.2.2.2
  selects ("UNC, extended with UI frames": REJ and SREJ are options 2 and
  3 of ISO 7809:1984 Table 1), so both are tolerated, never sent.
* RNR (busy): the link polls with RR until the meter is ready; UI pushes
  arriving meanwhile are queued, DM and FRMR end the wait.
* ``send_unconfirmed``: one UI frame (P=0) to the server or the all-station
  address, no link needed; ``trigger_pushes``: an empty UI frame with P=1,
  the UI frames that answer it are queued as pushes.
* ``disconnect``: DISC, expecting UA or DM.
* Time-outs: ``inter_octet_timeout`` makes the frame reader drop a partial
  frame whose octets stop; ``inactivity_timeout`` (the meter's HDLC setup
  value) makes ``send_apdu`` raise :class:`~pydlms.exceptions.LinkLostError`
  and the link DISCONNECTED once the meter has (nearly) dropped the link.

Modulo-128 numbering (opt-in, ``HdlcLink(modulus=128)``): ``connect`` sends
SNRME instead of SNRM (extended numbering: SNRME and the two-octet I and S
control fields per IBM SDLC Concepts GA27-3093-4 chapter 3 and ITU-T X.25
(10/96) Table 2-8). The DLMS profile is modulo 8: IEC 62056-53:2006 annex
B.2.2.2 selects the class "UNC, extended with UI frames", and extended
numbering is option 10 of ISO 7809:1984 Table 1 (both public as IS/IEC
62056-53 and IS 11418 (Part 3)), so modulo 128 is an extension. After
its UA, I and S frames carry two-octet control fields with seven-bit N(S)
and N(R), windows may be up to 127 frames, and FRMR has the five-octet
layout. A meter that answers SNRME with DM or FRMR, or not at all, gets an
SNRM next (windows capped to 7) unless ``modulus_fallback=False``.
:attr:`HdlcLink.modulus` is the numbering of the link set up last.

States: ``DISCONNECTED -> CONNECTED -> DISCONNECTED``. FRMR (raised as
:class:`~pydlms.exceptions.FrameRejectError` with the decoded reason), DM, and
every failure that leaves the sequence numbers unknown (a timeout after
recovery, exhausted retries or busy polls, an invalid N(R)) also end in
DISCONNECTED: the link needs a new ``connect`` (SNRM), as IEC 62056-46
6.4.4.9.4 requires after FRMR (clause number via cB-Sigma, *unverified*;
that only a mode-setting command clears the FRMR condition is per ISO
4335:1984 8.4, as IS 11418 (Part 2), and SDLC Concepts GA27-3093-4
chapter 3). Sequence numbers are
modulo 8 (:data:`~pydlms.hdlc.framing.SEQ_MODULUS`) or 128, arithmetic through
:func:`~pydlms.hdlc.framing.seq_add` / :func:`~pydlms.hdlc.framing.seq_diff`
with the link's modulus; up to ``window_tx`` I-frames are outstanding, and a valid N(R) lies between the
oldest of them and V(S). V(S) counts our I-frames, V(R) the peer's.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

import construct
from construct import (
    Const,
    FocusedSeq,
    GreedyBytes,
    GreedyRange,
    If,
    Int8ub,
    Peek,
    Prefixed,
    Struct,
    Terminated,
    this,
)

from pydlms.debug import TRACE, get_logger, hexstr
from pydlms.exceptions import (
    DlmsError,
    DlmsTimeoutError,
    FrameRejectError,
    FramingError,
    LinkLostError,
    ProtocolError,
)
from pydlms.hdlc.address import HdlcAddress
from pydlms.hdlc.framing import (
    LLC_REQUEST,
    MODULO_128,
    PF_BIT,
    SEQ_MODULUS,
    FrameReader,
    FrameType,
    HdlcFrame,
    check_modulus,
    control_i,
    control_rr,
    encode_frame,
    seq_add,
    seq_diff,
    strip_llc,
)
from pydlms.hdlc.frmr import FrameReject
from pydlms.link import ApduLink
from pydlms.transports.base import Transport

__all__ = [
    "HdlcParameters",
    "HdlcLink",
    "HdlcState",
    "ParameterFieldStruct",
    "max_window",
    "parameter_field",
    "parse_parameter_field",
]

log = get_logger("hdlc")

DEFAULT_MAX_INFO = 128
DEFAULT_WINDOW = 1
#: Largest information field an HDLC frame can carry (IEC 62056-46; jDLMS and
#: cB-Sigma both cap at 2030), and the largest window for modulo-8 numbering.
MAX_INFO_LIMIT = 2030
MAX_WINDOW = 7
#: The largest window for modulo-128 (SNRME) numbering.
MAX_WINDOW_128 = 127
#: Default cap on a reassembled APDU: the largest max-receive-pdu-size a
#: client can advertise (Unsigned16).
MAX_APDU_SIZE = 0xFFFF

_PARAM_FORMAT = 0x81
_PARAM_GROUP = 0x80
_USER_DATA = 0xFF
_P_MAX_INFO_TX = 0x05
_P_MAX_INFO_RX = 0x06
_P_WINDOW_TX = 0x07
_P_WINDOW_RX = 0x08
_PARAM_NAMES = {
    _P_MAX_INFO_TX: "max_info_tx",
    _P_MAX_INFO_RX: "max_info_rx",
    _P_WINDOW_TX: "window_tx",
    _P_WINDOW_RX: "window_rx",
}

#: One parameter of the HDLC parameter group: identifier, length, value.
_Parameter = Struct("id" / Int8ub, "value" / Prefixed(Int8ub, GreedyBytes))

#: The HDLC parameter group ``80 len parameters``; the parameters must fill
#: the group exactly.
_ParameterGroup = Struct(
    "id" / Const(_PARAM_GROUP, Int8ub),
    "parameters"
    / Prefixed(Int8ub, FocusedSeq("items", "items" / GreedyRange(_Parameter), Terminated)),
)

#: SNRM/UA information field (IEC 62056-46 6.4.4.4.3.2; ISO/IEC 13239
#: 5.5.3.2 and 5.5.3.2.3, via cB-Sigma ``hdlc/params.go``, clause numbers
#: *unverified*): the format identifier ``81``, an optional HDLC parameter
#: group, and an optional user data subfield ``FF data`` with no length
#: octet, which runs to the end of the field and so is always last (the
#: ISO/IEC 8885 user data subfield per ITU-T V.42 (03/2002) 12.2.1.3;
#: ``81``/``80`` with a one-octet group length per Wireshark
#: ``packet-cosem.c``).
ParameterFieldStruct = Struct(
    "format" / Const(_PARAM_FORMAT, Int8ub),
    "next_group" / Peek(Int8ub),
    "group" / If(this.next_group == _PARAM_GROUP, _ParameterGroup),
    "next_user_data" / Peek(Int8ub),
    "user_data"
    / If(
        this.next_user_data == _USER_DATA,
        FocusedSeq("data", Const(bytes([_USER_DATA])), "data" / GreedyBytes),
    ),
    Terminated,
)


def max_window(modulus: int = SEQ_MODULUS) -> int:
    """The largest window of a numbering: 7 for modulo 8, 127 for 128."""
    return MAX_WINDOW_128 if check_modulus(modulus) == MODULO_128 else MAX_WINDOW


@dataclass
class HdlcParameters:
    """HDLC negotiation parameters, from the sender's point of view.

    ``modulus`` is the numbering the windows are checked against: 1..7 for
    modulo 8 (the default), 1..127 for modulo 128 (SNRME). It is not part
    of the encoded field, the repr or equality.
    """

    max_info_tx: int = DEFAULT_MAX_INFO
    max_info_rx: int = DEFAULT_MAX_INFO
    window_tx: int = DEFAULT_WINDOW
    window_rx: int = DEFAULT_WINDOW
    modulus: int = field(default=SEQ_MODULUS, repr=False, compare=False)

    def __post_init__(self) -> None:
        for name in ("max_info_tx", "max_info_rx"):
            value = getattr(self, name)
            if not 1 <= value <= MAX_INFO_LIMIT:
                raise FramingError(f"HDLC {name} {value} outside 1..{MAX_INFO_LIMIT}")
        limit = max_window(self.modulus)
        for name in ("window_tx", "window_rx"):
            value = getattr(self, name)
            if not 1 <= value <= limit:
                raise FramingError(f"HDLC {name} {value} outside 1..{limit}")

    def to_bytes(self, user_data: bytes = b"") -> bytes:
        """Encode as the SNRM/UA information field (``81 80 len ...``),
        followed by the user data subfield when ``user_data`` is given; see
        :func:`parameter_field`."""
        return parameter_field(self, user_data)

    @classmethod
    def from_bytes(cls, data: bytes, modulus: int = SEQ_MODULUS) -> HdlcParameters:
        """Decode a SNRM/UA information field; absent parameters keep defaults.

        A value of 0 also means "the default" (IEC 62056-46 6.4.4.4.3.2, via
        cB-Sigma); values outside 1..2030 (lengths) or 1..7 (windows; 1..127
        with ``modulus`` 128) raise :class:`FramingError`. A user data
        subfield is accepted and dropped; :func:`parse_parameter_field`
        returns it.
        """
        return parse_parameter_field(data, modulus)[0]


def parameter_field(parameters: HdlcParameters | None, user_data: bytes = b"") -> bytes:
    """Build a SNRM/UA information field.

    ``parameters`` become the HDLC parameter group: the two maximum
    information field lengths on one octet each when both are at most 255,
    otherwise on two octets each (the two layouts of IEC 62056-46
    6.4.4.4.3.2 as cB-Sigma ``params.go`` reads them, *unverified*), the
    windows on four. For the defaults this is byte for byte the UA field of
    Rosseti STO 34.01-5.1-006-2019 Table 12.1 (``81 80 12 05 01 80 06 01
    80 07 04 00000001 08 04 00000001``); its 9.8 gives each parameter its
    own length octet and 128 / 1 as the defaults. ``user_data`` follows as
    ``FF data``. With neither, the field is empty (an SNRM without
    parameters).
    """
    if parameters is None and not user_data:
        return b""
    group = None
    if parameters is not None:
        size = 2 if max(parameters.max_info_tx, parameters.max_info_rx) > 0xFF else 1
        group = {
            "parameters": [
                {"id": _P_MAX_INFO_TX, "value": parameters.max_info_tx.to_bytes(size, "big")},
                {"id": _P_MAX_INFO_RX, "value": parameters.max_info_rx.to_bytes(size, "big")},
                {"id": _P_WINDOW_TX, "value": parameters.window_tx.to_bytes(4, "big")},
                {"id": _P_WINDOW_RX, "value": parameters.window_rx.to_bytes(4, "big")},
            ]
        }
    return ParameterFieldStruct.build(
        {
            "next_group": _PARAM_GROUP if group is not None else None,
            "group": group,
            "next_user_data": _USER_DATA if user_data else None,
            "user_data": bytes(user_data) if user_data else None,
        }
    )


def parse_parameter_field(data: bytes, modulus: int = SEQ_MODULUS) -> tuple[HdlcParameters, bytes]:
    """Decode a SNRM/UA information field into its parameters and user data.

    An empty field, an absent parameter or a value of 0 means the default.
    Unknown parameter identifiers are ignored. A field of the format
    identifier and user data only (``81 FF data``) gives the defaults. A
    missing or wrong identifier, a group or parameter cut short, a
    parameter of 0 or more than 4 octets, octets after the group that are
    not user data, and values out of range raise :class:`FramingError`
    (windows are checked against ``modulus``: up to 7, or 127 after SNRME).
    """
    if not data:
        return HdlcParameters(modulus=modulus), b""
    try:
        parsed = ParameterFieldStruct.parse(data)
    except construct.ConstructError as exc:
        raise FramingError(f"bad HDLC parameter field {data.hex()}: {exc}") from None
    if parsed.group is None and parsed.user_data is None:
        raise FramingError(f"HDLC parameter field {data.hex()} holds neither group nor user data")
    values: dict[str, int] = {}
    for parameter in parsed.group.parameters if parsed.group is not None else []:
        size = len(parameter.value)
        if not 1 <= size <= 4:
            raise FramingError(f"bad HDLC parameter 0x{parameter.id:02X} length {size}")
        name = _PARAM_NAMES.get(parameter.id)
        if name is None:
            log.debug("ignoring unknown HDLC parameter 0x%02X", parameter.id)
            continue
        value = int.from_bytes(parameter.value, "big")
        if value:  # 0 = the default
            values[name] = value
    user_data = bytes(parsed.user_data) if parsed.user_data is not None else b""
    return HdlcParameters(**values, modulus=modulus), user_data


class HdlcState(Enum):
    DISCONNECTED = "disconnected"
    CONNECTED = "connected"


class HdlcLink(ApduLink):
    """HDLC client link over a byte-stream transport.

    ``modulus=128`` (opt-in) sets the link up with SNRME for modulo-128
    numbering; with ``modulus_fallback`` (the default) a meter that refuses
    it (DM, FRMR, or no answer after the retries) is set up with SNRM and
    modulo 8 instead, the proposed windows capped to 7.
    """

    def __init__(
        self,
        transport: Transport,
        client_address: int = 16,
        server_address: HdlcAddress | int = 1,
        parameters: HdlcParameters | None = None,
        send_snrm_parameters: bool = True,
        timeout: float = 5.0,
        retries: int = 2,
        busy_polls: int = 10,
        busy_interval: float = 0.2,
        max_apdu_size: int = MAX_APDU_SIZE,
        snrm_user_data: bytes = b"",
        inter_octet_timeout: float | None = None,
        inactivity_timeout: float | None = None,
        clock: Callable[[], float] = time.monotonic,
        modulus: int = SEQ_MODULUS,
        modulus_fallback: bool = True,
    ) -> None:
        check_modulus(modulus)
        for name, value in (
            ("inter_octet_timeout", inter_octet_timeout),
            ("inactivity_timeout", inactivity_timeout),
        ):
            if value is not None and not value > 0:
                raise ValueError(f"{name} must be positive or None, got {value}")
        self.transport = transport
        self.client = HdlcAddress.client(client_address)
        self.server = (
            server_address
            if isinstance(server_address, HdlcAddress)
            else HdlcAddress.server(server_address)
        )
        self.proposed = parameters or HdlcParameters()
        for name in ("window_tx", "window_rx"):
            value = getattr(self.proposed, name)
            if value > max_window(modulus):
                raise ValueError(f"HDLC {name} {value} needs modulo-128 numbering (modulus=128)")
        #: The numbering ``connect`` asks for first: 8 (SNRM) or 128 (SNRME).
        self.proposed_modulus = modulus
        #: With ``proposed_modulus`` 128: fall back to SNRM when SNRME is
        #: refused (DM, FRMR) or not answered.
        self.modulus_fallback = modulus_fallback
        #: Sequence-number modulus of the link set up last: 8, or 128 once
        #: a UA answered SNRME.
        self.modulus = SEQ_MODULUS
        self.send_snrm_parameters = send_snrm_parameters
        #: Sent as the SNRM's user data subfield (``FF data``) when not empty.
        self.snrm_user_data = bytes(snrm_user_data)
        #: The user data subfield of the last UA (empty when it had none).
        self.ua_user_data = b""
        self.negotiated = HdlcParameters()
        self.timeout = timeout
        #: SNRM attempts beyond the first, and the RR polls / retransmissions
        #: tried after a lost frame before a request fails.
        self.retries = retries
        #: Largest APDU reassembled from I or UI segments.
        self.max_apdu_size = max_apdu_size
        #: How often to poll a meter that answered RNR (receiver not ready),
        #: and the pause between polls, before giving up.
        self.busy_polls = busy_polls
        self.busy_interval = busy_interval
        #: Inter-octet time-out (seconds) of the frame reader: a partial frame
        #: whose octets stop for longer is dropped. None: off.
        self.inter_octet_timeout = inter_octet_timeout
        #: The meter's inactivity time-out (seconds, its HDLC setup
        #: ``inactivity_time_out``): it drops the link after that long
        #: without traffic, so the link is taken as lost a little before
        #: (a tenth, at most 2 s) and :class:`LinkLostError` raised instead
        #: of sending into a dead link. None: not tracked.
        self.inactivity_timeout = inactivity_timeout
        #: Monotonic clock for activity and inter-octet tracking.
        self.clock = clock
        #: When the last frame was sent or octets were received.
        self._last_activity: float | None = None
        self.state = HdlcState.DISCONNECTED
        self.vs = 0  # next N(S) we send
        self.vr = 0  # next N(S) we expect
        self._reader = self._new_reader()
        self._pending: list[HdlcFrame] = []
        #: Our I-frames (N(S), info, segmented) the meter has not acknowledged
        #: yet, oldest first; at most ``negotiated.window_tx`` of them.
        self._unacked: deque[tuple[int, bytes, bool]] = deque()
        #: A request was sent and its response is not complete yet.
        self._awaiting = False
        #: (response awaited, last frame had P/F) of the I-frame APDU that
        #: receive_apdu just returned; see queue_push. Reset by a new request.
        self._returned: tuple[bool, bool] | None = None
        self._ui_buffer = bytearray()

    @property
    def client_sap(self) -> int:
        return self.client.upper

    @client_sap.setter
    def client_sap(self, sap: int) -> None:
        if self.state != HdlcState.DISCONNECTED:
            raise ProtocolError("change the HDLC client address only while disconnected")
        self.client = HdlcAddress.client(sap)

    # -- frame I/O -----------------------------------------------------------
    def _send_frame(
        self,
        control: int,
        info: bytes = b"",
        segmented: bool = False,
        dest: HdlcAddress | None = None,
    ) -> None:
        frame = HdlcFrame(dest or self.server, self.client, control, info, segmented, self.modulus)
        raw = encode_frame(frame)
        log.debug("HDLC TX %s", frame.describe())
        log.log(TRACE, "HDLC TX raw %s", hexstr(raw))
        self.transport.send(raw)
        self._last_activity = self.clock()

    def _receive_frame(
        self, timeout: float | None = None, deadline: float | None = None
    ) -> HdlcFrame:
        if deadline is None:
            deadline = time.monotonic() + (self.timeout if timeout is None else timeout)
        while not self._pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DlmsTimeoutError("no HDLC frame within the timeout")
            data = self.transport.recv(4096, remaining)
            self._last_activity = now = self.clock()
            for frame in self._reader.feed(data, now=now):
                if self._accept(frame):
                    self._pending.append(frame)
        frame = self._pending.pop(0)
        log.debug("HDLC RX %s", frame.describe())
        return frame

    def _new_reader(self) -> FrameReader:
        return FrameReader(
            inter_octet=self.inter_octet_timeout, clock=self.clock, modulus=self.modulus
        )

    # -- inactivity ------------------------------------------------------------
    def _inactive(self) -> bool:
        """Whether the meter's inactivity time-out has (nearly) run since
        the last traffic. That the meter drops the link then is per PJSC
        Rosseti STO 34.01-5.1-006-2019 7.4.15 (IC 23 attribute 8: without
        new frames for that long "the device breaks the connection"; 0 =
        not operational) and 9.7 (the channel goes "free"); IEC 62056-46
        6.4.4.10.3 itself is not public. The margin (a library choice) is a
        tenth of the time-out, at most 2 s."""
        limit = self.inactivity_timeout
        if limit is None or self._last_activity is None or self.state != HdlcState.CONNECTED:
            return False
        margin = min(limit / 10, 2.0)
        return self.clock() - self._last_activity >= limit - margin

    def _check_inactivity(self) -> None:
        """Raise :class:`LinkLostError` (link DISCONNECTED) when the meter
        has dropped the link by now. Never reconnects."""
        if self._inactive():
            idle = self.clock() - (self._last_activity or 0.0)
            raise self._link_lost(
                LinkLostError(
                    f"HDLC link idle for {idle:.1f}s; the meter's inactivity time-out "
                    f"({self.inactivity_timeout:g}s) has dropped it: connect again"
                )
            )

    @property
    def connected(self) -> bool:
        """The link is CONNECTED and the meter's inactivity time-out has not
        run; an expired link is set DISCONNECTED here."""
        if self._inactive():
            self._link_lost(LinkLostError("HDLC inactivity time-out"))
        return self.state == HdlcState.CONNECTED

    def _reset_buffers(self) -> None:
        """Forget frames of an earlier session or SNRM attempt."""
        if self._pending:
            log.debug("discarding %d stale HDLC frames", len(self._pending))
        self._pending.clear()
        self._reader = self._new_reader()
        self._ui_buffer.clear()
        self._unacked.clear()
        self._awaiting = False
        self._returned = None

    def _flush_stale(self) -> None:
        """Drop supervisory and unnumbered leftovers (late RR, UA) before a
        new request so they are not read as its acknowledgement. I-frames,
        UI pushes and DM/FRMR stay for the normal receive path."""
        keep = []
        for frame in self._pending:
            if frame.control & 0x01 and frame.control & ~PF_BIT & 0xFF not in (
                FrameType.UI,
                FrameType.DM,
                FrameType.FRMR,
            ):
                log.debug("discarding stale %s", frame.describe())
                continue
            keep.append(frame)
        self._pending[:] = keep

    def _accept(self, frame: HdlcFrame) -> bool:
        """Address filter: the frame must be for us and from our server.

        Servers never address the all-station client 0x7F except with UI
        pushes (IEC 62056-46 6.4.4.6, via cB-Sigma). A frame from another
        server (multidrop RS-485, a shared gateway line) is another meter's
        answer and is dropped; a stand-alone push listener (not connected)
        takes pushes from any server.
        """
        is_ui = frame.control & ~PF_BIT & 0xFF == FrameType.UI
        if frame.dest.upper != self.client.upper and not (is_ui and frame.dest.upper == 0x7F):
            log.debug("ignoring HDLC frame for %s (we are %s)", frame.dest, self.client)
            return False
        if is_ui and self.state == HdlcState.DISCONNECTED:
            return True
        if not self._from_server(frame.src):
            log.debug("ignoring HDLC frame from %s (we talk to %s)", frame.src, self.server)
            return False
        return True

    def _from_server(self, src: HdlcAddress) -> bool:
        """Compare logical and physical parts separately, so a 4-octet answer
        to a 2-octet address still matches. A configured all-station upper
        address matches any server; a configured CALLING physical address
        (0x7E / 0x3FFE) or none at all matches any physical address."""
        server = self.server
        broadcast = 0x7F if server.size in (1, 2) else 0x3FFF
        if server.upper != broadcast and src.upper != server.upper:
            return False
        if server.lower is None:
            return True
        calling = 0x7E if server.size == 2 else 0x3FFE
        if server.lower in (calling, broadcast):
            return True
        return src.lower == server.lower

    def _expect_unnumbered(self, frame: HdlcFrame, *kinds: FrameType) -> None:
        kind = frame.kind
        if kind == FrameType.FRMR:
            raise self._link_lost(_frame_reject_error(frame))
        if kind not in kinds:
            names = "/".join(k.name for k in kinds)
            raise ProtocolError(f"expected {names}, got {kind.name}")

    def _receive_unnumbered(self) -> HdlcFrame:
        """Wait for the U-frame answering SNRM/DISC, skipping leftovers of
        the data phase (I, UI, S frames) until the timeout."""
        deadline = time.monotonic() + self.timeout
        while True:
            frame = self._receive_frame(deadline=deadline)
            if frame.control & 0x03 == 0x03 and frame.kind != FrameType.UI:
                return frame
            log.debug("skipping %s while waiting for UA", frame.describe())

    # -- ApduLink --------------------------------------------------------------
    def connect(self) -> None:
        self.transport.open()
        self.state = HdlcState.DISCONNECTED
        self.modulus = SEQ_MODULUS
        self._reset_buffers()
        self.ua_user_data = b""
        moduli = [self.proposed_modulus]
        if self.proposed_modulus == MODULO_128 and self.modulus_fallback:
            moduli.append(SEQ_MODULUS)
        for index, modulus in enumerate(moduli):
            fallback = index < len(moduli) - 1
            command = FrameType.SNRME if modulus == MODULO_128 else FrameType.SNRM
            proposed = self._proposal(modulus)
            info = parameter_field(
                proposed if self.send_snrm_parameters else None, self.snrm_user_data
            )
            try:
                frame = self._set_mode(command, info)
            except DlmsTimeoutError as exc:
                if not fallback:
                    raise
                log.warning("meter did not answer %s (%s); trying SNRM", command.name, exc)
                continue
            if frame.kind in (FrameType.DM, FrameType.FRMR) and fallback:
                # A peer without extended numbering refuses SNRME: DM from a
                # disconnected station that does not accept the command, or
                # FRMR for an unimplemented control field (SDLC Concepts
                # GA27-3093-4 chapter 3, ITU-T X.25 2.3.4.10). An FRMR is in
                # its own modulo-8 layout. A mode-setting SNRM clears either.
                log.warning("meter refused %s with %s; trying SNRM", command.name, frame.kind.name)
                continue
            if frame.kind == FrameType.DM:
                raise ProtocolError(f"meter answered {command.name} with DM (disconnected mode)")
            self._expect_unnumbered(frame, FrameType.UA)
            server, self.ua_user_data = parse_parameter_field(frame.info, modulus)
            # The server's tx is our rx and vice versa.
            self.negotiated = HdlcParameters(
                max_info_tx=min(proposed.max_info_tx, server.max_info_rx),
                max_info_rx=min(proposed.max_info_rx, server.max_info_tx),
                window_tx=min(proposed.window_tx, server.window_rx),
                window_rx=min(proposed.window_rx, server.window_tx),
                modulus=modulus,
            )
            self.modulus = self._reader.modulus = modulus
            self.max_apdu = None
            self.vs = self.vr = 0
            self.clear_pushes()
            self.state = HdlcState.CONNECTED
            log.info(
                "HDLC connected %s->%s: max info tx=%d rx=%d window tx=%d rx=%d modulo %d",
                self.client,
                self.server,
                self.negotiated.max_info_tx,
                self.negotiated.max_info_rx,
                self.negotiated.window_tx,
                self.negotiated.window_rx,
                modulus,
            )
            return

    def _proposal(self, modulus: int) -> HdlcParameters:
        """The parameters to propose under ``modulus``: windows above 7 are
        capped for a modulo-8 fallback (cB-Sigma ``capWindows``)."""
        limit = max_window(modulus)
        p = self.proposed
        return HdlcParameters(
            p.max_info_tx,
            p.max_info_rx,
            min(p.window_tx, limit),
            min(p.window_rx, limit),
            modulus=modulus,
        )

    def _set_mode(self, command: FrameType, info: bytes) -> HdlcFrame:
        """Send the mode-setting ``command`` (SNRM or SNRME) until a U frame
        answers it, at most ``retries`` + 1 times; return that frame."""
        last_exc: Exception | None = None
        for attempt in range(self.retries + 1):
            # A late UA to an earlier attempt must not answer this one.
            self._pending.clear()
            self._send_frame(command | PF_BIT, info)
            try:
                return self._receive_unnumbered()
            except DlmsTimeoutError as exc:
                last_exc = exc
                log.debug("%s attempt %d timed out", command.name, attempt + 1)
        raise DlmsTimeoutError(
            f"no UA after {self.retries + 1} {command.name} attempts"
        ) from last_exc

    def disconnect(self) -> None:
        try:
            if self._inactive():
                # The meter is in disconnected mode already: a DISC would
                # only be answered with DM (or nothing).
                log.debug("HDLC inactivity time-out ran; closing without DISC")
                self.state = HdlcState.DISCONNECTED
            if self.state == HdlcState.CONNECTED:
                self._send_frame(FrameType.DISC | PF_BIT)
                try:
                    frame = self._receive_unnumbered()
                    self._expect_unnumbered(frame, FrameType.UA, FrameType.DM)
                except (DlmsTimeoutError, ProtocolError) as exc:
                    log.warning("HDLC DISC not acknowledged cleanly: %s", exc)
        finally:
            self.state = HdlcState.DISCONNECTED
            self.transport.close()

    def send_apdu(self, apdu: bytes) -> None:
        """Send ``apdu`` in I-frames, at most ``negotiated.window_tx`` before
        an acknowledgement. P=1 is set only on the last frame of each window
        (and on the final segment), then the link waits for the meter's
        RR/RNR/REJ; the final segment is acknowledged by the response."""
        if self.state != HdlcState.CONNECTED:
            raise ProtocolError("HDLC link is not connected")
        self._check_inactivity()
        self._flush_stale()
        payload = LLC_REQUEST + apdu
        size = self.negotiated.max_info_tx
        window = self.negotiated.window_tx
        chunks = [payload[i : i + size] for i in range(0, len(payload), size)] or [b""]
        if len(chunks) > 1:
            log.debug(
                "segmenting %d-octet APDU into %d I-frames (window %d)",
                len(apdu),
                len(chunks),
                window,
            )
        self._awaiting = False
        self._returned = None
        if self._unacked:
            # The meter answered without acknowledging them (a response
            # implies it had the whole request): forget them.
            log.debug("dropping %d unacknowledged I-frames", len(self._unacked))
            self._unacked.clear()
        for index, chunk in enumerate(chunks):
            last = index == len(chunks) - 1
            end_of_window = last or len(self._unacked) + 1 >= window
            self._send_i(chunk, segmented=not last, poll=end_of_window)
            if end_of_window and not last:
                self._await_window_ack()
        self._awaiting = True

    def _send_i(self, info: bytes, segmented: bool, poll: bool = True) -> None:
        self._send_frame(control_i(self.vs, self.vr, poll, self.modulus), info, segmented)
        self._unacked.append((self.vs, info, segmented))
        self.vs = seq_add(self.vs, 1, self.modulus)

    def _send_rr(self) -> None:
        """RR with P=1 acknowledging up to V(R)."""
        self._send_frame(control_rr(self.vr, True, self.modulus))

    def _oldest_unacked(self) -> int:
        """N(S) of the oldest unacknowledged I-frame (V(S) when none is)."""
        return seq_add(self.vs, -len(self._unacked), self.modulus)

    def _outstanding(self) -> str:
        return ",".join(str(ns) for ns, _, _ in self._unacked) or "none"

    def _retransmit(self, selective: bool = False) -> None:
        """Send unacknowledged I-frames again with their original N(S):
        all of them from the oldest (go-back-N), or with ``selective`` (an
        SREJ) only the oldest. P=1 goes on the last one sent."""
        frames = list(self._unacked)[:1] if selective else list(self._unacked)
        for k, (ns, info, segmented) in enumerate(frames):
            log.debug("retransmitting I-frame N(S)=%d", ns)
            last = k == len(frames) - 1
            self._send_frame(control_i(ns, self.vr, last, self.modulus), info, segmented)

    def _nr_valid(self, nr: int) -> bool:
        """N(R) lies in [V(S) - outstanding, V(S)] in sequence space."""
        return seq_diff(nr, self._oldest_unacked(), self.modulus) <= len(self._unacked)

    def _acknowledge(self, nr: int) -> None:
        """Forget every outstanding I-frame before N(R) (already checked)."""
        for _ in range(seq_diff(nr, self._oldest_unacked(), self.modulus)):
            self._unacked.popleft()

    def _check_nr(self, frame: HdlcFrame) -> None:
        """N(R) acknowledges our I-frames numbered before it. It must lie
        between the oldest unacknowledged frame and V(S); any other value
        acknowledges frames we never sent or that were acknowledged already
        (ISO/IEC 13239 invalid N(R), a frame-reject condition)."""
        nr = frame.nr
        if not self._nr_valid(nr):
            raise self._link_lost(
                ProtocolError(
                    f"invalid N(R)={nr} in {frame.kind.name} "
                    f"(V(S)={self.vs}, outstanding N(S)={self._outstanding()})"
                )
            )
        self._acknowledge(nr)

    def _check_srej(self, frame: HdlcFrame) -> None:
        """SREJ asks for the one outstanding I-frame numbered N(R); the
        frames before it count as acknowledged and only it is resent. Any
        other N(R) asks for a frame we never sent or the meter already
        acknowledged."""
        if not any(ns == frame.nr for ns, _, _ in self._unacked):
            raise self._link_lost(
                ProtocolError(
                    f"SREJ for N(S)={frame.nr}, but the outstanding "
                    + ("frames are" if len(self._unacked) > 1 else "frame is")
                    + (f" N(S)={self._outstanding()}" if self._unacked else " none")
                )
            )

    def _link_lost(self, exc: DlmsError) -> DlmsError:
        """Mark the link DISCONNECTED after a fatal error and return ``exc``
        for the caller to raise. The sequence state is unknown now, so the
        next request needs a new ``connect``."""
        if self.state == HdlcState.CONNECTED:
            log.warning("HDLC link lost: %s", exc)
        self.state = HdlcState.DISCONNECTED
        self._unacked.clear()
        self._awaiting = False
        return exc

    def _await_window_ack(self) -> None:
        """Wait until the meter acknowledges every outstanding I-frame of
        the window just sent (its last frame carried P=1).

        RR, RNR (after the busy wait), REJ and SREJ acknowledge the frames
        before N(R). An RR with F=0 only acknowledges; an RR with F=1 or a
        REJ that leaves frames unacknowledged makes the link resend them
        all from N(R) (go-back-N), an SREJ resends just that frame. A
        timeout is answered with an RR poll (P=1), never a blind resend.
        At most :attr:`retries` polls and resends without progress. The
        poll and the resend from N(R) are per ISO 4335:1984 8.2.4 and 8.2.1
        (IS 11418 (Part 2)); the IEC 62056-46 clauses 6.4.4.9.1 / 6.4.4.10.2
        and the retry limit are via cB-Sigma, *unverified*.
        """
        attempts = 0
        deadline = time.monotonic() + self.timeout
        while self._unacked:
            try:
                ack = self._receive_frame(deadline=deadline)
            except DlmsTimeoutError:
                if attempts >= self.retries:
                    raise self._link_lost(
                        DlmsTimeoutError(
                            f"segment N(S)={self._oldest_unacked()} not acknowledged "
                            f"after {attempts} RR polls"
                        )
                    ) from None
                attempts += 1
                log.debug("no RR for a window; poll %d/%d", attempts, self.retries)
                self._send_rr()
                deadline = time.monotonic() + self.timeout
                continue
            kind = ack.kind
            if kind == FrameType.UI:
                self._take_ui(ack, queue=True)
                continue
            if kind == FrameType.RNR:
                ack = self._wait_until_ready(ack)
                kind = ack.kind
            if kind == FrameType.SREJ:
                self._check_srej(ack)
            if kind not in (FrameType.RR, FrameType.REJ, FrameType.SREJ):
                self._raise_for(ack, "an RR after a segment")
            before = len(self._unacked)
            self._check_nr(ack)
            if len(self._unacked) < before:
                attempts = 0  # progress
            if not self._unacked or (kind == FrameType.RR and not ack.poll_final):
                continue
            if attempts >= self.retries:
                raise self._link_lost(ProtocolError(f"meter keeps rejecting segment N(S)={ack.nr}"))
            attempts += 1
            self._retransmit(selective=kind == FrameType.SREJ)
            deadline = time.monotonic() + self.timeout

    def _raise_for(self, frame: HdlcFrame, waiting_for: str) -> None:
        kind = frame.kind
        if kind == FrameType.DM:
            raise self._link_lost(ProtocolError("meter dropped the HDLC link (DM)"))
        if kind == FrameType.FRMR:
            raise self._link_lost(_frame_reject_error(frame))
        raise ProtocolError(f"expected {waiting_for}, got HDLC {kind.name}")

    def _wait_until_ready(self, rnr: HdlcFrame) -> HdlcFrame:
        """RNR acknowledges frames up to N(R)-1 but reports the meter busy:
        send nothing more until it is ready. Poll with RR (P=1) until the
        meter answers RR (ISO/IEC 13239 busy condition), at most
        :attr:`busy_polls` times. Each poll's answer is awaited until one
        deadline (UI pushes are queued meanwhile and do not extend it); DM
        or FRMR end the wait and the link."""
        if not self._nr_valid(rnr.nr):
            raise self._link_lost(
                ProtocolError(f"segment not acknowledged: N(R)={rnr.nr}, V(S)={self.vs}")
            )
        self._acknowledge(rnr.nr)
        for poll in range(1, self.busy_polls + 1):
            log.debug("meter busy (RNR); poll %d/%d", poll, self.busy_polls)
            time.sleep(self.busy_interval)
            self._send_rr()
            deadline = time.monotonic() + self.timeout
            while True:
                try:
                    frame = self._receive_frame(deadline=deadline)
                except DlmsTimeoutError:
                    raise self._link_lost(
                        DlmsTimeoutError(f"no answer to busy poll {poll}/{self.busy_polls}")
                    ) from None
                kind = frame.kind
                if kind == FrameType.UI:
                    self._take_ui(frame, queue=True)
                    continue
                if kind == FrameType.RR:
                    return frame
                if kind == FrameType.RNR:
                    break
                self._raise_for(frame, "RR or RNR to a busy poll")
        raise self._link_lost(
            DlmsTimeoutError(f"meter still busy (RNR) after {self.busy_polls} polls")
        )

    # -- unconfirmed sends and the push trigger --------------------------------
    def _all_station(self) -> HdlcAddress:
        """The all-station server address in the configured address size:
        0x7F per 7-bit part, 0x3FFF per 14-bit part (IEC 62056-46 6.4.2)."""
        size = self.server.size
        if size == 1:
            return HdlcAddress(0x7F)
        part = 0x7F if size == 2 else 0x3FFF
        return HdlcAddress(part, part, size)

    def send_unconfirmed(self, apdu: bytes, broadcast: bool = False) -> None:
        """Send an unconfirmed APDU in one UI frame with P=0.

        The frame goes to the server address, or with ``broadcast`` to the
        all-station address (upper and lower part). A UI frame needs no link
        (IEC 62056-53:2006 annex B.2.6.1 Table B.1: unconfirmed services go
        in "UI" frames, and an unconfirmed association needs no data link
        connection, B.2.6.2): without a connection the default maximum
        information length applies (128 per Rosseti STO 34.01-5.1-006-2019
        9.8; that it applies to UI frames without a link is *unverified*),
        so open the
        transport first (``link.transport.open()``). The APDU and its LLC
        header must fit one frame (per IEC 62056-53:2006 B.2.6.4 for the
        EventNotification APDU, "The APDU shall fit into one HDLC frame";
        applied to every unconfirmed APDU, IEC 62056-46 6.4.4.4.3.4 via
        cB-Sigma); a larger one raises :class:`ProtocolError` and nothing is
        sent. Sequence numbers and the awaited response are untouched.
        """
        info = LLC_REQUEST + apdu
        limit = self.negotiated.max_info_tx if self.connected else DEFAULT_MAX_INFO
        if len(info) > limit:
            raise ProtocolError(
                f"an unconfirmed APDU of {len(apdu)} octets does not fit one UI frame "
                f"({limit} octets of information including the LLC header)"
            )
        dest = self._all_station() if broadcast else self.server
        self._send_frame(FrameType.UI, info, dest=dest)

    def trigger_pushes(self, timeout: float | None = None) -> int:
        """Poll the meter for its pending UI frames and queue them as pushes.

        Sends an empty UI frame with P=1, which gives the server the right
        to send its pending UI frames (per IEC 62056-53:2006 annex B.2.6.4
        and Figure B.4: "the data link layer shall send out an empty UI frame
        with the P/F bit set to TRUE, giving the permission to the server
        side data link layer to send the pending PDU"; that the last answer
        carries F=1 is the ISO 4335:1984 6.3.2.1 NRM rule), then collects
        UI frames until one
        carries F=1 or ``timeout`` passes. Every complete APDU goes to the
        push queue (read it with :meth:`receive_push`); the number queued is
        returned, 0 when the meter answered nothing. Refused while a
        response is outstanding. On a connected link DM or FRMR end the
        link; other frames are left for the normal receive path.
        """
        if self._awaiting:
            raise ProtocolError("a response is outstanding; read it before triggering pushes")
        timeout = self.timeout if timeout is None else timeout
        self._send_frame(FrameType.UI | PF_BIT)
        count = 0
        others: list[HdlcFrame] = []
        deadline = time.monotonic() + timeout
        try:
            while True:
                try:
                    frame = self._receive_frame(deadline=deadline)
                except DlmsTimeoutError:
                    log.debug("push trigger: no final frame within %.1fs", timeout)
                    break
                kind = frame.kind
                if kind == FrameType.UI:
                    apdu = self._take_ui(frame, queue=False)
                    if apdu:  # an empty UI answers the poll with nothing
                        ApduLink.queue_push(self, apdu)
                        count += 1
                    if frame.poll_final:
                        break
                    continue
                if kind in (FrameType.DM, FrameType.FRMR) and self.state == HdlcState.CONNECTED:
                    self._raise_for(frame, "UI frames")
                others.append(frame)
                if frame.poll_final:
                    break
        finally:
            self._pending[:0] = others
        log.debug("push trigger queued %d APDUs", count)
        return count

    def receive_apdu(self, timeout: float | None = None) -> bytes:
        """Return the next response APDU (I-frames).

        On a connected link, UI frames (pushes, event notifications) that
        arrive meanwhile are never returned as the response: they are queued
        for :meth:`receive_push`. A link that is not connected is a push
        listener and returns UI APDUs here too.
        """
        return self._receive(timeout, push=False)

    def _receive_unsolicited(self, timeout: float | None) -> bytes:
        """The next UI (or unsolicited I) APDU, once the pushes queued during
        a request are drained (:meth:`ApduLink.receive_push`). Never polls
        the meter."""
        return self._receive(timeout, push=True)

    def queue_push(self, apdu: bytes, unwrapped=None, checked: bool = False) -> None:
        """Hold a push for :meth:`receive_push`.

        Called by the association for an I-frame APDU that :meth:`receive_apdu`
        returned but that turned out to be a notification: the response is
        then still due. If that push's last frame carried P/F, the meter has
        handed the turn back (normal response mode) and is polled with RR so
        it can send the response.
        """
        super().queue_push(apdu, unwrapped, checked)
        returned, self._returned = self._returned, None
        if returned is None or self.state != HdlcState.CONNECTED:
            return
        awaited, turn_back = returned
        if not awaited:
            return
        self._awaiting = True
        if turn_back:
            log.debug("I-frame APDU was a push; polling for the response")
            self._send_rr()

    def _take_ui(self, frame: HdlcFrame, queue: bool) -> bytes | None:
        """Collect a UI segment; return the APDU once complete (or queue it)."""
        self._ui_buffer += frame.info
        if len(self._ui_buffer) > self.max_apdu_size + len(LLC_REQUEST):
            self._ui_buffer.clear()
            raise FramingError(f"UI push exceeds {self.max_apdu_size} octets")
        if frame.segmented:
            return None
        apdu = strip_llc(bytes(self._ui_buffer))
        self._ui_buffer.clear()
        if queue:
            ApduLink.queue_push(self, apdu)
            return None
        return apdu

    def _receive(self, timeout: float | None, push: bool) -> bytes:
        """Collect one APDU.

        ``timeout`` bounds the wait for each next useful frame; frames that
        make no progress (RR, RNR, a late UA, duplicates) do not extend it.
        While a response is awaited, a timeout is recovered by polling with
        RR (P=1) and resending our last I-frame if the answer shows it lost,
        at most :attr:`retries` times; a pure push wait just times out.
        """
        timeout = self.timeout if timeout is None else timeout
        recover = not push and self.state == HdlcState.CONNECTED
        buffer = bytearray()
        attempts = 0
        deadline = time.monotonic() + timeout
        while True:
            try:
                frame = self._receive_frame(deadline=deadline)
            except DlmsTimeoutError:
                pending = recover and (self._awaiting or buffer)
                if not pending or attempts >= self.retries:
                    exc = DlmsTimeoutError(
                        f"no HDLC response within {timeout:.1f}s"
                        + (f" after {attempts} RR polls" if attempts else "")
                    )
                    raise (self._link_lost(exc) if pending else exc) from None
                attempts += 1
                log.debug("response timeout; RR poll %d/%d", attempts, self.retries)
                self._send_rr()
                deadline = time.monotonic() + timeout
                continue
            kind = frame.kind
            if kind == FrameType.UI:
                queue = not push and self.state == HdlcState.CONNECTED
                apdu = self._take_ui(frame, queue)
                if apdu is not None:
                    return apdu
                deadline = time.monotonic() + timeout
                continue
            if kind == FrameType.I:
                if self.state == HdlcState.CONNECTED:
                    self._check_nr(frame)
                if frame.ns != self.vr:
                    if frame.ns == seq_add(self.vr, -1, self.modulus):
                        # Our RR was lost and the meter repeats its frame:
                        # discard it and acknowledge again (ISO/IEC 13239).
                        log.debug("discarding duplicate I-frame N(S)=%d", frame.ns)
                        if frame.poll_final:
                            self._send_rr()
                        continue
                    if attempts >= self.retries:
                        raise self._link_lost(
                            ProtocolError(
                                f"out-of-sequence I-frame: N(S)={frame.ns}, V(R)={self.vr}"
                            )
                        )
                    attempts += 1
                    log.debug(
                        "out-of-sequence I-frame N(S)=%d (V(R)=%d); polling", frame.ns, self.vr
                    )
                    self._send_rr()
                    continue
                self.vr = seq_add(self.vr, 1, self.modulus)
                buffer += frame.info
                if len(buffer) > self.max_apdu_size + len(LLC_REQUEST):
                    raise FramingError(f"HDLC APDU exceeds {self.max_apdu_size} octets")
                deadline = time.monotonic() + timeout
                if frame.segmented:
                    # With window > 1 the server sets P/F only on the last
                    # frame of a window; acknowledge (and poll) only then.
                    if frame.poll_final:
                        self._send_rr()
                    continue
                # Taken as the response; see queue_push if it was a push.
                self._returned = (self._awaiting, frame.poll_final)
                self._awaiting = False
                return strip_llc(bytes(buffer))
            if kind in (FrameType.RR, FrameType.RNR, FrameType.REJ, FrameType.SREJ):
                if self.state == HdlcState.CONNECTED:
                    if kind == FrameType.SREJ:
                        self._check_srej(frame)
                    self._check_nr(frame)
                if (
                    kind != FrameType.RNR
                    and self._unacked
                    and (frame.poll_final or kind != FrameType.RR)
                ):
                    # The answer to our poll shows I-frames lost: resend
                    # from N(R) (just that frame after an SREJ).
                    if attempts >= self.retries:
                        raise self._link_lost(
                            ProtocolError(
                                f"meter did not receive I-frame N(S)={frame.nr} "
                                f"after {attempts} retransmissions"
                            )
                        )
                    attempts += 1
                    self._retransmit(selective=kind == FrameType.SREJ)
                    deadline = time.monotonic() + timeout
                    continue
                log.debug("ignoring %s while waiting for data", kind.name)
                continue
            if kind in (FrameType.UA, FrameType.SNRM, FrameType.DISC):
                log.debug("ignoring stale %s while waiting for data", kind.name)
                continue
            self._raise_for(frame, "an I-frame")


def _frame_reject_error(frame: HdlcFrame) -> FrameRejectError:
    """The error for an FRMR from the meter, naming its decoded reason in
    the layout of the frame's numbering (5 octets on a modulo-128 link). A
    field too short to decode is still a frame reject, reported unreadable."""
    try:
        reject = FrameReject.from_bytes(frame.info, frame.modulus)
    except FramingError:
        return FrameRejectError(
            f"meter rejected a frame (FRMR, reason unreadable: {frame.info.hex() or 'empty'})",
            None,
            frame.info,
        )
    return FrameRejectError(
        f"meter rejected a frame (FRMR): {reject.describe()}", reject, frame.info
    )
