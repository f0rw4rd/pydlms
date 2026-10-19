"""HDLC frame codec (IEC 62056-46, frame format type 3).

Wire layout::

    7E | frame-format(2) | dest(1/2/4) | src(1/2/4) | control(1/2)
       | [HCS(2) | information(n)] | FCS(2) | 7E

* frame-format: ``1010 S LLLLLLLLLLL`` - type 0xA, segmentation bit S,
  11-bit frame length counting every octet between the flags.
* HCS covers frame-format through control; it is present only when the frame
  has an information field. FCS covers everything between the flags except the
  FCS itself. Both are CRC-16/X-25, LSB first (:mod:`pydlms.hdlc.crc`).

The checksummed spans are expressed with ``construct`` ``RawCopy`` +
``Checksum`` so they are verified on parse and filled in on build.

The control field is one octet (IEC 62056-46, modulo-8 numbering). On a
link set up with SNRME (ISO/IEC 13239 extended numbering, modulo 128,
opt-in; IEC 62056-46 does not define it) I and S frames carry a two-octet
control field instead: the first octet holds the frame kind and N(S) (I) or
the supervisory bits (S) from bit 2, the second holds P/F in bit 1 and N(R)
in bits 2-8; U frames keep one octet (per ITU-T X.25 (10/96) Table 2-8 and
IBM SDLC Concepts GA27-3093-4 chapter 3; the ISO/IEC 13239 clause text was
not read). Nothing in the frame says which
numbering it uses, so :func:`decode_frame` and :class:`FrameReader` take the
link's ``modulus``. :class:`HdlcFrame` keeps the whole control field in
``control``: the first octet in the low byte and, when extended, the second
octet in the high byte.

DLMS information fields begin with the LLC header ``E6 E6 00`` (client to
server) or ``E6 E7 00`` (server to client) on I and UI frames that carry an
APDU; :func:`strip_llc` / :data:`LLC_REQUEST` handle it.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import IntEnum

import construct
from construct import (
    Bytes,
    Checksum,
    Const,
    Construct,
    Int16ub,
    Int16ul,
    RawCopy,
    Struct,
    this,
)

from pydlms.debug import TRACE, get_logger, hexstr
from pydlms.exceptions import ChecksumError, FramingError
from pydlms.hdlc.address import HdlcAddress, decode_address, read_address
from pydlms.hdlc.crc import crc16_x25

__all__ = [
    "FLAG",
    "LLC_REQUEST",
    "LLC_RESPONSE",
    "FrameType",
    "HdlcFrame",
    "HdlcFrameStruct",
    "encode_frame",
    "decode_frame",
    "FrameReader",
    "strip_llc",
    "control_i",
    "control_rr",
    "control_rnr",
    "control_rej",
    "control_octets",
    "SEQ_MODULUS",
    "MODULO_128",
    "MODULI",
    "check_modulus",
    "HdlcModeTracker",
    "seq_add",
    "seq_diff",
]

log = get_logger("hdlc")

FLAG = 0x7E
LLC_REQUEST = b"\xe6\xe6\x00"
LLC_RESPONSE = b"\xe6\xe7\x00"
_FORMAT_TYPE = 0xA000
_SEGMENT_BIT = 0x0800
_LENGTH_MASK = 0x07FF
PF_BIT = 0x10


class FrameType(IntEnum):
    """Unnumbered and supervisory control values with P/F cleared."""

    SNRM = 0x83
    #: Set normal response mode extended: modulo-128 numbering, ``110P 1111``
    #: written bit 8 first per IBM SDLC Concepts GA27-3093-4 Figure 19
    #: (ISO/IEC 13239 ``1111 P 011`` per cB-Sigma ``hdlc/control.go``).
    #: Opt-in only; IEC 62056-46 does not use it.
    SNRME = 0xCF
    DISC = 0x43
    UA = 0x63
    DM = 0x0F
    FRMR = 0x87
    UI = 0x03
    RR = 0x01
    RNR = 0x05
    #: Reject / selective reject (ISO/IEC 13239). pydlms never sends them;
    #: they are decoded so a meter that does is handled as a protocol event.
    REJ = 0x09
    SREJ = 0x0D
    I = 0x00  # noqa: E741 - the HDLC name


#: Sequence-number modulus of the one-octet control field: N(S) and N(R)
#: are three bits each (ISO/IEC 13239 modulo 8; the DLMS profile class is
#: "UNC, extended with UI frames" per IEC 62056-53:2006 annex B.2.2.2, which
#: leaves out extended numbering, option 10 of ISO 7809:1984 Table 1). Every sequence computation goes through :func:`seq_add` and
#: :func:`seq_diff` so a modulo-128 (SNRME) link only needs a wider control
#: field, not new arithmetic.
SEQ_MODULUS = 8
#: Extended (SNRME) numbering: N(S) and N(R) are seven bits each in a
#: two-octet control field on I and S frames.
MODULO_128 = 128
MODULI = (SEQ_MODULUS, MODULO_128)


def check_modulus(modulus: int) -> int:
    """Return ``modulus`` if it is 8 or 128, else raise ValueError."""
    if modulus not in MODULI:
        raise ValueError(f"HDLC sequence numbering is modulo 8 or 128, not {modulus}")
    return modulus


def seq_add(n: int, k: int = 1, modulus: int = SEQ_MODULUS) -> int:
    """``n + k`` in sequence space: the number ``k`` frames after ``n``
    (``k`` may be negative)."""
    return (n + k) % modulus


def seq_diff(a: int, b: int, modulus: int = SEQ_MODULUS) -> int:
    """How many frames lie from ``b`` up to (excluding) ``a``:
    ``(a - b) mod modulus``, in ``0..modulus-1``."""
    return (a - b) % modulus


def _extended_second(nr: int, poll: bool) -> int:
    """Second octet of a modulo-128 control field, placed in the high byte."""
    return (((nr % MODULO_128) << 1) | (1 if poll else 0)) << 8


def control_i(ns: int, nr: int, poll: bool = True, modulus: int = SEQ_MODULUS) -> int:
    """I-frame control field. Modulo 8: one octet ``N(R) P N(S) 0``;
    modulo 128: first octet ``N(S) 0`` (low byte), second ``N(R) P``
    (high byte). Numbers are reduced modulo ``modulus``."""
    if check_modulus(modulus) == MODULO_128:
        return ((ns % MODULO_128) << 1) | _extended_second(nr, poll)
    return ((nr % SEQ_MODULUS) << 5) | (PF_BIT if poll else 0) | ((ns % SEQ_MODULUS) << 1)


def _supervisory(code: int, nr: int, poll: bool, modulus: int) -> int:
    if check_modulus(modulus) == MODULO_128:
        return code | _extended_second(nr, poll)
    return ((nr % SEQ_MODULUS) << 5) | (PF_BIT if poll else 0) | code


def control_rr(nr: int, poll: bool = True, modulus: int = SEQ_MODULUS) -> int:
    """RR control field (see :func:`control_i` for the two layouts)."""
    return _supervisory(FrameType.RR, nr, poll, modulus)


def control_rnr(nr: int, poll: bool = True, modulus: int = SEQ_MODULUS) -> int:
    """RNR control field (see :func:`control_i` for the two layouts)."""
    return _supervisory(FrameType.RNR, nr, poll, modulus)


def control_rej(nr: int, poll: bool = True, modulus: int = SEQ_MODULUS) -> int:
    """REJ control field (see :func:`control_i` for the two layouts)."""
    return _supervisory(FrameType.REJ, nr, poll, modulus)


def _is_extended(control: int, modulus: int) -> bool:
    """A modulo-128 I or S frame: its first octet's bits 1 and 2 are not
    both 1 (U frames keep one octet)."""
    return modulus == MODULO_128 and control & 0x03 != 0x03


def control_octets(control: int, modulus: int = SEQ_MODULUS) -> bytes:
    """The control field ``control`` as sent: one octet, or two for an I or
    S frame under modulo 128 (first octet = low byte). A value that does
    not fit raises :class:`FramingError`."""
    check_modulus(modulus)
    if _is_extended(control, modulus):
        if not 0 <= control <= 0xFFFF:
            raise FramingError(f"HDLC control 0x{control:X} does not fit two octets")
        return bytes((control & 0xFF, control >> 8))
    if not 0 <= control <= 0xFF:
        raise FramingError(f"HDLC control 0x{control:X} does not fit one octet (modulo {modulus})")
    return bytes((control,))


def _context_modulus(context) -> int:
    params = context.get("_params") or {}
    return params.get("modulus", SEQ_MODULUS)


class _ControlField(Construct):
    """construct field for the control field: one octet, or two when the
    link numbers modulo 128 (passed as ``modulus=`` to parse/build) and the
    first octet starts an I or S frame."""

    def _parse(self, stream, context, path):
        first = construct.stream_read(stream, 1, path)[0]
        if _is_extended(first, _context_modulus(context)):
            return first | construct.stream_read(stream, 1, path)[0] << 8
        return first

    def _build(self, obj, stream, context, path):
        try:
            data = control_octets(obj, _context_modulus(context))
        except (FramingError, ValueError) as exc:
            raise construct.ConstructError(str(exc), path) from exc
        construct.stream_write(stream, data, len(data), path)
        return obj

    def _sizeof(self, context, path):
        raise construct.SizeofError("HDLC control field has a variable size", path=path)


class _HdlcAddressField(Construct):
    """construct field for a self-delimiting HDLC address (LSB = last octet)."""

    def _parse(self, stream, context, path):
        raw = bytearray()
        while True:
            octet = construct.stream_read(stream, 1, path)[0]
            raw.append(octet)
            if octet & 1:
                break
            if len(raw) >= 4:
                raise construct.ConstructError("HDLC address longer than 4 octets", path)
        try:
            return decode_address(bytes(raw))
        except FramingError as exc:
            raise construct.ConstructError(str(exc), path) from exc

    def _build(self, obj, stream, context, path):
        data = obj.to_bytes()
        construct.stream_write(stream, data, len(data), path)
        return obj

    def _sizeof(self, context, path):
        raise construct.SizeofError("HDLC address has a variable size", path=path)


_Header = Struct(
    "format" / Int16ub,
    "dest" / _HdlcAddressField(),
    "src" / _HdlcAddressField(),
    "control" / _ControlField(),
)


def _header_len(ctx) -> int:
    return len(ctx.header.data)


def _info_len(ctx) -> int:
    # length counts format..FCS: header + HCS(2) + info + FCS(2).
    total = ctx.header.value.format & _LENGTH_MASK
    return max(total - _header_len(ctx) - 4, 0)


def _has_info(ctx) -> bool:
    return (ctx.header.value.format & _LENGTH_MASK) > _header_len(ctx) + 2


#: The frame body between the flags, with both checksums verified on parse.
_Body = Struct(
    "header" / RawCopy(_Header),
    "hcs"
    / construct.If(
        _has_info,
        Checksum(Int16ul, crc16_x25, this.header.data),
    ),
    "info" / construct.IfThenElse(_has_info, Bytes(_info_len), construct.Computed(b"")),
    "fcs"
    / Checksum(
        Int16ul,
        crc16_x25,
        lambda ctx: (
            ctx.header.data
            + (ctx.hcs.to_bytes(2, "little") if ctx.hcs is not None else b"")
            + ctx.info
        ),
    ),
)

#: Full frame including both flags.
HdlcFrameStruct = Struct(
    Const(b"\x7e"),
    "body" / _Body,
    Const(b"\x7e"),
)


@dataclass
class HdlcFrame:
    """A decoded HDLC frame."""

    dest: HdlcAddress
    src: HdlcAddress
    control: int
    info: bytes = b""
    segmented: bool = False
    #: Sequence numbering of the link the frame belongs to (8 or 128). Under
    #: 128, ``control`` of an I or S frame holds two octets (see the module
    #: docstring).
    modulus: int = SEQ_MODULUS

    def __post_init__(self) -> None:
        check_modulus(self.modulus)

    @property
    def extended(self) -> bool:
        """The control field has two octets (modulo-128 I or S frame)."""
        return _is_extended(self.control, self.modulus)

    @property
    def control_octets(self) -> bytes:
        """The control field as sent."""
        return control_octets(self.control, self.modulus)

    @property
    def poll_final(self) -> bool:
        if self.extended:
            return bool(self.control >> 8 & 0x01)
        return bool(self.control & PF_BIT)

    @property
    def kind(self) -> FrameType:
        c = self.control & 0xFF if self.extended else self.control
        if c & 0x01 == 0:
            return FrameType.I
        if c & 0x03 == 0x01:
            return FrameType(c & 0x0F)  # RR / RNR / REJ / SREJ
        try:
            return FrameType(c & ~PF_BIT & 0xFF)
        except ValueError:
            raise FramingError(f"unsupported HDLC control 0x{c:02X}") from None

    @property
    def ns(self) -> int:
        """Send sequence number N(S) of an I-frame."""
        if self.extended:
            return (self.control >> 1) & 0x7F
        return (self.control >> 1) % SEQ_MODULUS

    @property
    def nr(self) -> int:
        """Receive sequence number N(R) of an I- or S-frame."""
        if self.extended:
            return (self.control >> 9) & 0x7F
        return (self.control >> 5) % SEQ_MODULUS

    def describe(self) -> str:
        try:
            kind = self.kind.name
        except FramingError:
            kind = f"0x{self.control:02X}"
        seq = ""
        if kind == "I":
            seq = f" N(S)={self.ns} N(R)={self.nr}"
        elif kind in ("RR", "RNR", "REJ", "SREJ"):
            seq = f" N(R)={self.nr}"
        seg = " SEG" if self.segmented else ""
        pf = " P/F" if self.poll_final else ""
        return f"{kind}{seq}{pf}{seg} {self.src}->{self.dest} info={len(self.info)}B"


def encode_frame(frame: HdlcFrame) -> bytes:
    """Build the wire bytes (with flags) for ``frame``."""
    dest = frame.dest.to_bytes()
    src = frame.src.to_bytes()
    control = control_octets(frame.control, frame.modulus)
    header_len = 2 + len(dest) + len(src) + len(control)
    length = header_len + 2 + (len(frame.info) + 2 if frame.info else 0)
    if length > _LENGTH_MASK:
        raise FramingError(f"HDLC frame of {length} octets exceeds the 11-bit length field")
    fmt = _FORMAT_TYPE | (_SEGMENT_BIT if frame.segmented else 0) | length
    obj = {
        "body": {
            "header": {
                "value": {
                    "format": fmt,
                    "dest": frame.dest,
                    "src": frame.src,
                    "control": frame.control,
                }
            },
            "hcs": None if not frame.info else 0,
            "info": frame.info,
            "fcs": 0,
        }
    }
    return HdlcFrameStruct.build(obj, modulus=frame.modulus)


def _repair_checksums(data: bytes, modulus: int = SEQ_MODULUS) -> bytes:
    """Rewrite HCS/FCS of ``data`` to the computed values (analysis only)."""
    raw = bytearray(data)
    pos = 3
    _, pos = read_address(raw, pos)
    _, pos = read_address(raw, pos)
    pos += 2 if _is_extended(raw[pos], modulus) else 1  # control
    length = int.from_bytes(raw[1:3], "big") & _LENGTH_MASK
    if length > pos + 1:  # has an information field, so an HCS follows
        raw[pos : pos + 2] = crc16_x25(bytes(raw[1:pos])).to_bytes(2, "little")
    raw[-3:-1] = crc16_x25(bytes(raw[1:-3])).to_bytes(2, "little")
    return bytes(raw)


def decode_frame(
    data: bytes, verify_checksums: bool = True, modulus: int = SEQ_MODULUS
) -> HdlcFrame:
    """Decode one complete frame (flags included). Verifies HCS and FCS.

    ``modulus`` is the numbering of the link (8, or 128 after SNRME): it
    decides whether an I or S frame has a one- or two-octet control field,
    which the frame does not say itself.

    ``verify_checksums=False`` accepts a frame with a wrong HCS/FCS (logged at
    WARNING). Never use it on a live link; it exists to analyse captures
    from sniffers that mangle checksums.
    """
    check_modulus(modulus)
    if len(data) < 9:
        raise FramingError(f"HDLC frame too short ({len(data)} octets)")
    if data[0] != FLAG or data[-1] != FLAG:
        raise FramingError("HDLC frame not delimited by 0x7E flags")
    fmt = int.from_bytes(data[1:3], "big")
    if fmt & 0xF000 != _FORMAT_TYPE:
        raise FramingError(f"HDLC frame format type 0x{fmt >> 12:X} is not 0xA")
    length = fmt & _LENGTH_MASK
    if length != len(data) - 2:
        raise FramingError(f"HDLC length field says {length}, frame has {len(data) - 2} octets")
    try:
        parsed = HdlcFrameStruct.parse(data, modulus=modulus)
    except construct.ChecksumError as exc:
        if verify_checksums:
            raise ChecksumError(f"HDLC checksum mismatch: {exc}") from exc
        log.warning("accepting HDLC frame with a bad checksum (verification disabled)")
        parsed = HdlcFrameStruct.parse(_repair_checksums(data, modulus), modulus=modulus)
    except construct.ConstructError as exc:
        raise FramingError(f"malformed HDLC frame: {exc}") from exc
    body = parsed.body
    header = body.header.value
    frame = HdlcFrame(
        dest=header.dest,
        src=header.src,
        control=header.control,
        info=bytes(body.info),
        segmented=bool(header.format & _SEGMENT_BIT),
        modulus=modulus,
    )
    return frame


def strip_llc(info: bytes) -> bytes:
    """Remove the ``E6 E6 00`` / ``E6 E7 00`` LLC header if present."""
    if info[:3] in (LLC_REQUEST, LLC_RESPONSE):
        return info[3:]
    return info


class HdlcModeTracker:
    """Follow the sequence numbering of a recorded or sniffed link.

    A capture does not say whether its I and S frames have one or two
    control octets; the mode-setting exchange does. Every decoded frame is
    passed to :meth:`observe`: an SNRME answered by UA switches to modulo
    128, an SNRM answered by UA back to 8; DM or FRMR leave the numbering
    as it was. Share one tracker between the readers of both directions so
    the client's SNRME and the meter's UA meet.
    """

    def __init__(self, modulus: int = SEQ_MODULUS) -> None:
        self.modulus = check_modulus(modulus)
        self._pending: int | None = None

    def observe(self, frame: HdlcFrame) -> None:
        try:
            kind = frame.kind
        except FramingError:
            return
        if kind == FrameType.SNRME:
            self._pending = MODULO_128
        elif kind == FrameType.SNRM:
            self._pending = SEQ_MODULUS
        elif kind == FrameType.UA and self._pending is not None:
            if self._pending != self.modulus:
                log.debug("HDLC capture switches to modulo %d", self._pending)
            self.modulus, self._pending = self._pending, None
        elif kind in (FrameType.DM, FrameType.FRMR, FrameType.DISC):
            self._pending = None


class FrameReader:
    """Incrementally extract HDLC frames from a byte stream.

    Bytes outside frames (line noise, a leading M-Bus short frame, the closing
    flag of a previous frame doubling as an opening flag) are skipped. A frame
    whose checksum fails is dropped and logged rather than raised, so one bad
    frame does not wedge a push listener; use :meth:`feed` with
    ``strict=True`` to raise instead.

    ``inter_octet`` (seconds) is the inter-octet time-out: when more than
    that passes between two :meth:`feed` calls while a frame is being
    received, the partial frame is dropped (counted in :attr:`dropped`) and
    the stream is scanned for the next opening flag. Per PJSC Rosseti STO
    34.01-5.1-006-2019 9.7 "exceeding the inter-octet time-out ends the
    reception of the frame" (time from a stop bit to the next start bit),
    and 7.4.15 (IC 23 attribute 7: after it, "all characters of the frame
    are taken as received"); a frame ended that way is incomplete, so it is
    dropped. IEC 62056-46 6.4.4.10.4 itself is not public. The time of
    a feed is its ``now`` argument, else ``clock()``. ``None`` turns the
    check off.

    ``modulus`` is the link's sequence numbering (8, or 128 after SNRME;
    set the attribute when it changes). A ``tracker``
    (:class:`HdlcModeTracker`) instead decides it frame by frame from the
    mode-setting frames seen, for captures.
    """

    def __init__(
        self,
        strict: bool = False,
        verify_checksums: bool = True,
        inter_octet: float | None = None,
        clock: Callable[[], float] = time.monotonic,
        modulus: int = SEQ_MODULUS,
        tracker: HdlcModeTracker | None = None,
    ) -> None:
        self.modulus = check_modulus(modulus)
        self.tracker = tracker
        if inter_octet is not None and not inter_octet > 0:
            raise ValueError(f"inter-octet time-out must be positive, got {inter_octet}")
        self._buf = bytearray()
        self.strict = strict
        self.verify_checksums = verify_checksums
        self.inter_octet = inter_octet
        self.clock = clock
        self._last: float | None = None
        self.dropped = 0

    def feed(self, data: bytes, now: float | None = None) -> list[HdlcFrame]:
        if self.inter_octet is not None:
            now = self.clock() if now is None else now
            if self._last is not None and now - self._last > self.inter_octet:
                self._drop_stale(now - self._last)
            self._last = now
        self._buf += data
        frames: list[HdlcFrame] = []
        while True:
            frame = self._next()
            if frame is None:
                return frames
            frames.append(frame)

    def _drop_stale(self, gap: float) -> None:
        """Forget a frame whose octets stopped arriving. A lone flag kept
        from the previous frame is no partial frame and is not counted."""
        if len(self._buf) > 1:
            self.dropped += 1
            log.debug(
                "dropping %d octets of a partial HDLC frame after a %.3fs gap: %s",
                len(self._buf),
                gap,
                hexstr(self._buf, 32),
            )
        self._buf.clear()

    def _next(self) -> HdlcFrame | None:
        buf = self._buf
        while True:
            start = buf.find(FLAG)
            if start < 0:
                buf.clear()
                return None
            if start:
                log.log(TRACE, "skipping %d octets before flag: %s", start, hexstr(buf[:start], 32))
                del buf[:start]
            if len(buf) < 3:
                return None
            fmt = int.from_bytes(buf[1:3], "big")
            if fmt & 0xF000 != _FORMAT_TYPE:
                # A flag followed by something that is not a frame header:
                # either a shared closing/opening flag or noise. Skip it.
                del buf[:1]
                continue
            length = fmt & _LENGTH_MASK
            if len(buf) < length + 2:
                return None
            if buf[length + 1] != FLAG:
                log.debug("HDLC length 0x%03X does not land on a flag; resyncing", length)
                del buf[:1]
                continue
            raw = bytes(buf[: length + 2])
            modulus = self.tracker.modulus if self.tracker is not None else self.modulus
            try:
                frame = decode_frame(raw, self.verify_checksums, modulus)
            except FramingError as exc:
                self.dropped += 1
                log.warning("dropping bad HDLC frame (%s): %s", exc, hexstr(raw, 48))
                del buf[:1]
                if self.strict:
                    raise
                continue
            # Keep the closing flag: it may double as the next opening flag.
            del buf[: length + 1]
            if self.tracker is not None:
                self.tracker.observe(frame)
            if log.isEnabledFor(TRACE):
                log.log(TRACE, "HDLC RX %s\n%s", frame.describe(), hexstr(raw))
            return frame
