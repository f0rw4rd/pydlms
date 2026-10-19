"""M-Bus long frames carrying DLMS (EN 13757-2 link layer, DLMS transport).

Customer interfaces in Austria and elsewhere (Kaifa MA309M, Netz NÖ P1,
Sagemcom on some ports) push DLMS APDUs wrapped in M-Bus long frames::

    68 L L 68 | C | A | CI | STSAP | DTSAP | data ... | CS | 16

* ``L`` counts C through the end of the data (so the frame is ``L + 6``).
* ``CS`` is the sum modulo 256 of C through the end of the data.
* ``CI`` 0x00..0x1F selects the DLMS transport with segmentation: the low
  nibble is the segment sequence number, bit 4 (0x10) marks the final
  segment. ``0x10`` therefore is an unsegmented APDU; Kaifa sends
  ``0x00`` then ``0x11``. After 1111 the sequence rolls over to 0000 while
  segments remain (Vorarlberg Netz / Honeywell "KSMWest H1 interface",
  2018, p. 6; single source), so an APDU is not limited to 16 segments.
* ``STSAP``/``DTSAP`` (source/destination transport SAPs, e.g. 0x01/0x67) are
  present in *every* segment; observed in the Netz NÖ capture where segment 2
  repeats ``01 67``.

CI 0x60/0x61 (to the meter) and 0x7C/0x7D (from the meter) carry one whole
APDU behind an M-Bus data header instead (no segmentation)::

    68 L L 68 | C | A | CI | header | STSAP | DTSAP | data ... | CS | 16

* long header (0x60, 0x7C), 12 octets: identification (4, BCD, LSB first),
  manufacturer (2, LSB first), version, device type, access number, status,
  configuration (2, LSB first);
* short header (0x61, 0x7D), 4 octets: access number, status, configuration.

Source: OMS Vol. 2 Issue 5.0.1 Table 1, Annex D.2/D.3 and 7.2.4 Table 18;
octet sizes and byte order from its Annex N example N.2.2; IEC 62056-7-3:2017
Figure 2 for the DLMS use of the four CIs. The transport SAPs after the header
follow from the MBUS-DATA primitives of IEC 62056-7-3 5.4.2 (STSAP/DTSAP for
every header type). A configuration field
whose security mode (bits 12..8) is not 0 means M-Bus-layer encryption, which
DLMS does not use: such frames are refused with :class:`FramingError`.

A single-character ``E5`` and short frames ``10 C A CS 16`` may appear on the
line and are skipped.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

import construct
from construct import (
    Byte,
    Bytes,
    Checksum,
    Const,
    Int8ub,
    Int16ul,
    Int32ul,
    Pass,
    RawCopy,
    Struct,
    Switch,
    this,
)

from pydlms.debug import TRACE, get_logger, hexstr
from pydlms.exceptions import ChecksumError, FramingError

__all__ = [
    "MbusFrame",
    "MbusTransportHeader",
    "MbusLongFrame",
    "MbusLongHeader",
    "MbusShortHeader",
    "encode_mbus_frame",
    "decode_mbus_frame",
    "MbusReader",
    "segment_apdu",
]

log = get_logger("mbus")

START_LONG = 0x68
START_SHORT = 0x10
STOP = 0x16
SINGLE_ACK = 0xE5
CI_FINAL = 0x10
MAX_USER_DATA = 252  # L <= 255 = C + A + CI + 2 SAPs + data

# CI values with an M-Bus data header (OMS Vol. 2 Table 1; IEC 62056-7-3 Fig. 2).
CI_LONG_DOWN = 0x60
CI_SHORT_DOWN = 0x61
CI_LONG_UP = 0x7C
CI_SHORT_UP = 0x7D
#: CI -> (long header, direction).
HEADER_CI = {
    CI_LONG_DOWN: (True, "down"),
    CI_SHORT_DOWN: (False, "down"),
    CI_LONG_UP: (True, "up"),
    CI_SHORT_UP: (False, "up"),
}
LONG_HEADER_SIZE = 12
SHORT_HEADER_SIZE = 4

#: Long M-Bus data header (OMS Vol. 2 Annex D.3; sizes from Annex N N.2.2).
MbusLongHeader = Struct(
    "identification" / Int32ul,
    "manufacturer" / Int16ul,
    "version" / Int8ub,
    "device_type" / Int8ub,
    "access_number" / Int8ub,
    "status" / Int8ub,
    "configuration" / Int16ul,
)

#: Short M-Bus data header (OMS Vol. 2 Annex D.2).
MbusShortHeader = Struct(
    "access_number" / Int8ub,
    "status" / Int8ub,
    "configuration" / Int16ul,
)


def _is_dlms_ci(ci: int) -> bool:
    return ci <= 0x1F or ci in HEADER_CI


def _header_size(ci: int) -> int:
    if ci not in HEADER_CI:
        return 0
    return LONG_HEADER_SIZE if HEADER_CI[ci][0] else SHORT_HEADER_SIZE


@dataclass
class MbusTransportHeader:
    """The M-Bus data header of a CI 0x60/0x61/0x7C/0x7D frame.

    ``direction`` is ``"down"`` (master to slave, CI 0x60/0x61) or ``"up"``
    (slave to master, CI 0x7C/0x7D). The four address fields are present
    only in the long header. ``identification`` is the raw little-endian
    value, so its hex digits are the BCD identification number.
    """

    direction: str
    access_number: int
    status: int
    configuration: int
    identification: int | None = None
    manufacturer: int | None = None
    version: int | None = None
    device_type: int | None = None

    def __post_init__(self) -> None:
        if self.direction not in ("down", "up"):
            raise ValueError(f"direction must be 'down' or 'up', not {self.direction!r}")

    @property
    def long(self) -> bool:
        return self.identification is not None

    @property
    def security_mode(self) -> int:
        """Configuration field bits 12..8 (OMS Vol. 2 7.2.4.1 Table 18); 0 = none."""
        return (self.configuration >> 8) & 0x1F

    @property
    def identification_number(self) -> str | None:
        return None if self.identification is None else f"{self.identification:08X}"


@dataclass
class MbusFrame:
    control: int
    address: int
    ci: int
    stsap: int
    dtsap: int
    data: bytes
    #: M-Bus data header for CI 0x60/0x61/0x7C/0x7D, ``None`` for 0x00..0x1F.
    header: MbusTransportHeader | None = None

    @property
    def sequence(self) -> int:
        return 0 if self.ci in HEADER_CI else self.ci & 0x0F

    @property
    def final(self) -> bool:
        return self.ci in HEADER_CI or bool(self.ci & CI_FINAL)


def _checksum(data: bytes) -> int:
    return sum(data) & 0xFF


#: construct definition of a DLMS-carrying M-Bus long frame; the checksum is
#: verified on parse and computed on build. ``header`` is a Switch on CI:
#: long or short M-Bus data header, nothing for the segmented 0x00..0x1F form.
MbusLongFrame = Struct(
    Const(b"\x68"),
    "length"
    / construct.Rebuild(
        Int8ub,
        lambda ctx: 5 + _header_size(ctx.body["value"]["ci"]) + len(ctx.body["value"]["data"]),
    ),
    "length2" / construct.Rebuild(Int8ub, this.length),
    Const(b"\x68"),
    "body"
    / RawCopy(
        Struct(
            "control" / Byte,
            "address" / Byte,
            "ci" / Byte,
            "header"
            / Switch(
                this.ci,
                {
                    CI_LONG_DOWN: MbusLongHeader,
                    CI_LONG_UP: MbusLongHeader,
                    CI_SHORT_DOWN: MbusShortHeader,
                    CI_SHORT_UP: MbusShortHeader,
                },
                default=Pass,
            ),
            "stsap" / Byte,
            "dtsap" / Byte,
            "data" / Bytes(lambda ctx: ctx._.length - 5 - _header_size(ctx.ci)),
        )
    ),
    "checksum" / Checksum(Byte, _checksum, this.body.data),
    Const(b"\x16"),
)


def _header_dict(ci: int, header: MbusTransportHeader | None) -> dict | None:
    if ci not in HEADER_CI:
        if header is not None:
            raise ValueError(f"M-Bus CI 0x{ci:02X} carries no data header")
        return None
    long, direction = HEADER_CI[ci]
    if header is None:
        raise ValueError(f"M-Bus CI 0x{ci:02X} needs a data header")
    if header.long != long:
        raise ValueError(f"M-Bus CI 0x{ci:02X} needs a {'long' if long else 'short'} header")
    if header.direction != direction:
        raise ValueError(
            f"M-Bus CI 0x{ci:02X} is direction {direction}, header says {header.direction}"
        )
    if header.security_mode:
        raise ValueError(f"M-Bus security mode {header.security_mode} is not supported")
    out = {
        "access_number": header.access_number,
        "status": header.status,
        "configuration": header.configuration,
    }
    if long:
        out.update(
            identification=header.identification,
            manufacturer=header.manufacturer,
            version=header.version,
            device_type=header.device_type,
        )
    return out


def encode_mbus_frame(frame: MbusFrame) -> bytes:
    """Build one long frame; ``frame.header`` must match the CI (none for 0x00..0x1F)."""
    if not _is_dlms_ci(frame.ci):
        raise ValueError(f"M-Bus CI 0x{frame.ci:02X} is not a DLMS transport CI")
    header = _header_dict(frame.ci, frame.header)
    room = 250 - _header_size(frame.ci)
    if len(frame.data) > room:
        raise ValueError(f"M-Bus long frame data of {len(frame.data)} octets exceeds L=255")
    try:
        return MbusLongFrame.build(
            {
                "body": {
                    "value": {
                        "control": frame.control,
                        "address": frame.address,
                        "ci": frame.ci,
                        "header": header,
                        "stsap": frame.stsap,
                        "dtsap": frame.dtsap,
                        "data": frame.data,
                    }
                }
            }
        )
    except construct.ConstructError as exc:
        raise ValueError(f"cannot build M-Bus frame: {exc}") from exc


def _transport_header(ci: int, parsed) -> MbusTransportHeader | None:
    if ci not in HEADER_CI:
        return None
    long, direction = HEADER_CI[ci]
    header = MbusTransportHeader(
        direction, parsed.access_number, parsed.status, parsed.configuration
    )
    if long:
        header.identification = parsed.identification
        header.manufacturer = parsed.manufacturer
        header.version = parsed.version
        header.device_type = parsed.device_type
    return header


def decode_mbus_frame(raw: bytes) -> MbusFrame:
    """Decode one complete long frame and verify its checksum."""
    if len(raw) < 11:
        raise FramingError(f"M-Bus long frame too short ({len(raw)} octets)")
    if raw[0] != START_LONG or raw[3] != START_LONG:
        raise FramingError("M-Bus long frame must start with 68 L L 68")
    if raw[1] != raw[2]:
        raise FramingError(f"M-Bus length octets disagree: {raw[1]} != {raw[2]}")
    length = raw[1]
    if len(raw) != length + 6:
        raise FramingError(f"M-Bus L={length} implies {length + 6} octets, got {len(raw)}")
    if raw[-1] != STOP:
        raise FramingError("M-Bus frame does not end with 0x16")
    if length < 5:
        raise FramingError("M-Bus frame too short for CI and transport SAPs")
    body = raw[4 : 4 + length]
    if _checksum(body) != raw[-2]:
        raise ChecksumError(f"M-Bus checksum 0x{raw[-2]:02X}, computed 0x{_checksum(body):02X}")
    ci = raw[6]
    if not _is_dlms_ci(ci):
        raise FramingError(f"M-Bus CI 0x{ci:02X} is not a DLMS transport CI")
    size = _header_size(ci)
    if length < 5 + size:
        raise FramingError(
            f"M-Bus CI 0x{ci:02X} needs a {size}-octet data header and two SAPs, "
            f"L={length} leaves {length - 3}"
        )
    try:
        parsed = MbusLongFrame.parse(raw)
    except construct.ChecksumError as exc:  # pragma: no cover - checked above
        raise ChecksumError("M-Bus checksum did not verify") from exc
    except construct.ConstructError as exc:
        raise FramingError(f"malformed M-Bus frame: {exc}") from exc
    fields = parsed.body.value
    header = _transport_header(ci, fields.header)
    if header is not None and header.security_mode:
        raise FramingError(
            f"M-Bus CI 0x{ci:02X} configuration 0x{header.configuration:04X} selects "
            f"security mode {header.security_mode} (M-Bus-layer encryption); refusing to "
            "pass ciphertext up as a DLMS APDU"
        )
    return MbusFrame(
        fields.control,
        fields.address,
        ci,
        fields.stsap,
        fields.dtsap,
        bytes(fields.data),
        header,
    )


def segment_apdu(
    apdu: bytes,
    control: int = 0x53,
    address: int = 0xFF,
    stsap: int = 0x01,
    dtsap: int = 0x67,
    max_data: int = 245,
) -> list[bytes]:
    """Split an APDU into M-Bus long frames (the inverse of :class:`MbusReader`)."""
    if not 1 <= max_data <= 250:
        raise ValueError("max_data must be 1..250")
    chunks = [apdu[i : i + max_data] for i in range(0, len(apdu), max_data)] or [b""]
    frames = []
    for seq, chunk in enumerate(chunks):
        # The 4-bit sequence rolls over from 15 to 0 (KSMWest H1 p. 6).
        ci = (seq & 0x0F) | (CI_FINAL if seq == len(chunks) - 1 else 0)
        frames.append(encode_mbus_frame(MbusFrame(control, address, ci, stsap, dtsap, chunk)))
    return frames


class MbusReader:
    """Extract frames from a byte stream and reassemble segmented APDUs.

    The segment sequence rolls over after 15, so the number of segments is
    unbounded; ``max_apdu_size`` (default 65535, the largest
    max-receive-pdu-size an AARQ can state) caps a reassembly instead, and
    ``dropped_apdus`` counts the ones discarded for it.
    """

    def __init__(self, max_apdu_size: int = 0xFFFF) -> None:
        self._buf = bytearray()
        self._segments: list[MbusFrame] = []
        self._size = 0
        self.max_apdu_size = max_apdu_size
        self.dropped = 0
        self.dropped_apdus = 0

    def feed(self, data: bytes) -> list[bytes]:
        """Feed octets; return every APDU completed by them."""
        self._buf += data
        apdus = []
        for frame in self._frames():
            apdu = self._add(frame)
            if apdu is not None:
                apdus.append(apdu)
        return apdus

    def _add(self, frame: MbusFrame) -> bytes | None:
        if frame.header is not None:
            if self._segments:
                log.warning(
                    "M-Bus: unsegmented CI 0x%02X frame, discarding %d buffered segment(s)",
                    frame.ci,
                    len(self._segments),
                )
                self._segments = []
                self._size = 0
            log.debug(
                "M-Bus CI=0x%02X %s header (%s) ACC=0x%02X SAP %d->%d, %d octets",
                frame.ci,
                "long" if frame.header.long else "short",
                frame.header.direction,
                frame.header.access_number,
                frame.stsap,
                frame.dtsap,
                len(frame.data),
            )
            return frame.data
        expected = len(self._segments) & 0x0F  # rolls over after 15
        if frame.sequence != expected:
            if frame.sequence == 0:
                log.warning(
                    "M-Bus: new APDU started, discarding %d stale segment(s)",
                    len(self._segments),
                )
            else:
                log.warning(
                    "M-Bus: segment %d out of order (expected %d), discarding",
                    frame.sequence,
                    expected,
                )
                self._segments = []
                self._size = 0
                return None
            self._segments = []
            self._size = 0
        self._size += len(frame.data)
        if self._size > self.max_apdu_size:
            log.warning(
                "M-Bus: reassembly exceeds %d octets after %d segment(s), discarding",
                self.max_apdu_size,
                len(self._segments) + 1,
            )
            self._segments = []
            self._size = 0
            self.dropped_apdus += 1
            return None
        self._segments.append(frame)
        log.debug(
            "M-Bus segment %d%s CI=0x%02X SAP %d->%d, %d octets",
            frame.sequence,
            " (final)" if frame.final else "",
            frame.ci,
            frame.stsap,
            frame.dtsap,
            len(frame.data),
        )
        if not frame.final:
            return None
        apdu = b"".join(s.data for s in self._segments)
        self._segments = []
        self._size = 0
        log.log(TRACE, "M-Bus reassembled APDU (%d octets): %s", len(apdu), hexstr(apdu, 64))
        return apdu

    def _frames(self) -> Iterator[MbusFrame]:
        buf = self._buf
        while buf:
            first = buf[0]
            if first == SINGLE_ACK:
                del buf[:1]
                continue
            if first == START_SHORT:
                if len(buf) < 5:
                    return
                if buf[4] == STOP:
                    del buf[:5]
                    continue
                del buf[:1]
                continue
            if first != START_LONG:
                start = buf.find(START_LONG)
                skipped = len(buf) if start < 0 else start
                log.log(TRACE, "M-Bus: skipping %d octets of noise", skipped)
                del buf[:skipped]
                continue
            if len(buf) < 4:
                return
            if buf[3] != START_LONG or buf[1] != buf[2]:
                del buf[:1]
                continue
            total = buf[1] + 6
            if len(buf) < total:
                return
            raw = bytes(buf[:total])
            try:
                frame = decode_mbus_frame(raw)
            except FramingError as exc:
                self.dropped += 1
                log.warning("dropping bad M-Bus frame (%s): %s", exc, hexstr(raw, 32))
                del buf[:1]
                continue
            del buf[:total]
            yield frame
