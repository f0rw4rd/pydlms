"""Redact session recordings (``--record`` files) before they are shared.

A recording made at a meter holds what identifies that meter and its owner:
serial numbers, the logical device name, system titles, the LLS password or
HLS challenges sent in the AARQ/AARE, and whatever else the session read.
:func:`redact_recording` (``pydlms redact FILE``) replaces those values with
fixed placeholders of the same length, so every length field stays valid,
then rebuilds every HDLC frame (HCS/FCS) and wrapper PDU with the framing
constructs (:func:`pydlms.hdlc.framing.encode_frame`,
:func:`pydlms.wrapper.encode_wrapper`). The result still parses, decodes
(``pydlms decode --file``) and replays (``pydlms simulate --replay``).

What is replaced (placeholder ``REDACTED`` repeated or cut to length):

* values of identification objects, matched by the request that read or
  wrote them: ``0.b.96.1.e.255`` (device ID, serial number), ``a.b.0.0.e.255``
  for ``a`` 1..9 (identification numbers), and ``0.0.42.0.0.255`` (COSEM
  logical device name; its first three characters, the manufacturer FLAG id,
  are kept),
* identifying or secret attributes and method parameters by class
  (:data:`SENSITIVE_ATTRIBUTES`, :data:`SENSITIVE_METHODS`): system titles and
  certificates of Security setup, the association secret, HLS pass 3/4,
  key transfer, network addresses, phone numbers, APN and PIN,
* AARQ/AARE calling and responding AP titles (the FLAG id kept), AE
  qualifiers, the authentication value (LLS password, CtoS, StoC), a
  dedicated key in a plaintext InitiateRequest,
* system titles in the security header of general-glo/-ded-ciphering,
  general-ciphering and general-signing APDUs,
* every other occurrence of a value replaced above (and of values passed
  as ``also``) anywhere in a plaintext APDU,
* the HDLC physical (lower) server address, which some vendors derive from
  the serial number (:data:`pydlms.hdlc.address.SERIAL_ADDRESS_RULES`).

What is dropped (only counts are logged, never the values):

* raw (``TX``/``RX``) AARQ, AARE, RLRQ/RLRE with user information, HLS pass
  3/4 and ciphered APDUs, unless the caller states the session used test keys
  (``test_keys=True``); ``drop_raw_auth=True`` drops them regardless. The
  plaintext ``*-APDU`` lines replay the session without them.
* anything that cannot be classified with certainty: an APDU that does not
  parse where a sensitive value is expected, Short-Name reads of an address
  no recorded object list explains, a sensitive value in a block transfer
  form that is not reassembled here, pushes (their payload layout is not in
  the recording), bytes outside any frame, incomplete segmented APDUs, and
  all comment lines.

Redacting a redacted recording changes nothing. Ciphered APDUs kept under
``test_keys`` no longer decipher (the system title is part of the IV), and
their plaintext stays readable to anyone holding the test keys: a test-key
session must not read anything that may not be published.
"""

from __future__ import annotations

import dataclasses
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

from pydlms.apdu.acse import AARE, AARQ, RLRE, RLRQ
from pydlms.apdu.gbt import decode_gbt
from pydlms.apdu.tags import Tag
from pydlms.apdu.xdlms import _Reader
from pydlms.axdr import decode_length
from pydlms.cosem.data import MAX_NESTING, decode_data
from pydlms.cosem.enums import DataType
from pydlms.cosem.interface_classes import ClassId
from pydlms.exceptions import DecodeError, DlmsError
from pydlms.hdlc.address import HdlcAddress
from pydlms.hdlc.framing import (
    FLAG,
    LLC_REQUEST,
    LLC_RESPONSE,
    FrameType,
    HdlcFrame,
    decode_frame,
    encode_frame,
)
from pydlms.obis import ObisCode
from pydlms.recording import parse_recording
from pydlms.security.ciphering import is_ciphered_apdu
from pydlms.sn_methods import method_offset
from pydlms.wrapper import HEADER_SIZE, decode_header, encode_wrapper

__all__ = [
    "PLACEHOLDER",
    "PHYSICAL_PLACEHOLDER",
    "SENSITIVE_ATTRIBUTES",
    "SENSITIVE_METHODS",
    "ScrubLog",
    "placeholder",
    "redact_records",
    "redact_recording",
]

#: Pattern every replaced value is filled with (repeated or cut to length).
PLACEHOLDER = b"REDACTED"
#: HDLC lower (physical) server address written in place of the meter's.
PHYSICAL_PLACEHOLDER = 0x11

HEADER = (
    "# pydlms recording v1: TX/RX raw buffers, TX-APDU/RX-APDU plaintext APDUs\n"
    "# redacted by pydlms redact: identifiers, system titles and authentication "
    "values replaced by same-length placeholders"
)

_C = ClassId

#: ``(class_id, attribute) -> what`` whose value is replaced wherever it is read
#: or written. Attribute numbers follow pydlms.cosem.interface_classes (Blue
#: Book attribute order; attribute 1 is the logical name).
SENSITIVE_ATTRIBUTES: dict[tuple[int, int], str] = {
    (_C.ASSOCIATION_LN, 7): "association secret",
    (_C.ASSOCIATION_LN, 10): "association user list",
    (_C.ASSOCIATION_LN, 11): "association user",
    (_C.ASSOCIATION_SN, 5): "association user list",
    (_C.ASSOCIATION_SN, 6): "association user",
    (_C.SECURITY_SETUP, 4): "system title",
    (_C.SECURITY_SETUP, 5): "system title",
    (_C.SECURITY_SETUP, 6): "certificate information",
    (_C.MODEM_CONFIGURATION, 3): "modem initialisation string",
    (_C.AUTO_ANSWER, 7): "allowed callers",
    (_C.AUTO_CONNECT, 6): "connection destination",
    (_C.PUSH_SETUP, 3): "push destination",
    (_C.IPV4_SETUP, 3): "network address",
    (_C.IPV4_SETUP, 4): "network address",
    (_C.IPV4_SETUP, 7): "network address",
    (_C.IPV4_SETUP, 9): "network address",
    (_C.IPV4_SETUP, 10): "network address",
    (_C.IPV6_SETUP, 4): "network address",
    (_C.IPV6_SETUP, 5): "network address",
    (_C.IPV6_SETUP, 6): "network address",
    (_C.IPV6_SETUP, 7): "network address",
    (_C.IPV6_SETUP, 8): "network address",
    (_C.MAC_ADDRESS_SETUP, 2): "network address",
    (_C.PPP_SETUP, 5): "PPP authentication",
    (_C.GPRS_MODEM_SETUP, 2): "APN",
    (_C.GPRS_MODEM_SETUP, 3): "PIN code",
    (_C.SMTP_SETUP, 3): "SMTP account",
    (_C.SMTP_SETUP, 4): "SMTP account",
    (_C.SMTP_SETUP, 5): "network address",
    (_C.SMTP_SETUP, 6): "network address",
    (_C.GSM_DIAGNOSTIC, 2): "mobile operator",
    (_C.GSM_DIAGNOSTIC, 6): "mobile cell",
    (_C.GSM_DIAGNOSTIC, 7): "mobile cell",
    (_C.MBUS_CLIENT, 6): "serial number",
}

#: ``(class_id, method) -> what`` whose parameters and return data are replaced.
#: Methods marked as authentication (HLS pass 3/4) are also dropped from raw
#: lines like the AARQ/AARE.
SENSITIVE_METHODS: dict[tuple[int, int], str] = {
    (_C.ASSOCIATION_LN, 1): "HLS pass 3/4",
    (_C.ASSOCIATION_LN, 2): "HLS secret",
    (_C.ASSOCIATION_SN, 5): "LLS secret",
    (_C.ASSOCIATION_SN, 6): "HLS secret",
    (_C.ASSOCIATION_SN, 8): "HLS pass 3/4",
    (_C.SECURITY_SETUP, 2): "key transfer",
    (_C.SECURITY_SETUP, 3): "key agreement",
    (_C.SECURITY_SETUP, 6): "certificate",
    (_C.SECURITY_SETUP, 7): "certificate",
}
_AUTH_METHODS = {(_C.ASSOCIATION_LN, 1), (_C.ASSOCIATION_SN, 8)}

_SN_ASSOCIATION_BASE = 0xFA00
_ASSOCIATION_SN_OBIS = ObisCode(0, 0, 40, 0, 0, 255)

# Content sizes of the fixed-width COSEM data types (IEC 62056-6-2 Data CHOICE,
# as decoded by pydlms.cosem.data).
_FIXED = {
    DataType.INTEGER: 1,
    DataType.UNSIGNED: 1,
    DataType.BCD: 1,
    DataType.LONG: 2,
    DataType.LONG_UNSIGNED: 2,
    DataType.DOUBLE_LONG: 4,
    DataType.DOUBLE_LONG_UNSIGNED: 4,
    DataType.FLOAT32: 4,
    DataType.LONG64: 8,
    DataType.LONG64_UNSIGNED: 8,
    DataType.FLOAT64: 8,
    DataType.DATE_TIME: 12,
    DataType.DATE: 5,
    DataType.TIME: 4,
    DataType.DELTA_INTEGER: 1,
    DataType.DELTA_UNSIGNED: 1,
    DataType.DELTA_LONG: 2,
    DataType.DELTA_LONG_UNSIGNED: 2,
    DataType.DELTA_DOUBLE_LONG: 4,
    DataType.DELTA_DOUBLE_LONG_UNSIGNED: 4,
}
# Kept as they are: one octet of state, not identity.
_KEPT = {DataType.BOOLEAN: 1, DataType.ENUM: 1, DataType.NULL: 0, DataType.DONT_CARE: 0}
_STRINGS = (DataType.OCTET_STRING, DataType.VISIBLE_STRING, DataType.UTF8_STRING)

Loc = tuple[int, int]  # (record index, octet offset)


def placeholder(length: int) -> bytes:
    """The fixed placeholder of ``length`` octets."""
    return (PLACEHOLDER * (length // len(PLACEHOLDER) + 1))[:length]


def _keep_flag(value: bytes) -> bytes:
    """Placeholder that keeps a leading three-letter manufacturer FLAG id."""
    if len(value) > 3 and value[:3].isalpha() and value[:3].isupper():
        return value[:3] + placeholder(len(value) - 3)
    return placeholder(len(value))


@dataclass
class ScrubLog:
    """What a redaction replaced and dropped: counts by category, no values."""

    replaced: Counter = field(default_factory=Counter)
    dropped: Counter = field(default_factory=Counter)

    def lines(self) -> list[str]:
        out = [f"replaced {n} x {what}" for what, n in sorted(self.replaced.items())]
        out += [f"dropped {n} x {what}" for what, n in sorted(self.dropped.items())]
        return out or ["nothing to redact"]

    def __str__(self) -> str:
        return "\n".join(self.lines())


@dataclass(frozen=True)
class _Sens:
    what: str
    keep_flag: bool = False
    auth: bool = False
    #: The value cannot be classified: drop what carries it.
    drop: bool = False


_UNCLASSIFIED_SN = _Sens("unclassified Short-Name value", drop=True)

#: Plaintext APDUs that carry no value of the session: kept as they are.
_NOTHING_TO_REDACT = {
    Tag.INITIATE_RESPONSE,
    Tag.WRITE_RESPONSE,
    Tag.CONFIRMED_SERVICE_ERROR,
    Tag.EXCEPTION_RESPONSE,
}


class _Drop(Exception):
    """Internal: drop the APDU being redacted, for the given reason."""


@dataclass
class _Container:
    """One record line, HDLC frame or wrapper PDU, as positions in the records."""

    kind: str
    locs: list[Loc]
    payload: list[Loc] = field(default_factory=list)
    frame: HdlcFrame | None = None
    source: int = 0
    destination: int = 0


@dataclass
class _Unit:
    """One APDU with the record positions of each of its octets."""

    data: bytes
    locs: list[Loc]
    containers: list[int]
    raw: bool


@dataclass
class _Buffer:
    """A value spread over several block-transfer APDUs."""

    sens: list
    data: bytearray = field(default_factory=bytearray)
    locs: list[Loc] = field(default_factory=list)


@dataclass
class _Context:
    """Request/response pairing of one layer (plaintext lines or raw frames)."""

    pending: dict[int, tuple[str, list]] = field(default_factory=dict)
    blocks: dict[int, _Buffer] = field(default_factory=dict)
    dropping: dict[int, str] = field(default_factory=dict)
    sn_map: dict[int, tuple[int, ObisCode, int]] = field(default_factory=dict)
    sn_pending: list = field(default_factory=list)
    sn_block: _Buffer | None = None


def attribute_rule(class_id: int, obis: ObisCode, attribute: int) -> _Sens | None:
    a, b, c, d, e, f = obis.groups
    if attribute == 2:
        if obis == ObisCode(0, 0, 42, 0, 0, 255):
            return _Sens("logical device name", keep_flag=True)
        if a == 0 and c == 96 and d == 1 and f == 255:
            return _Sens("serial number")
        if 1 <= a <= 9 and c == 0 and d == 0 and f == 255:
            return _Sens("serial number")
    what = SENSITIVE_ATTRIBUTES.get((int(class_id), attribute))
    if what is None:
        return None
    return _Sens(what, keep_flag=what == "system title")


def method_rule(class_id: int, method: int) -> _Sens | None:
    what = SENSITIVE_METHODS.get((int(class_id), method))
    if what is None:
        return None
    return _Sens(what, auth=(int(class_id), method) in _AUTH_METHODS)


class _Redactor:
    def __init__(self, records, test_keys: bool, drop_raw_auth: bool, also: Iterable[bytes]):
        self.records = [(d, bytes(b)) for d, b in records]
        self.drop_auth = drop_raw_auth or not test_keys
        self.log = ScrubLog()
        self.containers: list[_Container] = []
        self.units: list[_Unit] = []
        self.patch: dict[Loc, int] = {}
        self.dropped: set[int] = set()
        self.unframed: set[Loc] = set()
        self.values: dict[bytes, bytes] = {}
        for value in also:
            if len(value) >= 4:
                self.values[bytes(value)] = placeholder(len(value))
        self.contexts = {False: _Context(), True: _Context()}

    # -- splitting the recording into APDUs --------------------------------------
    def collect(self) -> None:
        streams: dict[str | None, list[Loc]] = {}
        for i, (direction, data) in enumerate(self.records):
            locs = [(i, k) for k in range(len(data))]
            if not data:
                continue
            if direction in ("TX-APDU", "RX-APDU"):
                cid = self._container(_Container("line", locs, locs))
                self.units.append(_Unit(data, locs, [cid], raw=False))
            else:
                streams.setdefault(direction, []).extend(locs)
        for locs in streams.values():
            data = bytes(self.records[i][1][k] for i, k in locs)
            first = self.records[locs[0][0]][1]
            framing = self._framing(first, data)
            gbt: list = []
            if framing == "hdlc":
                emitted = self._hdlc(data, locs)
            elif framing == "wrapper":
                emitted = self._wrapper(data, locs)
            else:
                emitted = []
                for record in sorted({i for i, _ in locs}):
                    rlocs = [loc for loc in locs if loc[0] == record]
                    cid = self._container(_Container("line", rlocs, rlocs))
                    emitted.append(_Unit(self.records[record][1], rlocs, [cid], True))
            for unit in emitted:
                self._gbt(unit, gbt)
            if gbt:
                self._drop_unit(
                    _Unit(b"", [], [c for u in gbt for c in u.containers], True),
                    "incomplete block transfer",
                )
        self.units.sort(key=lambda u: max(self.containers[c].locs[-1] for c in u.containers))

    def _container(self, container: _Container) -> int:
        self.containers.append(container)
        return len(self.containers) - 1

    @staticmethod
    def _framing(first: bytes, data: bytes) -> str:
        if first[:1] == b"\x68" and len(first) > 3 and first[3] == 0x68:
            raise DecodeError("redact does not handle M-Bus recordings")
        if first[:1] == bytes([FLAG]):
            return "hdlc"
        if first[:2] == b"\x00\x01":
            return "wrapper"
        if any(_frame_at(data, i)[0] for i in range(len(data)) if data[i] == FLAG):
            return "hdlc"  # e.g. an optical sign-on before the HDLC frames
        return "apdu"

    def _hdlc(self, data: bytes, locs: list[Loc]) -> list[_Unit]:
        units = []
        covered = [False] * len(data)
        segments: _Unit | None = None
        i = 0
        while i < len(data):
            frame, end = _frame_at(data, i)
            if frame is None:
                i += 1
                continue
            info_start = end - 3 - len(frame.info)
            cid = self._container(
                _Container("hdlc", locs[i:end], locs[info_start : end - 3], frame=frame)
            )
            covered[i:end] = [True] * (end - i)
            if frame.info and _carries_apdu(frame):
                info, ilocs = frame.info, locs[info_start : end - 3]
                if segments is None:
                    skip = 3 if info[:3] in (LLC_REQUEST, LLC_RESPONSE) else 0
                    segments = _Unit(info[skip:], ilocs[skip:], [cid], True)
                else:
                    segments = _Unit(
                        segments.data + info,
                        segments.locs + ilocs,
                        segments.containers + [cid],
                        True,
                    )
                if not frame.segmented:
                    units.append(segments)
                    segments = None
            # Frames may share a flag: the closing flag opens the next frame.
            i = end if end >= len(data) or data[end] == FLAG else end - 1
        if segments is not None:
            self._drop_unit(segments, "incomplete segmented APDU")
        self._unframed(data, locs, covered)
        return units

    def _wrapper(self, data: bytes, locs: list[Loc]) -> list[_Unit]:
        units = []
        covered = [False] * len(data)
        i = 0
        while len(data) - i >= HEADER_SIZE:
            try:
                header = decode_header(data[i : i + HEADER_SIZE])
            except DlmsError:
                break
            end = i + HEADER_SIZE + header.length
            if end > len(data):
                break
            plocs = locs[i + HEADER_SIZE : end]
            cid = self._container(
                _Container("wrapper", locs[i:end], plocs, None, header.source, header.destination)
            )
            covered[i:end] = [True] * (end - i)
            if end > i + HEADER_SIZE:
                units.append(_Unit(data[i + HEADER_SIZE : end], plocs, [cid], True))
            i = end
        self._unframed(data, locs, covered)
        return units

    def _unframed(self, data: bytes, locs: list[Loc], covered: list[bool]) -> None:
        stray = [k for k, c in enumerate(covered) if not c]
        self.unframed.update(locs[k] for k in stray)
        if any(data[k] != FLAG for k in stray):
            self.log.dropped["unframed or damaged raw octets"] += 1

    def _gbt(self, unit: _Unit, pending: list) -> None:
        if unit.data[:1] != bytes([Tag.GENERAL_BLOCK_TRANSFER]):
            self.units.append(unit)
            return
        try:
            block = decode_gbt(unit.data)
            _, start = decode_length(unit.data, 6)
        except DlmsError:
            self._drop_unit(unit, "malformed block transfer")
            return
        pending.append(_Unit(unit.data[start:], unit.locs[start:], unit.containers, True))
        if block.last:
            self.units.append(
                _Unit(
                    b"".join(u.data for u in pending),
                    [loc for u in pending for loc in u.locs],
                    [c for u in pending for c in u.containers],
                    True,
                )
            )
            pending.clear()

    # -- redaction -------------------------------------------------------------------
    def run(self) -> list[tuple[str | None, bytes]]:
        self.collect()
        for unit in self.units:
            try:
                self._unit(unit)
            except _Drop as reason:
                self._drop_unit(unit, str(reason))
            except (DlmsError, ValueError, IndexError):
                self._drop_unit(unit, "APDU that does not parse")
        self._sweep()
        return self._output()

    def _drop_unit(self, unit: _Unit, reason: str) -> None:
        self.dropped.update(unit.containers)
        self.log.dropped[reason] += 1

    def _replace(
        self, data: bytes, locs: list[Loc], start: int, end: int, what: str, keep_flag: bool = False
    ) -> None:
        if end > len(data) or start > end:
            raise DecodeError("value runs past the end of the APDU")
        value = bytes(data[start:end])
        new = _keep_flag(value) if keep_flag else placeholder(len(value))
        for loc, octet in zip(locs[start:end], new, strict=True):
            self.patch[loc] = octet
        if new != value:
            self.log.replaced[what] += 1
            if len(value) >= 4 and len(set(value)) >= 3:
                self.values.setdefault(value, new)

    def _unit(self, unit: _Unit) -> None:
        data, locs = unit.data, unit.locs
        tag = data[0]
        try:
            Tag(tag)
        except ValueError:
            raise _Drop("unrecognised APDU") from None
        if tag in (Tag.AARQ, Tag.AARE, Tag.RLRQ, Tag.RLRE):
            has_user_info = self._acse(data, locs)
            if unit.raw and self.drop_auth and (tag in (Tag.AARQ, Tag.AARE) or has_user_info):
                raise _Drop("raw AARQ/AARE/RLRQ/RLRE")
            return
        if is_ciphered_apdu(data):
            self._ciphered(data, locs, 0, len(data), self.contexts[unit.raw])
            if unit.raw and self.drop_auth:
                raise _Drop("raw ciphered APDU")
            return
        if tag in (
            Tag.DATA_NOTIFICATION,
            Tag.EVENT_NOTIFICATION_REQUEST,
            Tag.INFORMATION_REPORT_REQUEST,
        ):
            raise _Drop("push notification (payload layout unknown)")
        auth = self._service(data, locs, self.contexts[unit.raw])
        if auth and unit.raw and self.drop_auth:
            raise _Drop("raw HLS pass 3/4")

    # ACSE --------------------------------------------------------------------------
    def _acse(self, data: bytes, locs: list[Loc]) -> bool:
        codec = {Tag.AARQ: AARQ, Tag.AARE: AARE, Tag.RLRQ: RLRQ, Tag.RLRE: RLRE}[data[0]]
        codec.from_bytes(data)  # refuse what does not parse as the APDU it claims to be
        ((_, start, end),) = _ber(data, 0, len(data))
        user_info = False
        for tag, vstart, vend in _ber(data, start, end):
            if tag in (0xA6, 0xA4):
                (_, s, e), *_ = _ber(data, vstart, vend)
                self._replace(data, locs, s, e, "system title (AP title)", keep_flag=True)
            elif tag in (0xA7, 0xA5):
                (_, s, e), *_ = _ber(data, vstart, vend)
                self._replace(data, locs, s, e, "AE qualifier")
            elif tag in (0xAC, 0xAA):
                (_, s, e), *_ = _ber(data, vstart, vend)
                self._replace(data, locs, s, e, "LLS password / HLS challenge")
            elif tag == 0xBE:
                user_info = True
                (_, s, e), *_ = _ber(data, vstart, vend)
                self._user_information(data, locs, s, e)
        return user_info

    def _user_information(self, data: bytes, locs: list[Loc], start: int, end: int) -> None:
        if start >= end:
            return
        if data[start] == Tag.INITIATE_REQUEST and end - start > 2 and data[start + 1] == 1:
            length, pos = decode_length(data, start + 2)
            self._replace(data, locs, pos, pos + length, "dedicated key")
        elif is_ciphered_apdu(data[start:end]):
            self._ciphered(data, locs, start, end, None)

    # ciphered envelopes ------------------------------------------------------------
    def _ciphered(self, data, locs, start: int, end: int, ctx: _Context | None) -> None:
        tag = data[start]
        what = "system title (security header)"
        if tag in (Tag.GENERAL_GLO_CIPHERING, Tag.GENERAL_DED_CIPHERING):
            length, pos = decode_length(data, start + 1)
            self._replace(data, locs, pos, pos + length, what, keep_flag=True)
        elif tag in (Tag.GENERAL_CIPHERING, Tag.GENERAL_SIGNING):
            r = _Reader(data[:end], start + 1)
            r.octets()  # transaction-id
            for _ in range(2):  # originator, recipient
                length = r.length()
                self._replace(data, locs, r.pos, r.pos + length, what, keep_flag=True)
                r.take(length)
            if tag == Tag.GENERAL_SIGNING:
                r.octets()  # date-time
                r.octets()  # other-information
                length = r.length()
                content = r.pos
                r.take(length)
                if length and ctx is not None:
                    inner = data[content : content + length]
                    ilocs = locs[content : content + length]
                    if is_ciphered_apdu(inner):
                        self._ciphered(inner, ilocs, 0, length, ctx)
                    else:
                        self._service(inner, ilocs, ctx)

    # xDLMS services ------------------------------------------------------------------
    def _service(self, data: bytes, locs: list[Loc], ctx: _Context) -> bool:
        """Redact one plaintext service APDU; True for HLS pass 3/4."""
        tag = data[0]
        if tag in (Tag.GET_REQUEST, Tag.SET_REQUEST, Tag.ACTION_REQUEST):
            return self._request(data, locs, ctx)
        if tag in (Tag.GET_RESPONSE, Tag.SET_RESPONSE, Tag.ACTION_RESPONSE):
            return self._response(data, locs, ctx)
        if tag in (Tag.READ_REQUEST, Tag.WRITE_REQUEST, Tag.UNCONFIRMED_WRITE_REQUEST):
            return self._sn_request(data, locs, ctx)
        if tag == Tag.READ_RESPONSE:
            return self._sn_response(data, locs, ctx)
        if tag == Tag.INITIATE_REQUEST:
            self._user_information(data, locs, 0, len(data))
            return False
        if tag in _NOTHING_TO_REDACT:
            return False
        # ACCESS and anything else whose layout is not walked here.
        raise _Drop("APDU not classified by redact")

    def _value(self, sens: _Sens | None, data, locs, pos: int) -> int:
        """Redact the Data at ``pos`` as ``sens`` says; return its end."""
        if sens is None:
            return decode_data(data, pos)[1]
        if sens.drop:
            raise _Drop(sens.what)
        if sens.keep_flag and data[pos] in _STRINGS:
            length, start = decode_length(data, pos + 1)
            self._replace(data, locs, start, start + length, sens.what, keep_flag=True)
            return start + length
        spans, end = _leaves(data, pos)
        for start, stop in spans:
            self._replace(data, locs, start, stop, sens.what)
        return end

    def _request(self, data, locs, ctx: _Context) -> bool:
        tag, choice, iid = data[0], data[1], data[2] & 0x0F
        r = _Reader(data, 3)
        if tag == Tag.GET_REQUEST:
            if choice == 1:
                ctx.pending[iid] = ("get", [_descriptor(r)])
                _access_selection(r)
            elif choice == 3:
                rules = []
                for _ in range(r.length()):
                    rules.append(_descriptor(r))
                    _access_selection(r)
                ctx.pending[iid] = ("get", rules)
            return False
        if tag == Tag.SET_REQUEST:
            if choice == 1:
                sens = _descriptor(r)
                _access_selection(r)
                self._value(sens, data, locs, r.pos)
            elif choice == 4:
                rules = []
                for _ in range(r.length()):
                    rules.append(_descriptor(r))
                    _access_selection(r)
                count = r.length()
                for k in range(count):
                    r.pos = self._value(rules[k] if k < len(rules) else None, data, locs, r.pos)
            elif choice in (2, 5):  # first datablock: not reassembled here
                count = 1 if choice == 2 else r.length()
                rules = []
                for _ in range(count):
                    rules.append(_descriptor(r))
                    _access_selection(r)
                self._first_block(rules, r.u8() != 0, iid, ctx)
            elif choice == 3:
                self._next_block(data[3] != 0, iid, ctx)
            return False
        # ACTION
        if choice == 1:
            sens = _method(r)
            ctx.pending[iid] = ("action", [sens])
            if r.optional():
                self._value(sens, data, locs, r.pos)
            return bool(sens and sens.auth)
        if choice == 3:
            rules = [_method(r) for _ in range(r.length())]
            ctx.pending[iid] = ("action", rules)
            for k in range(r.length()):
                r.pos = self._value(rules[k] if k < len(rules) else None, data, locs, r.pos)
            return any(s and s.auth for s in rules)
        if choice in (4, 5):  # first parameter block: not reassembled here
            rules = [_method(r) for _ in range(1 if choice == 4 else r.length())]
            ctx.pending[iid] = ("action", rules)
            self._first_block(rules, r.u8() != 0, iid, ctx)
        elif choice == 6:
            self._next_block(data[3] != 0, iid, ctx)
        return False

    @staticmethod
    def _first_block(rules: list, last: bool, iid: int, ctx: _Context) -> None:
        if any(rules):
            if not last:
                ctx.dropping[iid] = "sensitive value in a block transfer"
            raise _Drop("sensitive value in a block transfer")

    @staticmethod
    def _next_block(last: bool, iid: int, ctx: _Context) -> None:
        if iid in ctx.dropping:
            reason = ctx.dropping.pop(iid) if last else ctx.dropping[iid]
            raise _Drop(reason)

    def _response(self, data, locs, ctx: _Context) -> bool:
        tag, choice, iid = data[0], data[1], data[2] & 0x0F
        r = _Reader(data, 3)
        if tag == Tag.SET_RESPONSE:
            return False
        _, rules = ctx.pending.get(iid, ("", []))
        if tag == Tag.GET_RESPONSE:
            if choice == 1:
                ctx.pending.pop(iid, None)
                if r.u8() == 0 and _at(rules, 0) is not None:
                    self._value(rules[0], data, locs, r.pos)
            elif choice == 3:
                ctx.pending.pop(iid, None)
                for k in range(r.length()):
                    if r.u8() == 0:
                        r.pos = self._value(_at(rules, k), data, locs, r.pos)
                    else:
                        r.u8()
            elif choice == 2:
                last = r.u8() != 0
                r.u32()
                if r.u8() != 0:  # data-access-result: the transfer ended
                    ctx.pending.pop(iid, None)
                    ctx.blocks.pop(iid, None)
                    return False
                length = r.length()
                if r.pos + length > len(data):
                    raise DecodeError("raw-data runs past the end of the APDU")
                if not any(rules):  # nothing to redact: no need to reassemble
                    if last:
                        ctx.pending.pop(iid, None)
                    return False
                buffer = ctx.blocks.setdefault(iid, _Buffer(rules))
                buffer.data += data[r.pos : r.pos + length]
                buffer.locs += locs[r.pos : r.pos + length]
                if last:
                    ctx.pending.pop(iid, None)
                    ctx.blocks.pop(iid)
                    self._block_value(buffer)
            return False
        # ACTION-Response
        if choice == 1:
            ctx.pending.pop(iid, None)
            sens = _at(rules, 0)
            r.u8()  # action-result
            if r.optional() and r.u8() == 0:
                self._value(sens, data, locs, r.pos)
            return bool(sens and sens.auth)
        if choice == 3:
            ctx.pending.pop(iid, None)
            for k in range(r.length()):
                r.u8()
                if r.optional():
                    if r.u8() == 0:
                        r.pos = self._value(_at(rules, k), data, locs, r.pos)
                    else:
                        r.u8()
            return any(s and s.auth for s in rules)
        if choice == 2 and any(rules):  # with-pblock: not reassembled here
            if data[3] != 0:
                ctx.pending.pop(iid, None)
            raise _Drop("sensitive value in a block transfer")
        return False

    def _block_value(self, buffer: _Buffer) -> None:
        data, locs = bytes(buffer.data), buffer.locs
        if len(buffer.sens) <= 1:
            self._value(_at(buffer.sens, 0), data, locs, 0)
            return
        r = _Reader(data, 0)
        for k in range(r.length()):
            if r.u8() == 0:
                r.pos = self._value(_at(buffer.sens, k), data, locs, r.pos)
            else:
                r.u8()

    # Short-Name services ---------------------------------------------------------------
    def _sn_rule(self, ctx: _Context, name: int) -> _Sens | None:
        if _SN_ASSOCIATION_BASE <= name < _SN_ASSOCIATION_BASE + 0x100:
            base, (class_id, version) = _SN_ASSOCIATION_BASE, (_C.ASSOCIATION_SN, 0)
        else:
            bases = [b for b in ctx.sn_map if b <= name < b + 0x100]
            if not bases:
                return _UNCLASSIFIED_SN
            base = max(bases)
            class_id, _, version = ctx.sn_map[base]
        offset = name - base
        if offset % 8:
            return _UNCLASSIFIED_SN
        first_method = method_offset(class_id, version)
        if first_method is not None and offset >= first_method:
            return method_rule(class_id, (offset - first_method) // 8 + 1)
        if class_id == _C.ASSOCIATION_SN and base == _SN_ASSOCIATION_BASE and offset == 8:
            return _Sens("object list")  # marker, not redacted: read to learn the map
        obis = ctx.sn_map[base][1] if base in ctx.sn_map else _ASSOCIATION_SN_OBIS
        return attribute_rule(class_id, obis, offset // 8 + 1)

    def _sn_spec(self, r: _Reader, ctx: _Context) -> tuple[_Sens | None, int | None]:
        choice = r.u8()
        if choice == 2:
            return self._sn_rule(ctx, r.u16()), None
        if choice == 4:
            name = r.u16()
            r.u8()
            sens = self._sn_rule(ctx, name)
            return sens, r.pos  # the parameter Data starts here
        if choice == 5:  # block-number-access: continues the pending transfer
            r.u16()
            return None, -1
        raise DecodeError(f"unsupported variable-access-specification choice {choice}")

    def _sn_request(self, data, locs, ctx: _Context) -> bool:
        r = _Reader(data, 1)
        specs = []
        auth = False
        for _ in range(r.length()):
            sens, param = self._sn_spec(r, ctx)
            if param is not None and param >= 0:
                r.pos = self._value(_real(sens), data, locs, param)
            specs.append((sens, param))
            auth |= bool(sens and sens.auth)
        if data[0] == Tag.READ_REQUEST:
            if not (len(specs) == 1 and specs[0][1] == -1):  # not a next-block request
                ctx.sn_pending = [s for s, _ in specs]
                ctx.sn_block = None
            return auth
        for k in range(r.length()):
            r.pos = self._value(_real(_at([s for s, _ in specs], k)), data, locs, r.pos)
        return auth

    def _sn_response(self, data, locs, ctx: _Context) -> bool:
        r = _Reader(data, 1)
        rules = ctx.sn_pending
        auth = any(s and s.auth for s in rules)
        for k in range(r.length()):
            choice = r.u8()
            sens = _at(rules, k)
            if choice == 0:
                start = r.pos
                r.pos = self._value(_real(sens), data, locs, r.pos)
                if sens is not None and sens.what == "object list":
                    self._learn_sn_map(ctx, data[start : r.pos])
            elif choice == 1:
                r.u8()
            elif choice == 2:
                last = r.u8() != 0
                r.u16()
                length = r.length()
                if r.pos + length > len(data):
                    raise DecodeError("raw-data runs past the end of the APDU")
                if ctx.sn_block is None:
                    ctx.sn_block = _Buffer([sens])
                ctx.sn_block.data += data[r.pos : r.pos + length]
                ctx.sn_block.locs += locs[r.pos : r.pos + length]
                r.take(length)
                if last:
                    buffer, ctx.sn_block = ctx.sn_block, None
                    first = _at(buffer.sens, 0)
                    self._value(_real(first), bytes(buffer.data), buffer.locs, 0)
                    if first is not None and first.what == "object list":
                        self._learn_sn_map(ctx, bytes(buffer.data))
            elif choice == 3:
                r.u16()
            else:
                raise DecodeError(f"unknown ReadResponse choice {choice}")
        return auth

    @staticmethod
    def _learn_sn_map(ctx: _Context, encoded: bytes) -> None:
        value, _ = decode_data(encoded)
        for entry in value.value or []:
            base, class_id, version, name = (v.value for v in entry.value[:4])
            ctx.sn_map[base & 0xFFFF] = (class_id, ObisCode.from_bytes(name), version)

    # -- the sweep and the output -------------------------------------------------------
    def _sweep(self) -> None:
        values = sorted(self.values.items(), key=lambda kv: -len(kv[0]))
        for unit in self.units:
            if not unit.data or is_ciphered_apdu(unit.data):
                continue
            if any(c in self.dropped for c in unit.containers):
                continue
            for value, new in values:
                start = unit.data.find(value)
                while start != -1:
                    span = unit.locs[start : start + len(value)]
                    if not any(loc in self.patch for loc in span):
                        for loc, octet in zip(span, new, strict=True):
                            self.patch[loc] = octet
                        self.log.replaced["value seen elsewhere in the session"] += 1
                    start = unit.data.find(value, start + 1)

    def _octet(self, loc: Loc) -> int:
        return self.patch.get(loc, self.records[loc[0]][1][loc[1]])

    def _output(self) -> list[tuple[str | None, bytes]]:
        kept: set[Loc] = set()
        delete = set(self.unframed)
        for cid, container in enumerate(self.containers):
            if cid in self.dropped:
                delete.update(container.locs)
            else:
                kept.update(container.locs)
                self._rebuild(container)
        delete -= kept
        out = []
        for i, (direction, data) in enumerate(self.records):
            body = bytes(self._octet((i, k)) for k in range(len(data)) if (i, k) not in delete)
            if body:
                out.append((direction, body))
        return out

    def _rebuild(self, container: _Container) -> None:
        payload = bytes(self._octet(loc) for loc in container.payload)
        if container.kind == "hdlc":
            frame = container.frame
            assert frame is not None
            dest, src = self._address(frame.dest), self._address(frame.src)
            if (dest, src) != (frame.dest, frame.src):
                self.log.replaced["HDLC physical address"] += 1
            new = encode_frame(dataclasses.replace(frame, dest=dest, src=src, info=payload))
        elif container.kind == "wrapper":
            new = encode_wrapper(container.source, container.destination, payload)
        else:
            return
        if len(new) != len(container.locs):  # pragma: no cover - same-length placeholders
            raise DecodeError("rebuilt frame changed its length")
        for loc, octet in zip(container.locs, new, strict=True):
            if octet != self.records[loc[0]][1][loc[1]]:
                self.patch[loc] = octet
            else:
                self.patch.pop(loc, None)

    @staticmethod
    def _address(address: HdlcAddress) -> HdlcAddress:
        if address.size == 1 or address.lower == PHYSICAL_PLACEHOLDER:
            return address
        return dataclasses.replace(address, lower=PHYSICAL_PLACEHOLDER)


# -- helpers ------------------------------------------------------------------------------


def _frame_at(data: bytes, i: int) -> tuple[HdlcFrame | None, int]:
    """The HDLC frame starting at ``data[i]`` (checksums verified), or None."""
    if data[i] != FLAG or i + 3 > len(data):
        return None, i
    fmt = int.from_bytes(data[i + 1 : i + 3], "big")
    if fmt & 0xF000 != 0xA000:
        return None, i
    end = i + (fmt & 0x07FF) + 2
    if end > len(data):
        return None, i
    # The numbering is not in the frame: a modulo-128 (SNRME) I or S frame
    # fails the modulo-8 HCS check and is tried with two control octets.
    for modulus in (8, 128):
        try:
            return decode_frame(data[i:end], modulus=modulus), end
        except DlmsError:
            continue
    return None, i


def _carries_apdu(frame: HdlcFrame) -> bool:
    try:
        return frame.kind in (FrameType.I, FrameType.UI)
    except DlmsError:
        return False


def _ber(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    """BER TLVs in ``data[start:end]`` as ``(tag, value_start, value_end)``.

    The same rules as :func:`pydlms.apdu.acse.parse_ber`, keeping offsets.
    """
    items = []
    pos = start
    while pos < end:
        if pos + 2 > end:
            raise DecodeError("truncated BER TLV")
        tag, first = data[pos], data[pos + 1]
        pos += 2
        if first < 0x80:
            length = first
        else:
            n = first & 0x7F
            if n == 0 or n > 4 or pos + n > end:
                raise DecodeError("bad BER length")
            length = int.from_bytes(data[pos : pos + n], "big")
            pos += n
        if pos + length > end:
            raise DecodeError(f"BER value of tag 0x{tag:02X} runs past the end")
        items.append((tag, pos, pos + length))
        pos += length
    if not items:
        raise DecodeError("empty BER field")
    return items


def _leaves(data: bytes, pos: int, depth: int = 0) -> tuple[list[tuple[int, int]], int]:
    """Content spans of every identifying leaf of the Data at ``pos``."""
    if pos >= len(data):
        raise DecodeError("COSEM data truncated")
    try:
        tag = DataType(data[pos])
    except ValueError:
        raise DecodeError(f"unknown COSEM data type tag 0x{data[pos]:02X}") from None
    pos += 1
    if tag in (DataType.ARRAY, DataType.STRUCTURE):
        if depth >= MAX_NESTING:
            raise DecodeError("COSEM data nested too deep")
        count, pos = decode_length(data, pos)
        spans = []
        for _ in range(count):
            inner, pos = _leaves(data, pos, depth + 1)
            spans += inner
        return spans, pos
    if tag in _KEPT:
        end = pos + _KEPT[tag]
        spans = []
    elif tag in _FIXED:
        end = pos + _FIXED[tag]
        spans = [(pos, end)]
    elif tag in _STRINGS:
        length, pos = decode_length(data, pos)
        end = pos + length
        spans = [(pos, end)]
    elif tag == DataType.BIT_STRING:
        bits, pos = decode_length(data, pos)
        end = pos + (bits + 7) // 8
        spans = [(pos, end)]
    else:  # compact-array: element boundaries need the type description
        raise _Drop("sensitive value in a compact array")
    if end > len(data):
        raise DecodeError("COSEM data truncated")
    return spans, end


def _descriptor(r: _Reader) -> _Sens | None:
    class_id = r.u16()
    obis = ObisCode.from_bytes(r.take(6))
    return attribute_rule(class_id, obis, r.u8())


def _method(r: _Reader) -> _Sens | None:
    class_id = r.u16()
    r.take(6)
    return method_rule(class_id, r.u8())


def _access_selection(r: _Reader) -> None:
    if r.optional():
        r.u8()
        r.data_value()


def _at(rules: list, index: int):
    return rules[index] if index < len(rules) else None


def _real(sens: _Sens | None) -> _Sens | None:
    """The object-list marker is read, not redacted."""
    return None if sens is not None and sens.what == "object list" else sens


def redact_records(
    records: Iterable[tuple[str | None, bytes]],
    *,
    test_keys: bool = False,
    drop_raw_auth: bool = False,
    also: Iterable[bytes] = (),
) -> tuple[list[tuple[str | None, bytes]], ScrubLog]:
    """Redact parsed recording records (:func:`pydlms.recording.parse_recording`).

    ``test_keys``: the session ran with keys that may be published, so raw
    AARQ/AARE and ciphered APDUs are kept (their secrets replaced).
    ``drop_raw_auth`` drops them anyway. ``also``: further values (4 octets or
    more) to replace wherever they appear in a plaintext APDU.
    Raises :class:`~pydlms.exceptions.DecodeError` for recordings it cannot
    take apart safely (M-Bus framing).
    """
    redactor = _Redactor(list(records), test_keys, drop_raw_auth, also)
    return redactor.run(), redactor.log


def redact_recording(text: str, **kwargs) -> tuple[str, ScrubLog]:
    """Redact recording text; returns the new text and the :class:`ScrubLog`.

    Comment lines are not copied: they are free text and may hold anything.
    Keyword arguments as for :func:`redact_records`.
    """
    records, log = redact_records(parse_recording(text), **kwargs)
    lines = [HEADER] + [
        f"{direction} {data.hex()}" if direction else data.hex() for direction, data in records
    ]
    return "\n".join(lines) + "\n", log
