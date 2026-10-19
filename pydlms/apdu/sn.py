"""Short-Name referencing services (IEC 62056-5-3, 9.3.x; legacy meters).

Objects are addressed by a 16-bit *base name*; attribute ``n`` of an object
lives at ``base_name + 8 * (n - 1)`` and methods at class-specific offsets.

* ReadRequest ``05`` / ReadResponse ``0C``
* WriteRequest ``06`` / WriteResponse ``0D``
* UnconfirmedWriteRequest ``16``, InformationReportRequest ``18``

variable-access-specification CHOICE: ``02`` variable-name, ``04``
parameterized-access, ``05`` block-number-access, ``06``
read-data-block-access, ``07`` write-data-block-access.

A Read or Write request too long for the server's PDU travels in blocks
(service-specific block transfer is available for Read and Write and each
block is acknowledged before the next, DLMS UA 1000-2 Ed. 9 Excerpt
9.1.4.4.5; the block content is not in the excerpt, *unverified*): the
request after its APDU tag (the item count, the
variable-access-specifications and, for Write, the list of data) is cut
into ``raw-data`` parts sent as ``ReadRequest {read-data-block-access}`` or
``WriteRequest {write-data-block-access}`` plus one octet-string per block.
The server acknowledges each non-final block with ``block-number`` and
answers the reassembled request after the last one. The layout of both
CHOICEs follows the jDLMS ASN.1 classes ``ReadDataBlockAccess`` /
``WriteDataBlockAccess``; the reassembled content and the octet-string in
the list of data follow the GuruxDLMS servers (``svr_handleReadDataBlockAccess``),
which pass the joined octets to their normal Read / Write handler.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import construct
from construct import Int8ub, Int16ub, Struct

from pydlms.apdu.tags import Tag
from pydlms.apdu.xdlms import _Reader
from pydlms.axdr import encode_length
from pydlms.cosem.data import DlmsData, encode_data
from pydlms.cosem.enums import DataAccessResult
from pydlms.exceptions import DecodeError

__all__ = [
    "VariableName",
    "ParameterizedAccess",
    "BlockNumberAccess",
    "ReadDataBlockAccess",
    "WriteDataBlockAccess",
    "ReadRequest",
    "ReadResult",
    "ReadResponse",
    "WriteRequest",
    "WriteResponse",
    "WriteBlockNumber",
    "UnconfirmedWriteRequest",
    "InformationReportRequest",
    "decode_sn_apdu",
    "attribute_address",
]


def attribute_address(base_name: int, attribute: int) -> int:
    """SN address of attribute ``attribute`` (1-based) of the object at ``base_name``."""
    return (base_name + 8 * (attribute - 1)) & 0xFFFF


@dataclass(frozen=True)
class VariableName:
    name: int

    def to_bytes(self) -> bytes:
        return b"\x02" + self.name.to_bytes(2, "big")


@dataclass(frozen=True)
class ParameterizedAccess:
    name: int
    selector: int
    parameter: DlmsData

    def to_bytes(self) -> bytes:
        return (
            b"\x04"
            + self.name.to_bytes(2, "big")
            + bytes([self.selector])
            + encode_data(self.parameter)
        )


@dataclass(frozen=True)
class BlockNumberAccess:
    block_number: int

    def to_bytes(self) -> bytes:
        return b"\x05" + self.block_number.to_bytes(2, "big")


#: ``last-block BOOLEAN, block-number Unsigned16`` shared by both data-block
#: accesses (jDLMS ``ReadDataBlockAccess`` / ``WriteDataBlockAccess``).
_BlockHeader = Struct("last_block" / Int8ub, "block_number" / Int16ub)
#: Highest SN block number (Unsigned16).
MAX_SN_BLOCK_NUMBER = 0xFFFF


def _check_block_number(number: int) -> None:
    if not 0 <= number <= MAX_SN_BLOCK_NUMBER:
        raise ValueError(f"SN block number {number} is not an Unsigned16")


def _block_header(last_block: bool, block_number: int) -> bytes:
    return _BlockHeader.build({"last_block": int(last_block), "block_number": block_number})


def _read_block_header(r: _Reader) -> tuple[bool, int]:
    try:
        header = _BlockHeader.parse(r.take(_BlockHeader.sizeof()))
    except construct.ConstructError as exc:  # pragma: no cover - take() checks the length
        raise DecodeError(f"malformed data-block-access header: {exc}") from exc
    if header.last_block not in (0, 1):
        raise DecodeError(f"last-block BOOLEAN must be 0 or 1, got {header.last_block}")
    return bool(header.last_block), header.block_number


@dataclass(frozen=True)
class ReadDataBlockAccess:
    """``read-data-block-access [6]``: one part of a long ReadRequest."""

    last_block: bool
    block_number: int
    raw_data: bytes

    def __post_init__(self) -> None:
        _check_block_number(self.block_number)

    def to_bytes(self) -> bytes:
        return (
            b"\x06"
            + _block_header(self.last_block, self.block_number)
            + encode_length(len(self.raw_data))
            + self.raw_data
        )


@dataclass(frozen=True)
class WriteDataBlockAccess:
    """``write-data-block-access [7]``: one part of a long WriteRequest; the
    part itself is the request's single octet-string in the list of data."""

    last_block: bool
    block_number: int

    def __post_init__(self) -> None:
        _check_block_number(self.block_number)

    def to_bytes(self) -> bytes:
        return b"\x07" + _block_header(self.last_block, self.block_number)


def _read_spec(r: _Reader):
    choice = r.u8()
    if choice == 2:
        return VariableName(r.u16())
    if choice == 4:
        name = r.u16()
        selector = r.u8()
        return ParameterizedAccess(name, selector, r.data_value())
    if choice == 5:
        return BlockNumberAccess(r.u16())
    if choice == 6:
        last, number = _read_block_header(r)
        return ReadDataBlockAccess(last, number, r.octets())
    if choice == 7:
        return WriteDataBlockAccess(*_read_block_header(r))
    raise DecodeError(f"unsupported variable-access-specification choice {choice}")


@dataclass
class ReadRequest:
    items: list = field(default_factory=list)

    def to_bytes(self) -> bytes:
        return (
            bytes([Tag.READ_REQUEST])
            + encode_length(len(self.items))
            + b"".join(i.to_bytes() for i in self.items)
        )


@dataclass
class ReadResult:
    """One ReadResponse item: data, error, data-block-result or block-number."""

    data: DlmsData | None = None
    error: DataAccessResult | int | None = None
    block_last: bool | None = None
    block_number: int | None = None
    raw_data: bytes | None = None

    def to_bytes(self) -> bytes:
        if self.error is not None:
            return bytes([1, int(self.error)])
        if self.raw_data is not None:
            assert self.block_number is not None
            return (
                bytes([2, int(bool(self.block_last))])
                + self.block_number.to_bytes(2, "big")
                + encode_length(len(self.raw_data))
                + self.raw_data
            )
        if self.data is None and self.block_number is not None:
            return b"\x03" + self.block_number.to_bytes(2, "big")
        assert self.data is not None
        return b"\x00" + encode_data(self.data)


@dataclass
class ReadResponse:
    results: list[ReadResult]

    def to_bytes(self) -> bytes:
        return (
            bytes([Tag.READ_RESPONSE])
            + encode_length(len(self.results))
            + b"".join(r.to_bytes() for r in self.results)
        )


@dataclass
class WriteRequest:
    items: list
    values: list[DlmsData]

    def to_bytes(self) -> bytes:
        return (
            bytes([Tag.WRITE_REQUEST])
            + encode_length(len(self.items))
            + b"".join(i.to_bytes() for i in self.items)
            + encode_length(len(self.values))
            + b"".join(encode_data(v) for v in self.values)
        )


@dataclass
class UnconfirmedWriteRequest(WriteRequest):
    def to_bytes(self) -> bytes:
        return bytes([Tag.UNCONFIRMED_WRITE_REQUEST]) + super().to_bytes()[1:]


@dataclass(frozen=True)
class WriteBlockNumber:
    """WriteResponse ``block-number [2]``: the meter accepted block ``block_number``."""

    block_number: int


@dataclass
class WriteResponse:
    """WriteResponse: per item ``success``, a data-access-error or a block number."""

    results: list[DataAccessResult | int | WriteBlockNumber]

    def to_bytes(self) -> bytes:
        out = bytearray([Tag.WRITE_RESPONSE]) + encode_length(len(self.results))
        for result in self.results:
            if isinstance(result, WriteBlockNumber):
                out += b"\x02" + result.block_number.to_bytes(2, "big")
            elif result == DataAccessResult.SUCCESS:
                out += b"\x00"
            else:
                out += bytes([1, int(result)])
        return bytes(out)


#: Length of the GeneralizedTime (COSEM date-time) in an InformationReport.
_REPORT_TIME_LEN = 12


@dataclass
class InformationReportRequest:
    """InformationReport-Request: optional time, variable names, values.

    ``current-time`` is ``GeneralizedTime OPTIONAL``, so the A-XDR form is a
    usage flag and then the octet string: ``01 0C`` + 12 octets. Gurux-based
    meters and the Gurux simulator omit the flag and send ``0C`` + 12 octets;
    that form is accepted on decode and recorded in :attr:`current_time_bare`
    so the APDU re-encodes as received. New APDUs use the spec form.
    """

    current_time: bytes | None
    names: list[int]
    values: list[DlmsData]
    current_time_bare: bool = False

    @property
    def timestamp(self):
        from pydlms.cosem.time import CosemDateTime

        if self.current_time and len(self.current_time) == 12:
            return CosemDateTime.from_bytes(self.current_time)
        return None

    def to_bytes(self) -> bytes:
        out = bytearray([Tag.INFORMATION_REPORT_REQUEST])
        if self.current_time:
            if not self.current_time_bare:
                out.append(0x01)
            out += encode_length(len(self.current_time)) + self.current_time
        else:
            out += b"\x00"
        out += encode_length(len(self.names))
        for name in self.names:
            out += VariableName(name).to_bytes()
        out += encode_length(len(self.values))
        for value in self.values:
            out += encode_data(value)
        return bytes(out)


def _result(value: int) -> DataAccessResult | int:
    """The enum member, or the bare code when the meter sent an undefined one."""
    try:
        return DataAccessResult(value)
    except ValueError:
        return value


def _count(r: _Reader) -> int:
    """A SEQUENCE OF length, refused when it exceeds the octets left (every
    element takes at least one), before any list is built."""
    n = r.length()
    if n > len(r.data) - r.pos:
        raise DecodeError(f"{n} elements announced, {len(r.data) - r.pos} octets left")
    return n


def decode_sn_apdu(apdu: bytes):
    if not apdu:
        raise DecodeError("empty APDU")
    tag = apdu[0]
    r = _Reader(apdu, 1)
    if tag == Tag.READ_REQUEST:
        result = ReadRequest([_read_spec(r) for _ in range(_count(r))])
    elif tag == Tag.READ_RESPONSE:
        results = []
        for _ in range(_count(r)):
            choice = r.u8()
            if choice == 0:
                results.append(ReadResult(data=r.data_value()))
            elif choice == 1:
                results.append(ReadResult(error=_result(r.u8())))
            elif choice == 2:
                last = r.u8() != 0
                number = r.u16()
                results.append(
                    ReadResult(block_last=last, block_number=number, raw_data=r.octets())
                )
            elif choice == 3:
                results.append(ReadResult(block_number=r.u16()))
            else:
                raise DecodeError(f"unknown ReadResponse choice {choice}")
        result = ReadResponse(results)
    elif tag in (Tag.WRITE_REQUEST, Tag.UNCONFIRMED_WRITE_REQUEST):
        items = [_read_spec(r) for _ in range(_count(r))]
        values = [r.data_value() for _ in range(_count(r))]
        cls = WriteRequest if tag == Tag.WRITE_REQUEST else UnconfirmedWriteRequest
        result = cls(items, values)
    elif tag == Tag.WRITE_RESPONSE:
        results = []
        for _ in range(_count(r)):
            choice = r.u8()
            if choice == 0:
                results.append(DataAccessResult.SUCCESS)
            elif choice == 1:
                results.append(_result(r.u8()))
            elif choice == 2:
                results.append(WriteBlockNumber(r.u16()))
            else:
                raise DecodeError(f"unknown WriteResponse choice {choice}")
        result = WriteResponse(results)
    elif tag == Tag.INFORMATION_REPORT_REQUEST:
        bare = not r.done() and r.data[r.pos] == _REPORT_TIME_LEN
        if bare:  # Gurux form: no usage flag before the 12-octet date-time
            time = r.octets()
        else:
            time = r.octets() if r.optional() else None
        names = []
        for _ in range(_count(r)):
            spec = _read_spec(r)
            if not isinstance(spec, VariableName):
                raise DecodeError("InformationReport carries only variable names")
            names.append(spec.name)
        values = [r.data_value() for _ in range(_count(r))]
        result = InformationReportRequest(time, names, values, current_time_bare=bare)
    else:
        raise DecodeError(f"0x{tag:02X} is not a short-name APDU")
    r.finish("SN APDU")
    return result
