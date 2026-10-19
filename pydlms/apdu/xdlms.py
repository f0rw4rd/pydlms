"""xDLMS services for Logical-Name referencing (IEC 62056-5-3, 9.3 / ASN.1 module).

Covered APDUs, each a dataclass with ``to_bytes()`` and decoded by
:func:`decode_apdu`:

* InitiateRequest / InitiateResponse with the 24-bit :class:`Conformance`.
* GET request (normal, next, with-list) / response (normal, with-datablock,
  with-list).
* SET request (normal, first-datablock, datablock, with-list) / response
  (normal, datablock, last-datablock, last-datablock-with-list, with-list).
* ACTION request (normal, next-pblock, with-list, with-first-pblock,
  with-pblock) / response (normal, with-pblock, with-list, next-pblock).
* Selective access (range and entry descriptors) on GET/SET.
* ACCESS request / response (``D9`` / ``DA``) with their specifications and
  results, using the Long-Invoke-Id-And-Priority.
* DataNotification and EventNotificationRequest (push).
* ExceptionResponse and ConfirmedServiceError.

Fixed-layout parts (descriptors, invoke-id byte) are ``construct`` structs;
values are COSEM :class:`~pydlms.cosem.data.DlmsData`.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import ClassVar

import construct
from construct import Int16ub, Struct

from pydlms.apdu.tags import Tag, tag_name
from pydlms.axdr import decode_length, encode_length
from pydlms.cosem.data import DlmsData, decode_data, encode_data
from pydlms.cosem.enums import ActionResult, DataAccessResult
from pydlms.cosem.time import CosemDateTime
from pydlms.exceptions import DecodeError
from pydlms.obis import Obis, ObisCode

__all__ = [
    "Conformance",
    "InitiateRequest",
    "InitiateResponse",
    "AttributeDescriptor",
    "MethodDescriptor",
    "SelectiveAccess",
    "range_descriptor",
    "date_time_value",
    "entry_descriptor",
    "GetRequestNormal",
    "GetRequestNext",
    "GetRequestWithList",
    "GetResponseNormal",
    "GetResponseWithDatablock",
    "GetResponseWithList",
    "SetRequestNormal",
    "SetRequestWithFirstDatablock",
    "SetRequestWithDatablock",
    "SetRequestWithList",
    "SetRequestWithListAndFirstDatablock",
    "SetResponseNormal",
    "SetResponseDatablock",
    "SetResponseLastDatablock",
    "SetResponseLastDatablockWithList",
    "SetResponseWithList",
    "ActionRequestNormal",
    "ActionRequestNextPblock",
    "ActionRequestWithList",
    "ActionRequestWithFirstPblock",
    "ActionRequestWithPblock",
    "ActionRequestWithListAndFirstPblock",
    "ActionResponseNormal",
    "ActionResponseWithPblock",
    "ActionResponseWithList",
    "ActionResponseNextPblock",
    "AccessKind",
    "AccessRequestGet",
    "AccessRequestSet",
    "AccessRequestAction",
    "AccessRequestGetWithSelection",
    "AccessRequestSetWithSelection",
    "AccessRequestSpecification",
    "AccessResponseGet",
    "AccessResponseSet",
    "AccessResponseAction",
    "AccessResponseSpecification",
    "AccessRequest",
    "AccessResponse",
    "DataNotification",
    "EventNotificationRequest",
    "ExceptionResponse",
    "ConfirmedServiceError",
    "GetDataResult",
    "invoke_id_byte",
    "long_invoke_id",
    "LongInvokeIdAndPriority",
    "ProcessingOption",
    "decode_apdu",
]


# --- conformance -------------------------------------------------------------


class Conformance(enum.IntFlag):
    """xDLMS conformance block: ASN.1 bit n has value ``0x800000 >> n``."""

    RESERVED_ZERO = 0x800000 >> 0
    GENERAL_PROTECTION = 0x800000 >> 1
    GENERAL_BLOCK_TRANSFER = 0x800000 >> 2
    READ = 0x800000 >> 3
    WRITE = 0x800000 >> 4
    UNCONFIRMED_WRITE = 0x800000 >> 5
    DELTA_VALUE_ENCODING = 0x800000 >> 6
    RESERVED_SEVEN = 0x800000 >> 7
    ATTRIBUTE0_SUPPORTED_WITH_SET = 0x800000 >> 8
    PRIORITY_MGMT_SUPPORTED = 0x800000 >> 9
    ATTRIBUTE0_SUPPORTED_WITH_GET = 0x800000 >> 10
    BLOCK_TRANSFER_WITH_GET_OR_READ = 0x800000 >> 11
    BLOCK_TRANSFER_WITH_SET_OR_WRITE = 0x800000 >> 12
    BLOCK_TRANSFER_WITH_ACTION = 0x800000 >> 13
    MULTIPLE_REFERENCES = 0x800000 >> 14
    INFORMATION_REPORT = 0x800000 >> 15
    DATA_NOTIFICATION = 0x800000 >> 16
    ACCESS = 0x800000 >> 17
    PARAMETERIZED_ACCESS = 0x800000 >> 18
    GET = 0x800000 >> 19
    SET = 0x800000 >> 20
    SELECTIVE_ACCESS = 0x800000 >> 21
    EVENT_NOTIFICATION = 0x800000 >> 22
    ACTION = 0x800000 >> 23

    @classmethod
    def default_ln(cls) -> Conformance:
        """A typical LN client proposal (``00 7E 1F`` plus block transfer)."""
        return (
            cls.PRIORITY_MGMT_SUPPORTED
            | cls.ATTRIBUTE0_SUPPORTED_WITH_GET
            | cls.BLOCK_TRANSFER_WITH_GET_OR_READ
            | cls.BLOCK_TRANSFER_WITH_SET_OR_WRITE
            | cls.BLOCK_TRANSFER_WITH_ACTION
            | cls.MULTIPLE_REFERENCES
            | cls.GET
            | cls.SET
            | cls.SELECTIVE_ACCESS
            | cls.EVENT_NOTIFICATION
            | cls.ACTION
        )

    @classmethod
    def default_sn(cls) -> Conformance:
        return (
            cls.READ
            | cls.WRITE
            | cls.UNCONFIRMED_WRITE
            | cls.BLOCK_TRANSFER_WITH_GET_OR_READ
            | cls.BLOCK_TRANSFER_WITH_SET_OR_WRITE
            | cls.MULTIPLE_REFERENCES
            | cls.INFORMATION_REPORT
            | cls.PARAMETERIZED_ACCESS
        )

    def to_bytes(self) -> bytes:
        """``5F 1F 04 00 xx xx xx`` ([APPLICATION 31] BIT STRING, 0 unused bits)."""
        return b"\x5f\x1f\x04\x00" + int(self).to_bytes(3, "big")

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> tuple[Conformance, int]:
        if data[offset : offset + 3] != b"\x5f\x1f\x04":
            raise DecodeError(
                f"conformance block must start 5F 1F 04, got {data[offset : offset + 3].hex()}"
            )
        end = offset + 7
        if end > len(data):
            raise DecodeError("truncated conformance block")
        return cls(int.from_bytes(data[offset + 4 : end], "big")), end

    def names(self) -> list[str]:
        return [m.name for m in type(self) if m in self and m.name]


# --- helpers ---------------------------------------------------------------------


class _Reader:
    def __init__(self, data: bytes, pos: int = 0) -> None:
        self.data = data
        self.pos = pos

    def take(self, n: int) -> bytes:
        end = self.pos + n
        if end > len(self.data):
            raise DecodeError(
                f"APDU truncated: need {n} octets at {self.pos}, have {len(self.data) - self.pos}"
            )
        out = self.data[self.pos : end]
        self.pos = end
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "big")

    def length(self) -> int:
        value, self.pos = decode_length(self.data, self.pos)
        return value

    def octets(self) -> bytes:
        return self.take(self.length())

    def data_value(self) -> DlmsData:
        value, self.pos = decode_data(self.data, self.pos)
        return value

    def optional(self) -> bool:
        flag = self.u8()
        if flag not in (0, 1):
            raise DecodeError(f"OPTIONAL presence flag must be 0 or 1, got {flag}")
        return bool(flag)

    def done(self) -> bool:
        return self.pos >= len(self.data)

    def finish(self, what: str) -> None:
        if not self.done():
            raise DecodeError(f"{len(self.data) - self.pos} trailing octets after {what}")


def invoke_id_byte(invoke_id: int, high_priority: bool = True, confirmed: bool = True) -> int:
    """Invoke-Id-And-Priority: bit7 priority, bit6 confirmed, bits3..0 id."""
    if not 0 <= invoke_id <= 15:
        raise ValueError("invoke id must be 0..15")
    return (0x80 if high_priority else 0) | (0x40 if confirmed else 0) | invoke_id


class ProcessingOption(enum.IntEnum):
    """Processing option of a Long-Invoke-Id-And-Priority (bit 29)."""

    CONTINUE_ON_ERROR = 0
    BREAK_ON_ERROR = 1


# Long-Invoke-Id-And-Priority, a 32-bit field, most significant bit first:
# priority, service class, processing option, self-descriptive, 4 reserved
# bits, 24-bit invoke id. DLMS UA 1000-2 Ed. 9 Excerpt 9.3.9.1.4 gives the
# invoke id range 0..16 777 215 (24 bits) and Table 21 (14.2) a confirmed,
# answered request with the field 40000000 (service class = bit 30); the
# ASN.1 (9.5) is not in the excerpt, so the priority, processing-option and
# self-descriptive positions are cross-checked against dlms-cosem-rs
# data_notification.rs:36-66 only (*unverified*).
_LongInvokeIdStruct = construct.BitStruct(
    "high_priority" / construct.Flag,
    "confirmed" / construct.Flag,
    "break_on_error" / construct.Flag,
    "self_descriptive" / construct.Flag,
    "reserved" / construct.BitsInteger(4),
    "invoke_id" / construct.BitsInteger(24),
)

#: Largest 24-bit invoke id of a Long-Invoke-Id-And-Priority.
MAX_LONG_INVOKE_ID = 0xFFFFFF


@dataclass(frozen=True)
class LongInvokeIdAndPriority:
    """The fields of a Long-Invoke-Id-And-Priority (32 bits, big-endian).

    ``reserved`` (bits 27..24) is kept so that any received value
    round-trips; :func:`long_invoke_id` always builds it as zero.
    """

    high_priority: bool
    confirmed: bool
    processing_option: ProcessingOption
    self_descriptive: bool
    invoke_id: int
    reserved: int = 0

    @classmethod
    def from_bytes(cls, raw: bytes) -> LongInvokeIdAndPriority:
        if len(raw) != 4:
            raise DecodeError(f"Long-Invoke-Id-And-Priority is 4 octets, got {len(raw)}")
        parsed = _LongInvokeIdStruct.parse(raw)
        return cls(
            high_priority=bool(parsed.high_priority),
            confirmed=bool(parsed.confirmed),
            processing_option=ProcessingOption(int(parsed.break_on_error)),
            self_descriptive=bool(parsed.self_descriptive),
            invoke_id=parsed.invoke_id,
            reserved=parsed.reserved,
        )

    @classmethod
    def from_int(cls, value: int) -> LongInvokeIdAndPriority:
        if not 0 <= value <= 0xFFFFFFFF:
            raise DecodeError(f"Long-Invoke-Id-And-Priority {value!r} is not a 32-bit value")
        return cls.from_bytes(value.to_bytes(4, "big"))

    def to_bytes(self) -> bytes:
        if not 0 <= self.invoke_id <= MAX_LONG_INVOKE_ID:
            raise ValueError("long invoke id must be 0..0xFFFFFF")
        return _LongInvokeIdStruct.build(
            {
                "high_priority": self.high_priority,
                "confirmed": self.confirmed,
                "break_on_error": self.processing_option == ProcessingOption.BREAK_ON_ERROR,
                "self_descriptive": self.self_descriptive,
                "reserved": self.reserved,
                "invoke_id": self.invoke_id,
            }
        )

    def to_int(self) -> int:
        return int.from_bytes(self.to_bytes(), "big")


def long_invoke_id(
    invoke_id: int,
    *,
    high_priority: bool = True,
    confirmed: bool = True,
    processing_option: ProcessingOption = ProcessingOption.CONTINUE_ON_ERROR,
    self_descriptive: bool = False,
) -> int:
    """Build a Long-Invoke-Id-And-Priority as the 32-bit integer APDUs carry.

    Bit 31 priority (set = high), bit 30 service class (set = confirmed),
    bit 29 processing option (set = break-on-error), bit 28 self-descriptive,
    bits 27..24 reserved (zero), bits 23..0 ``invoke_id`` (0..0xFFFFFF). The
    defaults match :func:`invoke_id_byte` (high priority, confirmed).
    ``long_invoke_id(5)`` is ``0xC0000005``. Raises ``ValueError`` when
    ``invoke_id`` does not fit in 24 bits.
    """
    if not 0 <= invoke_id <= MAX_LONG_INVOKE_ID:
        raise ValueError("long invoke id must be 0..0xFFFFFF")
    return LongInvokeIdAndPriority(
        high_priority, confirmed, ProcessingOption(processing_option), self_descriptive, invoke_id
    ).to_int()


# --- descriptors ------------------------------------------------------------------

_AttributeDescriptor = Struct(
    "class_id" / Int16ub,
    "instance_id" / Obis,
    "attribute_id" / construct.Int8sb,
)
_MethodDescriptor = Struct(
    "class_id" / Int16ub,
    "instance_id" / Obis,
    "method_id" / construct.Int8sb,
)


def _check_descriptor(class_id: int, member: str, member_id: int) -> None:
    """Green Book: class-id Unsigned16, attribute-id / method-id Integer8."""
    if not 0 <= class_id <= 0xFFFF:
        raise ValueError(f"class id {class_id} is outside Unsigned16 (0..65535)")
    if not -128 <= member_id <= 127:
        hint = f"; as a signed octet {member_id} is {member_id - 256}" if member_id < 256 else ""
        raise ValueError(f"{member} id {member_id} is outside Integer8 (-128..127){hint}")


@dataclass(frozen=True)
class AttributeDescriptor:
    class_id: int
    instance_id: ObisCode
    attribute_id: int

    def to_bytes(self) -> bytes:
        _check_descriptor(self.class_id, "attribute", self.attribute_id)
        return _AttributeDescriptor.build(
            {
                "class_id": self.class_id,
                "instance_id": self.instance_id,
                "attribute_id": self.attribute_id,
            }
        )

    @classmethod
    def read(cls, r: _Reader) -> AttributeDescriptor:
        p = _AttributeDescriptor.parse(r.take(9))
        return cls(p.class_id, p.instance_id, p.attribute_id)

    def __str__(self) -> str:
        return f"{self.class_id}/{self.instance_id}/{self.attribute_id}"


@dataclass(frozen=True)
class MethodDescriptor:
    class_id: int
    instance_id: ObisCode
    method_id: int

    def to_bytes(self) -> bytes:
        _check_descriptor(self.class_id, "method", self.method_id)
        return _MethodDescriptor.build(
            {
                "class_id": self.class_id,
                "instance_id": self.instance_id,
                "method_id": self.method_id,
            }
        )

    @classmethod
    def read(cls, r: _Reader) -> MethodDescriptor:
        p = _MethodDescriptor.parse(r.take(9))
        return cls(p.class_id, p.instance_id, p.method_id)

    def __str__(self) -> str:
        return f"{self.class_id}/{self.instance_id}/m{self.method_id}"


@dataclass(frozen=True)
class SelectiveAccess:
    """Access selector (1 = range, 2 = entry, others class-specific) + parameters."""

    selector: int
    parameters: DlmsData

    def to_bytes(self) -> bytes:
        return bytes([1, self.selector]) + encode_data(self.parameters)


def _capture_object(class_id: int, obis: ObisCode, attribute: int, data_index: int = 0):
    return DlmsData.structure(
        [
            DlmsData.uint16(class_id),
            DlmsData.octet_string(obis.to_bytes()),
            DlmsData.int8(attribute),
            DlmsData.uint16(data_index),
        ]
    )


def range_descriptor(
    from_value: DlmsData,
    to_value: DlmsData,
    restricting_object: tuple[int, ObisCode, int] = (8, ObisCode(0, 0, 1, 0, 0, 255), 2),
    selected_values: list[tuple[int, ObisCode, int, int]] | None = None,
) -> SelectiveAccess:
    """Profile-generic range selection (selector 1), by default on the clock."""
    cid, obis, attr = restricting_object
    columns = [_capture_object(*c) for c in (selected_values or [])]
    return SelectiveAccess(
        1,
        DlmsData.structure(
            [_capture_object(cid, obis, attr), from_value, to_value, DlmsData.array(columns)]
        ),
    )


def entry_descriptor(
    from_entry: int = 1, to_entry: int = 0, from_column: int = 1, to_column: int = 0
) -> SelectiveAccess:
    """Profile-generic entry selection (selector 2); 0 means "last"."""
    return SelectiveAccess(
        2,
        DlmsData.structure(
            [
                DlmsData.uint32(from_entry),
                DlmsData.uint32(to_entry),
                DlmsData.uint16(from_column),
                DlmsData.uint16(to_column),
            ]
        ),
    )


def date_time_value(value) -> DlmsData:
    """A date-time as the 12-octet octet-string range descriptors expect."""
    if not isinstance(value, CosemDateTime):
        value = CosemDateTime.from_datetime(value)
    return DlmsData.octet_string(value.to_bytes())


def _read_access(r: _Reader) -> SelectiveAccess | None:
    if not r.optional():
        return None
    selector = r.u8()
    return SelectiveAccess(selector, r.data_value())


def _access_bytes(access: SelectiveAccess | None) -> bytes:
    return access.to_bytes() if access else b"\x00"


# --- initiate -------------------------------------------------------------------


@dataclass
class InitiateRequest:
    conformance: Conformance = field(default_factory=Conformance.default_ln)
    max_receive_pdu_size: int = 0xFFFF
    dlms_version: int = 6
    # A key: never shown in repr (CLAUDE.md, secrets stay out of logs).
    dedicated_key: bytes | None = field(default=None, repr=False)
    response_allowed: bool = True
    quality_of_service: int | None = None

    def to_bytes(self) -> bytes:
        out = bytearray([Tag.INITIATE_REQUEST])
        if self.dedicated_key:
            out += b"\x01" + encode_length(len(self.dedicated_key)) + self.dedicated_key
        else:
            out += b"\x00"
        out += b"\x00" if self.response_allowed else b"\x01\x00"
        out += b"\x00" if self.quality_of_service is None else bytes([1, self.quality_of_service])
        out.append(self.dlms_version)
        out += self.conformance.to_bytes()
        out += self.max_receive_pdu_size.to_bytes(2, "big")
        return bytes(out)

    @classmethod
    def from_bytes(cls, data: bytes) -> InitiateRequest:
        r = _Reader(data)
        if r.u8() != Tag.INITIATE_REQUEST:
            raise DecodeError("not an InitiateRequest")
        key = r.octets() if r.optional() else None
        allowed = True
        if r.optional():
            allowed = bool(r.u8())
        qos = r.u8() if r.optional() else None
        version = r.u8()
        conformance, r.pos = Conformance.from_bytes(data, r.pos)
        size = r.u16()
        r.finish("InitiateRequest")
        return cls(conformance, size, version, key, allowed, qos)


@dataclass
class InitiateResponse:
    conformance: Conformance
    max_receive_pdu_size: int
    dlms_version: int = 6
    vaa_name: int = 0x0007
    quality_of_service: int | None = None

    def to_bytes(self) -> bytes:
        qos = b"\x00" if self.quality_of_service is None else bytes([1, self.quality_of_service])
        return (
            bytes([Tag.INITIATE_RESPONSE])
            + qos
            + bytes([self.dlms_version])
            + self.conformance.to_bytes()
            + self.max_receive_pdu_size.to_bytes(2, "big")
            + self.vaa_name.to_bytes(2, "big")
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> InitiateResponse:
        r = _Reader(data)
        if r.u8() != Tag.INITIATE_RESPONSE:
            raise DecodeError("not an InitiateResponse")
        qos = r.u8() if r.optional() else None
        version = r.u8()
        conformance, r.pos = Conformance.from_bytes(data, r.pos)
        size = r.u16()
        vaa = r.u16()
        r.finish("InitiateResponse")
        return cls(conformance, size, version, vaa, qos)


# --- GET -----------------------------------------------------------------------


@dataclass
class GetDataResult:
    """``Get-Data-Result``: either data or a data-access-result."""

    data: DlmsData | None = None
    error: DataAccessResult | int | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def to_bytes(self) -> bytes:
        if self.error is not None:
            return bytes([1, int(self.error)])
        assert self.data is not None
        return b"\x00" + encode_data(self.data)

    @classmethod
    def read(cls, r: _Reader) -> GetDataResult:
        choice = r.u8()
        if choice == 0:
            return cls(data=r.data_value())
        if choice == 1:
            return cls(error=_access_result(r.u8()))
        raise DecodeError(f"Get-Data-Result choice {choice} is not 0 or 1")


def decode_get_data_results(raw: bytes) -> list[GetDataResult]:
    """Decode the reassembled data blocks of a block-transferred
    GET-Response-With-List: an A-XDR ``SEQUENCE OF Get-Data-Result``."""
    r = _Reader(raw)
    count = r.length()
    results = [GetDataResult.read(r) for _ in range(count)]
    r.finish("block-transferred GET-with-list results")
    return results


def encode_get_data_results(results: list[GetDataResult]) -> bytes:
    """Inverse of :func:`decode_get_data_results`."""
    return encode_length(len(results)) + b"".join(r.to_bytes() for r in results)


def encode_data_list(values: list[DlmsData]) -> bytes:
    """An A-XDR ``SEQUENCE OF Data``: what the datablocks / pblocks of a
    SET or ACTION with-list request carry (per IEC 62056-53:2006
    7.4.1.8.2-7.4.1.8.4, see :class:`SetRequestWithListAndFirstDatablock`)."""
    return encode_length(len(values)) + b"".join(encode_data(v) for v in values)


def decode_data_list(raw: bytes) -> list[DlmsData]:
    """Inverse of :func:`encode_data_list`; the whole of ``raw`` must be used."""
    r = _Reader(raw)
    values = [r.data_value() for _ in range(_count(r, 1))]
    r.finish("block-transferred SEQUENCE OF Data")
    return values


def _count(r: _Reader, min_octets: int) -> int:
    """A SEQUENCE OF length, refused before any list is built when its
    elements (``min_octets`` each at least) cannot fit the octets left."""
    n = r.length()
    left = len(r.data) - r.pos
    if n * min_octets > left:
        raise DecodeError(f"{n} elements announced, {left} octets left")
    return n


#: Smallest encoded Cosem-Attribute-Descriptor-With-Selection (descriptor
#: and the access-selection flag) and Cosem-Method-Descriptor.
_ATTRIBUTE_WITH_SELECTION_MIN = 10
_METHOD_DESCRIPTOR_MIN = 9


def _access_result(value: int) -> DataAccessResult | int:
    """The enum member, or the bare code when the meter sent an undefined one."""
    try:
        return DataAccessResult(value)
    except ValueError:
        return value


def _action_result(value: int) -> ActionResult | int:
    try:
        return ActionResult(value)
    except ValueError:
        return value


@dataclass
class GetRequestNormal:
    invoke_id: int
    attribute: AttributeDescriptor
    access: SelectiveAccess | None = None

    def to_bytes(self) -> bytes:
        return (
            bytes([Tag.GET_REQUEST, 1, self.invoke_id])
            + self.attribute.to_bytes()
            + _access_bytes(self.access)
        )


@dataclass
class GetRequestNext:
    invoke_id: int
    block_number: int

    def to_bytes(self) -> bytes:
        return bytes([Tag.GET_REQUEST, 2, self.invoke_id]) + self.block_number.to_bytes(4, "big")


@dataclass
class GetRequestWithList:
    invoke_id: int
    items: list[tuple[AttributeDescriptor, SelectiveAccess | None]]

    def to_bytes(self) -> bytes:
        out = bytearray([Tag.GET_REQUEST, 3, self.invoke_id])
        out += encode_length(len(self.items))
        for attribute, access in self.items:
            out += attribute.to_bytes() + _access_bytes(access)
        return bytes(out)


@dataclass
class GetResponseNormal:
    invoke_id: int
    result: GetDataResult

    def to_bytes(self) -> bytes:
        return bytes([Tag.GET_RESPONSE, 1, self.invoke_id]) + self.result.to_bytes()


@dataclass
class GetResponseWithDatablock:
    """DataBlock-G: ``last-block, block-number, raw-data | data-access-result``."""

    invoke_id: int
    last_block: bool
    block_number: int
    raw_data: bytes | None = None
    error: DataAccessResult | int | None = None

    def to_bytes(self) -> bytes:
        head = bytes([Tag.GET_RESPONSE, 2, self.invoke_id, int(self.last_block)])
        head += self.block_number.to_bytes(4, "big")
        if self.error is not None:
            return head + bytes([1, int(self.error)])
        data = self.raw_data or b""
        return head + b"\x00" + encode_length(len(data)) + data


@dataclass
class GetResponseWithList:
    invoke_id: int
    results: list[GetDataResult]

    def to_bytes(self) -> bytes:
        out = bytearray([Tag.GET_RESPONSE, 3, self.invoke_id]) + encode_length(len(self.results))
        for result in self.results:
            out += result.to_bytes()
        return bytes(out)


# --- SET ---------------------------------------------------------------------------


@dataclass
class SetRequestNormal:
    invoke_id: int
    attribute: AttributeDescriptor
    value: DlmsData
    access: SelectiveAccess | None = None

    def to_bytes(self) -> bytes:
        return (
            bytes([Tag.SET_REQUEST, 1, self.invoke_id])
            + self.attribute.to_bytes()
            + _access_bytes(self.access)
            + encode_data(self.value)
        )


def _datablock_sa(last: bool, number: int, raw: bytes) -> bytes:
    return bytes([int(last)]) + number.to_bytes(4, "big") + encode_length(len(raw)) + raw


@dataclass
class SetRequestWithFirstDatablock:
    invoke_id: int
    attribute: AttributeDescriptor
    last_block: bool
    block_number: int
    raw_data: bytes
    access: SelectiveAccess | None = None

    def to_bytes(self) -> bytes:
        return (
            bytes([Tag.SET_REQUEST, 2, self.invoke_id])
            + self.attribute.to_bytes()
            + _access_bytes(self.access)
            + _datablock_sa(self.last_block, self.block_number, self.raw_data)
        )


@dataclass
class SetRequestWithDatablock:
    invoke_id: int
    last_block: bool
    block_number: int
    raw_data: bytes

    def to_bytes(self) -> bytes:
        return bytes([Tag.SET_REQUEST, 3, self.invoke_id]) + _datablock_sa(
            self.last_block, self.block_number, self.raw_data
        )


@dataclass
class SetRequestWithList:
    invoke_id: int
    items: list[tuple[AttributeDescriptor, SelectiveAccess | None, DlmsData]]

    def to_bytes(self) -> bytes:
        out = bytearray([Tag.SET_REQUEST, 4, self.invoke_id]) + encode_length(len(self.items))
        for attribute, access, _ in self.items:
            out += attribute.to_bytes() + _access_bytes(access)
        out += encode_length(len(self.items))
        for _, _, value in self.items:
            out += encode_data(value)
        return bytes(out)


@dataclass
class SetRequestWithListAndFirstDatablock:
    """Set-Request-With-List-And-First-Datablock (``C1 05``).

    Layout per the jDLMS ASN.1 class of the same name: invoke-id, the
    SEQUENCE OF Cosem-Attribute-Descriptor-With-Selection, then a
    DataBlock-SA (the same ASN.1 in IEC 62056-53:2006 8.6.1, public as
    IS/IEC 62056-53). ``raw_data`` is the first part of the encoded
    ``SEQUENCE OF Data`` holding the values (:func:`encode_data_list`): per
    7.4.1.8.2 the data "shall be encoded, as if they would fit into one
    APDU" and cut into blocks, 7.4.1.8.3 applies that to SET, and in one
    APDU the values are the ``value-list SEQUENCE OF Data`` of
    Set-Request-With-List. The attribute references travel only in the
    first block. No server available for testing implements it.
    """

    invoke_id: int
    items: list[tuple[AttributeDescriptor, SelectiveAccess | None]]
    last_block: bool
    block_number: int
    raw_data: bytes

    def to_bytes(self) -> bytes:
        out = bytearray([Tag.SET_REQUEST, 5, self.invoke_id]) + encode_length(len(self.items))
        for attribute, access in self.items:
            out += attribute.to_bytes() + _access_bytes(access)
        return bytes(out) + _datablock_sa(self.last_block, self.block_number, self.raw_data)


@dataclass
class SetResponseNormal:
    invoke_id: int
    result: DataAccessResult | int

    def to_bytes(self) -> bytes:
        return bytes([Tag.SET_RESPONSE, 1, self.invoke_id, int(self.result)])


@dataclass
class SetResponseDatablock:
    invoke_id: int
    block_number: int

    def to_bytes(self) -> bytes:
        return bytes([Tag.SET_RESPONSE, 2, self.invoke_id]) + self.block_number.to_bytes(4, "big")


@dataclass
class SetResponseLastDatablock:
    invoke_id: int
    result: DataAccessResult | int
    block_number: int

    def to_bytes(self) -> bytes:
        return bytes([Tag.SET_RESPONSE, 3, self.invoke_id, int(self.result)]) + (
            self.block_number.to_bytes(4, "big")
        )


@dataclass
class SetResponseLastDatablockWithList:
    """Set-Response-Last-Datablock-With-List: per-item results and the block number."""

    invoke_id: int
    results: list[DataAccessResult | int]
    block_number: int

    def to_bytes(self) -> bytes:
        return (
            bytes([Tag.SET_RESPONSE, 4, self.invoke_id])
            + encode_length(len(self.results))
            + bytes(int(r) for r in self.results)
            + self.block_number.to_bytes(4, "big")
        )


@dataclass
class SetResponseWithList:
    invoke_id: int
    results: list[DataAccessResult | int]

    def to_bytes(self) -> bytes:
        return (
            bytes([Tag.SET_RESPONSE, 5, self.invoke_id])
            + encode_length(len(self.results))
            + bytes(int(r) for r in self.results)
        )


# --- ACTION ------------------------------------------------------------------------


def _optional_data(value: DlmsData | None) -> bytes:
    return b"\x00" if value is None else b"\x01" + encode_data(value)


def _pblock(last: bool, number: int, raw: bytes) -> bytes:
    return bytes([int(last)]) + number.to_bytes(4, "big") + encode_length(len(raw)) + raw


@dataclass
class ActionRequestNormal:
    invoke_id: int
    method: MethodDescriptor
    parameters: DlmsData | None = None

    def to_bytes(self) -> bytes:
        return (
            bytes([Tag.ACTION_REQUEST, 1, self.invoke_id])
            + self.method.to_bytes()
            + _optional_data(self.parameters)
        )


@dataclass
class ActionRequestNextPblock:
    invoke_id: int
    block_number: int

    def to_bytes(self) -> bytes:
        return bytes([Tag.ACTION_REQUEST, 2, self.invoke_id]) + self.block_number.to_bytes(4, "big")


@dataclass
class ActionRequestWithList:
    invoke_id: int
    items: list[tuple[MethodDescriptor, DlmsData | None]]

    def to_bytes(self) -> bytes:
        out = bytearray([Tag.ACTION_REQUEST, 3, self.invoke_id]) + encode_length(len(self.items))
        for method, _ in self.items:
            out += method.to_bytes()
        out += encode_length(len(self.items))
        for _, params in self.items:
            out += encode_data(params if params is not None else DlmsData.null())
        return bytes(out)


@dataclass
class ActionRequestWithFirstPblock:
    invoke_id: int
    method: MethodDescriptor
    last_block: bool
    block_number: int
    raw_data: bytes

    def to_bytes(self) -> bytes:
        return (
            bytes([Tag.ACTION_REQUEST, 4, self.invoke_id])
            + self.method.to_bytes()
            + _pblock(self.last_block, self.block_number, self.raw_data)
        )


@dataclass
class ActionRequestWithPblock:
    invoke_id: int
    last_block: bool
    block_number: int
    raw_data: bytes

    def to_bytes(self) -> bytes:
        return bytes([Tag.ACTION_REQUEST, 6, self.invoke_id]) + _pblock(
            self.last_block, self.block_number, self.raw_data
        )


@dataclass
class ActionRequestWithListAndFirstPblock:
    """Action-Request-With-List-And-First-Pblock (``C3 05``).

    Layout per the jDLMS ASN.1 class of the same name: invoke-id, the
    SEQUENCE OF Cosem-Method-Descriptor, then a DataBlock-SA. ``raw_data``
    is the first part of the encoded ``SEQUENCE OF Data`` of the
    invocation parameters (the ``SEQUENCE OF Data`` of
    Action-Request-With-List, per IEC 62056-53:2006 7.4.1.8.4 and 8.6.1, as
    for :class:`SetRequestWithListAndFirstDatablock`).
    """

    invoke_id: int
    methods: list[MethodDescriptor]
    last_block: bool
    block_number: int
    raw_data: bytes

    def to_bytes(self) -> bytes:
        out = bytearray([Tag.ACTION_REQUEST, 5, self.invoke_id]) + encode_length(len(self.methods))
        for method in self.methods:
            out += method.to_bytes()
        return bytes(out) + _pblock(self.last_block, self.block_number, self.raw_data)


@dataclass
class ActionResponseNormal:
    invoke_id: int
    result: ActionResult | int
    return_data: GetDataResult | None = None

    def to_bytes(self) -> bytes:
        out = bytes([Tag.ACTION_RESPONSE, 1, self.invoke_id, int(self.result)])
        if self.return_data is None:
            return out + b"\x00"
        return out + b"\x01" + self.return_data.to_bytes()


@dataclass
class ActionResponseWithPblock:
    invoke_id: int
    last_block: bool
    block_number: int
    raw_data: bytes

    def to_bytes(self) -> bytes:
        return bytes([Tag.ACTION_RESPONSE, 2, self.invoke_id]) + _pblock(
            self.last_block, self.block_number, self.raw_data
        )


@dataclass
class ActionResponseWithList:
    invoke_id: int
    results: list[tuple[ActionResult | int, GetDataResult | None]]

    def to_bytes(self) -> bytes:
        out = bytearray([Tag.ACTION_RESPONSE, 3, self.invoke_id]) + encode_length(len(self.results))
        for result, data in self.results:
            out.append(int(result))
            out += b"\x00" if data is None else b"\x01" + data.to_bytes()
        return bytes(out)


@dataclass
class ActionResponseNextPblock:
    invoke_id: int
    block_number: int

    def to_bytes(self) -> bytes:
        return bytes([Tag.ACTION_RESPONSE, 4, self.invoke_id]) + self.block_number.to_bytes(
            4, "big"
        )


# --- ACCESS ----------------------------------------------------------------------------
#
# IEC 62056-5-3:2023 7.3.8 / Green Book ACCESS service (clause text not read
# here). Layout per the jDLMS ASN.1 classes AccessRequest* / AccessResponse*
# (GPL, behaviour only) and cB-Sigma dlms cosem/access.go (Apache-2.0), and
# checked byte for byte against the Table F.10 request and the annex I.2
# response (tests/test_access_service.py, tests/crypto/test_access_annex_i2.py):
#
#   Access-Request ::= long-invoke-id-and-priority Unsigned32, date-time
#     OCTET STRING (empty when absent), SEQUENCE OF Access-Request-
#     Specification, SEQUENCE OF Data (one per specification: null-data for
#     a get, the value of a set, the parameters of an action).
#   Access-Response ::= long-invoke-id-and-priority, date-time, OPTIONAL
#     SEQUENCE OF Access-Request-Specification (the request echoed), SEQUENCE
#     OF Data (the value read, the return parameters, else null-data),
#     SEQUENCE OF Access-Response-Specification (one result each).


class AccessKind(enum.IntEnum):
    """Access-Request-Specification CHOICE tags (Access-Response-Specification
    uses 1..3)."""

    GET = 1
    SET = 2
    ACTION = 3
    GET_WITH_SELECTION = 4
    SET_WITH_SELECTION = 5


def _selection_bytes(access: SelectiveAccess) -> bytes:
    """A Selective-Access-Descriptor that is not OPTIONAL: selector + Data."""
    return bytes([access.selector]) + encode_data(access.parameters)


@dataclass(frozen=True)
class AccessRequestGet:
    attribute: AttributeDescriptor
    kind: ClassVar[AccessKind] = AccessKind.GET

    def to_bytes(self) -> bytes:
        return bytes([self.kind]) + self.attribute.to_bytes()

    def __str__(self) -> str:
        return f"get {self.attribute}"


@dataclass(frozen=True)
class AccessRequestSet:
    attribute: AttributeDescriptor
    kind: ClassVar[AccessKind] = AccessKind.SET

    def to_bytes(self) -> bytes:
        return bytes([self.kind]) + self.attribute.to_bytes()

    def __str__(self) -> str:
        return f"set {self.attribute}"


@dataclass(frozen=True)
class AccessRequestAction:
    method: MethodDescriptor
    kind: ClassVar[AccessKind] = AccessKind.ACTION

    def to_bytes(self) -> bytes:
        return bytes([self.kind]) + self.method.to_bytes()

    def __str__(self) -> str:
        return f"action {self.method}"


@dataclass(frozen=True)
class AccessRequestGetWithSelection:
    attribute: AttributeDescriptor
    access: SelectiveAccess
    kind: ClassVar[AccessKind] = AccessKind.GET_WITH_SELECTION

    def to_bytes(self) -> bytes:
        return bytes([self.kind]) + self.attribute.to_bytes() + _selection_bytes(self.access)

    def __str__(self) -> str:
        return f"get {self.attribute} (selector {self.access.selector})"


@dataclass(frozen=True)
class AccessRequestSetWithSelection:
    attribute: AttributeDescriptor
    access: SelectiveAccess
    kind: ClassVar[AccessKind] = AccessKind.SET_WITH_SELECTION

    def to_bytes(self) -> bytes:
        return bytes([self.kind]) + self.attribute.to_bytes() + _selection_bytes(self.access)

    def __str__(self) -> str:
        return f"set {self.attribute} (selector {self.access.selector})"


AccessRequestSpecification = (
    AccessRequestGet
    | AccessRequestSet
    | AccessRequestAction
    | AccessRequestGetWithSelection
    | AccessRequestSetWithSelection
)


@dataclass(frozen=True)
class AccessResponseGet:
    result: DataAccessResult | int
    kind: ClassVar[AccessKind] = AccessKind.GET

    def to_bytes(self) -> bytes:
        return bytes([self.kind, int(self.result)])


@dataclass(frozen=True)
class AccessResponseSet:
    result: DataAccessResult | int
    kind: ClassVar[AccessKind] = AccessKind.SET

    def to_bytes(self) -> bytes:
        return bytes([self.kind, int(self.result)])


@dataclass(frozen=True)
class AccessResponseAction:
    result: ActionResult | int
    kind: ClassVar[AccessKind] = AccessKind.ACTION

    def to_bytes(self) -> bytes:
        return bytes([self.kind, int(self.result)])


AccessResponseSpecification = AccessResponseGet | AccessResponseSet | AccessResponseAction


class _LongInvokeIdFields:
    """Read-only views of the ``long_invoke_id`` field of an APDU."""

    long_invoke_id: int

    @property
    def priority_fields(self) -> LongInvokeIdAndPriority:
        """The raw :attr:`long_invoke_id` split into its fields."""
        return LongInvokeIdAndPriority.from_int(self.long_invoke_id)

    @property
    def high_priority(self) -> bool:
        return self.priority_fields.high_priority

    @property
    def confirmed(self) -> bool:
        return self.priority_fields.confirmed

    @property
    def processing_option(self) -> ProcessingOption:
        return self.priority_fields.processing_option

    @property
    def self_descriptive(self) -> bool:
        return self.priority_fields.self_descriptive

    @property
    def invoke_id(self) -> int:
        """The 24-bit invoke id (the raw field without the flag octet)."""
        return self.priority_fields.invoke_id


def _date_time_bytes(date_time: bytes | None) -> bytes:
    """An A-XDR OCTET STRING, empty (``00``) when there is no date-time."""
    value = date_time or b""
    return encode_length(len(value)) + value


def _timestamp(date_time: bytes | None) -> CosemDateTime | None:
    if date_time and len(date_time) == 12:
        return CosemDateTime.from_bytes(date_time)
    return None


def _check_long_invoke_id(value: int) -> None:
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"long invoke id {value!r} is not a 32-bit value")


@dataclass
class AccessRequest(_LongInvokeIdFields):
    """Access-Request (``D9``): several get / set / action operations at once.

    ``data`` has one entry per specification, in the same order: null-data
    for a get, the value of a set, the parameters of an action (null-data
    when there are none). Build ``long_invoke_id`` with
    :func:`long_invoke_id`; its processing option asks the server to break
    on the first error or continue.
    """

    long_invoke_id: int
    date_time: bytes | None
    specifications: list[AccessRequestSpecification]
    data: list[DlmsData]

    @property
    def timestamp(self) -> CosemDateTime | None:
        return _timestamp(self.date_time)

    def to_bytes(self) -> bytes:
        _check_long_invoke_id(self.long_invoke_id)
        if len(self.data) != len(self.specifications):
            raise ValueError(
                f"ACCESS request has {len(self.specifications)} specifications "
                f"but {len(self.data)} data"
            )
        out = bytearray([Tag.ACCESS_REQUEST]) + self.long_invoke_id.to_bytes(4, "big")
        out += _date_time_bytes(self.date_time)
        out += encode_length(len(self.specifications))
        for spec in self.specifications:
            out += spec.to_bytes()
        out += encode_length(len(self.data))
        for value in self.data:
            out += encode_data(value)
        return bytes(out)


@dataclass
class AccessResponse(_LongInvokeIdFields):
    """Access-Response (``DA``): one data and one result per operation.

    ``specifications`` is the optional echo of the request's
    specifications (None when the server left it out, which is usual).
    ``data`` holds the value read, an action's return parameters, or
    null-data; ``results`` the data-access-result (get, set) or
    action-result (action) of each operation.
    """

    long_invoke_id: int
    date_time: bytes | None
    specifications: list[AccessRequestSpecification] | None
    data: list[DlmsData]
    results: list[AccessResponseSpecification]

    @property
    def timestamp(self) -> CosemDateTime | None:
        return _timestamp(self.date_time)

    def to_bytes(self) -> bytes:
        _check_long_invoke_id(self.long_invoke_id)
        if len(self.data) != len(self.results):
            raise ValueError(
                f"ACCESS response has {len(self.data)} data but {len(self.results)} results"
            )
        if self.specifications is not None and len(self.specifications) != len(self.results):
            raise ValueError(
                f"ACCESS response echoes {len(self.specifications)} specifications "
                f"for {len(self.results)} results"
            )
        out = bytearray([Tag.ACCESS_RESPONSE]) + self.long_invoke_id.to_bytes(4, "big")
        out += _date_time_bytes(self.date_time)
        if self.specifications is None:
            out.append(0)
        else:
            out += b"\x01" + encode_length(len(self.specifications))
            for spec in self.specifications:
                out += spec.to_bytes()
        out += encode_length(len(self.data))
        for value in self.data:
            out += encode_data(value)
        out += encode_length(len(self.results))
        for result in self.results:
            out += result.to_bytes()
        return bytes(out)


# --- push ------------------------------------------------------------------------------


@dataclass
class DataNotification:
    """DataNotification: long-invoke-id, optional date-time, notification body.

    The date-time is an A-XDR OCTET STRING: ``00`` (absent) or ``0C`` + 12
    octets. Some meters (Kaifa) send it Data-tagged as ``09 0C`` + 12; that
    form is accepted on decode and recorded in :attr:`date_time_tagged`.
    """

    long_invoke_id: int
    body: DlmsData
    date_time: bytes | None = None
    date_time_tagged: bool = False

    @property
    def priority_fields(self) -> LongInvokeIdAndPriority:
        """The raw :attr:`long_invoke_id` split into its fields."""
        return LongInvokeIdAndPriority.from_int(self.long_invoke_id)

    @property
    def high_priority(self) -> bool:
        return self.priority_fields.high_priority

    @property
    def confirmed(self) -> bool:
        return self.priority_fields.confirmed

    @property
    def processing_option(self) -> ProcessingOption:
        return self.priority_fields.processing_option

    @property
    def self_descriptive(self) -> bool:
        return self.priority_fields.self_descriptive

    @property
    def invoke_id(self) -> int:
        """The 24-bit invoke id (the raw field without the flag octet)."""
        return self.priority_fields.invoke_id

    @property
    def timestamp(self) -> CosemDateTime | None:
        if self.date_time and len(self.date_time) == 12:
            return CosemDateTime.from_bytes(self.date_time)
        return None

    def to_bytes(self) -> bytes:
        out = bytearray([Tag.DATA_NOTIFICATION]) + self.long_invoke_id.to_bytes(4, "big")
        if self.date_time:
            if self.date_time_tagged:
                out.append(0x09)
            out += encode_length(len(self.date_time)) + self.date_time
        else:
            out.append(0)
        out += encode_data(self.body)
        return bytes(out)


@dataclass
class EventNotificationRequest:
    attribute: AttributeDescriptor
    value: DlmsData
    time: bytes | None = None

    @property
    def timestamp(self) -> CosemDateTime | None:
        if self.time and len(self.time) == 12:
            return CosemDateTime.from_bytes(self.time)
        return None

    def to_bytes(self) -> bytes:
        out = bytearray([Tag.EVENT_NOTIFICATION_REQUEST])
        out += b"\x00" if not self.time else b"\x01" + encode_length(len(self.time)) + self.time
        return bytes(out) + self.attribute.to_bytes() + encode_data(self.value)


# --- errors --------------------------------------------------------------------------


class StateError(enum.IntEnum):
    SERVICE_NOT_ALLOWED = 1
    SERVICE_UNKNOWN = 2


class ExceptionServiceError(enum.IntEnum):
    OPERATION_NOT_POSSIBLE = 1
    SERVICE_NOT_SUPPORTED = 2
    OTHER_REASON = 3
    PDU_TOO_LONG = 4
    DECIPHERING_ERROR = 5
    INVOCATION_COUNTER_ERROR = 6


@dataclass
class ExceptionResponse:
    state_error: int
    service_error: int
    invocation_counter: int | None = None

    def to_bytes(self) -> bytes:
        out = bytes([Tag.EXCEPTION_RESPONSE, self.state_error, self.service_error])
        if self.invocation_counter is not None:
            out += self.invocation_counter.to_bytes(4, "big")
        return out

    def describe(self) -> str:
        try:
            state = StateError(self.state_error).name
        except ValueError:
            state = str(self.state_error)
        try:
            service = ExceptionServiceError(self.service_error).name
        except ValueError:
            service = str(self.service_error)
        text = f"{state}/{service}"
        if self.invocation_counter is not None:
            text += f" (meter expects IC > {self.invocation_counter})"
        return text


class ServiceErrorChoice(enum.IntEnum):
    """Green Book ServiceError CHOICE tags; [8] (change-scope) is not used by DLMS.

    jDLMS numbers these the same way; Gurux numbers them sequentially, so its
    "task" is 8 on the wire and its "other-error" is 9.
    """

    APPLICATION_REFERENCE = 0
    HARDWARE_RESOURCE = 1
    VDE_STATE_ERROR = 2
    SERVICE = 3
    DEFINITION = 4
    ACCESS = 5
    INITIATE = 6
    LOAD_DATA_SET = 7
    TASK = 9
    OTHER_ERROR = 10


@dataclass
class ConfirmedServiceError:
    """``0E service error-choice value``; e.g. ``0E 01 06 01`` = initiateError,
    initiate, dlms-version-too-low."""

    service: int
    error_type: int
    value: int

    def to_bytes(self) -> bytes:
        return bytes([Tag.CONFIRMED_SERVICE_ERROR, self.service, self.error_type, self.value])

    def describe(self) -> str:
        try:
            kind = ServiceErrorChoice(self.error_type).name
        except ValueError:
            kind = str(self.error_type)
        initiate = {
            0: "other",
            1: "dlms-version-too-low",
            2: "incompatible-conformance",
            3: "pdu-size-too-short",
            4: "refused-by-the-VDE-handler",
        }
        detail = initiate.get(self.value, str(self.value)) if self.error_type == 6 else self.value
        return f"service {self.service} {kind} {detail}"


#: ConfirmedServiceError CHOICE: initiateError [1] .. terminateUpLoad [19].
_CONFIRMED_SERVICES = range(1, 20)


def _check_confirmed_service_error(error: ConfirmedServiceError) -> None:
    if error.service not in _CONFIRMED_SERVICES:
        raise DecodeError(f"ConfirmedServiceError service choice {error.service} is not defined")
    if error.error_type not in ServiceErrorChoice.__members__.values():
        raise DecodeError(f"ServiceError choice {error.error_type} is not defined")


# --- decoding --------------------------------------------------------------------------


def _decode_get_response(r: _Reader):
    choice = r.u8()
    invoke_id = r.u8()
    if choice == 1:
        return GetResponseNormal(invoke_id, GetDataResult.read(r))
    if choice == 2:
        last = r.u8() != 0
        number = r.u32()
        kind = r.u8()
        if kind == 0:
            return GetResponseWithDatablock(invoke_id, last, number, raw_data=r.octets())
        if kind == 1:
            return GetResponseWithDatablock(invoke_id, last, number, error=_access_result(r.u8()))
        raise DecodeError(f"DataBlock-G result choice {kind} is not 0 or 1")
    if choice == 3:
        n = r.length()
        return GetResponseWithList(invoke_id, [GetDataResult.read(r) for _ in range(n)])
    raise DecodeError(f"unknown GET-Response choice {choice}")


def _decode_get_request(r: _Reader):
    choice = r.u8()
    invoke_id = r.u8()
    if choice == 1:
        return GetRequestNormal(invoke_id, AttributeDescriptor.read(r), _read_access(r))
    if choice == 2:
        return GetRequestNext(invoke_id, r.u32())
    if choice == 3:
        n = r.length()
        return GetRequestWithList(
            invoke_id, [(AttributeDescriptor.read(r), _read_access(r)) for _ in range(n)]
        )
    raise DecodeError(f"unknown GET-Request choice {choice}")


def _read_datablock_sa(r: _Reader) -> tuple[bool, int, bytes]:
    last = r.u8() != 0
    number = r.u32()
    return last, number, r.octets()


def _decode_set_request(r: _Reader):
    choice = r.u8()
    invoke_id = r.u8()
    if choice == 1:
        attribute = AttributeDescriptor.read(r)
        access = _read_access(r)
        return SetRequestNormal(invoke_id, attribute, r.data_value(), access)
    if choice == 2:
        attribute = AttributeDescriptor.read(r)
        access = _read_access(r)
        last, number, raw = _read_datablock_sa(r)
        return SetRequestWithFirstDatablock(invoke_id, attribute, last, number, raw, access)
    if choice == 3:
        return SetRequestWithDatablock(invoke_id, *_read_datablock_sa(r))
    if choice == 4:
        n = r.length()
        refs = [(AttributeDescriptor.read(r), _read_access(r)) for _ in range(n)]
        m = r.length()
        if m != n:
            raise DecodeError(f"SET with-list has {n} descriptors but {m} values")
        return SetRequestWithList(invoke_id, [(a, s, r.data_value()) for a, s in refs])
    if choice == 5:
        n = _count(r, _ATTRIBUTE_WITH_SELECTION_MIN)
        refs = [(AttributeDescriptor.read(r), _read_access(r)) for _ in range(n)]
        return SetRequestWithListAndFirstDatablock(invoke_id, refs, *_read_datablock_sa(r))
    raise DecodeError(f"unsupported SET-Request choice {choice}")


def _decode_set_response(r: _Reader):
    choice = r.u8()
    invoke_id = r.u8()
    if choice == 1:
        return SetResponseNormal(invoke_id, _access_result(r.u8()))
    if choice == 2:
        return SetResponseDatablock(invoke_id, r.u32())
    if choice == 3:
        result = _access_result(r.u8())
        return SetResponseLastDatablock(invoke_id, result, r.u32())
    if choice in (4, 5):
        n = r.length()
        results = [_access_result(r.u8()) for _ in range(n)]
        if choice == 4:
            return SetResponseLastDatablockWithList(invoke_id, results, r.u32())
        return SetResponseWithList(invoke_id, results)
    raise DecodeError(f"unknown SET-Response choice {choice}")


def _decode_action_request(r: _Reader):
    choice = r.u8()
    invoke_id = r.u8()
    if choice == 1:
        method = MethodDescriptor.read(r)
        params = r.data_value() if r.optional() else None
        return ActionRequestNormal(invoke_id, method, params)
    if choice == 2:
        return ActionRequestNextPblock(invoke_id, r.u32())
    if choice == 3:
        n = r.length()
        methods = [MethodDescriptor.read(r) for _ in range(n)]
        m = r.length()
        if m != n:
            raise DecodeError(f"ACTION with-list has {n} methods but {m} parameters")
        return ActionRequestWithList(invoke_id, [(md, r.data_value()) for md in methods])
    if choice == 4:
        method = MethodDescriptor.read(r)
        return ActionRequestWithFirstPblock(invoke_id, method, *_read_datablock_sa(r))
    if choice == 5:
        n = _count(r, _METHOD_DESCRIPTOR_MIN)
        methods = [MethodDescriptor.read(r) for _ in range(n)]
        return ActionRequestWithListAndFirstPblock(invoke_id, methods, *_read_datablock_sa(r))
    if choice == 6:
        return ActionRequestWithPblock(invoke_id, *_read_datablock_sa(r))
    raise DecodeError(f"unsupported ACTION-Request choice {choice}")


def _read_action_return(r: _Reader) -> GetDataResult | None:
    return GetDataResult.read(r) if r.optional() else None


def _decode_action_response(r: _Reader):
    choice = r.u8()
    invoke_id = r.u8()
    if choice == 1:
        result = _action_result(r.u8())
        return ActionResponseNormal(invoke_id, result, _read_action_return(r))
    if choice == 2:
        return ActionResponseWithPblock(invoke_id, *_read_datablock_sa(r))
    if choice == 3:
        n = r.length()
        results = []
        for _ in range(n):
            result = _action_result(r.u8())
            results.append((result, _read_action_return(r)))
        return ActionResponseWithList(invoke_id, results)
    if choice == 4:
        return ActionResponseNextPblock(invoke_id, r.u32())
    raise DecodeError(f"unknown ACTION-Response choice {choice}")


def _decode_data_notification(r: _Reader) -> DataNotification:
    long_invoke_id = r.u32()
    tagged = False
    if (
        not r.done()
        and r.data[r.pos] == 0x09
        and r.pos + 1 < len(r.data)
        and r.data[r.pos + 1] == 0x0C
    ):
        r.u8()
        tagged = True
    date_time = r.octets() or None
    body = r.data_value()
    return DataNotification(long_invoke_id, body, date_time, tagged)


def _decode_event_notification(r: _Reader) -> EventNotificationRequest:
    time = r.octets() if r.optional() else None
    attribute = AttributeDescriptor.read(r)
    return EventNotificationRequest(attribute, r.data_value(), time)


#: Smallest encoded Access-Request-Specification (kind and a descriptor),
#: Data (null-data) and Access-Response-Specification (kind and result).
_ACCESS_SPEC_MIN = 10
_DATA_MIN = 1
_ACCESS_RESULT_MIN = 2


def _read_access_spec(r: _Reader) -> AccessRequestSpecification:
    kind = r.u8()
    if kind == AccessKind.GET:
        return AccessRequestGet(AttributeDescriptor.read(r))
    if kind == AccessKind.SET:
        return AccessRequestSet(AttributeDescriptor.read(r))
    if kind == AccessKind.ACTION:
        return AccessRequestAction(MethodDescriptor.read(r))
    if kind in (AccessKind.GET_WITH_SELECTION, AccessKind.SET_WITH_SELECTION):
        attribute = AttributeDescriptor.read(r)
        access = SelectiveAccess(r.u8(), r.data_value())
        if kind == AccessKind.GET_WITH_SELECTION:
            return AccessRequestGetWithSelection(attribute, access)
        return AccessRequestSetWithSelection(attribute, access)
    raise DecodeError(f"Access-Request-Specification choice {kind} is not 1..5")


def _read_access_result(r: _Reader) -> AccessResponseSpecification:
    kind = r.u8()
    if kind == AccessKind.GET:
        return AccessResponseGet(_access_result(r.u8()))
    if kind == AccessKind.SET:
        return AccessResponseSet(_access_result(r.u8()))
    if kind == AccessKind.ACTION:
        return AccessResponseAction(_action_result(r.u8()))
    raise DecodeError(f"Access-Response-Specification choice {kind} is not 1..3")


def _read_access_specs(r: _Reader) -> list[AccessRequestSpecification]:
    return [_read_access_spec(r) for _ in range(_count(r, _ACCESS_SPEC_MIN))]


def _read_data_list(r: _Reader) -> list[DlmsData]:
    return [r.data_value() for _ in range(_count(r, _DATA_MIN))]


def _decode_access_request(r: _Reader) -> AccessRequest:
    long_invoke_id = r.u32()
    date_time = r.octets() or None
    specs = _read_access_specs(r)
    data = _read_data_list(r)
    if len(data) != len(specs):
        raise DecodeError(f"ACCESS request has {len(specs)} specifications but {len(data)} data")
    return AccessRequest(long_invoke_id, date_time, specs, data)


def _decode_access_response(r: _Reader) -> AccessResponse:
    long_invoke_id = r.u32()
    date_time = r.octets() or None
    echo = _read_access_specs(r) if r.optional() else None
    data = _read_data_list(r)
    results = [_read_access_result(r) for _ in range(_count(r, _ACCESS_RESULT_MIN))]
    if len(results) != len(data):
        raise DecodeError(f"ACCESS response has {len(data)} data but {len(results)} results")
    if echo is not None and len(echo) != len(results):
        raise DecodeError(
            f"ACCESS response echoes {len(echo)} specifications for {len(results)} results"
        )
    return AccessResponse(long_invoke_id, date_time, echo, data, results)


_DECODERS = {
    Tag.GET_REQUEST: _decode_get_request,
    Tag.GET_RESPONSE: _decode_get_response,
    Tag.SET_REQUEST: _decode_set_request,
    Tag.SET_RESPONSE: _decode_set_response,
    Tag.ACTION_REQUEST: _decode_action_request,
    Tag.ACTION_RESPONSE: _decode_action_response,
    Tag.DATA_NOTIFICATION: _decode_data_notification,
    Tag.EVENT_NOTIFICATION_REQUEST: _decode_event_notification,
    Tag.ACCESS_REQUEST: _decode_access_request,
    Tag.ACCESS_RESPONSE: _decode_access_response,
}


def decode_apdu(apdu: bytes, strict: bool = True):
    """Decode a plaintext xDLMS APDU to its dataclass.

    ``strict`` rejects trailing octets. ACSE and SN APDUs live in
    :mod:`pydlms.apdu.acse` / :mod:`pydlms.apdu.sn`; ciphered ones must be
    unwrapped first.
    """
    if not apdu:
        raise DecodeError("empty APDU")
    tag = apdu[0]
    try:
        if tag == Tag.INITIATE_REQUEST:
            return InitiateRequest.from_bytes(apdu)
        if tag == Tag.INITIATE_RESPONSE:
            return InitiateResponse.from_bytes(apdu)
        if tag == Tag.EXCEPTION_RESPONSE:
            # Only invocation-counter-error [6] carries content (Unsigned32);
            # every other service-error alternative is IMPLICIT NULL.
            r = _Reader(apdu, 1)
            state, service = r.u8(), r.u8()
            ic = None
            if service == ExceptionServiceError.INVOCATION_COUNTER_ERROR and (
                strict or len(apdu) - r.pos >= 4
            ):
                ic = r.u32()
            if strict:
                r.finish("ExceptionResponse")
            return ExceptionResponse(state, service, ic)
        if tag == Tag.CONFIRMED_SERVICE_ERROR:
            r = _Reader(apdu, 1)
            result = ConfirmedServiceError(r.u8(), r.u8(), r.u8())
            if strict:
                _check_confirmed_service_error(result)
                r.finish("ConfirmedServiceError")
            return result
        decoder = _DECODERS.get(tag)
        if decoder is None:
            raise DecodeError(f"no xDLMS decoder for APDU {tag_name(tag)}")
        r = _Reader(apdu, 1)
        result = decoder(r)
        if strict:
            r.finish(tag_name(tag))
        return result
    except construct.ConstructError as exc:
        raise DecodeError(f"malformed {tag_name(tag)}: {exc}") from exc
