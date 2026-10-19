"""The COSEM ``Data`` type (A-XDR CHOICE, IEC 62056-6-2 Annex A).

Every attribute value, every GET response and every DataNotification payload is
a ``Data`` value: a one-octet type tag followed by type-specific content. The
composite types ``array`` (1) and ``structure`` (2) are recursive, so this is a
self-referential codec.

Representation: a :class:`DlmsData` wrapper carrying the :class:`DataType` tag
and a Python value. The tag is kept explicitly because several tags map to the
same Python type (``unsigned``/``long-unsigned``/... are all ``int``), so a bare
Python value could not be re-encoded unambiguously. Use :meth:`DlmsData.to_python`
to collapse a tree to plain Python for easy reading.

The codec is exposed as :data:`CosemData`, a ``construct`` subconstruct, plus
:func:`encode_data` / :func:`decode_data` for direct byte work.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

import construct
from construct import Construct, stream_read, stream_write

from pydlms.axdr import encode_length, read_length
from pydlms.cosem.enums import DataType
from pydlms.exceptions import DecodeError

__all__ = [
    "DlmsData",
    "CosemData",
    "TypeDescription",
    "TypeDescriptionCodec",
    "Untagged",
    "CompactArray",
    "decode_type_description",
    "encode_type_description",
    "decode_untagged",
    "encode_untagged",
    "encode_data",
    "decode_data",
    "MAX_NESTING",
]

#: Deepest array/structure nesting accepted from the wire. Real meters nest a
#: handful of levels; this only exists so hostile input cannot exhaust the
#: interpreter stack.
MAX_NESTING = 32

# Fixed-width signed/unsigned integer tags -> (struct format, signed).
_INT_FORMATS: dict[DataType, str] = {
    DataType.INTEGER: ">b",
    DataType.UNSIGNED: ">B",
    DataType.LONG: ">h",
    DataType.LONG_UNSIGNED: ">H",
    DataType.DOUBLE_LONG: ">i",
    DataType.DOUBLE_LONG_UNSIGNED: ">I",
    DataType.LONG64: ">q",
    DataType.LONG64_UNSIGNED: ">Q",
    # Delta types share the base integer's wire form (not resolved here).
    DataType.DELTA_INTEGER: ">b",
    DataType.DELTA_LONG: ">h",
    DataType.DELTA_DOUBLE_LONG: ">i",
    DataType.DELTA_UNSIGNED: ">B",
    DataType.DELTA_LONG_UNSIGNED: ">H",
    DataType.DELTA_DOUBLE_LONG_UNSIGNED: ">I",
}
_ENUM_AS_U8 = DataType.ENUM  # carried as uint8, kept distinct from UNSIGNED by tag
_ONE_OCTET_RAW = (DataType.ENUM, DataType.BCD)  # single opaque octet, value is int
# Fixed-size opaque octet payloads (semantic decode lives in time.py).
_FIXED_OCTETS: dict[DataType, int] = {
    DataType.DATE_TIME: 12,
    DataType.DATE: 5,
    DataType.TIME: 4,
}
# Tags without content: null-data [0] and dont-care [255] (both IMPLICIT NULL).
_EMPTY = (DataType.NULL, DataType.DONT_CARE)
_STRING_ENCODINGS: dict[DataType, str] = {
    DataType.VISIBLE_STRING: "latin-1",  # lossless over 0..255; visible-string is ASCII
    DataType.UTF8_STRING: "utf-8",
}


@dataclass
class DlmsData:
    """A tagged COSEM ``Data`` value."""

    tag: DataType
    value: Any = None

    def __post_init__(self) -> None:
        self.tag = DataType(self.tag)

    # -- convenience constructors ------------------------------------------
    @classmethod
    def null(cls) -> DlmsData:
        return cls(DataType.NULL, None)

    @classmethod
    def array(cls, items: list[DlmsData]) -> DlmsData:
        return cls(DataType.ARRAY, list(items))

    @classmethod
    def structure(cls, items: list[DlmsData]) -> DlmsData:
        return cls(DataType.STRUCTURE, list(items))

    @classmethod
    def boolean(cls, value: bool) -> DlmsData:
        return cls(DataType.BOOLEAN, bool(value))

    @classmethod
    def enum(cls, value: int) -> DlmsData:
        return cls(DataType.ENUM, int(value))

    @classmethod
    def octet_string(cls, value: bytes) -> DlmsData:
        return cls(DataType.OCTET_STRING, bytes(value))

    @classmethod
    def visible_string(cls, value: str) -> DlmsData:
        return cls(DataType.VISIBLE_STRING, value)

    @classmethod
    def uint8(cls, value: int) -> DlmsData:
        return cls(DataType.UNSIGNED, value)

    @classmethod
    def uint16(cls, value: int) -> DlmsData:
        return cls(DataType.LONG_UNSIGNED, value)

    @classmethod
    def uint32(cls, value: int) -> DlmsData:
        return cls(DataType.DOUBLE_LONG_UNSIGNED, value)

    @classmethod
    def int8(cls, value: int) -> DlmsData:
        return cls(DataType.INTEGER, value)

    @classmethod
    def int16(cls, value: int) -> DlmsData:
        return cls(DataType.LONG, value)

    @classmethod
    def int32(cls, value: int) -> DlmsData:
        return cls(DataType.DOUBLE_LONG, value)

    # -- unwrap ------------------------------------------------------------
    def to_python(self) -> Any:
        """Collapse the tree to plain Python (composites become lists)."""
        if self.tag in (DataType.ARRAY, DataType.STRUCTURE):
            return [item.to_python() for item in self.value]
        if self.tag == DataType.COMPACT_ARRAY:
            return [item.to_python() for item in self.value.items]
        return self.value


def _encode_into(obj: DlmsData, out: bytearray) -> None:
    tag = DataType(obj.tag)
    out.append(tag.value)

    if tag in _EMPTY:
        return
    if tag in (DataType.ARRAY, DataType.STRUCTURE):
        items = obj.value
        out += encode_length(len(items))
        for item in items:
            _encode_into(item, out)
        return
    if tag == DataType.BOOLEAN:
        out.append(1 if obj.value else 0)
        return
    if tag in _INT_FORMATS:
        fmt = _INT_FORMATS[tag]
        try:
            out += struct.pack(fmt, obj.value)
        except struct.error as exc:
            raise ValueError(f"{tag.name} value {obj.value!r} out of range: {exc}") from exc
        return
    if tag in _ONE_OCTET_RAW:
        if not 0 <= obj.value <= 255:
            raise ValueError(f"{tag.name} value {obj.value!r} out of range 0..255")
        out.append(obj.value)
        return
    if tag == DataType.FLOAT32:
        try:
            out += struct.pack(">f", obj.value)
        except OverflowError as exc:
            raise ValueError(f"FLOAT32 value {obj.value!r} out of range: {exc}") from exc
        return
    if tag == DataType.FLOAT64:
        out += struct.pack(">d", obj.value)
        return
    if tag == DataType.OCTET_STRING:
        data = bytes(obj.value)
        out += encode_length(len(data))
        out += data
        return
    if tag in _STRING_ENCODINGS:
        data = obj.value.encode(_STRING_ENCODINGS[tag])
        out += encode_length(len(data))
        out += data
        return
    if tag in _FIXED_OCTETS:
        data = bytes(obj.value)
        if len(data) != _FIXED_OCTETS[tag]:
            raise ValueError(f"{tag.name} is {_FIXED_OCTETS[tag]} octets, got {len(data)}")
        out += data
        return
    if tag == DataType.BIT_STRING:
        bits = obj.value  # list[bool]
        out += encode_length(len(bits))
        out += _pack_bits(bits)
        return
    if tag == DataType.COMPACT_ARRAY:
        compact = obj.value
        if not isinstance(compact, CompactArray):
            raise ValueError("COMPACT_ARRAY value must be a CompactArray")
        if _has_uncounted_array(compact.description):
            raise ValueError("a compact-array description needs a count for every array")
        _encode_type_description(compact.description, out)
        body = bytearray()
        for item in compact.items:
            _encode_untagged(item, compact.description, body)
        out += encode_length(len(body))
        out += body
        return
    raise NotImplementedError(f"encoding of COSEM data type {tag.name} is not implemented")


def _pack_bits(bits: list[bool]) -> bytes:
    nbytes = (len(bits) + 7) // 8
    out = bytearray(nbytes)
    for i, bit in enumerate(bits):
        if bit:
            out[i // 8] |= 0x80 >> (i % 8)  # MSB-first within each octet
    return bytes(out)


def _unpack_bits(raw: bytes, nbits: int) -> list[bool]:
    return [bool(raw[i // 8] & (0x80 >> (i % 8))) for i in range(nbits)]


def encode_data(obj: DlmsData) -> bytes:
    """Encode a :class:`DlmsData` tree to A-XDR bytes."""
    out = bytearray()
    _encode_into(obj, out)
    return bytes(out)


def decode_data(data: bytes, offset: int = 0) -> tuple[DlmsData, int]:
    """Decode one :class:`DlmsData` tree. Returns ``(data, next_offset)``."""
    reader = _BytesReader(data, offset)
    value = _decode(reader)
    return value, reader.pos


class _CosemData(Construct):
    """``construct`` wrapper around the recursive COSEM data codec."""

    def _parse(self, stream, _context, path):
        # COSEM data is self-delimiting; pull one tag at a time off the stream
        # so it composes inside a larger construct without a known length.
        try:
            return _decode(_StreamReader(stream, path))
        except ValueError as exc:
            raise construct.ConstructError(str(exc), path) from exc

    def _build(self, obj, stream, _context, path):
        if not isinstance(obj, DlmsData):
            raise construct.ConstructError(f"expected DlmsData, got {type(obj).__name__}", path)
        try:
            data = encode_data(obj)
        except (ValueError, NotImplementedError) as exc:
            raise construct.ConstructError(str(exc), path) from exc
        stream_write(stream, data, len(data), path)
        return obj

    def _sizeof(self, _context, path):
        raise construct.SizeofError("CosemData has a variable size", path=path)


class _StreamReader:
    """Reader backed by a construct stream (for embedded parsing)."""

    def __init__(self, stream, path):
        self._stream = stream
        self._path = path

    def read(self, n: int) -> bytes:
        return stream_read(self._stream, n, self._path)


class _BytesReader:
    """Reader backed by a bytes buffer, tracking the consumed offset."""

    def __init__(self, data: bytes, offset: int = 0):
        self._data = data
        self.pos = offset

    def read(self, n: int) -> bytes:
        end = self.pos + n
        if end > len(self._data):
            raise DecodeError(
                f"need {n} octets at offset {self.pos}, only {len(self._data) - self.pos} remain"
            )
        chunk = self._data[self.pos : end]
        self.pos = end
        return chunk


def _decode(reader, depth: int = 0) -> DlmsData:
    raw = reader.read(1)
    try:
        tag = DataType(raw[0])
    except ValueError:
        raise DecodeError(f"unknown COSEM data type tag 0x{raw[0]:02X}") from None
    return _decode_content(reader, tag, depth)


def _decode_content(reader, tag: DataType, depth: int) -> DlmsData:
    if tag in _EMPTY:
        return DlmsData(tag, None)
    if tag in (DataType.ARRAY, DataType.STRUCTURE):
        if depth >= MAX_NESTING:
            raise DecodeError(f"COSEM data nested deeper than {MAX_NESTING} levels")
        count = _read_length(reader)
        return DlmsData(tag, [_decode(reader, depth + 1) for _ in range(count)])
    if tag == DataType.COMPACT_ARRAY:
        description = _decode_type_description(reader, depth)
        length = _read_length(reader)
        body = _BytesReader(reader.read(length))
        budget = _Budget(length)
        items = []
        while body.pos < length:
            before = body.pos
            items.append(_decode_untagged(body, description, depth + 1, budget))
            if body.pos == before:
                raise DecodeError(
                    f"compact-array element type {description.tag.name} occupies 0 octets"
                )
        return DlmsData(tag, CompactArray(description, items))
    if tag == DataType.BOOLEAN:
        return DlmsData(tag, reader.read(1)[0] != 0)
    if tag in _INT_FORMATS:
        fmt = _INT_FORMATS[tag]
        size = struct.calcsize(fmt)
        (value,) = struct.unpack(fmt, reader.read(size))
        return DlmsData(tag, value)
    if tag in _ONE_OCTET_RAW:
        return DlmsData(tag, reader.read(1)[0])
    if tag == DataType.FLOAT32:
        (value,) = struct.unpack(">f", reader.read(4))
        return DlmsData(tag, value)
    if tag == DataType.FLOAT64:
        (value,) = struct.unpack(">d", reader.read(8))
        return DlmsData(tag, value)
    if tag == DataType.OCTET_STRING:
        length = _read_length(reader)
        return DlmsData(tag, reader.read(length))
    if tag in _STRING_ENCODINGS:
        length = _read_length(reader)
        raw = reader.read(length)
        try:
            return DlmsData(tag, raw.decode(_STRING_ENCODINGS[tag]))
        except UnicodeDecodeError as exc:  # latin-1 is total, so only utf8-string
            raise DecodeError(f"utf8-string is not valid UTF-8: {exc.reason}") from None
    if tag in _FIXED_OCTETS:
        return DlmsData(tag, reader.read(_FIXED_OCTETS[tag]))
    if tag == DataType.BIT_STRING:
        nbits = _read_length(reader)
        raw = reader.read((nbits + 7) // 8)
        return DlmsData(tag, _unpack_bits(raw, nbits))
    raise DecodeError(f"decoding of COSEM data type {tag.name} is not implemented")


def _read_length(reader) -> int:
    return read_length(reader.read)


# --- compact-array (tag 19) ------------------------------------------------
#
# IEC 62056-6-2 compact-array: ``content-description`` (a TypeDescription)
# followed by ``array-contents`` as a length-prefixed octet string in which the
# elements are packed back to back *without* their type tags.
#
#   TypeDescription ::= CHOICE {
#       <simple tag>            -- the type alone
#       array [1]   SEQUENCE { number-of-elements Unsigned16, TypeDescription }
#       structure [2] SEQUENCE OF TypeDescription   -- A-XDR length + items
#   }


@dataclass(frozen=True)
class TypeDescription:
    """Type of the elements of a compact array."""

    tag: DataType
    #: For ``ARRAY``: (number_of_elements, element description). A count of
    #: ``None`` is the Compact data (IC 62) template form: the description
    #: has no count and every value carries its own (see
    #: :func:`pydlms.cosem.compact_data.decode_template_description`).
    array_of: tuple[int | None, TypeDescription] | None = None
    #: For ``STRUCTURE``: the member descriptions.
    members: tuple[TypeDescription, ...] = ()

    @classmethod
    def of(cls, value: DlmsData) -> TypeDescription:
        """Derive the description of an (untagged-encodable) value."""
        if value.tag == DataType.STRUCTURE:
            return cls(value.tag, members=tuple(cls.of(v) for v in value.value))
        if value.tag == DataType.ARRAY:
            if not value.value:
                raise ValueError("cannot describe an empty array")
            return cls(value.tag, array_of=(len(value.value), cls.of(value.value[0])))
        return cls(value.tag)


@dataclass
class CompactArray:
    """Value of a ``COMPACT_ARRAY``: element description plus tagged items."""

    description: TypeDescription
    items: list[DlmsData]


def _has_uncounted_array(desc: TypeDescription) -> bool:
    if desc.array_of is not None:
        return desc.array_of[0] is None or _has_uncounted_array(desc.array_of[1])
    return any(_has_uncounted_array(m) for m in desc.members)


def _encode_type_description(desc: TypeDescription, out: bytearray) -> None:
    out.append(desc.tag.value)
    if desc.tag == DataType.ARRAY:
        assert desc.array_of is not None
        count, element = desc.array_of
        if count is not None:
            out += struct.pack(">H", count)
        _encode_type_description(element, out)
    elif desc.tag == DataType.STRUCTURE:
        out += encode_length(len(desc.members))
        for member in desc.members:
            _encode_type_description(member, out)


def _decode_type_description(
    reader, depth: int = 0, counted_arrays: bool = True
) -> TypeDescription:
    if depth >= MAX_NESTING:
        raise DecodeError(f"type description nested deeper than {MAX_NESTING} levels")
    raw = reader.read(1)[0]
    try:
        tag = DataType(raw)
    except ValueError:
        raise DecodeError(f"unknown type tag 0x{raw:02X} in compact-array description") from None
    if tag == DataType.ARRAY:
        count = struct.unpack(">H", reader.read(2))[0] if counted_arrays else None
        element = _decode_type_description(reader, depth + 1, counted_arrays)
        return TypeDescription(tag, array_of=(count, element))
    if tag == DataType.STRUCTURE:
        n = _read_length(reader)
        return TypeDescription(
            tag,
            members=tuple(
                _decode_type_description(reader, depth + 1, counted_arrays) for _ in range(n)
            ),
        )
    if tag == DataType.COMPACT_ARRAY:
        raise DecodeError("compact-array cannot describe nested compact-arrays")
    return TypeDescription(tag)


def _encode_untagged(item: DlmsData, desc: TypeDescription, out: bytearray) -> None:
    if DataType(item.tag) != desc.tag:
        raise ValueError(
            f"compact-array element is {item.tag.name}, description says {desc.tag.name}"
        )
    if desc.tag == DataType.STRUCTURE:
        if len(item.value) != len(desc.members):
            raise ValueError("structure member count does not match its description")
        for member, member_desc in zip(item.value, desc.members, strict=True):
            _encode_untagged(member, member_desc, out)
        return
    if desc.tag == DataType.ARRAY:
        assert desc.array_of is not None
        count, element = desc.array_of
        if count is None:
            out += encode_length(len(item.value))
        elif len(item.value) != count:
            raise ValueError("array element count does not match its description")
        for member in item.value:
            _encode_untagged(member, element, out)
        return
    # Simple types: the normal encoding minus the leading tag octet.
    out += encode_data(item)[1:]


class _Budget:
    """Upper bound on the values one compact-array may expand to.

    Every value whose type has a non-zero width consumes at least one octet,
    and each such value has at most ``MAX_NESTING`` composite ancestors, so an
    honest compact-array of ``n`` content octets yields at most
    ``(MAX_NESTING + 1) * n`` values. Only zero-width types (null-data, empty
    structures, arrays of them) can exceed that, and they could otherwise
    expand a few octets into billions of objects.
    """

    def __init__(self, octets: int) -> None:
        self.limit = (MAX_NESTING + 1) * octets
        self.left = self.limit

    def take(self) -> None:
        self.left -= 1
        if self.left < 0:
            raise DecodeError(
                f"compact-array expands to more than {self.limit} values; "
                "its element type is (partly) zero-width"
            )


def _decode_untagged(reader, desc: TypeDescription, depth: int, budget: _Budget) -> DlmsData:
    if depth >= MAX_NESTING:
        raise DecodeError(f"compact-array element nested deeper than {MAX_NESTING} levels")
    budget.take()
    if desc.tag == DataType.STRUCTURE:
        return DlmsData(
            desc.tag, [_decode_untagged(reader, m, depth + 1, budget) for m in desc.members]
        )
    if desc.tag == DataType.ARRAY:
        assert desc.array_of is not None
        count, element = desc.array_of
        if count is None:
            count = _read_length(reader)
        return DlmsData(
            desc.tag,
            [_decode_untagged(reader, element, depth + 1, budget) for _ in range(count)],
        )
    return _decode_content(reader, desc.tag, depth)


# --- public type-description / untagged codec ----------------------------------------
#
# Compact data (IC 62) carries a TypeDescription on its own
# (``template_description``) and the untagged values in ``compact_buffer``.


def encode_type_description(desc: TypeDescription) -> bytes:
    """Encode a compact-array :class:`TypeDescription`."""
    out = bytearray()
    _encode_type_description(desc, out)
    return bytes(out)


def decode_type_description(data: bytes, *, counted_arrays: bool = True) -> TypeDescription:
    """Decode a :class:`TypeDescription` that must fill ``data`` exactly.

    ``counted_arrays=False`` reads the Compact data template form, where an
    array is its tag and element description only (count ``None``).
    """
    data = bytes(data)
    reader = _BytesReader(data)
    desc = _decode_type_description(reader, 0, counted_arrays)
    if reader.pos != len(data):
        raise DecodeError(f"{len(data) - reader.pos} trailing octets after the type description")
    return desc


def encode_untagged(value: DlmsData, desc: TypeDescription) -> bytes:
    """Encode ``value`` without type tags, as ``desc`` describes it.

    Raises :class:`ValueError` when ``value`` does not match ``desc``.
    """
    out = bytearray()
    _encode_untagged(value, desc, out)
    return bytes(out)


def decode_untagged(data: bytes, desc: TypeDescription) -> DlmsData:
    """Decode one untagged value of type ``desc`` that must fill ``data`` exactly.

    The compact-array expansion budget applies (at least one value per
    octet of nesting depth), so a zero-width description cannot expand a
    few octets into millions of values.
    """
    data = bytes(data)
    reader = _BytesReader(data)
    value = _decode_untagged(reader, desc, 0, _Budget(max(len(data), 1)))
    if reader.pos != len(data):
        raise DecodeError(f"{len(data) - reader.pos} trailing octets after the untagged value")
    return value


class _TypeDescriptionCodec(Construct):
    """``construct`` wrapper for a :class:`TypeDescription` (self-delimiting)."""

    def _parse(self, stream, _context, path):
        try:
            return _decode_type_description(_StreamReader(stream, path))
        except ValueError as exc:
            raise construct.ConstructError(str(exc), path) from exc

    def _build(self, obj, stream, _context, path):
        if not isinstance(obj, TypeDescription):
            raise construct.ConstructError(
                f"expected TypeDescription, got {type(obj).__name__}", path
            )
        data = encode_type_description(obj)
        stream_write(stream, data, len(data), path)
        return obj

    def _sizeof(self, _context, path):
        raise construct.SizeofError("TypeDescription has a variable size", path=path)


class Untagged(Construct):
    """``construct`` for one untagged value of a fixed :class:`TypeDescription`.

    Parsing takes the rest of the stream, which the value must fill exactly
    (wrap it in ``construct.Prefixed`` or ``FixedSized`` to bound it).
    """

    def __init__(self, description: TypeDescription) -> None:
        super().__init__()
        self.description = description

    def _parse(self, stream, _context, path):
        data = construct.stream_read_entire(stream, path)
        try:
            return decode_untagged(data, self.description)
        except ValueError as exc:
            raise construct.ConstructError(str(exc), path) from exc

    def _build(self, obj, stream, _context, path):
        try:
            data = encode_untagged(obj, self.description)
        except (ValueError, NotImplementedError, AttributeError, TypeError) as exc:
            raise construct.ConstructError(str(exc), path) from exc
        stream_write(stream, data, len(data), path)
        return obj

    def _sizeof(self, _context, path):
        raise construct.SizeofError("untagged values have a variable size", path=path)


#: construct subconstruct for a compact-array :class:`TypeDescription`.
TypeDescriptionCodec = _TypeDescriptionCodec()

#: construct subconstruct for a COSEM ``Data`` value.
CosemData = _CosemData()
