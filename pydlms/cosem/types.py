"""Typed views of COSEM ``Data``: descriptors that decode to Python and back.

A descriptor knows the A-XDR shape of one attribute or method parameter and
turns a :class:`~pydlms.cosem.data.DlmsData` tree into a convenient Python
value (and back):

======================  ====================================================
descriptor              Python value
======================  ====================================================
``Integer(tag)``        ``int`` (any integer tag accepted on decode)
``Boolean()``           ``bool``
``Float()``             ``float``
``Enum(cls)``           member of ``cls`` (unknown values stay ``int``)
``OctetString()``       ``bytes``
``Text()``              ``str`` (visible/utf8 string, or ASCII octet string)
``Obis()``              :class:`~pydlms.obis.ObisCode` (6-octet octet string)
``DateTime()``          :class:`~pydlms.cosem.time.CosemDateTime`
``Date()`` / ``Time()`` :class:`CosemDate` / :class:`CosemTime`
``BitString()``         ``list[bool]``
``Array(item)``         ``list`` of the item's Python values
``Struct(cls, fields)`` instance of the dataclass ``cls`` (nested freely)
``Any()``               the :class:`DlmsData` itself (unknown/choice shapes)
======================  ====================================================

Descriptors are strict about structure (a ``Struct`` must receive a
structure with the declared number of members) but lenient about integer
widths, because meters routinely send ``long-unsigned`` where the Blue Book
says ``double-long-unsigned``. Every mismatch raises :class:`DecodeError`
naming the path, e.g. ``capture_objects[3].logical_name``.
"""

from __future__ import annotations

import dataclasses
import enum
from typing import Any as _Any

from pydlms.cosem.data import DlmsData
from pydlms.cosem.enums import DataType
from pydlms.cosem.time import CosemDate, CosemDateTime, CosemTime
from pydlms.exceptions import DecodeError
from pydlms.obis import ObisCode

__all__ = [
    "Type",
    "Integer",
    "U8",
    "U16",
    "U32",
    "U64",
    "I8",
    "I16",
    "I32",
    "I64",
    "Boolean",
    "Float",
    "Enum",
    "OctetString",
    "Text",
    "Obis",
    "DateTime",
    "Date",
    "Time",
    "BitString",
    "Array",
    "Struct",
    "Any",
    "Null",
]

_INTEGER_TAGS = {
    DataType.INTEGER,
    DataType.LONG,
    DataType.DOUBLE_LONG,
    DataType.LONG64,
    DataType.UNSIGNED,
    DataType.LONG_UNSIGNED,
    DataType.DOUBLE_LONG_UNSIGNED,
    DataType.LONG64_UNSIGNED,
    DataType.ENUM,
    DataType.BCD,
}


def _fail(path: str, expected: str, got: DlmsData) -> DecodeError:
    return DecodeError(f"{path or 'value'}: expected {expected}, got {got.tag.name}")


class Type:
    """Base descriptor."""

    def decode(self, data: DlmsData, path: str = "") -> _Any:
        raise NotImplementedError

    def encode(self, value: _Any) -> DlmsData:
        raise NotImplementedError

    def describe(self) -> str:
        return type(self).__name__


class Null(Type):
    def decode(self, data, path=""):
        if data.tag != DataType.NULL:
            raise _fail(path, "null-data", data)
        return None

    def encode(self, value):
        return DlmsData.null()


class Integer(Type):
    def __init__(self, tag: DataType = DataType.DOUBLE_LONG_UNSIGNED) -> None:
        self.tag = DataType(tag)

    def decode(self, data, path=""):
        if data.tag not in _INTEGER_TAGS:
            raise _fail(path, f"an integer ({self.tag.name})", data)
        return int(data.value)

    def encode(self, value):
        if isinstance(value, DlmsData):
            return value
        return DlmsData(self.tag, int(value))

    def describe(self):
        return self.tag.name.lower()


U8, U16, U32, U64 = (
    Integer(DataType.UNSIGNED),
    Integer(DataType.LONG_UNSIGNED),
    Integer(DataType.DOUBLE_LONG_UNSIGNED),
    Integer(DataType.LONG64_UNSIGNED),
)
I8, I16, I32, I64 = (
    Integer(DataType.INTEGER),
    Integer(DataType.LONG),
    Integer(DataType.DOUBLE_LONG),
    Integer(DataType.LONG64),
)


class Boolean(Type):
    def decode(self, data, path=""):
        if data.tag != DataType.BOOLEAN:
            raise _fail(path, "boolean", data)
        return bool(data.value)

    def encode(self, value):
        return DlmsData.boolean(bool(value))


class Float(Type):
    def __init__(self, tag: DataType = DataType.FLOAT32) -> None:
        self.tag = DataType(tag)

    def decode(self, data, path=""):
        if data.tag in (DataType.FLOAT32, DataType.FLOAT64):
            return float(data.value)
        if data.tag in _INTEGER_TAGS:
            return float(data.value)
        raise _fail(path, "a float", data)

    def encode(self, value):
        return DlmsData(self.tag, float(value))


class Enum(Type):
    """``enum`` (tag 22), mapped onto a Python :class:`enum.IntEnum` if given."""

    def __init__(self, cls: type[enum.IntEnum] | None = None) -> None:
        self.cls = cls

    def decode(self, data, path=""):
        if data.tag not in _INTEGER_TAGS:
            raise _fail(path, "enum", data)
        if self.cls is None:
            return int(data.value)
        try:
            return self.cls(data.value)
        except ValueError:
            return int(data.value)  # vendor value outside the standard range

    def encode(self, value):
        return DlmsData.enum(int(value))

    def describe(self):
        return f"enum {self.cls.__name__}" if self.cls else "enum"


class OctetString(Type):
    def __init__(self, size: int | None = None) -> None:
        self.size = size

    def decode(self, data, path=""):
        if data.tag != DataType.OCTET_STRING:
            raise _fail(path, "octet-string", data)
        raw = bytes(data.value)
        if self.size is not None and len(raw) != self.size:
            raise DecodeError(f"{path or 'value'}: expected {self.size} octets, got {len(raw)}")
        return raw

    def encode(self, value):
        raw = bytes(value)
        if self.size is not None and len(raw) != self.size:
            raise ValueError(f"expected {self.size} octets, got {len(raw)}")
        return DlmsData.octet_string(raw)


class Text(Type):
    """Visible/UTF-8 string; ASCII octet strings are accepted on decode."""

    def __init__(self, tag: DataType = DataType.VISIBLE_STRING) -> None:
        self.tag = DataType(tag)

    def decode(self, data, path=""):
        if data.tag in (DataType.VISIBLE_STRING, DataType.UTF8_STRING):
            return data.value
        if data.tag == DataType.OCTET_STRING:
            return bytes(data.value).decode("latin-1")
        raise _fail(path, "a string", data)

    def encode(self, value):
        if self.tag == DataType.OCTET_STRING:
            return DlmsData.octet_string(str(value).encode("latin-1"))
        return DlmsData(self.tag, str(value))


class Obis(Type):
    def decode(self, data, path=""):
        if data.tag != DataType.OCTET_STRING or len(data.value) != 6:
            raise _fail(path, "a 6-octet logical name", data)
        return ObisCode.from_bytes(bytes(data.value))

    def encode(self, value):
        obis = ObisCode.parse(value) if isinstance(value, str) else value
        return DlmsData.octet_string(obis.to_bytes())

    def describe(self):
        return "logical-name"


class _Moment(Type):
    cls: type
    size: int
    tag: DataType
    name: str

    def decode(self, data, path=""):
        if data.tag not in (DataType.OCTET_STRING, self.tag) or len(data.value) != self.size:
            raise _fail(path, f"a {self.size}-octet {self.name}", data)
        return self.cls.from_bytes(bytes(data.value))

    def encode(self, value):
        if not isinstance(value, self.cls):
            value = self.cls.from_datetime(value) if self.cls is CosemDateTime else value
        return DlmsData.octet_string(value.to_bytes())

    def describe(self):
        return self.name


class DateTime(_Moment):
    cls, size, tag, name = CosemDateTime, 12, DataType.DATE_TIME, "date-time"


class Date(_Moment):
    cls, size, tag, name = CosemDate, 5, DataType.DATE, "date"


class Time(_Moment):
    cls, size, tag, name = CosemTime, 4, DataType.TIME, "time"


class BitString(Type):
    def decode(self, data, path=""):
        if data.tag != DataType.BIT_STRING:
            raise _fail(path, "bit-string", data)
        return list(data.value)

    def encode(self, value):
        return DlmsData(DataType.BIT_STRING, [bool(b) for b in value])


class Array(Type):
    def __init__(self, item: Type) -> None:
        self.item = item

    def decode(self, data, path=""):
        if data.tag not in (DataType.ARRAY, DataType.COMPACT_ARRAY):
            raise _fail(path, "array", data)
        items = data.value.items if data.tag == DataType.COMPACT_ARRAY else data.value
        return [self.item.decode(v, f"{path}[{i}]") for i, v in enumerate(items)]

    def encode(self, value):
        return DlmsData.array([self.item.encode(v) for v in value])

    def describe(self):
        return f"array of {self.item.describe()}"


class Struct(Type):
    """A structure decoded into the dataclass ``cls``; ``fields`` in order."""

    def __init__(self, cls: type, fields: list[tuple[str, Type]]) -> None:
        if not dataclasses.is_dataclass(cls):
            raise TypeError(f"{cls.__name__} must be a dataclass")
        self.cls = cls
        self.fields = fields

    def decode(self, data, path=""):
        if data.tag != DataType.STRUCTURE:
            raise _fail(path, f"structure {self.cls.__name__}", data)
        if len(data.value) != len(self.fields):
            raise DecodeError(
                f"{path or 'value'}: {self.cls.__name__} has {len(self.fields)} members, "
                f"got {len(data.value)}"
            )
        values = {
            name: kind.decode(item, f"{path}.{name}" if path else name)
            for (name, kind), item in zip(self.fields, data.value, strict=True)
        }
        return self.cls(**values)

    def encode(self, value):
        return DlmsData.structure([kind.encode(getattr(value, name)) for name, kind in self.fields])

    def describe(self):
        return f"structure {self.cls.__name__}"


class Any(Type):
    """Pass the :class:`DlmsData` through unchanged (CHOICE / vendor shapes)."""

    def decode(self, data, path=""):
        return data

    def encode(self, value):
        if not isinstance(value, DlmsData):
            raise TypeError("Any() attributes take a DlmsData value")
        return value

    def describe(self):
        return "any"
