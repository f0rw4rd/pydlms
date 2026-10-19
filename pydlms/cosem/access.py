"""Access rights of an Association LN object list entry.

Each ``object_list`` element of an Association LN (class 15, attribute 2)
ends with ``access_rights``::

    access_rights ::= structure {
        attribute_access: array of structure {
            attribute_id     integer,
            access_mode      enum,
            access_selectors CHOICE { null-data, array of integer }
        },
        method_access: array of structure {
            method_id        integer,
            access_mode      boolean (class version 0) | enum (version 1 and later)
        }
    }

How ``access_mode`` reads depends on the Association LN class version:

* versions 0 to 2: :class:`AttributeAccessMode` (values 0 to 6) and, from
  version 1 on, :class:`MethodAccessMode`; version 0 methods carry a
  boolean.
* version 3: the same enum octets are bit maps, :class:`AccessMode3` and
  :class:`MethodAccessMode3`, adding the request/response protection each
  attribute or method needs.

Sources: the version 3 bit map (and that it starts with Association LN
version 3 / Association SN version 4) is per DLMS UA 1000-2 Ed. 9 Excerpt
9.2.7.2.2 Table 8 (bit 0 read / method access, 1 write / not used, 2..4
authenticated, encrypted, signed request, 5..7 the same for the response).
The version 0 to 2 values are not in the DLMS UA excerpts ("for older
versions, see ... the Blue Book"). The values themselves are per PJSC
Rosseti STO 34.01-5.1-006-2019 (SPODES, the Russian DLMS companion
specification) 7.4.12, which lists attribute modes 0 no_access to 6
authenticated_read_and_write and method modes 0 no_access, 1 access, 2
authenticated_access for Association LN *version 1*. The authenticated
values are therefore not a version 2 addition (DLMS UA 1000-1 Ed. 11
Excerpt 4.4.4 names client user identification as what version 2 adds);
pydlms accepts all seven values under versions 0 to 2. Which of them
version 0 defines stays *unverified*. Implementations agree:

* the v0 to v2 values 0 to 6 and the method values 0 to 2 agree between the
  OpenMUC jDLMS ``AttributeAccessMode`` / ``MethodAccessMode`` enums and the
  Gurux.DLMS.Net ``AccessMode`` / ``MethodAccessMode`` enums, and are on the
  wire in ``tests/fixtures/object_lists/`` (jDLMS 1.8.0 sends 4 and 6 under
  class version 1, so they are accepted there too);
* the v3 bit positions agree between Gurux.DLMS.Net ``AccessMode3`` /
  ``MethodAccessMode3`` and pwitab dlms-cosem ``parse_access_right``; no
  version 3 meter capture is available yet.

The modes describe the *current* association (the view is read through
``0.0.40.0.0.255``). An attribute the view does not list has unknown access:
meters that list only supported attributes are common, so callers get
``None`` rather than "no access" for it (the public excerpts do not say what
an unlisted attribute means; *unverified*).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

from pydlms.cosem.data import DlmsData
from pydlms.cosem.enums import DataType
from pydlms.exceptions import DecodeError

__all__ = [
    "AccessMode3",
    "AccessRights",
    "AttributeAccess",
    "AttributeAccessMode",
    "MethodAccess",
    "MethodAccessMode",
    "MethodAccessMode3",
    "decode_access_rights",
    "infer_association_version",
]


class AttributeAccessMode(enum.IntEnum):
    """Attribute ``access_mode`` for Association LN versions 0 to 2."""

    NO_ACCESS = 0
    READ_ONLY = 1
    WRITE_ONLY = 2
    READ_AND_WRITE = 3
    # Listed for class version 1 by SPODES 7.4.12 (see module doc).
    AUTHENTICATED_READ_ONLY = 4
    AUTHENTICATED_WRITE_ONLY = 5
    AUTHENTICATED_READ_AND_WRITE = 6

    @property
    def readable(self) -> bool:
        return self in _READABLE

    @property
    def writable(self) -> bool:
        return self in _WRITABLE

    @property
    def authenticated(self) -> bool:
        """The access needs an authenticated (protected) request."""
        return self >= AttributeAccessMode.AUTHENTICATED_READ_ONLY


_READABLE = frozenset(
    {
        AttributeAccessMode.READ_ONLY,
        AttributeAccessMode.READ_AND_WRITE,
        AttributeAccessMode.AUTHENTICATED_READ_ONLY,
        AttributeAccessMode.AUTHENTICATED_READ_AND_WRITE,
    }
)
_WRITABLE = frozenset(
    {
        AttributeAccessMode.WRITE_ONLY,
        AttributeAccessMode.READ_AND_WRITE,
        AttributeAccessMode.AUTHENTICATED_WRITE_ONLY,
        AttributeAccessMode.AUTHENTICATED_READ_AND_WRITE,
    }
)


class MethodAccessMode(enum.IntEnum):
    """Method ``access_mode`` for Association LN versions 1 and 2."""

    NO_ACCESS = 0
    ACCESS = 1
    AUTHENTICATED_ACCESS = 2

    @property
    def executable(self) -> bool:
        return self != MethodAccessMode.NO_ACCESS


class AccessMode3(enum.IntFlag):
    """Attribute ``access_mode`` bit map of Association LN version 3
    (DLMS UA 1000-2 Ed. 9 Excerpt 9.2.7.2.2 Table 8)."""

    NO_ACCESS = 0
    READ = 0x01
    WRITE = 0x02
    AUTHENTICATED_REQUEST = 0x04
    ENCRYPTED_REQUEST = 0x08
    DIGITALLY_SIGNED_REQUEST = 0x10
    AUTHENTICATED_RESPONSE = 0x20
    ENCRYPTED_RESPONSE = 0x40
    DIGITALLY_SIGNED_RESPONSE = 0x80

    @property
    def readable(self) -> bool:
        return bool(self & AccessMode3.READ)

    @property
    def writable(self) -> bool:
        return bool(self & AccessMode3.WRITE)


class MethodAccessMode3(enum.IntFlag):
    """Method ``access_mode`` bit map of Association LN version 3 (bit 1 not
    used; DLMS UA 1000-2 Ed. 9 Excerpt 9.2.7.2.2 Table 8)."""

    NO_ACCESS = 0
    ACCESS = 0x01
    AUTHENTICATED_REQUEST = 0x04
    ENCRYPTED_REQUEST = 0x08
    DIGITALLY_SIGNED_REQUEST = 0x10
    AUTHENTICATED_RESPONSE = 0x20
    ENCRYPTED_RESPONSE = 0x40
    DIGITALLY_SIGNED_RESPONSE = 0x80

    @property
    def executable(self) -> bool:
        return bool(self & MethodAccessMode3.ACCESS)


@dataclass(frozen=True)
class AttributeAccess:
    """One ``attribute_access`` item. An enum value the class version does
    not define stays a plain ``int`` (its access is unknown)."""

    attribute_id: int
    access_mode: AttributeAccessMode | AccessMode3 | int
    #: Supported selective-access selectors; ``None`` for null-data (none).
    access_selectors: tuple[int, ...] | None = None

    @property
    def readable(self) -> bool | None:
        return _flag(self.access_mode, "readable")

    @property
    def writable(self) -> bool | None:
        return _flag(self.access_mode, "writable")


@dataclass(frozen=True)
class MethodAccess:
    """One ``method_access`` item; ``access_mode`` is a ``bool`` in version 0."""

    method_id: int
    access_mode: bool | MethodAccessMode | MethodAccessMode3 | int

    @property
    def executable(self) -> bool | None:
        if isinstance(self.access_mode, bool):
            return self.access_mode
        return _flag(self.access_mode, "executable")


def _flag(mode, name: str) -> bool | None:
    if isinstance(mode, (AttributeAccessMode, AccessMode3, MethodAccessMode, MethodAccessMode3)):
        return getattr(mode, name)
    return None  # a value the class version does not define


@dataclass(frozen=True)
class AccessRights:
    """Decoded ``access_rights`` of one object list entry."""

    attributes: tuple[AttributeAccess, ...]
    methods: tuple[MethodAccess, ...]
    #: Association LN class version the modes were read with.
    version: int = 1

    def attribute(self, attribute_id: int) -> AttributeAccess | None:
        return next((a for a in self.attributes if a.attribute_id == attribute_id), None)

    def method(self, method_id: int) -> MethodAccess | None:
        return next((m for m in self.methods if m.method_id == method_id), None)

    def can_read(self, attribute_id: int) -> bool | None:
        """``None`` when the attribute is not listed or its mode is unknown."""
        item = self.attribute(attribute_id)
        return None if item is None else item.readable

    def can_write(self, attribute_id: int) -> bool | None:
        item = self.attribute(attribute_id)
        return None if item is None else item.writable

    def can_execute(self, method_id: int) -> bool | None:
        item = self.method(method_id)
        return None if item is None else item.executable

    def summary(self) -> str:
        """Compact ``r=1-3,5 w=2 x=1`` form (``-`` for none), for listings."""
        readable = [a.attribute_id for a in self.attributes if a.readable]
        writable = [a.attribute_id for a in self.attributes if a.writable]
        executable = [m.method_id for m in self.methods if m.executable]
        return f"r={_ranges(readable)} w={_ranges(writable)} x={_ranges(executable)}"

    def to_data(self) -> DlmsData:
        """Encode back to the ``access_rights`` structure."""
        attributes = [
            DlmsData.structure(
                [
                    DlmsData.int8(a.attribute_id),
                    DlmsData.enum(int(a.access_mode)),
                    DlmsData.null()
                    if a.access_selectors is None
                    else DlmsData.array([DlmsData.int8(s) for s in a.access_selectors]),
                ]
            )
            for a in self.attributes
        ]
        methods = [
            DlmsData.structure(
                [
                    DlmsData.int8(m.method_id),
                    DlmsData.boolean(m.access_mode)
                    if isinstance(m.access_mode, bool)
                    else DlmsData.enum(int(m.access_mode)),
                ]
            )
            for m in self.methods
        ]
        return DlmsData.structure([DlmsData.array(attributes), DlmsData.array(methods)])


def _ranges(ids: list[int]) -> str:
    if not ids:
        return "-"
    ids = sorted(set(ids))
    parts = []
    start = prev = ids[0]
    for i in [*ids[1:], None]:
        if i is not None and i == prev + 1:
            prev = i
            continue
        parts.append(str(start) if start == prev else f"{start}-{prev}")
        if i is not None:
            start = prev = i
    return ",".join(parts)


_INTEGERS = frozenset(
    {
        DataType.INTEGER,
        DataType.LONG,
        DataType.DOUBLE_LONG,
        DataType.UNSIGNED,
        DataType.LONG_UNSIGNED,
        DataType.DOUBLE_LONG_UNSIGNED,
    }
)


def _items(data: DlmsData, size: int, what: str) -> list[DlmsData]:
    if data.tag != DataType.STRUCTURE or len(data.value) != size:
        found = f"{len(data.value)} elements" if data.tag == DataType.STRUCTURE else data.tag.name
        raise DecodeError(f"{what} is not a structure of {size} elements ({found})")
    return data.value


def _array(data: DlmsData, what: str) -> list[DlmsData]:
    if data.tag != DataType.ARRAY:
        raise DecodeError(f"{what} is {data.tag.name}, not an array")
    return data.value


def _integer(data: DlmsData, what: str) -> int:
    if data.tag not in _INTEGERS:
        raise DecodeError(f"{what} is {data.tag.name}, not an integer")
    return data.value


def _enum(data: DlmsData, what: str) -> int:
    if data.tag != DataType.ENUM:
        raise DecodeError(f"{what} is {data.tag.name}, not an enum")
    return data.value


def infer_association_version(data: DlmsData) -> int:
    """Class version implied by the encoding alone: 0 when a method mode is
    a boolean, else 1. Version 3 bit maps cannot be told from version 1/2
    enums by their encoding, so 3 is never inferred."""
    try:
        methods = _array(_items(data, 2, "access_rights")[1], "method_access")
    except DecodeError:
        return 1
    for item in methods:
        if (
            item.tag == DataType.STRUCTURE
            and len(item.value) == 2
            and item.value[1].tag == DataType.BOOLEAN
        ):
            return 0
    return 1


def _attribute_mode(value: int, version: int) -> AttributeAccessMode | AccessMode3 | int:
    if version >= 3:
        return AccessMode3(value)
    try:
        return AttributeAccessMode(value)
    except ValueError:
        return value


def _method_mode(data: DlmsData, version: int, what: str):
    if data.tag == DataType.BOOLEAN:
        return bool(data.value)
    value = _enum(data, what)
    if version >= 3:
        return MethodAccessMode3(value)
    try:
        return MethodAccessMode(value)
    except ValueError:
        return value


def decode_access_rights(data: DlmsData, association_version: int | None = None) -> AccessRights:
    """Decode an object list entry's ``access_rights``.

    ``association_version`` is the Association LN class version of the view
    (its own ``0.0.40.0.0.255`` entry). ``None`` infers it from the encoding
    (:func:`infer_association_version`). Raises :class:`DecodeError` on a
    shape that is not ``access_rights``.
    """
    version = (
        infer_association_version(data) if association_version is None else association_version
    )
    attribute_part, method_part = _items(data, 2, "access_rights")
    attributes: list[AttributeAccess] = []
    seen: set[int] = set()
    for number, item in enumerate(_array(attribute_part, "attribute_access"), 1):
        what = f"attribute_access item {number}"
        ident, mode, selectors = _items(item, 3, what)
        attribute_id = _integer(ident, f"{what} attribute_id")
        if attribute_id in seen:
            raise DecodeError(f"attribute {attribute_id} is listed twice in access_rights")
        seen.add(attribute_id)
        if selectors.tag == DataType.NULL:
            chosen = None
        else:
            chosen = tuple(
                _integer(s, f"{what} access_selector")
                for s in _array(selectors, f"{what} access_selectors")
            )
        attributes.append(
            AttributeAccess(
                attribute_id,
                _attribute_mode(_enum(mode, f"{what} access_mode"), version),
                chosen,
            )
        )
    methods: list[MethodAccess] = []
    seen = set()
    for number, item in enumerate(_array(method_part, "method_access"), 1):
        what = f"method_access item {number}"
        ident, mode = _items(item, 2, what)
        method_id = _integer(ident, f"{what} method_id")
        if method_id in seen:
            raise DecodeError(f"method {method_id} is listed twice in access_rights")
        seen.add(method_id)
        methods.append(MethodAccess(method_id, _method_mode(mode, version, f"{what} access_mode")))
    return AccessRights(tuple(attributes), tuple(methods), version)
