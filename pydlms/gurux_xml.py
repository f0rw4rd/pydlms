"""APDUs in the Gurux translator XML dialect (``pydlms decode --xml --dialect gurux``).

The Gurux DLMS libraries ship ``GXDLMSTranslator``, whose "simple XML" output is
the de-facto way DLMS traces are exchanged as XML (Gurux Director, GXDLMS
translator tools, many forum posts)::

    <GetRequest>
      <GetRequestNormal>
        <InvokeIdAndPriority Value="C1" />
        <AttributeDescriptor>
          <ClassId Value="0003" />
          <InstanceId Value="0100010800FF" />
          <AttributeId Value="02" />
        </AttributeDescriptor>
      </GetRequestNormal>
    </GetRequest>

:func:`apdu_to_gurux_xml` writes that dialect and :func:`gurux_xml_to_apdu`
reads it, from pydlms or from Gurux. The element names, value widths and enum
spellings were taken from what ``GXDLMSTranslator.PduToXml`` prints for each
APDU (Gurux.DLMS.Net, the commit pinned in
``tests/integration/gurux_client/Dockerfile``); no Gurux code is used. The
integration test ``tests/integration/test_gurux_xml.py`` compares both
directions against the translator itself.

Where Gurux's own output cannot carry an APDU, pydlms writes the element Gurux
would need rather than copy the loss. These are pydlms additions that Gurux
does not print:

* ``GetResponseWithList`` error results (Gurux drops them) as
  ``<DataAccessError>``, like ``ReadResponse``.
* ``ActionRequestWithList`` / ``ActionResponseWithList`` contents (Gurux
  prints an empty list or fails).
* ``SetRequestFirstDataBlock`` without the repeated descriptor and empty
  ``<Value>`` Gurux appends; ``AccessSelection`` in SET requests and lists.
* The ``ExceptionResponse`` invocation counter, a tagged DataNotification
  date-time, the InformationReport current-time (``Bare`` when it came in
  Gurux's own flagless form), ``UnconfirmedWriteRequest``, the ``RawData``
  of an SN ``ReadDataBlockAccess`` (Gurux prints only the block header),
  a ``MechanismName`` of ``None`` (mechanism 0), and ``ResponseAllowed`` in an
  InitiateRequest (Gurux writes a second QualityOfService for it).
* The ACCESS with-selection specifications (``AccessRequestGetWithSelection``
  / ``AccessRequestSetWithSelection`` with an ``AccessSelection``; Gurux
  knows kinds 1..3 only) and the request echo of an AccessResponse
  (``AccessRequestSpecification`` in the body; Gurux reads it as data).
* Strings with characters Gurux would hex-dump or drop are written as XML
  character references, which every XML reader restores.

An APDU the dialect still cannot hold exactly (a NUL inside a visible-string,
an unknown tag, a vendor quirk) is written as ``<Raw Value="...">`` with the
best-effort Gurux element inside ``<Decoded>``; ``Raw`` encodes back to the
original bytes, so a session survives ``decode --xml`` / ``encode`` intact.
Gurux itself cannot read ``Raw``.

Ciphered APDUs keep their ciphertext (``<glo_GetRequest Value="...">``,
``<GeneralGloCiphering>``, ``<GeneralCiphering>``), as Gurux writes them; with
keys, the deciphered APDU is added as an XML comment, never as elements, so
editing it cannot silently change what is encoded. Authentication values are
redacted as in :mod:`pydlms.apduxml` unless ``secrets=True``.
"""

from __future__ import annotations

import re
import struct
import xml.etree.ElementTree as ET  # nosec B405
from enum import IntEnum

from pydlms.apdu import gbt, sn, xdlms
from pydlms.apdu.acse import AARE, AARQ, RLRE, RLRQ, ApplicationContext
from pydlms.apdu.tags import PLAIN_FOR_CIPHERED, Tag, tag_name
from pydlms.axdr import decode_length, encode_length
from pydlms.catalog import obis_name
from pydlms.cosem.data import CompactArray, DlmsData, TypeDescription
from pydlms.cosem.enums import ActionResult, DataAccessResult, DataType
from pydlms.cosem.time import CosemDateTime
from pydlms.exceptions import DecodeError, DlmsError
from pydlms.obis import ObisCode

__all__ = [
    "GuruxXmlWriter",
    "apdu_to_gurux_xml",
    "gurux_xml_to_apdu",
    "gurux_element_to_apdu",
    "is_gurux_element",
]

_REDACTED = "redacted"

# --- name tables (as GXDLMSTranslator prints them) --------------------------------------

#: DataAccessResult; Gurux uses the same names for ActionResult values.
_RESULT_NAMES = {
    0: "Success",
    1: "HardwareFault",
    2: "TemporaryFailure",
    3: "ReadWriteDenied",
    4: "UndefinedObject",
    9: "InconsistentClass",
    11: "UnavailableObject",
    12: "UnmatchedType",
    13: "AccessViolated",
    14: "DataBlockUnavailable",
    15: "LongGetOrReadAborted",
    16: "NoLongGetOrReadInProgress",
    17: "LongSetOrWriteAborted",
    18: "NoLongSetOrWriteInProgress",
    19: "DataBlockNumberInvalid",
    250: "OtherReason",
}
_STATE_ERRORS = {1: "ServiceNotAllowed", 2: "ServiceUnknown"}
_SERVICE_ERRORS = {
    1: "OperationNotPossible",
    2: "ServiceNotSupported",
    3: "OtherReason",
    4: "PduTooLong",
    5: "DecipheringError",
    6: "InvocationCounterError",
}
#: ConfirmedServiceError: error choice -> (element, {value: name}).
_CSE = {
    0: (
        "ApplicationReference",
        [
            "Other",
            "TimeElapsed",
            "ApplicationUnreachable",
            "ApplicationReferenceInvalid",
            "ApplicationContextUnsupported",
            "ProviderCommunicationError",
            "DecipheringError",
        ],
    ),
    1: (
        "HardwareResource",
        [
            "Other",
            "MemoryUnavailable",
            "ProcessorResourceUnavailable",
            "MassStorageUnavailable",
            "OtherResourceUnavailable",
        ],
    ),
    2: (
        "VdeStateError",
        ["Other", "NoDlmsContext", "LoadingDataSet", "StatusNochange", "StatusInoperable"],
    ),
    3: ("Service", ["Other", "PduSize", "ServiceUnsupported"]),
    4: (
        "Definition",
        ["Other", "ObjectUndefined", "ObjectClassInconsistent", "ObjectAttributeInconsistent"],
    ),
    5: (
        "Access",
        [
            "Other",
            "ScopeOfAccessViolated",
            "ObjectAccessInvalid",
            "HardwareFault",
            "ObjectUnavailable",
        ],
    ),
    6: (
        "Initiate",
        [
            "Other",
            "DlmsVersionTooLow",
            "IncompatibleConformance",
            "PduSizeTooShort",
            "RefusedByTheVDEHandler",
        ],
    ),
    7: (
        "LoadDataSet",
        [
            "Other",
            "PrimitiveOutOfSequence",
            "NotLoadable",
            "DatasetSizeTooLarge",
            "NotAwaitedSegment",
            "InterpretationFailure",
            "StorageFailure",
            "DataSetNotReady",
        ],
    ),
    8: ("Task", ["Other", "NoRemoteControl", "tiStopped", "tiRunning", "tiUnusable"]),
}
_CONTEXT_NAMES = {
    ApplicationContext.LN: "LN",
    ApplicationContext.SN: "SN",
    ApplicationContext.LN_CIPHERED: "LN_WITH_CIPHERING",
    ApplicationContext.SN_CIPHERED: "SN_WITH_CIPHERING",
}
_MECHANISMS = ["None", "Low", "High", "HighMD5", "HighSHA1", "HighGMAC", "HighSHA256", "HighECDSA"]
_RLRQ_REASONS = {0: "Normal", 1: "Urgent", 30: "UserDefined"}
_RLRE_REASONS = {0: "Normal", 1: "NotFinished", 30: "UserDefined"}

#: COSEM data: tag -> (element, hex width in octets or None).
_DATA = {
    DataType.NULL: ("None", None),
    DataType.BOOLEAN: ("Boolean", None),
    DataType.BIT_STRING: ("BitString", None),
    DataType.DOUBLE_LONG: ("Int32", 4),
    DataType.DOUBLE_LONG_UNSIGNED: ("UInt32", 4),
    DataType.OCTET_STRING: ("OctetString", None),
    DataType.VISIBLE_STRING: ("String", None),
    DataType.UTF8_STRING: ("StringUTF8", None),
    DataType.BCD: ("Bcd", 1),
    DataType.INTEGER: ("Int8", 1),
    DataType.LONG: ("Int16", 2),
    DataType.UNSIGNED: ("UInt8", 1),
    DataType.LONG_UNSIGNED: ("UInt16", 2),
    DataType.LONG64: ("Int64", 8),
    DataType.LONG64_UNSIGNED: ("UInt64", 8),
    DataType.ENUM: ("Enum", 1),
    # Gurux simple-tag names (TranslatorSimpleTags.cs): fact only.
    DataType.DELTA_INTEGER: ("Delta-Int8", 1),
    DataType.DELTA_LONG: ("Delta-Int16", 2),
    DataType.DELTA_DOUBLE_LONG: ("Delta-Int32", 4),
    DataType.DELTA_UNSIGNED: ("Delta-UInt8", 1),
    DataType.DELTA_LONG_UNSIGNED: ("Delta-UInt16", 2),
    DataType.DELTA_DOUBLE_LONG_UNSIGNED: ("Delta-UInt32", 4),
    DataType.FLOAT32: ("Float32", 4),
    DataType.FLOAT64: ("Float64", 8),
    DataType.DATE_TIME: ("DateTime", None),
    DataType.DATE: ("Date", None),
    DataType.TIME: ("Time", None),
    DataType.ARRAY: ("Array", None),
    DataType.STRUCTURE: ("Structure", None),
    DataType.COMPACT_ARRAY: ("CompactArray", None),
}
_SIGNED = {
    DataType.DOUBLE_LONG,
    DataType.INTEGER,
    DataType.LONG,
    DataType.LONG64,
    DataType.DELTA_INTEGER,
    DataType.DELTA_LONG,
    DataType.DELTA_DOUBLE_LONG,
}
_DATA_BY_NAME = {name: tag for tag, (name, _) in _DATA.items()}
_BYTES = {DataType.OCTET_STRING, DataType.DATE_TIME, DataType.DATE, DataType.TIME}

#: The plain APDU element a glo-/ded- tag ciphers, by plain tag.
_PLAIN_ROOT = {
    Tag.GET_REQUEST: "GetRequest",
    Tag.SET_REQUEST: "SetRequest",
    Tag.EVENT_NOTIFICATION_REQUEST: "EventNotificationRequest",
    Tag.ACTION_REQUEST: "ActionRequest",
    Tag.GET_RESPONSE: "GetResponse",
    Tag.SET_RESPONSE: "SetResponse",
    Tag.ACTION_RESPONSE: "ActionResponse",
    Tag.INITIATE_REQUEST: "InitiateRequest",
    Tag.INITIATE_RESPONSE: "InitiateResponse",
    Tag.READ_REQUEST: "ReadRequest",
    Tag.WRITE_REQUEST: "WriteRequest",
    Tag.READ_RESPONSE: "ReadResponse",
    Tag.WRITE_RESPONSE: "WriteResponse",
    Tag.CONFIRMED_SERVICE_ERROR: "ConfirmedServiceError",
    Tag.UNCONFIRMED_WRITE_REQUEST: "UnconfirmedWriteRequest",
    Tag.INFORMATION_REPORT_REQUEST: "InformationReportRequest",
}
#: ``glo_GetRequest`` -> 0xC8, ``ded_GetRequest`` -> 0xD0.
_CIPHERED_NAMES: dict[str, int] = {}
for _tag, (_plain, _dedicated) in PLAIN_FOR_CIPHERED.items():
    _CIPHERED_NAMES[("ded_" if _dedicated else "glo_") + _PLAIN_ROOT[_plain]] = _tag
_CIPHERED_BY_TAG = {tag: name for name, tag in _CIPHERED_NAMES.items()}

_ROOTS = {
    "GetRequest",
    "GetResponse",
    "SetRequest",
    "SetResponse",
    "ActionRequest",
    "ActionResponse",
    "AssociationRequest",
    "AssociationResponse",
    "ReleaseRequest",
    "ReleaseResponse",
    "GeneralBlockTransfer",
    "GeneralGloCiphering",
    "GeneralDedCiphering",
    "GeneralCiphering",
    "GeneralSigning",
} | set(_CIPHERED_NAMES)
#: Root names pydlms's own dialect also uses: Gurux when their children are CamelCase.
_SHARED_ROOTS = {
    "AccessRequest",
    "AccessResponse",
    "DataNotification",
    "EventNotificationRequest",
    "ExceptionResponse",
    "ConfirmedServiceError",
    "InitiateRequest",
    "InitiateResponse",
    "ReadRequest",
    "ReadResponse",
    "WriteRequest",
    "WriteResponse",
    "UnconfirmedWriteRequest",
    "InformationReportRequest",
    "Raw",
}


def _camel(name: str) -> str:
    return "".join(part.capitalize() for part in name.lower().split("_"))


_CONFORMANCE = {_camel(bit.name): bit for bit in xdlms.Conformance}

# --- small helpers -------------------------------------------------------------------


def _hex(value: int, octets: int) -> str:
    return f"{value:0{octets * 2}X}"


def _qty(n: int) -> str:
    return f"{n:02X}"


def _sub(parent: ET.Element, tag: str, value: str | None = None, **attrs: str) -> ET.Element:
    el = ET.SubElement(parent, tag)
    if value is not None:
        el.set("Value", value)
    for key, val in attrs.items():
        el.set(key, val)
    return el


def _comment(parent: ET.Element, text: str) -> None:
    while "--" in text:
        text = text.replace("--", "- -")
    parent.append(ET.Comment(f" {text.strip()} "))


def _value(el: ET.Element, what: str | None = None) -> str:
    value = el.get("Value")
    if value is None:
        raise DecodeError(f"<{what or el.tag}> needs a Value attribute")
    if value == _REDACTED:
        raise DecodeError(f"<{el.tag}> is redacted; write the XML with secrets=True to encode it")
    return value


def _int(el: ET.Element) -> int:
    try:
        return int(_value(el), 16)
    except ValueError:
        raise DecodeError(f"<{el.tag}> Value is not hex: {el.get('Value')!r}") from None


def _octets(el: ET.Element) -> bytes:
    try:
        return bytes.fromhex(_value(el))
    except ValueError:
        raise DecodeError(f"<{el.tag}> Value is not hex octets: {el.get('Value')!r}") from None


def _children(el: ET.Element) -> list[ET.Element]:
    """Element children; comments are not elements."""
    return [c for c in el if isinstance(c.tag, str)]


def _need(el: ET.Element, tag: str) -> ET.Element:
    found = el.find(tag)
    if found is None:
        raise DecodeError(f"<{el.tag}> needs a <{tag}>")
    return found


def _named(table: dict[int, str], el: ET.Element) -> int:
    value = _value(el)
    for key, name in table.items():
        if name == value:
            return key
    try:
        return int(value, 16)
    except ValueError:
        raise DecodeError(f"<{el.tag}> has an unknown value {value!r}") from None


def _only(el: ET.Element) -> ET.Element:
    kids = _children(el)
    if len(kids) != 1:
        raise DecodeError(f"<{el.tag}> holds exactly one element, found {len(kids)}")
    return kids[0]


# --- COSEM data ----------------------------------------------------------------------


def _attr_text_ok(text: str) -> bool:
    """Representable in an attribute (NUL and other XML-forbidden chars are not)."""
    return all(
        ch in "\t\n\r" or 0x20 <= ord(ch) <= 0xD7FF or 0xE000 <= ord(ch) <= 0xFFFD for ch in text
    )


def _scalar(item: DlmsData) -> str:
    tag, value = item.tag, item.value
    if tag == DataType.BOOLEAN:
        return "true" if value else "false"
    if tag == DataType.BIT_STRING:
        return "".join("1" if bit else "0" for bit in value)
    if tag in _BYTES:
        return bytes(value).hex().upper()
    if tag == DataType.VISIBLE_STRING:
        return value
    if tag == DataType.UTF8_STRING:
        return value
    if tag == DataType.FLOAT32:
        return struct.pack(">f", value).hex().upper()
    if tag == DataType.FLOAT64:
        return struct.pack(">d", value).hex().upper()
    width = _DATA[tag][1]
    return _hex(value & ((1 << (8 * width)) - 1), width)


def _compact_cell(item: DlmsData) -> str:
    if item.tag == DataType.BOOLEAN:
        return "True" if item.value else "False"
    if item.tag in _BYTES:
        return " ".join(f"{b:02X}" for b in item.value)
    if item.tag in (DataType.VISIBLE_STRING, DataType.UTF8_STRING):
        return item.value
    if item.tag == DataType.BIT_STRING:
        return _scalar(item)
    if item.tag in (DataType.FLOAT32, DataType.FLOAT64):
        return repr(float(item.value))
    if item.tag == DataType.NULL:
        return ""
    return str(int(item.value))


def _description(parent: ET.Element, desc: TypeDescription) -> None:
    if desc.tag == DataType.STRUCTURE:
        for member in desc.members:
            _description(parent, member)
        return
    if desc.tag == DataType.ARRAY or desc.tag not in _DATA:
        raise DecodeError("compact arrays of arrays have no Gurux form")
    parent.append(ET.Element(_DATA[desc.tag][0]))


def data_element(item: DlmsData) -> ET.Element:
    """One COSEM ``Data`` value as a Gurux element."""
    if item.tag not in _DATA:
        raise DecodeError(f"{item.tag!r} has no Gurux element")
    name = _DATA[item.tag][0]
    el = ET.Element(name)
    if item.tag == DataType.NULL:
        return el
    if item.tag in (DataType.ARRAY, DataType.STRUCTURE):
        el.set("Qty", _qty(len(item.value)))
        for member in item.value:
            _data_into(el, member)
        return el
    if item.tag == DataType.COMPACT_ARRAY:
        compact: CompactArray = item.value
        _description(ET.SubElement(el, "ContentsDescription"), compact.description)
        contents = ET.SubElement(el, "ArrayContents")
        if compact.description.tag == DataType.STRUCTURE:
            rows = [";".join(_compact_cell(c) for c in row.value) for row in compact.items]
            contents.text = "".join(f"\n{row}" for row in rows) + ("\n" if rows else "")
        else:
            contents.text = ";".join(_compact_cell(row) for row in compact.items)
        return el
    text = _scalar(item)
    if not _attr_text_ok(text):
        raise DecodeError("a string holds characters an XML attribute cannot")
    el.set("Value", text)
    return el


def _data_comment(item: DlmsData) -> str | None:
    """A hint for octet-strings that look like OBIS codes or date-times, and floats."""
    text = None
    if item.tag == DataType.OCTET_STRING and len(item.value) == 6:
        obis = ObisCode.from_bytes(item.value)
        name = obis_name(obis)
        text = f"{obis}" + (f" {name}" if name else "")
    elif item.tag in (DataType.OCTET_STRING, DataType.DATE_TIME) and len(item.value) == 12:
        try:
            text = str(CosemDateTime.from_bytes(item.value))
        except (DlmsError, ValueError):
            text = None
    elif item.tag in (DataType.FLOAT32, DataType.FLOAT64):
        text = repr(float(item.value))
    return text


def _cell(tag: DataType, text: str) -> DlmsData:
    text = text.strip()
    try:
        if tag == DataType.BOOLEAN:
            return DlmsData(tag, text.lower() == "true")
        if tag in _BYTES:
            return DlmsData(tag, bytes.fromhex(text))
        if tag in (DataType.VISIBLE_STRING, DataType.UTF8_STRING):
            return DlmsData(tag, text)
        if tag == DataType.BIT_STRING:
            return DlmsData(tag, [ch == "1" for ch in text])
        if tag in (DataType.FLOAT32, DataType.FLOAT64):
            return DlmsData(tag, float(text))
        if tag == DataType.NULL:
            return DlmsData.null()
        return DlmsData(tag, int(text))
    except ValueError:
        raise DecodeError(f"compact-array cell {text!r} is not a {tag.name}") from None


def _read_description(el: ET.Element) -> TypeDescription:
    members = []
    for child in _children(el):
        if child.tag not in _DATA_BY_NAME:
            raise DecodeError(f"<{child.tag}> is not a data type")
        members.append(TypeDescription(_DATA_BY_NAME[child.tag]))
    if len(members) == 1:
        return members[0]
    return TypeDescription(DataType.STRUCTURE, members=tuple(members))


def element_data(el: ET.Element) -> DlmsData:
    """Inverse of :func:`data_element`."""
    if el.tag not in _DATA_BY_NAME:
        raise DecodeError(f"<{el.tag}> is not a Gurux data element")
    tag = _DATA_BY_NAME[el.tag]
    if tag == DataType.NULL:
        return DlmsData.null()
    if tag in (DataType.ARRAY, DataType.STRUCTURE):
        members = [element_data(child) for child in _children(el)]
        qty = el.get("Qty")
        if qty is not None and int(qty, 16) != len(members):
            raise DecodeError(f"<{el.tag} Qty={qty!r}> holds {len(members)} elements")
        return DlmsData(tag, members)
    if tag == DataType.COMPACT_ARRAY:
        desc = _read_description(_need(el, "ContentsDescription"))
        text = (_need(el, "ArrayContents").text or "").strip()
        rows: list[DlmsData] = []
        if desc.tag == DataType.STRUCTURE:
            for line in filter(None, (line.strip() for line in text.splitlines())):
                cells = line.split(";")
                if len(cells) != len(desc.members):
                    raise DecodeError(f"compact-array row {line!r} does not match its description")
                rows.append(
                    DlmsData.structure(
                        [_cell(m.tag, c) for m, c in zip(desc.members, cells, strict=True)]
                    )
                )
        elif text or desc.tag in (DataType.OCTET_STRING, DataType.VISIBLE_STRING):
            rows = [_cell(desc.tag, cell) for cell in text.split(";")] if text else []
        return DlmsData(tag, CompactArray(desc, rows))
    text = _value(el)
    try:
        if tag == DataType.BOOLEAN:
            if text.lower() not in ("true", "false"):
                raise ValueError(text)
            return DlmsData(tag, text.lower() == "true")
        if tag == DataType.BIT_STRING:
            if set(text) - {"0", "1"}:
                raise ValueError(text)
            return DlmsData(tag, [ch == "1" for ch in text])
        if tag in _BYTES:
            return DlmsData(tag, bytes.fromhex(text))
        if tag in (DataType.VISIBLE_STRING, DataType.UTF8_STRING):
            return DlmsData(tag, text)
        if tag == DataType.FLOAT32:
            return DlmsData(tag, struct.unpack(">f", bytes.fromhex(text))[0])
        if tag == DataType.FLOAT64:
            return DlmsData(tag, struct.unpack(">d", bytes.fromhex(text))[0])
        width = _DATA[tag][1]
        raw = int(text, 16)
        if raw >= 1 << (8 * width):
            raise ValueError(text)
        if tag in _SIGNED and raw >= 1 << (8 * width - 1):
            raw -= 1 << (8 * width)
        return DlmsData(tag, raw)
    except (ValueError, struct.error):
        raise DecodeError(f"<{el.tag} Value={text!r}> is not a valid {tag.name}") from None


def _data_into(parent: ET.Element, item: DlmsData) -> None:
    comment = _data_comment(item)
    if comment is not None:
        _comment(parent, comment)
    parent.append(data_element(item))


def _one_data(el: ET.Element) -> DlmsData:
    return element_data(_only(el))


# --- writer --------------------------------------------------------------------------


def _priority_comment(parent: ET.Element, invoke_id: int) -> None:
    _comment(
        parent,
        f"Priority: {'High' if invoke_id & 0x80 else 'Normal'}, "
        f"ServiceClass: {'Confirmed' if invoke_id & 0x40 else 'UnConfirmed'}, "
        f"Invoke ID: {invoke_id & 0x0F}",
    )


def _iip(parent: ET.Element, invoke_id: int) -> None:
    _priority_comment(parent, invoke_id)
    _sub(parent, "InvokeIdAndPriority", _hex(invoke_id, 1))


def _descriptor(parent: ET.Element, d, method: bool = False) -> None:
    el = _sub(parent, "MethodDescriptor" if method else "AttributeDescriptor")
    _sub(el, "ClassId", _hex(d.class_id, 2))
    name = obis_name(d.instance_id)
    _comment(el, f"{d.instance_id}" + (f" {name}" if name else ""))
    _sub(el, "InstanceId", d.instance_id.to_bytes().hex().upper())
    if method:
        _sub(el, "MethodId", _hex(d.method_id, 1))
    else:
        _sub(el, "AttributeId", _hex(d.attribute_id & 0xFF, 1))


def _access(parent: ET.Element, access: xdlms.SelectiveAccess | None) -> None:
    if access is None:
        return
    el = _sub(parent, "AccessSelection")
    _sub(el, "AccessSelector", _hex(access.selector, 1))
    _data_into(_sub(el, "AccessParameters"), access.parameters)


def _block(parent: ET.Element, name: str, last: bool, number: int, raw: bytes, sn_width=False):
    el = _sub(parent, name)
    _sub(el, "LastBlock", "01" if last else "00")
    _sub(el, "BlockNumber", _hex(number, 2 if sn_width else 4))
    _sub(el, "RawData", raw.hex().upper())
    return el


def _get_result(parent: ET.Element, result: xdlms.GetDataResult) -> None:
    if result.data is not None:
        _data_into(_sub(parent, "Data"), result.data)
    else:
        _sub(
            parent,
            "DataAccessError",
            _RESULT_NAMES.get(int(result.error), _hex(int(result.error), 1)),
        )


def _result_name(value: int) -> str:
    return _RESULT_NAMES.get(int(value), _hex(int(value), 1))


#: ACCESS specification and result elements by kind (Gurux prints kinds 1..3;
#: the with-selection kinds 4 and 5 are pydlms additions it cannot read).
_ACCESS_SPEC_NAMES = {
    xdlms.AccessKind.GET: "AccessRequestGet",
    xdlms.AccessKind.SET: "AccessRequestSet",
    xdlms.AccessKind.ACTION: "AccessRequestAction",
    xdlms.AccessKind.GET_WITH_SELECTION: "AccessRequestGetWithSelection",
    xdlms.AccessKind.SET_WITH_SELECTION: "AccessRequestSetWithSelection",
}
_ACCESS_RESULT_NAMES = {
    xdlms.AccessKind.GET: "AccessResponseGet",
    xdlms.AccessKind.SET: "AccessResponseSet",
    xdlms.AccessKind.ACTION: "AccessResponseAction",
}


def _long_invoke_id_comment(parent: ET.Element, value: int) -> None:
    f = xdlms.LongInvokeIdAndPriority.from_int(value)
    _comment(
        parent,
        f"Priority: {'High' if f.high_priority else 'Normal'}, "
        f"ServiceClass: {'Confirmed' if f.confirmed else 'UnConfirmed'}, "
        f"{'BreakOnError' if f.processing_option else 'ContinueOnError'}, "
        f"{'SelfDescriptive, ' if f.self_descriptive else ''}Invoke ID: {f.invoke_id}",
    )


def _access_header(root: ET.Element, obj) -> None:
    _long_invoke_id_comment(root, obj.long_invoke_id)
    # Gurux prints the request's id with at least 2 digits, the response's with 8.
    width = 4 if isinstance(obj, xdlms.AccessResponse) else 1
    _sub(root, "LongInvokeIdAndPriority", _hex(obj.long_invoke_id, width))
    stamp = None
    try:
        stamp = obj.timestamp
    except DlmsError:
        pass
    if stamp is not None:
        _comment(root, str(stamp))
    _sub(root, "DateTime", (obj.date_time or b"").hex().upper())


def _access_specs(parent: ET.Element, specs: list) -> None:
    lst = _sub(parent, "AccessRequestSpecification", Qty=_qty(len(specs)))
    for spec in specs:
        el = _sub(_sub(lst, "_AccessRequestSpecification"), _ACCESS_SPEC_NAMES[spec.kind])
        if isinstance(spec, xdlms.AccessRequestAction):
            # Gurux writes the method as an AttributeDescriptor with AttributeId.
            m = spec.method
            _descriptor(el, xdlms.AttributeDescriptor(m.class_id, m.instance_id, m.method_id))
        else:
            _descriptor(el, spec.attribute)
            _access(el, getattr(spec, "access", None))


def _data_list(parent: ET.Element, name: str, values: list[DlmsData]) -> None:
    lst = _sub(parent, name, Qty=_qty(len(values)))
    for value in values:
        _data_into(lst, value)


class GuruxXmlWriter:
    """Turn APDUs into Gurux translator elements.

    Keys are only used to add the deciphered content of ciphered APDUs as a
    comment; the ciphertext is what the element encodes.
    """

    def __init__(
        self,
        encryption_key: bytes | None = None,
        authentication_key: bytes | None = None,
        system_title: bytes | None = None,
        secrets: bool = False,
    ) -> None:
        from pydlms.apduxml import XmlWriter

        self.secrets = secrets
        # The pydlms writer keeps the titles learnt from AARQ/AARE and the
        # inbound invocation counters; reuse it for deciphering.
        self._plain = XmlWriter(encryption_key, authentication_key, system_title, secrets)
        self._hls_invoke: int | None = None

    def apdu(self, apdu: bytes, direction: str | None = None) -> ET.Element:
        if not apdu:
            raise DecodeError("empty APDU")
        from pydlms.apduxml import _decode_plain, _encode_object

        try:
            if apdu[0] in _CIPHERED_BY_TAG or apdu[0] in (
                Tag.GENERAL_GLO_CIPHERING,
                Tag.GENERAL_DED_CIPHERING,
                Tag.GENERAL_CIPHERING,
                Tag.GENERAL_SIGNING,
            ):
                el = self._ciphered(apdu, direction)
                exact = True
            else:
                obj = _decode_plain(apdu)
                self._plain._learn_titles(obj)
                el = self._object(obj, direction)
                exact = _encode_object(obj) == apdu
        except (DlmsError, ValueError, NotImplementedError) as exc:
            raw = ET.Element("Raw", Value=apdu.hex().upper())
            _comment(raw, f"{tag_name(apdu[0])}: no Gurux form: {exc}")
            return raw
        if exact:
            try:
                exact = gurux_element_to_apdu(el) == apdu
            except DlmsError:
                exact = self._redacted(el)
            if exact:
                return el
        raw = ET.Element("Raw", Value=apdu.hex().upper())
        _comment(raw, "the Gurux form does not encode back to these bytes; they are used")
        ET.SubElement(raw, "Decoded").append(el)
        return raw

    @staticmethod
    def _redacted(el: ET.Element) -> bool:
        return any(child.get("Value") == _REDACTED for child in el.iter())

    def _secret(self, parent: ET.Element, tag: str, value: bytes) -> None:
        _sub(parent, tag, value.hex().upper() if self.secrets else _REDACTED)

    # -- ciphered ---------------------------------------------------------------------
    def _ciphered(self, apdu: bytes, direction: str | None) -> ET.Element:
        tag = apdu[0]
        if tag in _CIPHERED_BY_TAG:
            length, pos = decode_length(apdu, 1)
            if pos + length != len(apdu):
                raise DecodeError("ciphered APDU length does not match")
            el = ET.Element(_CIPHERED_BY_TAG[tag], Value=apdu[pos:].hex().upper())
        elif tag in (Tag.GENERAL_GLO_CIPHERING, Tag.GENERAL_DED_CIPHERING):
            el = ET.Element(
                "GeneralGloCiphering" if tag == Tag.GENERAL_GLO_CIPHERING else "GeneralDedCiphering"
            )
            title, pos = _octet_string(apdu, 1)
            content, pos = _octet_string(apdu, pos)
            if pos != len(apdu):
                raise DecodeError("trailing octets after the ciphered service")
            _sub(el, "SystemTitle", title.hex().upper())
            _sub(el, "CipheredService", content.hex().upper())
        elif tag == Tag.GENERAL_SIGNING:
            el = _general_signing(apdu)
        else:
            el = _general_ciphering(apdu)
        self._plaintext_comment(el, apdu, direction)
        return el

    def _plaintext_comment(self, el: ET.Element, apdu: bytes, direction) -> None:
        if self._plain.security is None:
            return
        from pydlms.security.ciphering import unwrap

        sender = self._plain.titles.get(direction)
        try:
            if sender is not None:
                self._plain.security.server_system_title = sender
            result = unwrap(self._plain.security, apdu, strict=False)
            inner = self.apdu(result.plaintext, direction)
        except (DlmsError, ValueError) as exc:
            _comment(el, f"not deciphered: {type(exc).__name__}: {exc}")
            return
        ET.indent(inner, "  ")
        text = ET.tostring(inner, encoding="unicode")
        _comment(
            el,
            f"Deciphered ({result.security_control.describe()}, IC {result.invocation_counter}, "
            f"{'tag verified' if result.authenticated else 'tag not verified'}):\n{text}\n",
        )

    # -- plain APDUs ------------------------------------------------------------------
    def _object(self, obj, direction) -> ET.Element:  # noqa: C901 - one case per APDU type
        x = xdlms
        if isinstance(obj, (x.GetRequestNormal, x.GetRequestNext, x.GetRequestWithList)):
            root = ET.Element("GetRequest")
            if isinstance(obj, x.GetRequestNormal):
                el = _sub(root, "GetRequestNormal")
                _iip(el, obj.invoke_id)
                _descriptor(el, obj.attribute)
                _access(el, obj.access)
            elif isinstance(obj, x.GetRequestNext):
                el = _sub(root, "GetRequestForNextDataBlock")
                _iip(el, obj.invoke_id)
                _sub(el, "BlockNumber", _hex(obj.block_number, 4))
            else:
                el = _sub(root, "GetRequestWithList")
                _iip(el, obj.invoke_id)
                lst = _sub(el, "AttributeDescriptorList", Qty=_qty(len(obj.items)))
                for attribute, access in obj.items:
                    item = _sub(lst, "AttributeDescriptorWithSelection")
                    _descriptor(item, attribute)
                    _access(item, access)
            return root
        if isinstance(
            obj, (x.GetResponseNormal, x.GetResponseWithDatablock, x.GetResponseWithList)
        ):
            root = ET.Element("GetResponse")
            if isinstance(obj, x.GetResponseNormal):
                el = _sub(root, "GetResponseNormal")
                _iip(el, obj.invoke_id)
                _get_result(_sub(el, "Result"), obj.result)
            elif isinstance(obj, x.GetResponseWithDatablock):
                el = _sub(root, "GetResponsewithDataBlock")
                _iip(el, obj.invoke_id)
                result = _sub(el, "Result")
                _sub(result, "LastBlock", "01" if obj.last_block else "00")
                _sub(result, "BlockNumber", _hex(obj.block_number, 4))
                inner = _sub(result, "Result")
                if obj.raw_data is not None:
                    _sub(inner, "RawData", obj.raw_data.hex().upper())
                else:
                    _sub(inner, "DataAccessResult", _result_name(obj.error))
            else:
                el = _sub(root, "GetResponseWithList")
                _iip(el, obj.invoke_id)
                lst = _sub(el, "Result", Qty=_qty(len(obj.results)))
                for result in obj.results:
                    _get_result(lst, result)
            return root
        if isinstance(
            obj,
            (
                x.SetRequestNormal,
                x.SetRequestWithFirstDatablock,
                x.SetRequestWithDatablock,
                x.SetRequestWithList,
            ),
        ):
            root = ET.Element("SetRequest")
            if isinstance(obj, x.SetRequestNormal):
                el = _sub(root, "SetRequestNormal")
                _iip(el, obj.invoke_id)
                _descriptor(el, obj.attribute)
                _access(el, obj.access)
                _data_into(_sub(el, "Value"), obj.value)
            elif isinstance(obj, x.SetRequestWithFirstDatablock):
                el = _sub(root, "SetRequestFirstDataBlock")
                _iip(el, obj.invoke_id)
                _descriptor(el, obj.attribute)
                _access(el, obj.access)
                _block(el, "DataBlock", obj.last_block, obj.block_number, obj.raw_data)
            elif isinstance(obj, x.SetRequestWithDatablock):
                el = _sub(root, "SetRequestWithDataBlock")
                _iip(el, obj.invoke_id)
                _block(el, "DataBlock", obj.last_block, obj.block_number, obj.raw_data)
            else:
                el = _sub(root, "SetRequestWithList")
                _iip(el, obj.invoke_id)
                lst = _sub(el, "AttributeDescriptorList", Qty=_qty(len(obj.items)))
                for attribute, access, _ in obj.items:
                    item = _sub(lst, "AttributeDescriptorWithSelection")
                    _descriptor(item, attribute)
                    _access(item, access)
                values = _sub(el, "ValueList", Qty=_qty(len(obj.items)))
                for _, _, value in obj.items:
                    _data_into(values, value)
            return root
        if isinstance(
            obj,
            (
                x.SetResponseNormal,
                x.SetResponseDatablock,
                x.SetResponseLastDatablock,
                x.SetResponseWithList,
            ),
        ):
            root = ET.Element("SetResponse")
            if isinstance(obj, x.SetResponseNormal):
                el = _sub(root, "SetResponseNormal")
                _iip(el, obj.invoke_id)
                _sub(el, "Result", _result_name(obj.result))
            elif isinstance(obj, x.SetResponseDatablock):
                el = _sub(root, "SetResponseDataBlock")
                _iip(el, obj.invoke_id)
                _sub(el, "BlockNumber", _hex(obj.block_number, 4))
            elif isinstance(obj, x.SetResponseLastDatablock):
                el = _sub(root, "SetResponseWithLastDataBlock")
                _iip(el, obj.invoke_id)
                _sub(el, "Result", _result_name(obj.result))
                _sub(el, "BlockNumber", _hex(obj.block_number, 4))
            else:
                el = _sub(root, "SetResponseWithList")
                _iip(el, obj.invoke_id)
                lst = _sub(el, "Result", Qty=str(len(obj.results)))
                for result in obj.results:
                    _sub(lst, "DataAccessResult", _result_name(result))
            return root
        if isinstance(
            obj,
            (
                x.ActionRequestNormal,
                x.ActionRequestNextPblock,
                x.ActionRequestWithList,
                x.ActionRequestWithFirstPblock,
                x.ActionRequestWithPblock,
            ),
        ):
            root = ET.Element("ActionRequest")
            if isinstance(obj, x.ActionRequestNormal):
                el = _sub(root, "ActionRequestNormal")
                _iip(el, obj.invoke_id)
                _descriptor(el, obj.method, method=True)
                if obj.parameters is not None:
                    params = _sub(el, "MethodInvocationParameters")
                    if self._is_hls(obj):
                        self._hls_invoke = obj.invoke_id
                        if not self.secrets:
                            _comment(params, "HLS f(StoC): write with secrets=True to show it")
                            params.set("Value", _REDACTED)
                            return root
                    _data_into(params, obj.parameters)
            elif isinstance(obj, x.ActionRequestNextPblock):
                el = _sub(root, "ActionRequestForNextPBlock")
                _iip(el, obj.invoke_id)
                _sub(el, "BlockNumber", _hex(obj.block_number, 4))
            elif isinstance(obj, x.ActionRequestWithList):
                el = _sub(root, "ActionRequestWithList")
                _iip(el, obj.invoke_id)
                lst = _sub(el, "MethodDescriptorList", Qty=_qty(len(obj.items)))
                for method, _ in obj.items:
                    _descriptor(lst, method, method=True)
                params = _sub(el, "MethodInvocationParameters", Qty=_qty(len(obj.items)))
                for _, value in obj.items:
                    _data_into(params, value if value is not None else DlmsData.null())
            elif isinstance(obj, x.ActionRequestWithFirstPblock):
                el = _sub(root, "ActionRequestWithFirstBlock")
                _iip(el, obj.invoke_id)
                _descriptor(el, obj.method, method=True)
                _block(el, "DataBlock", obj.last_block, obj.block_number, obj.raw_data)
            else:
                el = _sub(root, "ActionRequestWithBlock")
                _iip(el, obj.invoke_id)
                _block(el, "DataBlock", obj.last_block, obj.block_number, obj.raw_data)
            return root
        if isinstance(
            obj,
            (
                x.ActionResponseNormal,
                x.ActionResponseWithPblock,
                x.ActionResponseWithList,
                x.ActionResponseNextPblock,
            ),
        ):
            root = ET.Element("ActionResponse")
            if isinstance(obj, x.ActionResponseNormal):
                el = _sub(root, "ActionResponseNormal")
                _iip(el, obj.invoke_id)
                _sub(el, "Result", _result_name(obj.result))
                if obj.return_data is not None:
                    params = _sub(el, "ReturnParameters")
                    if obj.invoke_id == self._hls_invoke:
                        self._hls_invoke = None
                        if not self.secrets:
                            _comment(params, "HLS f(CtoS): write with secrets=True to show it")
                            params.set("Value", _REDACTED)
                            return root
                    _get_result(params, obj.return_data)
            elif isinstance(obj, x.ActionResponseWithPblock):
                el = _sub(root, "ActionResponseWithPBlock")
                _iip(el, obj.invoke_id)
                _block(el, "PBlock", obj.last_block, obj.block_number, obj.raw_data)
            elif isinstance(obj, x.ActionResponseWithList):
                el = _sub(root, "ActionResponseWithList")
                _iip(el, obj.invoke_id)
                lst = _sub(el, "Result", Qty=_qty(len(obj.results)))
                for result, data in obj.results:
                    item = _sub(lst, "ActionResponseWithOptionalData")
                    _sub(item, "Result", _result_name(result))
                    if data is not None:
                        _get_result(_sub(item, "ReturnParameters"), data)
            else:
                el = _sub(root, "ActionResponseNextBlock")
                _iip(el, obj.invoke_id)
                _sub(el, "BlockNumber", _hex(obj.block_number, 4))
            return root
        if isinstance(obj, x.AccessRequest):
            root = ET.Element("AccessRequest")
            _access_header(root, obj)
            body = _sub(root, "AccessRequestBody")
            _access_specs(body, obj.specifications)
            _data_list(body, "AccessRequestListOfData", obj.data)
            return root
        if isinstance(obj, x.AccessResponse):
            root = ET.Element("AccessResponse")
            _access_header(root, obj)
            body = _sub(root, "AccessResponseBody")
            if obj.specifications is not None:  # pydlms addition: Gurux skips the echo
                _access_specs(body, obj.specifications)
            _data_list(body, "AccessResponseListOfData", obj.data)
            lst = _sub(body, "AccessResponseSpecification", Qty=_qty(len(obj.results)))
            for result in obj.results:
                el = _sub(
                    _sub(lst, "_AccessResponseSpecification"), _ACCESS_RESULT_NAMES[result.kind]
                )
                _sub(el, "Result", _result_name(result.result))
            return root
        if isinstance(obj, x.DataNotification):
            root = ET.Element("DataNotification")
            _sub(root, "LongInvokeIdAndPriority", _hex(obj.long_invoke_id, 4))
            dt = _sub(root, "DateTime", (obj.date_time or b"").hex().upper())
            if obj.date_time_tagged:
                dt.set("Tagged", "true")
            _data_into(_sub(_sub(root, "NotificationBody"), "DataValue"), obj.body)
            return root
        if isinstance(obj, x.EventNotificationRequest):
            root = ET.Element("EventNotificationRequest")
            if obj.time is not None:
                _sub(root, "DateTime", obj.time.hex().upper())
            _descriptor(root, obj.attribute)
            _data_into(_sub(root, "AttributeValue"), obj.value)
            return root
        if isinstance(obj, x.ExceptionResponse):
            root = ET.Element("ExceptionResponse")
            _sub(root, "StateError", _STATE_ERRORS.get(obj.state_error, _hex(obj.state_error, 1)))
            _sub(
                root,
                "ServiceError",
                _SERVICE_ERRORS.get(obj.service_error, _hex(obj.service_error, 1)),
            )
            if obj.invocation_counter is not None:
                _sub(root, "InvocationCounter", _hex(obj.invocation_counter, 4))
            return root
        if isinstance(obj, x.ConfirmedServiceError):
            root = ET.Element("ConfirmedServiceError")
            _sub(root, "Service", _hex(obj.service, 1))
            name, values = _CSE.get(obj.error_type, (f"Error{obj.error_type:02X}", []))
            value = values[obj.value] if obj.value < len(values) else _hex(obj.value, 1)
            _sub(_sub(root, "ServiceError"), name, value)
            return root
        if isinstance(obj, x.InitiateRequest):
            root = ET.Element("InitiateRequest")
            if obj.dedicated_key is not None:
                self._secret(root, "DedicatedKey", obj.dedicated_key)
            if not obj.response_allowed:
                # Gurux writes response-allowed FALSE as a QualityOfService of 0;
                # alone that cannot be told from a real QoS 0.
                if obj.quality_of_service is None:
                    _sub(root, "ResponseAllowed", "false")
                else:
                    _sub(root, "ProposedQualityOfService", "0")
            if obj.quality_of_service is not None:
                _sub(root, "ProposedQualityOfService", str(obj.quality_of_service))
            _sub(root, "ProposedDlmsVersionNumber", _hex(obj.dlms_version, 1))
            _conformance(_sub(root, "ProposedConformance"), obj.conformance)
            _sub(root, "ProposedMaxPduSize", _hex(obj.max_receive_pdu_size, 2))
            return root
        if isinstance(obj, x.InitiateResponse):
            root = ET.Element("InitiateResponse")
            if obj.quality_of_service is not None:
                _sub(root, "NegotiatedQualityOfService", str(obj.quality_of_service))
            _sub(root, "NegotiatedDlmsVersionNumber", _hex(obj.dlms_version, 1))
            _conformance(_sub(root, "NegotiatedConformance"), obj.conformance)
            _sub(root, "NegotiatedMaxPduSize", _hex(obj.max_receive_pdu_size, 2))
            _sub(root, "VaaName", _hex(obj.vaa_name, 2))
            return root
        if isinstance(obj, (AARQ, AARE, RLRQ, RLRE)):
            return self._acse(obj, direction)
        if isinstance(obj, gbt.GbtBlock):
            root = ET.Element("GeneralBlockTransfer")
            _sub(root, "BlockControl", _hex(obj.control(), 1))
            _sub(root, "BlockNumber", _hex(obj.block_number, 2))
            _sub(root, "BlockNumberAck", _hex(obj.block_number_ack, 2))
            _sub(root, "BlockData", " ".join(f"{b:02X}" for b in obj.data))
            return root
        return self._short_name(obj)

    def _short_name(self, obj) -> ET.Element:
        if isinstance(obj, sn.ReadRequest):
            root = ET.Element("ReadRequest", Qty=_qty(len(obj.items)))
            for item in obj.items:
                _variable_access(root, item)
            return root
        if isinstance(obj, sn.ReadResponse):
            root = ET.Element("ReadResponse", Qty=_qty(len(obj.results)))
            for result in obj.results:
                if result.data is not None:
                    _data_into(_sub(root, "Data"), result.data)
                elif result.error is not None:
                    _sub(root, "DataAccessError", _result_name(result.error))
                else:
                    _block(
                        root,
                        "DataBlockResult",
                        bool(result.block_last),
                        result.block_number or 0,
                        result.raw_data or b"",
                        sn_width=True,
                    )
            return root
        if isinstance(obj, (sn.WriteRequest, sn.UnconfirmedWriteRequest)):
            root = ET.Element(type(obj).__name__)
            specs = _sub(root, "ListOfVariableAccessSpecification", Qty=_qty(len(obj.items)))
            for item in obj.items:
                _variable_access(specs, item)
            data = _sub(root, "ListOfData", Qty=_qty(len(obj.values)))
            for value in obj.values:
                _data_into(data, value)
            return root
        if isinstance(obj, sn.WriteResponse):
            root = ET.Element("WriteResponse", Qty=_qty(len(obj.results)))
            for result in obj.results:
                if isinstance(result, sn.WriteBlockNumber):
                    raise DecodeError("Gurux has no WriteResponse block-number form")
                if int(result) == 0:
                    _sub(root, "Ok")
                else:
                    _sub(root, "DataAccessError", _result_name(result))
            return root
        if isinstance(obj, sn.InformationReportRequest):
            root = ET.Element("InformationReportRequest")
            if obj.current_time is not None:
                ct = _sub(root, "CurrentTime", obj.current_time.hex().upper())
                if obj.current_time_bare:
                    ct.set("Bare", "true")
            specs = _sub(root, "ListOfVariableAccessSpecification", Qty=_qty(len(obj.names)))
            for name in obj.names:
                _sub(specs, "VariableName", _hex(name, 2))
            data = _sub(root, "ListOfData", Qty=_qty(len(obj.values)))
            for value in obj.values:
                _data_into(data, value)
            return root
        raise DecodeError(f"{type(obj).__name__} has no Gurux form")

    def _acse(self, obj, direction) -> ET.Element:
        if isinstance(obj, (RLRQ, RLRE)):
            root = ET.Element("ReleaseRequest" if isinstance(obj, RLRQ) else "ReleaseResponse")
            reasons = _RLRQ_REASONS if isinstance(obj, RLRQ) else _RLRE_REASONS
            if obj.reason is not None:
                _sub(root, "Reason", reasons.get(obj.reason, _hex(obj.reason, 1)))
            if obj.user_information:
                _sub(root, "UserInformation").append(self.apdu(obj.user_information, direction))
            return root
        request = isinstance(obj, AARQ)
        root = ET.Element("AssociationRequest" if request else "AssociationResponse")
        _sub(root, "ApplicationContextName", _CONTEXT_NAMES[obj.application_context])
        if request:
            if obj.calling_ap_title is not None:
                _sub(root, "CallingAPTitle", obj.calling_ap_title.hex().upper())
            if obj.calling_ae_qualifier is not None:
                _sub(root, "CallingAEQualifier", obj.calling_ae_qualifier.hex().upper())
            auth = obj.calling_authentication_value
        else:
            _comment(root, _association_result(obj.result))
            _sub(root, "AssociationResult", _hex(obj.result, 1))
            diag = _sub(root, "ResultSourceDiagnostic")
            _sub(
                diag,
                "ACSEServiceUser" if obj.diagnostic_source == 1 else "ACSEServiceProvider",
                _hex(obj.diagnostic, 1),
            )
            if obj.responding_ap_title is not None:
                _sub(root, "RespondingAPTitle", obj.responding_ap_title.hex().upper())
            if obj.responding_ae_qualifier is not None:
                _sub(root, "RespondingAEQualifier", obj.responding_ae_qualifier.hex().upper())
            auth = obj.responding_authentication_value
        if obj.mechanism is not None:
            _sub(root, "SenderACSERequirements" if request else "ResponderACSERequirement", "1")
            name = (
                _MECHANISMS[obj.mechanism]
                if obj.mechanism < len(_MECHANISMS)
                else _hex(obj.mechanism, 1)
            )
            _sub(root, "MechanismName", name)
        if auth is not None:
            self._secret(
                root, "CallingAuthentication" if request else "RespondingAuthentication", auth
            )
        if obj.user_information:
            root.append(self.apdu(obj.user_information, direction))
        return root

    @staticmethod
    def _is_hls(obj: xdlms.ActionRequestNormal) -> bool:
        from pydlms.apduxml import _HLS_METHOD

        m = obj.method
        return (m.class_id, m.instance_id, m.method_id) == _HLS_METHOD


def _association_result(result: int) -> str:
    return {0: "Accepted", 1: "PermanentRejected", 2: "TransientRejected"}.get(result, "")


def _conformance(parent: ET.Element, conformance: xdlms.Conformance) -> None:
    for bit in sorted(xdlms.Conformance, key=int, reverse=True):
        if conformance & bit:
            _sub(parent, "ConformanceBit", Name=_camel(bit.name))


def _variable_access(parent: ET.Element, item) -> None:
    if isinstance(item, sn.VariableName):
        _sub(parent, "VariableName", _hex(item.name, 2))
    elif isinstance(item, sn.BlockNumberAccess):
        _sub(_sub(parent, "BlockNumberAccess"), "BlockNumber", _hex(item.block_number, 2))
    elif isinstance(item, sn.ParameterizedAccess):
        el = _sub(parent, "ParameterisedAccess")
        _sub(el, "VariableName", _hex(item.name, 2))
        _sub(el, "Selector", _hex(item.selector, 1))
        _data_into(_sub(el, "Parameter"), item.parameter)
    elif isinstance(item, sn.ReadDataBlockAccess):
        # Gurux prints LastBlock and BlockNumber only; RawData is a pydlms addition.
        _block(
            parent,
            "ReadDataBlockAccess",
            item.last_block,
            item.block_number,
            item.raw_data,
            sn_width=True,
        )
    elif isinstance(item, sn.WriteDataBlockAccess):
        el = _sub(parent, "WriteDataBlockAccess")
        _sub(el, "LastBlock", "01" if item.last_block else "00")
        _sub(el, "BlockNumber", _hex(item.block_number, 2))
    else:
        raise DecodeError(f"{type(item).__name__} has no Gurux form")


def _octet_string(data: bytes, pos: int) -> tuple[bytes, int]:
    length, pos = decode_length(data, pos)
    if pos + length > len(data):
        raise DecodeError("octet-string runs past the end of the APDU")
    return data[pos : pos + length], pos + length


_GENERAL_HEADER = (
    "TransactionId",
    "OriginatorSystemTitle",
    "RecipientSystemTitle",
    "DateTime",
    "OtherInformation",
)


def _general_signing(apdu: bytes) -> ET.Element:
    """general-signing (0xDF): the header, the signed content and the signature."""
    el = ET.Element("GeneralSigning")
    pos = 1
    for name in (*_GENERAL_HEADER, "Content", "Signature"):
        value, pos = _octet_string(apdu, pos)
        _sub(el, name, value.hex().upper())
    if pos != len(apdu):
        raise DecodeError("trailing octets after the signature")
    return el


def _general_ciphering(apdu: bytes) -> ET.Element:
    """general-ciphering (0xDD) with no key-info or an agreed-key key-info."""
    el = ET.Element("GeneralCiphering")
    pos = 1
    for name in _GENERAL_HEADER:
        value, pos = _octet_string(apdu, pos)
        _sub(el, name, value.hex().upper())
    if pos >= len(apdu):
        raise DecodeError("general-ciphering ends before its key-info")
    if apdu[pos] == 1:
        if pos + 1 >= len(apdu) or apdu[pos + 1] != 2:
            raise DecodeError("only the agreed-key key-info has a Gurux form")
        agreed = _sub(_sub(el, "KeyInfo"), "AgreedKey")
        params, pos = _octet_string(apdu, pos + 2)
        data, pos = _octet_string(apdu, pos)
        _sub(agreed, "KeyParameters", params.hex().upper())
        _sub(agreed, "KeyCipheredData", data.hex().upper())
    elif apdu[pos] == 0:
        pos += 1
    else:
        raise DecodeError(f"key-info presence flag {apdu[pos]:#04x}")
    content, pos = _octet_string(apdu, pos)
    if pos != len(apdu):
        raise DecodeError("trailing octets after the ciphered content")
    _sub(el, "CipheredContent", content.hex().upper())
    return el


# --- reader --------------------------------------------------------------------------


def _attribute_descriptor(el: ET.Element) -> xdlms.AttributeDescriptor:
    attribute_id = _int(_need(el, "AttributeId"))
    if attribute_id > 0x7F:
        attribute_id -= 0x100
    return xdlms.AttributeDescriptor(
        _int(_need(el, "ClassId")),
        ObisCode.from_bytes(_octets(_need(el, "InstanceId"))),
        attribute_id,
    )


def _method_descriptor(el: ET.Element) -> xdlms.MethodDescriptor:
    return xdlms.MethodDescriptor(
        _int(_need(el, "ClassId")),
        ObisCode.from_bytes(_octets(_need(el, "InstanceId"))),
        _int(_need(el, "MethodId")),
    )


def _read_access(el: ET.Element) -> xdlms.SelectiveAccess | None:
    sel = el.find("AccessSelection")
    if sel is None:
        return None
    return xdlms.SelectiveAccess(
        _int(_need(sel, "AccessSelector")), _one_data(_need(sel, "AccessParameters"))
    )


def _read_block(el: ET.Element) -> tuple[bool, int, bytes]:
    return (
        _int(_need(el, "LastBlock")) != 0,
        _int(_need(el, "BlockNumber")),
        _octets(_need(el, "RawData")),
    )


def _result_code(value: int, kind: type[IntEnum]) -> IntEnum | int:
    """The enum member, or the bare code (as the APDU decoders keep it)."""
    if not 0 <= value <= 0xFF:
        raise DecodeError(f"result code {value} does not fit one octet")
    try:
        return kind(value)
    except ValueError:
        return value


def _read_result(value: int) -> DataAccessResult | int:
    return _result_code(value, DataAccessResult)


def _read_get_result(el: ET.Element) -> xdlms.GetDataResult:
    if el.tag == "Data":
        return xdlms.GetDataResult(data=_one_data(el))
    if el.tag in ("DataAccessError", "DataAccessResult"):
        return xdlms.GetDataResult(error=_read_result(_named(_RESULT_NAMES, el)))
    raise DecodeError(f"<{el.tag}> is not a get-data-result")


def _iid(el: ET.Element) -> int:
    return _int(_need(el, "InvokeIdAndPriority"))


def _service(el: ET.Element) -> ET.Element:
    """The single CHOICE element inside GetRequest, SetResponse and the like."""
    return _only(el)


def _read_get_request(root: ET.Element):
    el = _service(root)
    if el.tag == "GetRequestNormal":
        return xdlms.GetRequestNormal(
            _iid(el), _attribute_descriptor(_need(el, "AttributeDescriptor")), _read_access(el)
        )
    if el.tag == "GetRequestForNextDataBlock":
        return xdlms.GetRequestNext(_iid(el), _int(_need(el, "BlockNumber")))
    if el.tag == "GetRequestWithList":
        items = [
            (_attribute_descriptor(_need(item, "AttributeDescriptor")), _read_access(item))
            for item in _need(el, "AttributeDescriptorList").findall(
                "AttributeDescriptorWithSelection"
            )
        ]
        return xdlms.GetRequestWithList(_iid(el), items)
    raise DecodeError(f"<{el.tag}> is not a get-request")


def _read_get_response(root: ET.Element):
    el = _service(root)
    if el.tag == "GetResponseNormal":
        return xdlms.GetResponseNormal(_iid(el), _read_get_result(_only(_need(el, "Result"))))
    if el.tag == "GetResponsewithDataBlock":
        result = _need(el, "Result")
        inner = _only(_need(result, "Result"))
        last = _int(_need(result, "LastBlock")) != 0
        number = _int(_need(result, "BlockNumber"))
        if inner.tag == "RawData":
            return xdlms.GetResponseWithDatablock(_iid(el), last, number, raw_data=_octets(inner))
        return xdlms.GetResponseWithDatablock(
            _iid(el), last, number, error=_read_result(_named(_RESULT_NAMES, inner))
        )
    if el.tag == "GetResponseWithList":
        results = [_read_get_result(child) for child in _children(_need(el, "Result"))]
        return xdlms.GetResponseWithList(_iid(el), results)
    raise DecodeError(f"<{el.tag}> is not a get-response")


def _read_set_request(root: ET.Element):
    el = _service(root)
    if el.tag == "SetRequestNormal":
        return xdlms.SetRequestNormal(
            _iid(el),
            _attribute_descriptor(_need(el, "AttributeDescriptor")),
            _one_data(_need(el, "Value")),
            _read_access(el),
        )
    if el.tag == "SetRequestFirstDataBlock":
        # Gurux repeats the descriptor and adds an empty <Value> after the
        # data block; the first descriptor is the one that counts.
        last, number, raw = _read_block(_need(el, "DataBlock"))
        return xdlms.SetRequestWithFirstDatablock(
            _iid(el),
            _attribute_descriptor(_need(el, "AttributeDescriptor")),
            last,
            number,
            raw,
            _read_access(el),
        )
    if el.tag == "SetRequestWithDataBlock":
        return xdlms.SetRequestWithDatablock(_iid(el), *_read_block(_need(el, "DataBlock")))
    if el.tag == "SetRequestWithList":
        specs = _need(el, "AttributeDescriptorList").findall("AttributeDescriptorWithSelection")
        values = [element_data(v) for v in _children(_need(el, "ValueList"))]
        if len(specs) != len(values):
            raise DecodeError("SetRequestWithList: descriptor and value counts differ")
        items = [
            (_attribute_descriptor(_need(s, "AttributeDescriptor")), _read_access(s), v)
            for s, v in zip(specs, values, strict=True)
        ]
        return xdlms.SetRequestWithList(_iid(el), items)
    raise DecodeError(f"<{el.tag}> is not a set-request")


def _read_set_response(root: ET.Element):
    el = _service(root)
    if el.tag == "SetResponseNormal":
        return xdlms.SetResponseNormal(
            _iid(el), _read_result(_named(_RESULT_NAMES, _need(el, "Result")))
        )
    if el.tag == "SetResponseDataBlock":
        return xdlms.SetResponseDatablock(_iid(el), _int(_need(el, "BlockNumber")))
    if el.tag == "SetResponseWithLastDataBlock":
        return xdlms.SetResponseLastDatablock(
            _iid(el),
            _read_result(_named(_RESULT_NAMES, _need(el, "Result"))),
            _int(_need(el, "BlockNumber")),
        )
    if el.tag == "SetResponseWithList":
        results = [
            _read_result(_named(_RESULT_NAMES, child)) for child in _children(_need(el, "Result"))
        ]
        return xdlms.SetResponseWithList(_iid(el), results)
    raise DecodeError(f"<{el.tag}> is not a set-response")


def _action_result(el: ET.Element) -> ActionResult | int:
    return _result_code(_named(_RESULT_NAMES, el), ActionResult)


def _read_action_request(root: ET.Element):
    el = _service(root)
    if el.tag == "ActionRequestNormal":
        params = el.find("MethodInvocationParameters")
        return xdlms.ActionRequestNormal(
            _iid(el),
            _method_descriptor(_need(el, "MethodDescriptor")),
            None if params is None else _one_data(_redaction_check(params)),
        )
    if el.tag == "ActionRequestForNextPBlock":
        return xdlms.ActionRequestNextPblock(_iid(el), _int(_need(el, "BlockNumber")))
    if el.tag == "ActionRequestWithList":
        methods = [
            _method_descriptor(m)
            for m in _need(el, "MethodDescriptorList").findall("MethodDescriptor")
        ]
        params = [element_data(p) for p in _children(_need(el, "MethodInvocationParameters"))]
        if len(methods) != len(params):
            raise DecodeError("ActionRequestWithList: method and parameter counts differ")
        return xdlms.ActionRequestWithList(_iid(el), list(zip(methods, params, strict=True)))
    if el.tag == "ActionRequestWithFirstBlock":
        return xdlms.ActionRequestWithFirstPblock(
            _iid(el),
            _method_descriptor(_need(el, "MethodDescriptor")),
            *_read_block(_need(el, "DataBlock")),
        )
    if el.tag == "ActionRequestWithBlock":
        return xdlms.ActionRequestWithPblock(_iid(el), *_read_block(_need(el, "DataBlock")))
    raise DecodeError(f"<{el.tag}> is not an action-request")


def _redaction_check(el: ET.Element) -> ET.Element:
    if el.get("Value") == _REDACTED:
        raise DecodeError(f"<{el.tag}> is redacted; write the XML with secrets=True to encode it")
    return el


def _read_action_response(root: ET.Element):
    el = _service(root)
    if el.tag == "ActionResponseNormal":
        params = el.find("ReturnParameters")
        data = None if params is None else _read_get_result(_only(_redaction_check(params)))
        return xdlms.ActionResponseNormal(_iid(el), _action_result(_need(el, "Result")), data)
    if el.tag == "ActionResponseWithPBlock":
        return xdlms.ActionResponseWithPblock(_iid(el), *_read_block(_need(el, "PBlock")))
    if el.tag == "ActionResponseWithList":
        results = []
        for item in _need(el, "Result").findall("ActionResponseWithOptionalData"):
            params = item.find("ReturnParameters")
            data = None if params is None else _read_get_result(_only(params))
            results.append((_action_result(_need(item, "Result")), data))
        return xdlms.ActionResponseWithList(_iid(el), results)
    if el.tag == "ActionResponseNextBlock":
        return xdlms.ActionResponseNextPblock(_iid(el), _int(_need(el, "BlockNumber")))
    raise DecodeError(f"<{el.tag}> is not an action-response")


def _read_access_spec(el: ET.Element):
    if el.tag == "_AccessRequestSpecification":
        el = _only(el)
    if el.tag == "AccessRequestAction":
        found = el.find("MethodDescriptor")
        if found is not None:
            return xdlms.AccessRequestAction(_method_descriptor(found))
        d = _attribute_descriptor(_need(el, "AttributeDescriptor"))
        return xdlms.AccessRequestAction(
            xdlms.MethodDescriptor(d.class_id, d.instance_id, d.attribute_id)
        )
    kinds = {
        "AccessRequestGet": xdlms.AccessRequestGet,
        "AccessRequestSet": xdlms.AccessRequestSet,
        "AccessRequestGetWithSelection": xdlms.AccessRequestGetWithSelection,
        "AccessRequestSetWithSelection": xdlms.AccessRequestSetWithSelection,
    }
    if el.tag not in kinds:
        raise DecodeError(f"<{el.tag}> is not an access-request-specification")
    attribute = _attribute_descriptor(_need(el, "AttributeDescriptor"))
    if el.tag in ("AccessRequestGet", "AccessRequestSet"):
        return kinds[el.tag](attribute)
    access = _read_access(el)
    if access is None:
        raise DecodeError(f"<{el.tag}> needs an <AccessSelection>")
    return kinds[el.tag](attribute, access)


def _read_access_result(el: ET.Element):
    if el.tag == "_AccessResponseSpecification":
        el = _only(el)
    result = _named(_RESULT_NAMES, _need(el, "Result"))
    if el.tag == "AccessResponseGet":
        return xdlms.AccessResponseGet(_read_result(result))
    if el.tag == "AccessResponseSet":
        return xdlms.AccessResponseSet(_read_result(result))
    if el.tag == "AccessResponseAction":
        return xdlms.AccessResponseAction(_result_code(result, ActionResult))
    raise DecodeError(f"<{el.tag}> is not an access-response-specification")


def _read_access_service(root: ET.Element):
    long_invoke_id = _int(_need(root, "LongInvokeIdAndPriority"))
    dt = root.find("DateTime")
    date_time = (_octets(dt) if dt is not None else b"") or None
    if root.tag == "AccessRequest":
        body = _need(root, "AccessRequestBody")
        specs = [_read_access_spec(c) for c in _children(_need(body, "AccessRequestSpecification"))]
        data = [element_data(c) for c in _children(_need(body, "AccessRequestListOfData"))]
        if len(specs) != len(data):
            raise DecodeError("AccessRequest: specification and data counts differ")
        return xdlms.AccessRequest(long_invoke_id, date_time, specs, data)
    body = _need(root, "AccessResponseBody")
    echo = body.find("AccessRequestSpecification")
    specs = None if echo is None else [_read_access_spec(c) for c in _children(echo)]
    data = [element_data(c) for c in _children(_need(body, "AccessResponseListOfData"))]
    results = [
        _read_access_result(c) for c in _children(_need(body, "AccessResponseSpecification"))
    ]
    if len(results) != len(data) or (specs is not None and len(specs) != len(results)):
        raise DecodeError("AccessResponse: data, result and echo counts differ")
    return xdlms.AccessResponse(long_invoke_id, date_time, specs, data, results)


def _read_conformance(el: ET.Element) -> xdlms.Conformance:
    value = xdlms.Conformance(0)
    for bit in el.findall("ConformanceBit"):
        name = bit.get("Name", "")
        if name not in _CONFORMANCE:
            raise DecodeError(f"unknown conformance bit {name!r}")
        value |= _CONFORMANCE[name]
    return value


def _read_initiate_request(el: ET.Element) -> xdlms.InitiateRequest:
    qos = el.findall("ProposedQualityOfService")
    allowed = el.find("ResponseAllowed")
    response_allowed = allowed is None or _value(allowed).lower() != "false"
    if len(qos) == 2:  # Gurux: the first one stands for response-allowed FALSE
        response_allowed = False
        qos = qos[1:]
    key = el.find("DedicatedKey")
    return xdlms.InitiateRequest(
        _read_conformance(_need(el, "ProposedConformance")),
        _int(_need(el, "ProposedMaxPduSize")),
        dlms_version=_int(_need(el, "ProposedDlmsVersionNumber")),
        dedicated_key=None if key is None else _octets(key),
        response_allowed=response_allowed,
        quality_of_service=int(_value(qos[0])) if qos else None,
    )


def _read_initiate_response(el: ET.Element) -> xdlms.InitiateResponse:
    qos = el.find("NegotiatedQualityOfService")
    return xdlms.InitiateResponse(
        _read_conformance(_need(el, "NegotiatedConformance")),
        _int(_need(el, "NegotiatedMaxPduSize")),
        dlms_version=_int(_need(el, "NegotiatedDlmsVersionNumber")),
        vaa_name=_int(_need(el, "VaaName")),
        quality_of_service=None if qos is None else int(_value(qos)),
    )


_USER_INFORMATION = {
    "InitiateRequest",
    "InitiateResponse",
    "ConfirmedServiceError",
    "Raw",
} | {name for name in _CIPHERED_NAMES if name.endswith(("InitiateRequest", "InitiateResponse"))}


def _user_information(el: ET.Element) -> bytes:
    found = [child for child in _children(el) if child.tag in _USER_INFORMATION]
    if len(found) > 1:
        raise DecodeError(f"<{el.tag}> holds more than one user-information APDU")
    return gurux_element_to_apdu(found[0]) if found else b""


def _context(el: ET.Element) -> ApplicationContext:
    value = _value(el)
    for context, name in _CONTEXT_NAMES.items():
        if name == value:
            return context
    raise DecodeError(f"unknown application context {value!r}")


def _mechanism(el: ET.Element) -> int | None:
    found = el.find("MechanismName")
    if found is None:
        return None
    value = _value(found)
    if value in _MECHANISMS:
        return _MECHANISMS.index(value)
    try:
        return int(value, 16)
    except ValueError:
        raise DecodeError(f"unknown mechanism {value!r}") from None


def _optional_octets(el: ET.Element, tag: str) -> bytes | None:
    found = el.find(tag)
    return None if found is None else _octets(found)


def _read_acse(root: ET.Element):
    if root.tag in ("ReleaseRequest", "ReleaseResponse"):
        reasons = _RLRQ_REASONS if root.tag == "ReleaseRequest" else _RLRE_REASONS
        reason = root.find("Reason")
        info = root.find("UserInformation")
        cls = RLRQ if root.tag == "ReleaseRequest" else RLRE
        return cls(
            None if reason is None else _named(reasons, reason),
            b"" if info is None else gurux_element_to_apdu(_only(info)),
        )
    context = _context(_need(root, "ApplicationContextName"))
    if root.tag == "AssociationRequest":
        return AARQ(
            context,
            _user_information(root),
            mechanism=_mechanism(root),
            calling_authentication_value=_optional_octets(root, "CallingAuthentication"),
            calling_ap_title=_optional_octets(root, "CallingAPTitle"),
            calling_ae_qualifier=_optional_octets(root, "CallingAEQualifier"),
        )
    diag = _only(_need(root, "ResultSourceDiagnostic"))
    if diag.tag not in ("ACSEServiceUser", "ACSEServiceProvider"):
        raise DecodeError(f"<{diag.tag}> is not a result-source-diagnostic")
    return AARE(
        context,
        _int(_need(root, "AssociationResult")),
        1 if diag.tag == "ACSEServiceUser" else 2,
        _int(diag),
        responding_ap_title=_optional_octets(root, "RespondingAPTitle"),
        responding_ae_qualifier=_optional_octets(root, "RespondingAEQualifier"),
        mechanism=_mechanism(root),
        responding_authentication_value=_optional_octets(root, "RespondingAuthentication"),
        user_information=_user_information(root),
    )


def _variable_item(el: ET.Element):
    if el.tag == "VariableName":
        return sn.VariableName(_int(el))
    if el.tag == "BlockNumberAccess":
        return sn.BlockNumberAccess(_int(_need(el, "BlockNumber")))
    if el.tag == "ReadDataBlockAccess":
        return sn.ReadDataBlockAccess(*_read_block(el))
    if el.tag == "WriteDataBlockAccess":
        last = _int(_need(el, "LastBlock"))
        if last not in (0, 1):
            raise DecodeError(f"LastBlock must be 00 or 01, got {last:02X}")
        return sn.WriteDataBlockAccess(bool(last), _int(_need(el, "BlockNumber")))
    if el.tag == "ParameterisedAccess":
        return sn.ParameterizedAccess(
            _int(_need(el, "VariableName")),
            _int(_need(el, "Selector")),
            _one_data(_need(el, "Parameter")),
        )
    raise DecodeError(f"<{el.tag}> is not a variable-access-specification")


def _read_short_name(root: ET.Element):
    if root.tag == "ReadRequest":
        return sn.ReadRequest([_variable_item(child) for child in _children(root)])
    if root.tag == "ReadResponse":
        results = []
        for child in _children(root):
            if child.tag == "Data":
                results.append(sn.ReadResult(data=_one_data(child)))
            elif child.tag == "DataAccessError":
                results.append(sn.ReadResult(error=_read_result(_named(_RESULT_NAMES, child))))
            elif child.tag == "DataBlockResult":
                last, number, raw = _read_block(child)
                results.append(sn.ReadResult(block_last=last, block_number=number, raw_data=raw))
            else:
                raise DecodeError(f"<{child.tag}> is not a read-result")
        return sn.ReadResponse(results)
    if root.tag in ("WriteRequest", "UnconfirmedWriteRequest"):
        items = [
            _variable_item(c) for c in _children(_need(root, "ListOfVariableAccessSpecification"))
        ]
        values = [element_data(c) for c in _children(_need(root, "ListOfData"))]
        cls = sn.WriteRequest if root.tag == "WriteRequest" else sn.UnconfirmedWriteRequest
        return cls(items, values)
    if root.tag == "WriteResponse":
        return sn.WriteResponse(
            [
                DataAccessResult.SUCCESS
                if c.tag == "Ok"
                else _read_result(_named(_RESULT_NAMES, c))
                for c in _children(root)
            ]
        )
    if root.tag == "InformationReportRequest":
        names = [_int(c) for c in _children(_need(root, "ListOfVariableAccessSpecification"))]
        values = [element_data(c) for c in _children(_need(root, "ListOfData"))]
        ct = root.find("CurrentTime")
        return sn.InformationReportRequest(
            None if ct is None else _octets(ct),
            names,
            values,
            current_time_bare=ct is not None and (ct.get("Bare") or "").lower() == "true",
        )
    raise DecodeError(f"<{root.tag}> is not a Gurux APDU element")


def _read_push(root: ET.Element):
    if root.tag == "DataNotification":
        dt = _need(root, "DateTime")
        date_time = _octets(dt) or None
        return xdlms.DataNotification(
            _int(_need(root, "LongInvokeIdAndPriority")),
            _one_data(_need(_need(root, "NotificationBody"), "DataValue")),
            date_time,
            date_time_tagged=(dt.get("Tagged") or "").lower() == "true",
        )
    if root.tag == "EventNotificationRequest":
        return xdlms.EventNotificationRequest(
            _attribute_descriptor(_need(root, "AttributeDescriptor")),
            _one_data(_need(root, "AttributeValue")),
            _optional_octets(root, "DateTime"),
        )
    if root.tag == "ExceptionResponse":
        ic = root.find("InvocationCounter")
        return xdlms.ExceptionResponse(
            _named(_STATE_ERRORS, _need(root, "StateError")),
            _named(_SERVICE_ERRORS, _need(root, "ServiceError")),
            None if ic is None else _int(ic),
        )
    if root.tag == "ConfirmedServiceError":
        error = _only(_need(root, "ServiceError"))
        for choice, (name, values) in _CSE.items():
            if name == error.tag:
                value = _value(error)
                index = values.index(value) if value in values else int(value, 16)
                return xdlms.ConfirmedServiceError(_int(_need(root, "Service")), choice, index)
        raise DecodeError(f"<{error.tag}> is not a confirmed-service-error choice")
    return None


def _read_general_signing(root: ET.Element) -> bytes:
    out = bytearray([Tag.GENERAL_SIGNING])
    for name in (*_GENERAL_HEADER, "Content", "Signature"):
        value = _octets(_need(root, name))
        out += encode_length(len(value)) + value
    return bytes(out)


def _read_general_ciphering(root: ET.Element) -> bytes:
    out = bytearray([Tag.GENERAL_CIPHERING])
    for name in _GENERAL_HEADER:
        value = _octets(_need(root, name))
        out += encode_length(len(value)) + value
    info = root.find("KeyInfo")
    if info is None:
        out.append(0)
    else:
        agreed = _need(info, "AgreedKey")
        out += b"\x01\x02"
        for name in ("KeyParameters", "KeyCipheredData"):
            value = _octets(_need(agreed, name))
            out += encode_length(len(value)) + value
    content = _octets(_need(root, "CipheredContent"))
    return bytes(out + encode_length(len(content)) + content)


def is_gurux_element(el: ET.Element) -> bool:
    """Whether ``el`` is a Gurux translator element (not pydlms's own dialect)."""
    if el.tag in _ROOTS:
        return True
    if el.tag not in _SHARED_ROOTS:
        return False
    if "Value" in el.attrib or "Qty" in el.attrib:
        return True
    return any(child.tag[:1].isupper() for child in _children(el))


def gurux_element_to_apdu(el: ET.Element) -> bytes:  # noqa: C901 - dispatch on the root
    """Encode one Gurux APDU element."""
    tag = el.tag
    try:
        if tag == "Raw":
            return _octets(el)
        if tag in _CIPHERED_NAMES:
            content = _octets(el)
            return bytes([_CIPHERED_NAMES[tag]]) + encode_length(len(content)) + content
        if tag in ("GeneralGloCiphering", "GeneralDedCiphering"):
            title = _octets(_need(el, "SystemTitle"))
            content = _octets(_need(el, "CipheredService"))
            code = (
                Tag.GENERAL_GLO_CIPHERING
                if tag == "GeneralGloCiphering"
                else Tag.GENERAL_DED_CIPHERING
            )
            return (
                bytes([code])
                + encode_length(len(title))
                + title
                + encode_length(len(content))
                + content
            )
        if tag == "GeneralCiphering":
            return _read_general_ciphering(el)
        if tag == "GeneralSigning":
            return _read_general_signing(el)
        if tag == "GeneralBlockTransfer":
            control = _int(_need(el, "BlockControl"))
            data = _octets(_need(el, "BlockData"))
            return gbt.encode_gbt(
                gbt.GbtBlock(
                    bool(control & 0x80),
                    bool(control & 0x40),
                    control & 0x3F,
                    _int(_need(el, "BlockNumber")),
                    _int(_need(el, "BlockNumberAck")),
                    data,
                )
            )
        readers = {
            "GetRequest": _read_get_request,
            "GetResponse": _read_get_response,
            "SetRequest": _read_set_request,
            "SetResponse": _read_set_response,
            "ActionRequest": _read_action_request,
            "ActionResponse": _read_action_response,
            "InitiateRequest": _read_initiate_request,
            "InitiateResponse": _read_initiate_response,
            "AssociationRequest": _read_acse,
            "AssociationResponse": _read_acse,
            "ReleaseRequest": _read_acse,
            "ReleaseResponse": _read_acse,
            "AccessRequest": _read_access_service,
            "AccessResponse": _read_access_service,
        }
        if tag in readers:
            return readers[tag](el).to_bytes()
        obj = _read_push(el)
        if obj is None:
            obj = _read_short_name(el)
        return obj.to_bytes()
    except (ValueError, OverflowError, struct.error) as exc:
        if isinstance(exc, DlmsError):
            raise
        raise DecodeError(f"<{tag}> cannot be encoded: {exc}") from exc


# --- text ----------------------------------------------------------------------------

_ESCAPES = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "\n": "&#10;",
    "\r": "&#13;",
    "\t": "&#9;",
}


def _escape(text: str) -> str:
    return "".join(_ESCAPES.get(ch, ch) for ch in text)


def _serialize(el, out: list[str], depth: int) -> None:
    pad = "  " * depth
    if el.tag is ET.Comment:
        out.append(f"{pad}<!--{el.text}-->")
        return
    attrs = "".join(f' {k}="{_escape(v)}"' for k, v in el.attrib.items())
    children = list(el)
    if el.tag == "ArrayContents":
        out.append(f"{pad}<{el.tag}>{_escape_text(el.text or '', pad)}</{el.tag}>")
        return
    elements = [child for child in children if child.tag is not ET.Comment]
    if not elements and el.attrib and el.tag not in ("Array", "Structure"):
        # Comments of a leaf (the deciphered content of a glo- APDU) go first.
        for child in children:
            _serialize(child, out, depth)
        out.append(f"{pad}<{el.tag}{attrs} />")
        return
    if not children:
        if el.tag in _LEAVES:
            out.append(f"{pad}<{el.tag} />")
        else:
            out.append(f"{pad}<{el.tag}{attrs}{' ' if 'Qty' in el.attrib else ''}>")
            out.append(f"{pad}</{el.tag}>")
        return
    out.append(f"{pad}<{el.tag}{attrs}{' ' if 'Qty' in el.attrib else ''}>")
    for child in children:
        if el.tag == "ContentsDescription" and child.tag is not ET.Comment:
            out.append(f"{pad}  <{child.tag}/>")
            continue
        _serialize(child, out, depth + 1)
    out.append(f"{pad}</{el.tag}>")


def _escape_text(text: str, pad: str) -> str:
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    if "\n" not in text:
        return text
    rows = [row for row in text.split("\n") if row]
    return "".join(f"\n{pad}  {row}" for row in rows) + f"\n{pad}"


#: Elements that are complete without a Value (written as ``<Ok />``).
_LEAVES = {"None", "Ok"}


def to_text(el: ET.Element) -> str:
    """Gurux-style text: two-space indent, ``<X Value="..." />``."""
    out: list[str] = []
    _serialize(el, out, 0)
    return "\n".join(out) + "\n"


_BAD_DATA = re.compile(r'<Data="([0-9A-Fa-f ]*)"\s*/>')
_VALUE_ATTR = re.compile(r'(Value=")([^"]*)(")')
_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
_ENTITY = re.compile(r"&(#[0-9]+|#x[0-9A-Fa-f]+|amp|lt|gt|quot|apos);")


def _repair(text: str) -> str:
    """Make Gurux output well-formed: it writes ``<Data="...">`` for APDUs it
    cannot translate and does not escape ``&``/``<`` inside Value attributes."""
    text = _BAD_DATA.sub(lambda m: f'<Raw Value="{m.group(1).replace(" ", "")}" />', text)
    text = _COMMENT.sub(lambda m: "<!--" + m.group(1).replace("--", "- -") + "-->", text)

    def fix(match: re.Match) -> str:
        value = match.group(2)
        parts = []
        pos = 0
        for entity in _ENTITY.finditer(value):
            parts.append(value[pos : entity.start()].replace("&", "&amp;").replace("<", "&lt;"))
            parts.append(entity.group(0))
            pos = entity.end()
        parts.append(value[pos:].replace("&", "&amp;").replace("<", "&lt;"))
        return match.group(1) + "".join(parts) + match.group(3)

    return _VALUE_ATTR.sub(fix, text)


def from_text(text: str) -> ET.Element:
    try:
        # Same parser and limits as pydlms.apduxml._from_text.
        return ET.fromstring(text)  # nosec B314
    except ET.ParseError:
        pass
    try:
        return ET.fromstring(_repair(text))  # nosec B314
    except ET.ParseError as exc:
        raise DecodeError(f"not well-formed XML: {exc}") from exc


def apdu_to_gurux_xml(
    apdu: bytes,
    encryption_key: bytes | None = None,
    authentication_key: bytes | None = None,
    system_title: bytes | None = None,
    secrets: bool = False,
) -> str:
    """One APDU in the Gurux translator dialect."""
    writer = GuruxXmlWriter(encryption_key, authentication_key, system_title, secrets)
    return to_text(writer.apdu(apdu))


def gurux_xml_to_apdu(text: str) -> bytes:
    """The APDU of one Gurux translator element (from pydlms or from Gurux)."""
    return gurux_element_to_apdu(from_text(text))
