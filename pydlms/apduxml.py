"""APDUs as XML and back (``pydlms decode --xml``, ``pydlms encode``).

Every APDU pydlms decodes (xDLMS LN services, Short-Name services, ACSE,
general-block-transfer, pushes, exception and error APDUs) becomes one XML
element named after its pydlms class, with one child per field::

    <GetRequestNormal>
      <invoke-id value="0xC1" />
      <attribute>
        <class-id value="3" />
        <instance-id value="1.0.1.8.0.255">
          <!-- Active energy import (+A) total -->
        </instance-id>
        <attribute-id value="2" />
      </attribute>
    </GetRequestNormal>

COSEM ``Data`` values use the A-XDR CHOICE names (``structure``,
``double-long-unsigned``, ``octet-string`` ...). Comments carry decoded
hints (OBIS names, date-times, conformance bits) and are ignored when reading.

**The format is pydlms's own.** Element names follow the pydlms dataclasses,
which mirror the Green Book ASN.1 component names closely but not exactly; it
is neither the DLMS UA XML schema nor the Gurux translator dialect, and
neither tool will read it. What it guarantees is a lossless round trip:
:func:`xml_to_apdu` (``pydlms encode``) rebuilds the identical bytes from an
unedited element, and an edited element encodes what the fields say. An APDU
whose decoded form would not re-encode to the same bytes (an unknown tag, a
lenient decode of a vendor quirk) is written as ``<Raw value="...">`` with the
decoded form inside ``<decoded>`` for reading only.

Ciphered APDUs are ``<Ciphered value="...">``: the envelope bytes are what
encode back; the security header and, when keys are given, the deciphered
``<plaintext>`` are informational. Editing the plaintext does not re-cipher.

Authentication material is redacted unless ``secrets=True``: the AARQ/AARE
authentication values (LLS password, CtoS, StoC) and the HLS pass 3/4
f(StoC)/f(CtoS). A redacted element cannot be encoded back.

``dialect="gurux"`` writes the Gurux translator dialect instead
(:mod:`pydlms.gurux_xml`); the readers accept both dialects, and a file of
several Gurux elements one after another reads as a session.
"""

from __future__ import annotations

import dataclasses
import enum
import functools
import re
import types
import typing
import xml.etree.ElementTree as ET  # nosec B405
from collections.abc import Iterable

from pydlms.apdu.tags import PLAIN_FOR_CIPHERED, Tag, tag_name
from pydlms.catalog import obis_name
from pydlms.cosem.data import DlmsData, decode_data, encode_data
from pydlms.cosem.enums import DataType
from pydlms.cosem.time import CosemDateTime
from pydlms.exceptions import DecodeError, DlmsError
from pydlms.obis import ObisCode

__all__ = [
    "XmlWriter",
    "apdu_to_xml",
    "xml_to_apdu",
    "session_to_xml",
    "xml_to_session",
]

SESSION = "pydlms-session"
#: Integer fields written in hex (the way DLMS traces show them).
_HEX_FIELDS = {"invoke_id", "long_invoke_id"}
#: LLS password / CtoS / StoC, and the dedicated key an InitiateRequest carries.
_SECRET_FIELDS = {
    "calling_authentication_value",
    "responding_authentication_value",
    "dedicated_key",
}
_HLS_METHOD = (15, ObisCode(0, 0, 40, 0, 0, 255), 1)


def _kebab(name: str) -> str:
    out = []
    for i, ch in enumerate(name):
        if ch.isupper() and i and (name[i - 1].islower() or name[i - 1].isdigit()):
            out.append("-")
        out.append(ch.lower())
    return "".join(out).replace("_", "-")


@functools.cache
def _classes() -> dict[str, type]:
    """APDU and component dataclasses by class name."""
    from pydlms.apdu import acse, gbt, sn, xdlms

    found: dict[str, type] = {}
    for module in (xdlms, sn, acse, gbt):
        for name in dir(module):
            obj = getattr(module, name)
            if (
                isinstance(obj, type)
                and dataclasses.is_dataclass(obj)
                and obj.__module__ == module.__name__
            ):
                found[name] = obj
    return found


@functools.cache
def _by_element() -> dict[str, type]:
    return {_kebab(name): cls for name, cls in _classes().items()}


@functools.cache
def _hints(cls: type) -> dict[str, typing.Any]:
    return typing.get_type_hints(cls)


def _strip_optional(hint) -> tuple[typing.Any, ...]:
    """The non-None members of a union, or ``(hint,)``."""
    if typing.get_origin(hint) in (typing.Union, types.UnionType):
        return tuple(a for a in typing.get_args(hint) if a is not type(None))
    return (hint,)


def _name_for(hint) -> str:
    """Element name of a list item / tuple position of type ``hint``."""
    (hint, *_) = _strip_optional(hint)
    if hint is DlmsData:
        return "data"
    if isinstance(hint, type):
        return _kebab(hint.__name__)
    return "item"


def _encode_object(obj) -> bytes:
    from pydlms.apdu.gbt import GbtBlock, encode_gbt

    if isinstance(obj, GbtBlock):
        return encode_gbt(obj)
    return obj.to_bytes()


def _decode_plain(apdu: bytes):
    tag = apdu[0]
    if tag in (Tag.AARQ, Tag.AARE, Tag.RLRQ, Tag.RLRE):
        from pydlms.apdu.acse import decode_acse

        return decode_acse(apdu)
    if tag in (
        Tag.READ_REQUEST,
        Tag.READ_RESPONSE,
        Tag.WRITE_REQUEST,
        Tag.WRITE_RESPONSE,
        Tag.UNCONFIRMED_WRITE_REQUEST,
        Tag.INFORMATION_REPORT_REQUEST,
    ):
        from pydlms.apdu.sn import decode_sn_apdu

        return decode_sn_apdu(apdu)
    if tag == Tag.GENERAL_BLOCK_TRANSFER:
        from pydlms.apdu.gbt import decode_gbt

        return decode_gbt(apdu)
    from pydlms.apdu.xdlms import decode_apdu

    return decode_apdu(apdu)


# --- COSEM Data -----------------------------------------------------------------------

_OCTETS = {DataType.OCTET_STRING, DataType.DATE_TIME, DataType.DATE, DataType.TIME}
_STRINGS = {DataType.VISIBLE_STRING: "latin-1", DataType.UTF8_STRING: "utf-8"}


def _xml_safe(text: str) -> bool:
    """Printable in an attribute without escapes (control characters go to hex)."""
    return all(0x20 <= ord(ch) <= 0xD7FF or 0xE000 <= ord(ch) <= 0xFFFD for ch in text)


def _comment(text: str) -> ET.Element:
    """An XML comment; ``--`` is not allowed inside one."""
    while "--" in text:
        text = text.replace("--", "- -")
    return ET.Comment(f" {text.strip()} ")


def _octets_comment(tag: DataType, raw: bytes) -> str | None:
    if tag == DataType.OCTET_STRING and len(raw) == 6:
        obis = ObisCode.from_bytes(raw)
        name = obis_name(obis)
        return f"OBIS {obis}" + (f" ({name})" if name else "")
    if len(raw) == 12 and tag in (DataType.OCTET_STRING, DataType.DATE_TIME):
        try:
            return str(CosemDateTime.from_bytes(raw))
        except (DlmsError, ValueError):
            return None
    if tag == DataType.OCTET_STRING and raw and all(0x20 <= b < 0x7F for b in raw):
        return repr(raw.decode("ascii"))
    return None


def data_element(item: DlmsData) -> ET.Element:
    """One COSEM Data value as an element named after its A-XDR choice."""
    tag = item.tag
    el = ET.Element(tag.name.lower().replace("_", "-"))
    if tag in (DataType.ARRAY, DataType.STRUCTURE):
        for child in item.value:
            el.append(data_element(child))
    elif tag in (DataType.NULL, DataType.DONT_CARE):
        pass
    elif tag == DataType.COMPACT_ARRAY:
        el.set("raw", encode_data(item).hex())
        el.append(_comment(f"{len(item.value.items)} entries; edit as raw A-XDR "))
    elif tag == DataType.BOOLEAN:
        el.set("value", "true" if item.value else "false")
    elif tag == DataType.BIT_STRING:
        el.set("value", "".join("1" if bit else "0" for bit in item.value))
    elif tag in (DataType.FLOAT32, DataType.FLOAT64):
        el.set("value", repr(float(item.value)))
    elif tag in _OCTETS:
        raw = bytes(item.value)
        el.set("value", raw.hex())
        comment = _octets_comment(tag, raw)
        if comment:
            el.append(_comment(comment))
    elif tag in _STRINGS:
        if _xml_safe(item.value):
            el.set("value", item.value)
        else:
            el.set("hex", item.value.encode(_STRINGS[tag]).hex())
    else:
        el.set("value", str(int(item.value)))
    return el


def _attr(el: ET.Element, name: str = "value") -> str:
    value = el.get(name)
    if value is None:
        raise DecodeError(f"<{el.tag}> lacks its {name!r} attribute")
    return value


def element_data(el: ET.Element) -> DlmsData:
    """Inverse of :func:`data_element`."""
    try:
        tag = DataType[el.tag.upper().replace("-", "_")]
    except KeyError:
        raise DecodeError(f"<{el.tag}> is not a COSEM data type") from None
    if tag in (DataType.ARRAY, DataType.STRUCTURE):
        return DlmsData(tag, [element_data(child) for child in el])
    if tag in (DataType.NULL, DataType.DONT_CARE):
        return DlmsData(tag, None)
    if tag == DataType.COMPACT_ARRAY:
        value, _ = decode_data(bytes.fromhex(_attr(el, "raw")))
        return value
    if tag == DataType.BOOLEAN:
        return DlmsData(tag, _attr(el) == "true")
    if tag == DataType.BIT_STRING:
        return DlmsData(tag, [ch == "1" for ch in _attr(el)])
    if tag in (DataType.FLOAT32, DataType.FLOAT64):
        return DlmsData(tag, float(_attr(el)))
    if tag in _OCTETS:
        return DlmsData(tag, bytes.fromhex(_attr(el)))
    if tag in _STRINGS:
        if el.get("hex") is not None:
            return DlmsData(tag, bytes.fromhex(el.get("hex")).decode(_STRINGS[tag]))
        return DlmsData(tag, _attr(el))
    return DlmsData(tag, int(_attr(el), 0))


# --- writing ----------------------------------------------------------------------------


class XmlWriter:
    """Turn APDUs into XML elements, deciphering when keys are given.

    One writer per session: it learns the client and server system titles
    from the AARQ and AARE it sees, so glo-/ded- APDUs of both directions can
    be deciphered, and it keeps the inbound invocation-counter check per
    sender like the client does.
    """

    def __init__(
        self,
        encryption_key: bytes | None = None,
        authentication_key: bytes | None = None,
        system_title: bytes | None = None,
        secrets: bool = False,
    ) -> None:
        self.secrets = secrets
        self.security = None
        self.titles: dict[str | None, bytes | None] = {
            "TX": None,
            "RX": system_title,
            None: system_title,
        }
        self._hls_invoke: int | None = None
        if encryption_key:
            from pydlms.security.context import SecurityContext

            self.security = SecurityContext(
                encryption_key,
                authentication_key,
                server_system_title=system_title,
                allow_unverified_auth=authentication_key is None,
            )

    # -- APDUs ------------------------------------------------------------------------
    def apdu(self, apdu: bytes, direction: str | None = None) -> ET.Element:
        if not apdu:
            raise DecodeError("empty APDU")
        from pydlms.security.ciphering import is_ciphered_apdu

        if is_ciphered_apdu(apdu):
            return self._ciphered(apdu, direction)
        try:
            obj = _decode_plain(apdu)
            exact = _encode_object(obj) == apdu
        except (DlmsError, ValueError, NotImplementedError) as exc:
            raw = ET.Element("Raw", value=apdu.hex())
            raw.append(_comment(f"{tag_name(apdu[0])}: not decoded: {exc} "))
            return raw
        self._learn_titles(obj)
        el = self._object(obj, direction, root=True)
        if exact:
            return el
        raw = ET.Element("Raw", value=apdu.hex())
        raw.append(_comment("the decoded form re-encodes differently; these bytes are used "))
        ET.SubElement(raw, "decoded").append(el)
        return raw

    def _learn_titles(self, obj) -> None:
        from pydlms.apdu.acse import AARE, AARQ

        if isinstance(obj, AARQ) and obj.calling_ap_title:
            self.titles["TX"] = obj.calling_ap_title
        elif isinstance(obj, AARE) and obj.responding_ap_title:
            self.titles["RX"] = self.titles[None] = obj.responding_ap_title

    def _ciphered(self, apdu: bytes, direction: str | None) -> ET.Element:
        from pydlms.axdr import decode_length

        el = ET.Element("Ciphered", value=apdu.hex(), tag=tag_name(apdu[0]))
        try:
            content = None
            if apdu[0] in PLAIN_FOR_CIPHERED:
                length, pos = decode_length(apdu, 1)
                content = apdu[pos : pos + length]
            elif apdu[0] in (Tag.GENERAL_GLO_CIPHERING, Tag.GENERAL_DED_CIPHERING):
                length, pos = decode_length(apdu, 1)
                ET.SubElement(el, "system-title", value=apdu[pos : pos + length].hex())
                length, pos = decode_length(apdu, pos + length)
                content = apdu[pos : pos + length]
            if content is not None and len(content) >= 5:
                ET.SubElement(el, "security-control", value=f"0x{content[0]:02X}")
                ET.SubElement(
                    el, "invocation-counter", value=str(int.from_bytes(content[1:5], "big"))
                )
        except (DlmsError, ValueError, IndexError) as exc:
            el.append(_comment(f"malformed security header: {exc} "))
        if self.security is None:
            el.append(_comment("no key given: not deciphered "))
            return el
        from pydlms.security.ciphering import unwrap

        sender = self.titles.get(direction)
        try:
            if sender is not None:
                self.security.server_system_title = sender
            result = unwrap(self.security, apdu, strict=False)
        except (DlmsError, ValueError) as exc:
            el.append(_comment(f"not deciphered: {type(exc).__name__}: {exc} "))
            return el
        el.append(
            _comment(
                f"{result.security_control.describe()}, IC {result.invocation_counter}, "
                f"from {result.system_title.hex()}, "
                f"{'tag verified' if result.authenticated else 'tag not verified'}"
            )
        )
        ET.SubElement(el, "plaintext").append(self.apdu(result.plaintext, direction))
        return el

    # -- dataclass objects ---------------------------------------------------------------
    def _object(self, obj, direction, root=False, typed=False) -> ET.Element:
        cls = type(obj)
        el = ET.Element(cls.__name__ if root else _kebab(cls.__name__))
        if typed:
            el.set("type", cls.__name__)
        hints = _hints(cls)
        redact = self._hls_redaction(obj)
        for f in dataclasses.fields(obj):
            value = getattr(obj, f.name)
            if value is None:
                continue
            child = ET.SubElement(el, _kebab(f.name))
            if (f.name in _SECRET_FIELDS or f.name in redact) and not self.secrets:
                child.set("redacted", "secret; write with secrets=True to show it")
                continue
            self._fill(child, value, hints[f.name], f.name, direction)
        return el

    def _hls_redaction(self, obj) -> set[str]:
        """Fields holding HLS pass 3/4 material: f(StoC) and f(CtoS)."""
        from pydlms.apdu.xdlms import ActionRequestNormal, ActionResponseNormal

        if isinstance(obj, ActionRequestNormal):
            m = obj.method
            if (m.class_id, m.instance_id, m.method_id) == _HLS_METHOD:
                self._hls_invoke = obj.invoke_id
                return {"parameters"}
        if isinstance(obj, ActionResponseNormal) and obj.invoke_id == self._hls_invoke:
            self._hls_invoke = None
            return {"return_data"}
        return set()

    def _fill(self, el: ET.Element, value, hint, name: str, direction) -> None:
        options = _strip_optional(hint)
        if isinstance(value, DlmsData):
            el.append(data_element(value))
        elif dataclasses.is_dataclass(value) and not isinstance(value, ObisCode):
            typed = len(options) > 1 or not isinstance(options[0], type)
            inner = self._object(value, direction, typed=typed)
            el.extend(list(inner))
            if typed:
                el.set("type", type(value).__name__)
        elif isinstance(value, (list, tuple)):
            self._sequence(el, value, options[0], direction)
        else:
            el.set("value", _scalar_text(value, name))
            if isinstance(value, enum.IntFlag):
                names = [m.name for m in type(value) if m.name and m in value]
                el.append(_comment(", ".join(names)))
            elif isinstance(value, ObisCode):
                label = obis_name(value)
                if label:
                    el.append(_comment(f"{label} "))
            elif name == "user_information" and value:
                ET.SubElement(el, "decoded").append(self.apdu(value, direction))

    def _sequence(self, el: ET.Element, values, hint, direction) -> None:
        args = typing.get_args(hint)
        if typing.get_origin(hint) is tuple:
            for value, position in zip(values, args, strict=True):
                if value is not None:
                    child = ET.SubElement(el, _name_for(position))
                    self._fill(child, value, position, "", direction)
            return
        item_hint = args[0] if args else None
        # A list of several dataclasses (the ACCESS specifications): each
        # element is named by its own class and carries it in ``type``.
        mixed = item_hint is not None and len(_strip_optional(item_hint)) > 1
        mixed = mixed and all(dataclasses.is_dataclass(o) for o in _strip_optional(item_hint))
        for value in values:
            if mixed:
                child = ET.SubElement(el, _kebab(type(value).__name__))
                self._fill(child, value, item_hint, "", direction)
            elif item_hint is None:  # untyped list: name the element by its class
                child = ET.SubElement(el, _kebab(type(value).__name__))
                self._fill(child, value, type(value), "", direction)
            else:
                child = ET.SubElement(el, _name_for(item_hint))
                self._fill(child, value, item_hint, "", direction)


def _scalar_text(value, name: str) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, enum.IntFlag):
        return f"0x{int(value):06X}"
    if isinstance(value, enum.IntEnum):
        return value.name if value.name else str(int(value))
    if isinstance(value, int):
        return f"0x{value:02X}" if name in _HEX_FIELDS else str(value)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, ObisCode):
        return str(value)
    raise DecodeError(f"cannot write {type(value).__name__} {name!r} as XML")


# --- reading ----------------------------------------------------------------------------


def _parse_scalar(text: str, hint, name: str):
    if hint is bool:
        if text not in ("true", "false"):
            raise DecodeError(f"{name}: {text!r} is not true/false")
        return text == "true"
    if isinstance(hint, type) and issubclass(hint, enum.IntFlag):
        return hint(int(text, 0))
    if isinstance(hint, type) and issubclass(hint, enum.IntEnum):
        if text in hint.__members__:
            return hint[text]
        return hint(int(text, 0))
    if hint is int:
        return int(text, 0)
    if hint is bytes:
        return bytes.fromhex(text)
    if hint is ObisCode:
        return ObisCode.parse(text)
    raise DecodeError(f"{name}: cannot read a {hint!r} from XML")


def _read(el: ET.Element, hint, name: str):
    if el.get("redacted") is not None:
        raise DecodeError(f"<{el.tag}> was redacted; write the XML with secrets=True to encode it")
    options = _strip_optional(hint)
    if el.get("type") is not None:
        cls = _classes().get(el.get("type"))
        if cls is None:
            raise DecodeError(f"<{el.tag}>: unknown type {el.get('type')!r}")
        return _read_object(el, cls)
    hint = options[0]
    if hint is DlmsData:
        children = list(el)
        if len(children) != 1:
            raise DecodeError(f"<{el.tag}> must hold exactly one data value")
        return element_data(children[0])
    if isinstance(hint, type) and dataclasses.is_dataclass(hint) and hint is not ObisCode:
        return _read_object(el, hint)
    origin = typing.get_origin(hint)
    if origin is tuple:
        positions = typing.get_args(hint)
        values = []
        for position in positions:
            child = el.find(_name_for(position))
            values.append(None if child is None else _read(child, position, child.tag))
        return tuple(values)
    if origin is list or hint is list:
        args = typing.get_args(hint)
        if not args:  # untyped list: each element names its class
            out = []
            for child in el:
                cls = _by_element().get(child.tag)
                if cls is None:
                    raise DecodeError(f"<{child.tag}> is not a known element")
                out.append(_read_object(child, cls))
            return out
        return [_read(child, args[0], child.tag) for child in el]
    text = _attr(el)
    if (
        int in options
        and isinstance(hint, type)
        and issubclass(hint, enum.IntEnum)
        and text not in hint.__members__
    ):
        # ``Enum | int``: a code the enum does not define stays a bare int.
        value = int(text, 0)
        return hint(value) if value in hint._value2member_map_ else value
    return _parse_scalar(text, hint, name)


def _read_object(el: ET.Element, cls: type):
    hints = _hints(cls)
    kwargs = {}
    for f in dataclasses.fields(cls):
        child = el.find(_kebab(f.name))
        if child is not None:
            kwargs[f.name] = _read(child, hints[f.name], f.name)
        elif f.default is dataclasses.MISSING and f.default_factory is dataclasses.MISSING:
            if type(None) not in typing.get_args(hints[f.name]):
                raise DecodeError(f"<{el.tag}> lacks <{_kebab(f.name)}>")
            kwargs[f.name] = None
    try:
        return cls(**kwargs)
    except (TypeError, ValueError) as exc:
        raise DecodeError(f"<{el.tag}>: {exc}") from exc


def element_to_apdu(el: ET.Element) -> bytes:
    """Encode one APDU element (inverse of :meth:`XmlWriter.apdu`), either dialect."""
    from pydlms.gurux_xml import gurux_element_to_apdu, is_gurux_element

    if is_gurux_element(el):
        return gurux_element_to_apdu(el)
    if el.tag in ("Raw", "Ciphered"):
        return bytes.fromhex(_attr(el))
    cls = _classes().get(el.tag)
    if cls is None or not (hasattr(cls, "to_bytes") or el.tag == "GbtBlock"):
        raise DecodeError(f"<{el.tag}> is not an APDU element")
    try:
        return _encode_object(_read_object(el, cls))
    except (ValueError, OverflowError) as exc:
        raise DecodeError(f"<{el.tag}> cannot be encoded: {exc}") from exc


# --- public API ---------------------------------------------------------------------


def _to_text(el: ET.Element) -> str:
    ET.indent(el)
    return ET.tostring(el, encoding="unicode") + "\n"


def _from_text(text: str) -> ET.Element:
    # The standard parser does not fetch external entities or DTDs; expat
    # (>= 2.4.1, bundled with every supported Python) limits entity expansion.
    try:
        return ET.fromstring(text)  # nosec B314
    except ET.ParseError:
        from pydlms.gurux_xml import from_text

        return from_text(text)  # Gurux output that needs repairing first


DIALECTS = ("pydlms", "gurux")


def _writer(dialect: str, *args, **kwargs):
    if dialect == "gurux":
        from pydlms.gurux_xml import GuruxXmlWriter

        return GuruxXmlWriter(*args, **kwargs)
    if dialect != "pydlms":
        raise ValueError(f"unknown XML dialect {dialect!r}; use one of {DIALECTS}")
    return XmlWriter(*args, **kwargs)


def apdu_to_xml(
    apdu: bytes,
    encryption_key: bytes | None = None,
    authentication_key: bytes | None = None,
    system_title: bytes | None = None,
    secrets: bool = False,
    dialect: str = "pydlms",
) -> str:
    """One APDU as XML text."""
    writer = _writer(dialect, encryption_key, authentication_key, system_title, secrets)
    if dialect == "gurux":
        from pydlms.gurux_xml import to_text

        return to_text(writer.apdu(apdu))
    return _to_text(writer.apdu(apdu))


def xml_to_apdu(text: str) -> bytes:
    """The APDU of an XML element written by :func:`apdu_to_xml`."""
    return element_to_apdu(_from_text(text))


def session_to_xml(
    records: Iterable[tuple[str | None, bytes]],
    encryption_key: bytes | None = None,
    authentication_key: bytes | None = None,
    system_title: bytes | None = None,
    secrets: bool = False,
    dialect: str = "pydlms",
) -> str:
    """``(direction, apdu)`` records (see :func:`pydlms.recording.session_apdus`)
    as one ``<pydlms-session>`` document."""
    writer = _writer(dialect, encryption_key, authentication_key, system_title, secrets)
    if dialect == "gurux":
        from pydlms.gurux_xml import to_text

        out = [f'<{SESSION} version="1" dialect="gurux">\n']
        for direction, apdu in records:
            attr = f' direction="{direction}"' if direction else ""
            body = to_text(writer.apdu(apdu, direction))
            out.append(f"  <apdu{attr}>\n")
            out.extend(f"    {line}\n" if line else "\n" for line in body.splitlines())
            out.append("  </apdu>\n")
        out.append(f"</{SESSION}>\n")
        return "".join(out)
    root = ET.Element(SESSION, version="1")
    for direction, apdu in records:
        wrapper = ET.SubElement(root, "apdu")
        if direction:
            wrapper.set("direction", direction)
        wrapper.append(writer.apdu(apdu, direction))
    return _to_text(root)


_LIST = "pydlms-xml-list"


def xml_to_session(text: str) -> list[tuple[str | None, bytes]]:
    """Inverse of :func:`session_to_xml`; a bare APDU element gives one record,
    and several elements one after another (concatenated Gurux translator
    output) give one record each."""
    try:
        root = _from_text(text)
    except DecodeError:
        body = re.sub(r"^\s*<\?xml[^>]*\?>", "", text)
        root = _from_text(f"<{_LIST}>{body}</{_LIST}>")
        elements = [child for child in root if isinstance(child.tag, str)]
        return [(None, element_to_apdu(child)) for child in elements]
    if root.tag != SESSION:
        return [(None, element_to_apdu(root))]
    out = []
    for wrapper in root:
        children = list(wrapper)
        if wrapper.tag != "apdu" or len(children) != 1:
            raise DecodeError("each <apdu> of a session holds exactly one APDU element")
        out.append((wrapper.get("direction"), element_to_apdu(children[0])))
    return out
