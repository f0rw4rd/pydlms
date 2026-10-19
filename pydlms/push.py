"""Push decoding (DataNotification, EventNotification, SN InformationReport):
from wire bytes to labelled OBIS values.

Meters push in several payload shapes; :func:`extract_records` recognises
all the ones seen in the field and turns them into :class:`PushRecord` s:

* **structure per object**: ``{obis, value [, scaler_unit]}`` items, nested in
  a structure or array (Iskra AM550, Norway HAN/Aidon, Kaifa, Salzburg).
* **flat**: ``obis, value [, scaler_unit], obis, value, ...`` directly in the
  body, possibly with leading/trailing values that carry no OBIS (Netz NÖ,
  L+G E450, Kamstrup). Those become records with ``obis=None``.
* **self-descriptive**: element 0 is the push object list (array of capture
  object definitions ``{class_id, obis, attribute, data_index, ...}``) and
  element *i* is the value of definition *i* (L+G E450 Cyprus, Energomera).
* **descriptor pairs** (Sagemcom XT211, EGD): ``{enum, array of
  {raw class(2)+obis(6)+attribute(1), value}}``; the descriptor octets carry
  no type tag, so this is decoded by a dedicated parser.
* **compact** (no OBIS at all, e.g. Wiener Netze or Kaifa MA304H3E HAN): the
  values are mapped onto OBIS codes by a :class:`~pydlms.profiles.Profile`.

:class:`PushDecoder` adds the transport side: it accepts raw HDLC / M-Bus
streams or bare APDUs, reassembles HDLC segmentation and general-block-
transfer, deciphers with a :class:`~pydlms.security.context.SecurityContext`
and returns :class:`PushMessage` objects.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from pydlms.apdu.gbt import GbtReassembler, decode_gbt
from pydlms.apdu.tags import Tag, tag_name
from pydlms.apdu.xdlms import DataNotification, decode_apdu
from pydlms.axdr import read_length
from pydlms.cosem.data import DlmsData, _BytesReader, _decode
from pydlms.cosem.enums import DataType, Unit
from pydlms.cosem.scaler import apply_scaler
from pydlms.cosem.time import CosemDateTime
from pydlms.debug import TRACE, get_logger, hexdump
from pydlms.exceptions import DecodeError, DlmsError
from pydlms.obis import ObisCode

__all__ = [
    "PushRecord",
    "PushMessage",
    "PushDecoder",
    "extract_records",
    "parse_capture_objects",
    "decode_notification",
    "decode_body_lenient",
]

log = get_logger("push")

CLOCK = ObisCode(0, 0, 1, 0, 0, 255)


@dataclass
class PushRecord:
    """One value from a push, with whatever labelling the payload carried."""

    obis: ObisCode | None
    data: DlmsData
    scaler: int = 0
    unit: Unit | int | None = None
    class_id: int | None = None
    attribute: int | None = None
    #: Short name (base name + attribute offset) of an SN InformationReport.
    short_name: int | None = None

    @property
    def raw(self) -> Any:
        return self.data.to_python()

    @property
    def is_numeric(self) -> bool:
        return (
            isinstance(self.raw, (int, float))
            and not isinstance(self.raw, bool)
            or (self.data.tag == DataType.BOOLEAN)
        )

    @property
    def value(self) -> Any:
        """Scaled number, :class:`CosemDateTime`, text, or the raw value."""
        raw = self.raw
        if self.data.tag == DataType.BOOLEAN:
            return int(raw)
        if isinstance(raw, (int, float)):
            return apply_scaler(raw, self.scaler)
        dt = self.datetime
        if dt is not None:
            return dt
        if isinstance(raw, (bytes, bytearray)):
            text = _printable(bytes(raw))
            return text if text is not None else bytes(raw)
        return raw

    @property
    def datetime(self) -> CosemDateTime | None:
        if self.data.tag == DataType.DATE_TIME:
            return CosemDateTime.from_bytes(bytes(self.data.value))
        if self.data.tag == DataType.OCTET_STRING and _looks_like_datetime(bytes(self.data.value)):
            o = self.obis
            # Clock objects (x.x.1.0.e.255 in group A=0) or an unlabelled stamp.
            if o is None or self.class_id == 8 or (o.a == 0 and o.c == 1 and o.d == 0):
                return CosemDateTime.from_bytes(bytes(self.data.value))
        return None

    @property
    def text(self) -> str | None:
        raw = self.raw
        if isinstance(raw, str):
            return raw.rstrip("\x00")  # fixed-width fields are NUL padded
        if isinstance(raw, (bytes, bytearray)):
            return _printable(bytes(raw))
        return None

    @property
    def unit_symbol(self) -> str:
        if isinstance(self.unit, Unit):
            return self.unit.symbol
        return ""

    def __str__(self) -> str:
        if self.obis:
            label = str(self.obis)
        elif self.short_name is not None:
            label = f"SN 0x{self.short_name:04X}"
        else:
            label = "-"
        value = self.value
        if isinstance(value, float):
            value = round(value, 6)
        return f"{label:<20} {value} {self.unit_symbol}".rstrip()


@dataclass
class PushMessage:
    #: DataNotification, EventNotificationRequest or (SN) InformationReportRequest.
    notification: Any
    records: list[PushRecord]
    system_title: bytes | None = None
    invocation_counter: int | None = None
    authenticated: bool = False
    complete: bool = True

    def by_obis(self) -> dict[ObisCode, PushRecord]:
        return {r.obis: r for r in self.records if r.obis is not None}

    def get(self, obis: str | ObisCode, default=None):
        key = ObisCode.parse(obis) if isinstance(obis, str) else obis
        record = self.by_obis().get(key)
        return default if record is None else record.value

    @property
    def timestamp(self) -> CosemDateTime | None:
        return getattr(self.notification, "timestamp", None)


def _printable(raw: bytes) -> str | None:
    stripped = raw.rstrip(b"\x00")
    if stripped and all(0x20 <= b < 0x7F for b in stripped):
        return stripped.decode("ascii")
    if not raw:
        return ""
    return None


def _looks_like_datetime(raw: bytes) -> bool:
    if len(raw) != 12:
        return False
    year = int.from_bytes(raw[0:2], "big")
    month, day, hour, minute = raw[2], raw[3], raw[5], raw[6]
    deviation = int.from_bytes(raw[9:11], "big", signed=True)
    return (
        (deviation == -0x8000 or -720 <= deviation <= 720)
        and (year == 0xFFFF or 1970 <= year <= 2200)
        and (month == 0xFF or 1 <= month <= 12 or month in (0xFD, 0xFE))
        and (day == 0xFF or 1 <= day <= 31 or day in (0xFD, 0xFE))
        and (hour == 0xFF or hour < 24)
        and (minute == 0xFF or minute < 60)
    )


def _is_obis(item: DlmsData) -> bool:
    return item.tag == DataType.OCTET_STRING and len(item.value) == 6


def _is_push_setup_name(item: DlmsData) -> bool:
    """A Push setup (IC 40) logical name, 0-b:25.9.e.255 (Blue Book, Push setup).

    IDIS push object lists start with ``{40, 0-0:25.9.0.255, 1}``: the
    first pushed value is the push setup's own logical name, not a label.
    """
    if not _is_obis(item):
        return False
    raw = bytes(item.value)
    return raw[0] == 0 and raw[2] == 25 and raw[3] == 9 and raw[5] == 0xFF


def _count_obis(items: list[DlmsData], depth: int = 0) -> int:
    """OBIS candidates in a body, nested composites included (push setup
    names excluded)."""
    count = 0
    for item in items:
        if _is_obis(item) and not _is_push_setup_name(item):
            count += 1
        elif item.tag in (DataType.STRUCTURE, DataType.ARRAY) and depth < 8:
            count += _count_obis(item.value, depth + 1)
    return count


def _labels(items: list[DlmsData], i: int, total: int) -> bool:
    """Whether ``items[i]`` (a 6-octet string) labels ``items[i + 1]``.

    A 6-octet value is ambiguous (an OBIS code or, say, a meter id). It is
    taken as a label only where a flat ``obis, value[, scaler_unit]``
    pairing is plausible:

    * the next element is not itself an OBIS candidate, or it is one but the
      element after it is again an OBIS candidate or the end of the list
      (``obis, <6-octet value>, obis, ...``);
    * and the body holds another OBIS candidate (``total`` counts them,
      nested ones included), or the list is exactly ``{obis, value[,
      scaler_unit]}``. A lone 6-octet string inside a longer compact payload
      is a value.
    """
    n = len(items)
    if i + 1 >= n:
        return False
    if total <= 1 and not (i == 0 and (n == 2 or (n == 3 and _is_scaler_unit(items[2])))):
        return False
    if not _is_obis(items[i + 1]):
        return True
    return i + 2 >= n or _is_obis(items[i + 2])


def _is_scaler_unit(item: DlmsData) -> bool:
    return (
        item.tag == DataType.STRUCTURE
        and len(item.value) == 2
        and item.value[0].tag == DataType.INTEGER
        and item.value[1].tag == DataType.ENUM
    )


def _unit(value: int) -> Unit | int:
    try:
        return Unit(value)
    except ValueError:
        return value


def _is_capture_definition(item: DlmsData) -> bool:
    v = item.value
    return (
        item.tag == DataType.STRUCTURE
        and len(v) >= 4
        and v[0].tag == DataType.LONG_UNSIGNED
        and _is_obis(v[1])
        and v[2].tag == DataType.INTEGER
    )


def _record(obis_item, value, scaler_unit=None, **kw) -> PushRecord:
    scaler, unit = 0, None
    if scaler_unit is not None:
        scaler = scaler_unit.value[0].value
        unit = _unit(scaler_unit.value[1].value)
    obis = ObisCode.from_bytes(bytes(obis_item.value)) if obis_item is not None else None
    return PushRecord(obis, value, scaler, unit, **kw)


def _walk(
    items: list[DlmsData], out: list[PushRecord], depth: int = 0, total: int | None = None
) -> None:
    if total is None:
        total = _count_obis(items)
    i = 0
    n = len(items)
    while i < n:
        item = items[i]
        if _is_push_setup_name(item):
            out.append(_record(item, item, class_id=40, attribute=1))
            i += 1
            continue
        if _is_obis(item) and _labels(items, i, total):
            value = items[i + 1]
            if value.tag in (DataType.STRUCTURE, DataType.ARRAY) and not _is_scaler_unit(value):
                # {obis, structure}: a labelled composite value
                out.append(_record(item, value))
                i += 2
                continue
            if i + 2 < n and _is_scaler_unit(items[i + 2]):
                out.append(_record(item, value, items[i + 2]))
                i += 3
            else:
                out.append(_record(item, value))
                i += 2
            continue
        if item.tag in (DataType.STRUCTURE, DataType.ARRAY) and depth < 8:
            inner = item.value
            if (
                item.tag == DataType.STRUCTURE
                and 2 <= len(inner) <= 3
                and _is_obis(inner[0])
                and (len(inner) == 2 or _is_scaler_unit(inner[2]))
            ):
                value = inner[1]
                if value.tag in (DataType.STRUCTURE, DataType.ARRAY) and not _is_scaler_unit(value):
                    # e.g. {obis, {obis, value}}: look inside for a nested record
                    nested: list[PushRecord] = []
                    _walk(value.value, nested, depth + 1, total)
                    out.append(_record(inner[0], value))
                    out.extend(nested)
                else:
                    out.append(_record(inner[0], value, inner[2] if len(inner) == 3 else None))
            else:
                _walk(inner, out, depth + 1, total)
            i += 1
            continue
        out.append(PushRecord(None, item))
        i += 1


def parse_capture_objects(objects: Any) -> list[tuple[int, ObisCode, int, int]]:
    """Normalise a push setup ``push_object_list`` (IC 40 attribute 2).

    Accepts the :class:`DlmsData` array read from the meter (each entry a
    structure ``{class_id, logical_name, attribute_index, data_index}``) or a
    list of ``(class_id, obis, attribute[, data_index])`` tuples, where
    ``obis`` is an :class:`ObisCode`, its text form or its 6 octets.
    Returns ``(class_id, ObisCode, attribute, data_index)`` tuples.
    """
    out: list[tuple[int, ObisCode, int, int]] = []
    if isinstance(objects, DlmsData):
        if objects.tag not in (DataType.ARRAY, DataType.STRUCTURE):
            raise DecodeError(f"push_object_list is {objects.tag.name}, not an array")
        for number, entry in enumerate(objects.value, 1):
            v = entry.value if entry.tag == DataType.STRUCTURE else None
            if (
                v is None
                or len(v) < 3
                or not isinstance(v[0].value, int)
                or not _is_obis(v[1])
                or not isinstance(v[2].value, int)
            ):
                raise DecodeError(
                    f"push_object_list entry {number} is not "
                    "{class_id, logical_name, attribute_index, data_index}"
                )
            index = v[3].value if len(v) > 3 and isinstance(v[3].value, int) else 0
            out.append((v[0].value, ObisCode.from_bytes(bytes(v[1].value)), v[2].value, index))
        return out
    for entry in objects:
        cid, obis, attr, *rest = entry
        if isinstance(obis, str):
            obis = ObisCode.parse(obis)
        elif isinstance(obis, (bytes, bytearray)):
            obis = ObisCode.from_bytes(bytes(obis))
        out.append((int(cid), obis, int(attr), int(rest[0]) if rest else 0))
    return out


def parse_capture_objects_text(text: str) -> list[tuple[int, ObisCode, int, int]]:
    """Parse a capture-object list file (the ``pydlms push --capture-objects`` format).

    Two forms, told apart by the first non-blank character:

    * text, one entry per line: ``class_id logical_name attribute [data_index]``
      separated by whitespace or commas, e.g. ``3 1.0.1.8.0.255 2``; blank
      lines and ``#`` comments are ignored;
    * JSON, an array whose entries are ``[class_id, "a.b.c.d.e.f", attribute
      [, data_index]]`` arrays or ``{"class_id", "logical_name",
      "attribute_index" [, "data_index"]}`` objects (the push setup's own
      field names).

    Anything else raises :class:`DecodeError`.
    """
    stripped = text.lstrip()
    entries: list[Any] = []
    try:
        if stripped.startswith(("[", "{")):
            raw = json.loads(stripped)
            if not isinstance(raw, list):
                raise DecodeError("capture object JSON must be an array")
            for number, item in enumerate(raw, 1):
                if isinstance(item, dict):
                    try:
                        item = [
                            item["class_id"],
                            item["logical_name"],
                            item["attribute_index"],
                            item.get("data_index", 0),
                        ]
                    except KeyError as exc:
                        raise DecodeError(f"capture object {number} lacks {exc}") from None
                if not isinstance(item, list) or not 3 <= len(item) <= 4:
                    raise DecodeError(f"capture object {number} is not [class, obis, attribute]")
                if not all(
                    isinstance(i, int) and not isinstance(i, bool) for i in item[:1] + item[2:]
                ):
                    raise DecodeError(f"capture object {number} has a non-integer field")
                if not isinstance(item[1], str):
                    raise DecodeError(f"capture object {number} logical name is not text")
                entries.append(item)
        else:
            for number, line in enumerate(text.splitlines(), 1):
                line = line.split("#", 1)[0].replace(",", " ").split()
                if not line:
                    continue
                if not 3 <= len(line) <= 4:
                    raise DecodeError(f"line {number}: expected class_id obis attribute [index]")
                try:
                    entries.append([int(line[0]), line[1], *(int(f) for f in line[2:])])
                except ValueError:
                    raise DecodeError(f"line {number}: non-integer field") from None
        parsed = parse_capture_objects(entries)
    except json.JSONDecodeError as exc:
        raise DecodeError(f"capture object file is not valid JSON: {exc}") from None
    except (ValueError, TypeError) as exc:  # bad OBIS text or out-of-range field
        if isinstance(exc, DecodeError):
            raise
        raise DecodeError(f"bad capture object: {exc}") from None
    if not parsed:
        raise DecodeError("capture object list is empty")
    return parsed


def format_capture_objects(objects: Any) -> str:
    """The text form of a capture-object list; :func:`parse_capture_objects_text` reads it back."""
    return "".join(
        f"{cid} {obis} {attr} {index}\n"
        for cid, obis, attr, index in parse_capture_objects(objects)
    )


def _positional(
    items: list[DlmsData], objects: list[tuple[int, ObisCode, int, int]], partial: bool
) -> list[PushRecord]:
    if len(items) != len(objects) and not (partial and len(items) < len(objects)):
        raise DecodeError(
            f"push_object_list has {len(objects)} entries but the push carries {len(items)} values"
        )
    return [
        PushRecord(obis, value, class_id=cid, attribute=attr)
        for (cid, obis, attr, _), value in zip(objects, items, strict=False)
    ]


def extract_records(
    body: DlmsData, capture_objects: Any = None, *, partial: bool = False
) -> list[PushRecord]:
    """Label the values of a DataNotification body (see the module docstring).

    With ``capture_objects`` (the push setup's ``push_object_list``, see
    :func:`parse_capture_objects`) the body is decoded positionally, the way the
    Blue Book defines a push (IC 40): value *i* is the attribute of entry
    *i*, and the record is keyed by that entry's OBIS. The counts must match
    (:class:`DecodeError` otherwise); ``partial=True`` accepts fewer values,
    for a damaged body. Without it the heuristics below apply.
    """
    items = body.value if body.tag in (DataType.STRUCTURE, DataType.ARRAY) else [body]
    if capture_objects is not None:
        return _positional(items, parse_capture_objects(capture_objects), partial)
    if (
        items
        and items[0].tag == DataType.ARRAY
        and items[0].value
        and all(_is_capture_definition(d) for d in items[0].value)
    ):
        definitions = items[0].value
        if len(definitions) == len(items):
            records = []
            for definition, value in zip(definitions, items, strict=True):
                cid, ln, attr = definition.value[0], definition.value[1], definition.value[2]
                if value is items[0]:
                    continue  # the push setup's own object list
                record = _record(ln, value, class_id=cid.value, attribute=attr.value)
                records.append(record)
                if value.tag in (DataType.STRUCTURE, DataType.ARRAY):
                    nested: list[PushRecord] = []
                    _walk(value.value, nested)
                    records.extend(r for r in nested if r.obis is not None)
            return records
        log.debug(
            "capture list has %d entries for %d values; using heuristics",
            len(definitions),
            len(items),
        )
    out: list[PushRecord] = []
    _walk(items, out)
    return out


# --- lenient and vendor-specific body parsing ---------------------------------------------


def decode_body_lenient(raw: bytes, offset: int = 0) -> tuple[DlmsData, bool]:
    """Decode a body; on damage keep the top-level elements decoded so far.

    Returns ``(data, complete)``. Used for pushes whose tail is corrupt (a lost
    M-Bus segment) so the intact leading values are still usable. Octets left
    after an intact body also make ``complete`` False.
    """
    try:
        reader = _BytesReader(raw, offset)
        body = _decode(reader)
    except DecodeError:
        pass
    else:
        if reader.pos != len(raw):
            log.warning("push body followed by %d unexpected octets", len(raw) - reader.pos)
            return body, False
        return body, True
    tag = raw[offset] if offset < len(raw) else None
    if tag not in (DataType.STRUCTURE, DataType.ARRAY):
        raise DecodeError("body is damaged and is not a composite")
    reader = _BytesReader(raw, offset + 1)
    count = _read_count(reader)
    items: list[DlmsData] = []
    for _ in range(count):
        mark = reader.pos
        try:
            items.append(_decode(reader))
        except DecodeError as exc:
            log.warning(
                "push body damaged after %d of %d elements (offset %d): %s",
                len(items),
                count,
                mark,
                exc,
            )
            break
    return DlmsData(DataType(tag), items), False


def _read_count(reader) -> int:
    return read_length(reader.read)


def decode_descriptor_pairs(raw: bytes, offset: int) -> list[PushRecord] | None:
    """Sagemcom/EGD body ``02 02 16 xx 01 n {02 02 <cid obis attr> Data}*n``."""
    if raw[offset : offset + 3] != b"\x02\x02\x16" or raw[offset + 4 : offset + 5] != b"\x01":
        return None
    reader = _BytesReader(raw, offset + 5)
    count = _read_count(reader)
    records = []
    for _ in range(count):
        if reader.read(2) != b"\x02\x02":
            return None
        descriptor = reader.read(9)
        value = _decode(reader)
        records.append(
            PushRecord(
                ObisCode.from_bytes(descriptor[2:8]),
                value,
                class_id=int.from_bytes(descriptor[0:2], "big"),
                attribute=descriptor[8],
            )
        )
    return records


PUSH_TAGS = (
    Tag.DATA_NOTIFICATION,
    Tag.EVENT_NOTIFICATION_REQUEST,
    Tag.INFORMATION_REPORT_REQUEST,
)


def decode_notification(
    plain: bytes, capture_objects: Any = None
) -> tuple[Any, list[PushRecord], bool]:
    """Decode a plaintext unsolicited APDU into records.

    Accepts a DataNotification (LN push), an EventNotification-Request (one
    attribute value, LN) and an InformationReport-Request (SN: values keyed
    by short name, no OBIS). Returns ``(notification, records, complete)``.
    ``capture_objects`` decodes a DataNotification body positionally (see
    :func:`extract_records`).
    """
    if not plain or plain[0] not in PUSH_TAGS:
        raise DecodeError(
            "expected DataNotification, EventNotification or InformationReport, got "
            f"{tag_name(plain[0]) if plain else 'nothing'}"
        )
    if plain[0] == Tag.EVENT_NOTIFICATION_REQUEST:
        event = decode_apdu(plain)
        a = event.attribute
        record = PushRecord(
            a.instance_id, event.value, class_id=a.class_id, attribute=a.attribute_id
        )
        return event, [record], True
    if plain[0] == Tag.INFORMATION_REPORT_REQUEST:
        from pydlms.apdu.sn import decode_sn_apdu

        report = decode_sn_apdu(plain)
        if len(report.names) != len(report.values):
            raise DecodeError(
                f"InformationReport has {len(report.names)} names but {len(report.values)} values"
            )
        records = [
            PushRecord(None, value, short_name=name)
            for name, value in zip(report.names, report.values, strict=True)
        ]
        return report, records, True
    try:
        note = decode_apdu(plain, strict=False)
        complete = True
        try:
            decode_apdu(plain)
        except DecodeError as exc:  # only trailing octets: the body itself decoded
            log.warning("DataNotification not complete: %s", exc)
            complete = False
        return note, extract_records(note.body, capture_objects), complete
    except DecodeError as first_error:
        # Locate the body after long-invoke-id and the date-time field.
        pos = 5
        tagged = plain[pos : pos + 2] == b"\x09\x0c"
        if tagged:
            pos += 1
        if len(plain) <= pos:  # too short for the date-time length octet
            raise first_error from None
        dt_len = plain[pos]
        date_time = plain[pos + 1 : pos + 1 + dt_len] or None
        pos += 1 + dt_len
        long_invoke_id = int.from_bytes(plain[1:5], "big")
        pairs = decode_descriptor_pairs(plain, pos)
        if pairs is not None:
            note = DataNotification(long_invoke_id, DlmsData.null(), date_time, tagged)
            return note, pairs, True
        try:
            body, complete = decode_body_lenient(plain, pos)
        except DecodeError:
            raise first_error from None
        note = DataNotification(long_invoke_id, body, date_time, tagged)
        return note, extract_records(body, capture_objects, partial=not complete), complete


# --- stream decoder --------------------------------------------------------------------------


@dataclass
class PushDecoder:
    """Turn raw push traffic into :class:`PushMessage` objects.

    ``framing`` is ``"hdlc"``, ``"mbus"``, ``"wrapper"`` or ``"raw"`` (each
    :meth:`feed` call is one APDU). ``profile`` relabels compact payloads.
    ``verify_checksums=False`` accepts HDLC frames with a bad FCS; for
    analysing captures only. ``capture_objects`` is the push setup's
    ``push_object_list`` (IC 40 attribute 2, as read from the meter or as
    ``(class_id, obis, attribute)`` tuples): DataNotification bodies are then
    decoded positionally and keyed by those OBIS codes.
    """

    framing: str = "hdlc"
    security: Any = None
    profile: Any = None
    verify_checksums: bool = True
    capture_objects: Any = None
    _gbt: GbtReassembler = field(default_factory=GbtReassembler)
    _hdlc_buffer: bytearray = field(default_factory=bytearray)
    _reader: Any = None

    def __post_init__(self) -> None:
        if self.capture_objects is not None:
            self.capture_objects = parse_capture_objects(self.capture_objects)
        if self.framing == "hdlc":
            from pydlms.hdlc.framing import FrameReader

            self._reader = FrameReader(verify_checksums=self.verify_checksums)
        elif self.framing == "mbus":
            from pydlms.mbus import MbusReader

            self._reader = MbusReader()
        elif self.framing == "wrapper":
            self._reader = bytearray()
        elif self.framing != "raw":
            raise ValueError(f"unknown framing {self.framing!r}")

    def feed(self, data: bytes) -> list[PushMessage]:
        messages = []
        for apdu in self._apdus(data):
            message = self.decode_apdu(apdu)
            if message is not None:
                messages.append(message)
        return messages

    def _apdus(self, data: bytes) -> list[bytes]:
        if self.framing == "raw":
            return [data]
        if self.framing == "mbus":
            return self._reader.feed(data)
        if self.framing == "wrapper":
            from pydlms.wrapper import HEADER_SIZE, decode_header

            self._reader += data
            out = []
            while len(self._reader) >= HEADER_SIZE:
                header = decode_header(bytes(self._reader[:HEADER_SIZE]))
                total = HEADER_SIZE + header.length
                if len(self._reader) < total:
                    break
                out.append(bytes(self._reader[HEADER_SIZE:total]))
                del self._reader[:total]
            return out
        from pydlms.hdlc.framing import FrameType, strip_llc

        out = []
        for frame in self._reader.feed(data):
            if frame.kind not in (FrameType.UI, FrameType.I):
                continue
            first = not self._hdlc_buffer
            self._hdlc_buffer += strip_llc(frame.info) if first else frame.info
            if frame.segmented:
                continue
            out.append(bytes(self._hdlc_buffer))
            self._hdlc_buffer.clear()
        return out

    def decode_apdu(self, apdu: bytes) -> PushMessage | None:
        """Decode one APDU (GBT blocks are buffered until complete)."""
        log.log(TRACE, "push APDU (%d octets)\n%s", len(apdu), hexdump(apdu, prefix="    "))
        if apdu and apdu[0] == Tag.GENERAL_BLOCK_TRANSFER:
            complete = self._gbt.add(decode_gbt(apdu))
            if complete is None:
                return None
            apdu = complete
        system_title = invocation_counter = None
        authenticated = False
        from pydlms.security.ciphering import is_ciphered_apdu

        if is_ciphered_apdu(apdu):
            if self.security is None:
                raise DlmsError(
                    f"push is ciphered ({tag_name(apdu[0])}); pass a SecurityContext with the key"
                )
            from pydlms.security.ciphering import unwrap

            result = unwrap(self.security, apdu)
            apdu = result.plaintext
            system_title = result.system_title
            invocation_counter = result.invocation_counter
            authenticated = result.authenticated
        return self._message(apdu, system_title, invocation_counter, authenticated)

    def decode_queued(self, push: Any) -> PushMessage | None:
        """Decode a :class:`~pydlms.link.QueuedPush`.

        A push the association already deciphered and checked while waiting
        for a response is decoded from its plaintext with the recorded
        system title, invocation counter and authentication verdict; it is
        never deciphered again (the inbound counter has moved past it).
        Anything else goes through :meth:`decode_apdu`.
        """
        result = push.unwrapped
        if result is None:
            return self.decode_apdu(push.apdu)
        if push.apdu != result.plaintext:
            raise DlmsError("queued push does not match its deciphering result")
        log.log(TRACE, "queued deciphered push (%d octets)", len(push.apdu))
        return self._message(
            result.plaintext, result.system_title, result.invocation_counter, result.authenticated
        )

    def _message(
        self,
        apdu: bytes,
        system_title: bytes | None,
        invocation_counter: int | None,
        authenticated: bool,
    ) -> PushMessage:
        note, records, complete = decode_notification(apdu, self.capture_objects)
        if self.profile is not None:
            records = self.profile.apply(records)
        if not complete:
            log.warning("push decoded partially: %d records before the damage", len(records))
        log.debug(
            "push: %d records, IC=%s, title=%s",
            len(records),
            invocation_counter,
            system_title.hex() if system_title else None,
        )
        return PushMessage(note, records, system_title, invocation_counter, authenticated, complete)
