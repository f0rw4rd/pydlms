"""Invocation-counter evidence report (``pydlms discover-ic --report``).

Where a meter keeps the invocation counter of its secured clients is known
for a handful of vendors only.
:func:`ic_report` collects that evidence from a meter through the public
client (SAP 16, no authentication, no ciphering) in a form that can be pasted
into a public issue:

* the manufacturer FLAG id: the first three characters of the COSEM logical
  device name ``0.0.42.0.0.255`` (or of the server system title when the
  name is unreadable),
* the active firmware identifier ``1.0.0.2.0.255``, if readable,
* every invocation-counter object found, how it was found (``object list``,
  ``vendor table`` (:data:`pydlms.counters.VENDOR_LOCATIONS`) or ``blind
  probe`` (:data:`pydlms.counters.BLIND_CANDIDATES`, when the object list is
  unreadable)), whether a GET returned a counter, and the data type,
* class id and version of the Security setup objects ``0.0.43.0.e.255`` in
  the object list.

It never contains counter values, serial numbers, the logical device name
beyond its FLAG id, system titles or the endpoint address.
"""

from __future__ import annotations

from pydlms import __version__
from pydlms.cosem.enums import DataType
from pydlms.cosem.interface_classes import ClassId
from pydlms.counters import BLIND_CANDIDATES, VENDOR_LOCATIONS, is_counter_obis
from pydlms.debug import get_logger
from pydlms.exceptions import DlmsError
from pydlms.obis import ObisCode

__all__ = ["ic_report", "LOGICAL_DEVICE_NAME", "FIRMWARE_ID"]

log = get_logger("client")

#: COSEM logical device name (IEC 62056-6-2; pydlms/data/obis_names.csv).
LOGICAL_DEVICE_NAME = ObisCode(0, 0, 42, 0, 0, 255)
#: Active firmware identifier (pydlms/data/obis_names.csv).
FIRMWARE_ID = ObisCode(1, 0, 0, 2, 0, 255)

_COUNTER_TYPES = (
    DataType.DOUBLE_LONG_UNSIGNED,
    DataType.LONG64_UNSIGNED,
    DataType.LONG_UNSIGNED,
    DataType.DOUBLE_LONG,
)
_MAX_FIRMWARE_CHARS = 64


def _flag(raw) -> str | None:
    text = raw.decode("ascii", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
    head = text[:3]
    return head if len(head) == 3 and head.isascii() and head.isalpha() else None


def _printable(raw) -> str | None:
    if isinstance(raw, (bytes, bytearray)):
        if raw and all(0x20 <= b < 0x7F for b in raw):
            return raw.decode("ascii")[:_MAX_FIRMWARE_CHARS]
        return raw.hex()[:_MAX_FIRMWARE_CHARS] if raw else None
    if isinstance(raw, str) and raw.isprintable():
        return raw[:_MAX_FIRMWARE_CHARS]
    return None


def _manufacturer(client) -> tuple[str | None, str | None]:
    try:
        flag = _flag(client.get(LOGICAL_DEVICE_NAME).value)
        if flag:
            return flag.upper(), "logical device name"
    except DlmsError as exc:
        log.debug("logical device name not readable: %s", exc)
    title = getattr(client.association, "server_system_title", None)
    if title:
        flag = _flag(bytes(title))
        if flag:
            return flag.upper(), "server system title"
    return None, None


def _firmware(client) -> str | None:
    try:
        return _printable(client.get(FIRMWARE_ID).value)
    except DlmsError as exc:
        log.debug("firmware identifier not readable: %s", exc)
        return None


def ic_report(client) -> dict:
    """Collect the report on an associated public client; see the module doc."""
    manufacturer, source = _manufacturer(client)
    candidates: list[tuple[ObisCode, int, str]] = []
    security_setup = None
    try:
        view = client.get_association_view()
        object_list = "read"
    except DlmsError as exc:
        log.debug("object list not readable (%s); probing the standard objects", exc)
        view = None
        object_list = "unreadable"
    if view is not None:
        candidates += [
            (e.logical_name, e.class_id, "object list")
            for e in view
            if is_counter_obis(e.logical_name)
        ]
        security_setup = [
            {"obis": str(e.logical_name), "class_id": e.class_id, "version": e.version}
            for e in view
            if e.logical_name.groups[:4] == (0, 0, 43, 0)
            and e.logical_name.groups[5] == 255
            and e.class_id == ClassId.SECURITY_SETUP
        ]
    if manufacturer:
        candidates += [
            (loc.obis, loc.class_id, "vendor table")
            for loc in VENDOR_LOCATIONS.get(manufacturer, [])
        ]
    if view is None:
        candidates += [(obis, ClassId.DATA, "blind probe") for obis in BLIND_CANDIDATES]
    counters = []
    seen = set()
    for obis, class_id, found_by in candidates:
        if (obis, class_id) in seen:
            continue
        seen.add((obis, class_id))
        try:
            value = client.get(obis, class_id, 2)
        except DlmsError as exc:
            log.debug("no invocation counter at %s: %s", obis, exc)
            value = None
        readable = value is not None and value.tag in _COUNTER_TYPES
        if not readable and found_by != "object list":
            continue  # a probe that found nothing is no evidence
        counters.append(
            {
                "obis": str(obis),
                "class_id": int(class_id),
                "attribute": 2,
                "found_by": found_by,
                "readable": readable,
                "type": value.tag.name if readable else None,
            }
        )
    return {
        "report": "pydlms-ic-report",
        "format": 1,
        "pydlms": __version__,
        "client_sap": 16,
        "manufacturer": manufacturer,
        "manufacturer_source": source,
        "firmware_id": _firmware(client),
        "object_list": object_list,
        "invocation_counters": counters,
        "security_setup": security_setup,
    }
