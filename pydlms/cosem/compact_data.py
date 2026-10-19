"""Compact data (IC 62): one capture of several attributes without type tags.

A Compact data object (class_id 62, version 1, per DLMS UA 1000-1 Ed. 13
Excerpt 4.3.10 and the Ed. 17 Part 2 contents; version 0 is a previous
version, Ed. 17 Part 2 5.3.2) holds:

* attribute 2 ``compact_buffer``: octet-string, the captured values packed
  back to back without their A-XDR type tags;
* attribute 3 ``capture_objects``: the captured attributes, as in Profile
  generic (``{class_id, logical_name, attribute_index, data_index}``);
* attribute 4 ``template_id``: unsigned;
* attribute 5 ``template_description``: octet-string, a structure with one
  member per capture object;
* attribute 6 ``capture_method``: enum, explicit capturing (an external
  trigger) or implicit capturing (upon reading ``compact_buffer``). The
  Ed. 13 excerpt names the two modes but not their values; 0 = capture
  method, 1 = implicit follows Gurux (*unverified*: Blue Book table not in
  the public excerpts).

``compact_buffer`` has no octet of its own in front of the values: the
Ed. 13 examples (4.3.10.2, Tables 6/7, 9/10, 13/14) capture the template_id
as the *first capture object* (class 62, ``0-0:66.0.0.255``, attribute 4),
so its value is the first member of the template description and the
first octet of the buffer. The generic decoder here covers that and a
buffer without it.

Arrays in ``template_description`` (Ed. 13 Table 14, the logbook example
``02 02 11 01 02 02 06 11``) are the array tag followed by the element
description, without a count; the buffer carries the element count (A-XDR
length, ``32`` for 50 entries) before the elements. This differs from the
compact-array (tag 19) type description, whose arrays carry an Unsigned16
count. Gurux GXDLMSCompactData writes the counted form, so a template that
does not parse in the Blue Book form is read in the counted form instead.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydlms.cosem.data import DlmsData, TypeDescription, decode_type_description, decode_untagged
from pydlms.cosem.enums import DataType
from pydlms.cosem.profile import Column
from pydlms.exceptions import DecodeError

__all__ = ["CompactData", "decode_compact_buffer", "decode_template_description"]


@dataclass
class CompactData:
    """A Compact data object as read by ``DlmsClient.read_compact_data``.

    ``cells`` are the decoded buffer members (one per capture object, empty
    when nothing has been captured yet); ``values`` the same as plain or
    typed Python values (:mod:`pydlms.cosem.profile`).
    """

    columns: list[Column]
    template_id: int
    template_description: TypeDescription
    capture_method: int | None
    cells: list[DlmsData] = field(default_factory=list)
    values: list[Any] = field(default_factory=list)


def decode_template_description(data: bytes) -> TypeDescription:
    """Decode a ``template_description`` (attribute 5).

    The Blue Book form (an array is its tag and element description; the
    count is in ``compact_buffer``) is tried first; a template that does
    not parse that way is read with Unsigned16 array counts (the
    compact-array form Gurux writes). Raises :class:`DecodeError` when
    neither parses.
    """
    try:
        return decode_type_description(data, counted_arrays=False)
    except DecodeError as blue_book_error:
        try:
            return decode_type_description(data)
        except DecodeError:
            raise blue_book_error from None


def decode_compact_buffer(
    template_description: bytes | TypeDescription, compact_buffer: bytes
) -> list[DlmsData]:
    """Decode one capture of ``compact_buffer`` with its template description.

    ``template_description`` is the raw attribute 5 octets or a decoded
    :class:`TypeDescription`; it must be a structure. Returns its members,
    one ``Data`` per capture object. The buffer must hold exactly one
    capture: truncated or trailing octets raise :class:`DecodeError`.
    """
    if isinstance(template_description, TypeDescription):
        desc = template_description
    else:
        desc = decode_template_description(template_description)
    if desc.tag != DataType.STRUCTURE:
        raise DecodeError(f"template_description is {desc.tag.name}, not a structure")
    return list(decode_untagged(compact_buffer, desc).value)
