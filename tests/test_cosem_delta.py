"""Delta integer data types 28..33 (codec only; values are not resolved).

Tag numbers: Green Book Data CHOICE [28]..[33] (IEC 62056-6-2 ed. 10, clause
unverified), cross-checked against Gurux.DLMS.Net ``Enums/DataType.cs`` and the
Rust ``dlms_cosem`` crate behaviour (``delta-integer 5`` decodes from 1c05).
Vectors are hand-derived: tag octet then the big-endian value of the base type.
"""

from __future__ import annotations

import pytest

from pydlms import apduxml
from pydlms.cosem.data import CompactArray, DlmsData, TypeDescription, decode_data, encode_data
from pydlms.cosem.enums import DataType as T
from pydlms.cosem.types import Integer
from pydlms.exceptions import DecodeError

# tag, name, width, signed
DELTAS = [
    (28, "DELTA_INTEGER", 1, True),
    (29, "DELTA_LONG", 2, True),
    (30, "DELTA_DOUBLE_LONG", 4, True),
    (31, "DELTA_UNSIGNED", 1, False),
    (32, "DELTA_LONG_UNSIGNED", 2, False),
    (33, "DELTA_DOUBLE_LONG_UNSIGNED", 4, False),
]
IDS = [d[1] for d in DELTAS]


@pytest.mark.parametrize("tag,name,width,signed", DELTAS, ids=IDS)
def test_tag_values(tag, name, width, signed):
    assert T[name] == tag


@pytest.mark.parametrize(
    "hexstr,tag,value",
    [
        ("1c05", T.DELTA_INTEGER, 5),
        ("1cfb", T.DELTA_INTEGER, -5),
        ("1d0102", T.DELTA_LONG, 0x0102),
        ("1dfffe", T.DELTA_LONG, -2),
        ("1e00000100", T.DELTA_DOUBLE_LONG, 256),
        ("1effffffff", T.DELTA_DOUBLE_LONG, -1),
        ("1fff", T.DELTA_UNSIGNED, 255),
        ("20fffe", T.DELTA_LONG_UNSIGNED, 0xFFFE),
        ("21ffffffff", T.DELTA_DOUBLE_LONG_UNSIGNED, 0xFFFFFFFF),
    ],
)
def test_known_vectors(hexstr, tag, value):
    raw = bytes.fromhex(hexstr)
    obj = DlmsData(tag, value)
    assert encode_data(obj) == raw
    decoded, consumed = decode_data(raw)
    assert consumed == len(raw)
    assert decoded == obj
    assert decoded.to_python() == value


@pytest.mark.parametrize("tag,name,width,signed", DELTAS, ids=IDS)
def test_round_trip_limits(tag, name, width, signed):
    lo, hi = (
        (-(1 << (8 * width - 1)), (1 << (8 * width - 1)) - 1)
        if signed
        else (0, (1 << 8 * width) - 1)
    )
    for value in (lo, 0, hi):
        obj = DlmsData(T(tag), value)
        assert decode_data(encode_data(obj))[0] == obj
    for value in (lo - 1, hi + 1):
        with pytest.raises(ValueError):
            encode_data(DlmsData(T(tag), value))


@pytest.mark.parametrize("tag,name,width,signed", DELTAS, ids=IDS)
def test_truncated(tag, name, width, signed):
    raw = bytes([tag]) + b"\x01" * width
    for cut in range(len(raw)):
        with pytest.raises(DecodeError):
            decode_data(raw[:cut])


def test_inside_structure_and_array():
    obj = DlmsData.structure(
        [DlmsData(T.DELTA_LONG, -7), DlmsData.array([DlmsData(T.DELTA_UNSIGNED, 9)])]
    )
    assert encode_data(obj) == bytes.fromhex("02 02 1d fff9 01 01 1f 09")
    assert decode_data(encode_data(obj))[0] == obj


@pytest.mark.parametrize("tag,name,width,signed", DELTAS, ids=IDS)
def test_in_compact_array(tag, name, width, signed):
    desc = TypeDescription(T(tag))
    items = [DlmsData(T(tag), 1), DlmsData(T(tag), 2)]
    obj = DlmsData(T.COMPACT_ARRAY, CompactArray(desc, items))
    body = b"".join(i.value.to_bytes(width, "big") for i in items)
    expected = bytes([19, tag, len(body)]) + body
    assert encode_data(obj) == expected
    assert decode_data(expected)[0] == obj


def test_compact_array_truncated_delta_element():
    # description delta-long, content 3 octets: one whole element then a stub
    with pytest.raises(DecodeError):
        decode_data(bytes.fromhex("13 1d 03 0001 02"))


def test_delta_is_not_an_absolute_integer():
    with pytest.raises(DecodeError):
        Integer(T.DOUBLE_LONG_UNSIGNED).decode(DlmsData(T.DELTA_DOUBLE_LONG_UNSIGNED, 1))


def test_unknown_neighbour_tags_still_rejected():
    for tag in (34, 0x80):
        with pytest.raises(DecodeError):
            decode_data(bytes([tag, 0]))


@pytest.mark.parametrize("tag,name,width,signed", DELTAS, ids=IDS)
def test_apduxml_element(tag, name, width, signed):
    value = -1 if signed else 1
    el = apduxml.data_element(DlmsData(T(tag), value))
    assert el.tag == name.lower().replace("_", "-")
    assert apduxml.element_data(el) == DlmsData(T(tag), value)
