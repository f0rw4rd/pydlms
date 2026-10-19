"""Tests for the recursive COSEM Data (A-XDR CHOICE) codec."""

from __future__ import annotations

import pytest

from pydlms.cosem.data import MAX_NESTING, CosemData, DlmsData, decode_data, encode_data
from pydlms.cosem.enums import DataType
from pydlms.exceptions import DecodeError


@pytest.mark.parametrize(
    "obj,encoded",
    [
        (DlmsData.null(), b"\x00"),
        (DlmsData.boolean(True), b"\x03\x01"),
        (DlmsData.boolean(False), b"\x03\x00"),
        (DlmsData.uint8(0x11), b"\x11\x11"),
        (DlmsData.uint16(1000), b"\x12\x03\xe8"),
        (DlmsData.uint32(0x01020304), b"\x06\x01\x02\x03\x04"),
        (DlmsData.int8(-1), b"\x0f\xff"),
        (DlmsData.int16(-2), b"\x10\xff\xfe"),
        (DlmsData.int32(-1), b"\x05\xff\xff\xff\xff"),
        (DlmsData.enum(30), b"\x16\x1e"),
        (DlmsData.octet_string(bytes([1, 0, 1, 8, 0, 255])), b"\x09\x06\x01\x00\x01\x08\x00\xff"),
        (DlmsData.visible_string("OK"), b"\x0a\x02OK"),
        (DlmsData(DataType.UTF8_STRING, "µ"), b"\x0c\x02\xc2\xb5"),
        (DlmsData(DataType.FLOAT32, 1.0), b"\x17\x3f\x80\x00\x00"),
        (DlmsData(DataType.DATE_TIME, bytes(12)), b"\x19" + bytes(12)),
    ],
)
def test_scalar_known_vectors(obj, encoded):
    assert encode_data(obj) == encoded
    decoded, consumed = decode_data(encoded)
    assert consumed == len(encoded)
    assert decoded == obj


def test_structure_known_vector():
    obj = DlmsData.structure([DlmsData.uint16(1000), DlmsData.enum(30)])
    assert encode_data(obj) == b"\x02\x02\x12\x03\xe8\x16\x1e"
    assert decode_data(encode_data(obj))[0] == obj


def test_array_known_vector():
    obj = DlmsData.array([DlmsData.uint8(1), DlmsData.uint8(2), DlmsData.uint8(3)])
    assert encode_data(obj) == b"\x01\x03\x11\x01\x11\x02\x11\x03"
    assert decode_data(encode_data(obj))[0] == obj


def test_nested_structure_round_trip():
    obj = DlmsData.structure(
        [
            DlmsData.octet_string(bytes([0, 0, 1, 0, 0, 255])),
            DlmsData.array(
                [
                    DlmsData.structure([DlmsData.uint16(230), DlmsData.enum(35)]),
                    DlmsData.structure([DlmsData.uint16(231), DlmsData.enum(35)]),
                ]
            ),
            DlmsData.null(),
        ]
    )
    assert decode_data(encode_data(obj))[0] == obj


def test_bit_string_round_trip_and_vector():
    obj = DlmsData(DataType.BIT_STRING, [True, False, True, False])
    assert encode_data(obj) == b"\x04\x04\xa0"  # 4 bits, 1010 0000
    assert decode_data(encode_data(obj))[0] == obj


def test_to_python_collapses_tree():
    obj = DlmsData.structure([DlmsData.uint16(1000), DlmsData.array([DlmsData.uint8(1)])])
    assert obj.to_python() == [1000, [1]]


def test_construct_wrapper_round_trip():
    obj = DlmsData.structure([DlmsData.uint16(1000), DlmsData.enum(30)])
    built = CosemData.build(obj)
    assert built == encode_data(obj)
    assert CosemData.parse(built) == obj


def test_decode_leaves_trailing_bytes():
    data = encode_data(DlmsData.uint8(5)) + b"\xde\xad"
    value, consumed = decode_data(data)
    assert value == DlmsData.uint8(5)
    assert data[consumed:] == b"\xde\xad"


def test_integer_range_checked_on_build():
    with pytest.raises(ValueError):
        encode_data(DlmsData.uint8(256))
    with pytest.raises(ValueError):
        encode_data(DlmsData.int8(128))


def test_truncated_compact_array_rejected():
    with pytest.raises(ValueError):
        decode_data(b"\x13\x00")


def test_unknown_tag_rejected():
    with pytest.raises(DecodeError, match="0x07"):
        decode_data(b"\x07\x00")


def test_nesting_limit_rejects_hostile_input():
    hostile = b"\x01\x01" * (MAX_NESTING + 1) + b"\x00"
    with pytest.raises(DecodeError, match="nested"):
        decode_data(hostile)


def test_nesting_at_limit_accepted():
    ok = b"\x01\x01" * (MAX_NESTING - 1) + b"\x00"
    value, consumed = decode_data(ok)
    assert consumed == len(ok)


def test_oversized_length_field_rejected():
    with pytest.raises(DecodeError):
        decode_data(b"\x09\x85\x00\x00\x00\x00\x01\x00")


def test_bcd_round_trip():
    obj = DlmsData(DataType.BCD, 0x42)
    assert encode_data(obj) == b"\x0d\x42"
    assert decode_data(b"\x0d\x42")[0] == obj


def test_short_read_rejected():
    with pytest.raises(ValueError):
        decode_data(b"\x12\x03")  # long-unsigned needs 2 content octets


@pytest.mark.parametrize("raw", ["0c01ff", "0c02c328", "0c03eda080"])
def test_invalid_utf8_is_a_decode_error(raw):
    # Lone continuation octet, truncated sequence, encoded surrogate.
    with pytest.raises(DecodeError, match="utf8-string"):
        decode_data(bytes.fromhex(raw))


def test_invalid_utf8_inside_an_apdu_is_a_decode_error():
    from pydlms.apdu.xdlms import decode_apdu

    with pytest.raises(DecodeError):
        decode_apdu(bytes.fromhex("c401c1000c01ff"))


def test_float32_out_of_range_is_a_value_error():
    with pytest.raises(ValueError, match="FLOAT32"):
        encode_data(DlmsData(DataType.FLOAT32, 1e40))


# Green Book Data CHOICE: dont-care [255] IMPLICIT NULL (also in jDLMS).


def test_dont_care_round_trip():
    value, consumed = decode_data(b"\xff")
    assert consumed == 1
    assert value == DlmsData(DataType.DONT_CARE, None)
    assert value.to_python() is None
    assert encode_data(value) == b"\xff"
    nested = bytes.fromhex("0202ff1105")
    value, consumed = decode_data(nested)
    assert consumed == len(nested) and encode_data(value) == nested
    assert value.to_python() == [None, 5]
