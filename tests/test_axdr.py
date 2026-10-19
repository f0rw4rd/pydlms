"""Tests for the DLMS A-XDR variable-length codec."""

from __future__ import annotations

import construct
import pytest

from pydlms.axdr import DlmsLength, decode_length, encode_length
from pydlms.cosem.data import decode_data
from pydlms.exceptions import DecodeError


@pytest.mark.parametrize(
    "value,encoded",
    [
        (0, b"\x00"),
        (1, b"\x01"),
        (0x7F, b"\x7f"),  # last short-form value
        (0x80, b"\x81\x80"),  # first long-form value
        (0xFF, b"\x81\xff"),
        (0x100, b"\x82\x01\x00"),
        (0xFFFF, b"\x82\xff\xff"),
        (0x010000, b"\x83\x01\x00\x00"),
        (0x01020304, b"\x84\x01\x02\x03\x04"),
    ],
)
def test_known_vectors(value, encoded):
    assert encode_length(value) == encoded
    assert decode_length(encoded) == (value, len(encoded))


@pytest.mark.parametrize("value", [0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x1234, 0xFFFF, 0x12345678])
def test_round_trip_helpers(value):
    assert decode_length(encode_length(value)) == (value, len(encode_length(value)))


@pytest.mark.parametrize("value", [0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x1234, 0xFFFF, 0x12345678])
def test_round_trip_construct(value):
    built = DlmsLength.build(value)
    assert built == encode_length(value)
    assert DlmsLength.parse(built) == value


def test_decode_offset_and_trailing():
    data = b"\x82\x01\x00\xaa\xbb"
    value, nxt = decode_length(data, 0)
    assert value == 0x100
    assert data[nxt:] == b"\xaa\xbb"


def test_indefinite_length_rejected():
    with pytest.raises(ValueError, match="indefinite"):
        decode_length(b"\x80")
    with pytest.raises(construct.ConstructError, match="indefinite"):
        DlmsLength.parse(b"\x80")


def test_truncated_long_form_rejected():
    with pytest.raises(ValueError, match="only"):
        decode_length(b"\x82\x01")  # says 2 octets follow, only 1 present


def test_negative_length_rejected():
    with pytest.raises(ValueError):
        encode_length(-1)


def test_empty_input_rejected():
    with pytest.raises(ValueError):
        decode_length(b"")


# One cap for every A-XDR length decoder: at most 4 length octets (0x84),
# the most Gurux (GetObjectCount) accepts and enough for any DLMS length.


@pytest.mark.parametrize("raw", ["85" + "00" * 4 + "01", "8f" + "00" * 15, "ff" + "00" * 127])
def test_more_than_four_length_octets_rejected(raw):
    data = bytes.fromhex(raw)
    with pytest.raises(DecodeError, match="4"):
        decode_length(data)
    with pytest.raises(construct.ConstructError, match="4"):
        DlmsLength.parse(data)
    with pytest.raises(DecodeError, match="4"):
        decode_data(b"\x09" + data)


def test_encode_refuses_more_than_four_octets():
    assert encode_length(0xFFFFFFFF) == b"\x84\xff\xff\xff\xff"
    with pytest.raises(ValueError):
        encode_length(0x100000000)


def test_lenient_push_body_uses_the_same_cap():
    from pydlms.push import decode_body_lenient

    # structure whose element count claims 5 length octets
    with pytest.raises(DecodeError):
        decode_body_lenient(bytes.fromhex("02 85 0000000001 1105"))
