"""Tests for OBIS code parsing, formatting and the construct adapter."""

from __future__ import annotations

import pytest

from pydlms.obis import ObisAdapter, ObisCode


def test_from_bytes_and_back():
    raw = bytes([1, 0, 1, 8, 0, 255])
    code = ObisCode.from_bytes(raw)
    assert code.groups == (1, 0, 1, 8, 0, 255)
    assert code.to_bytes() == raw


def test_str_and_iec_forms():
    code = ObisCode(1, 0, 1, 8, 0, 255)
    assert str(code) == "1.0.1.8.0.255"
    assert code.to_iec() == "1-0:1.8.0*255"


@pytest.mark.parametrize(
    "text",
    [
        "1.0.1.8.0.255",
        "1-0:1.8.0*255",
        "1.0.1.8.0",  # 5 groups -> F defaults to 255
        "1-0:1.8.0",
    ],
)
def test_parse_equivalent_forms(text):
    assert ObisCode.parse(text) == ObisCode(1, 0, 1, 8, 0, 255)


def test_parse_round_trip():
    code = ObisCode(0, 0, 42, 0, 0, 255)  # logical device name
    assert ObisCode.parse(str(code)) == code
    assert ObisCode.parse(code.to_iec()) == code


def test_group_range_validation():
    with pytest.raises(ValueError):
        ObisCode(1, 0, 1, 8, 0, 256)
    with pytest.raises(ValueError):
        ObisCode(-1, 0, 0, 0, 0, 0)


def test_from_bytes_wrong_length():
    with pytest.raises(ValueError):
        ObisCode.from_bytes(b"\x01\x00\x01")


def test_parse_wrong_group_count():
    with pytest.raises(ValueError):
        ObisCode.parse("1.0.1.8")  # 4 groups


def test_ordering_and_hash():
    a = ObisCode(1, 0, 1, 8, 0, 255)
    b = ObisCode(1, 0, 2, 8, 0, 255)
    assert a < b
    assert len({a, b, ObisCode(1, 0, 1, 8, 0, 255)}) == 2


def test_construct_adapter_round_trip():
    raw = bytes([0, 0, 96, 1, 0, 255])
    code = ObisAdapter.parse(raw)
    assert code == ObisCode(0, 0, 96, 1, 0, 255)
    assert ObisAdapter.build(code) == raw


def test_construct_adapter_accepts_string():
    assert ObisAdapter.build("1.0.1.8.0.255") == bytes([1, 0, 1, 8, 0, 255])


@pytest.mark.parametrize(
    "text",
    [
        "1.0.-1.8.0.255",  # the sign used to vanish into a separator
        "1.0.1_0.8.0.255",  # int() accepts underscores
        "1..0.1.8.0.255",  # empty group
        "1.0.1.8.0.255.",
        ".1.0.1.8.0.255",
        "1-0:1-8.0*255",  # '-' only between A and B
        "1.0.1.8.0*255*1",
        "1.0.١.8.0.255",  # non-ASCII digit
        "1.0.1.8.0.+255",
        "1.0.1.8.0.0255",  # more than three digits
        "1.0.1.8.0.256",
        "",
    ],
)
def test_parse_rejects_malformed_text(text):
    with pytest.raises(ValueError):
        ObisCode.parse(text)


def test_parse_tolerates_surrounding_whitespace():
    assert ObisCode.parse(" 1-0:1.8.0*255\n") == ObisCode(1, 0, 1, 8, 0, 255)
