"""Tests for COSEM date / time / date-time decoding."""

from __future__ import annotations

import datetime as dt

import pytest

from pydlms.cosem.time import ClockStatus, CosemDate, CosemDateTime, CosemTime
from pydlms.exceptions import DecodeError

# Kaifa MA309M push (esphome-libs/dlms_parser mbus_kaifa_ma309m, Apache-2.0):
# 2026-06-05 12:37:45.00, deviation 0x8880 = -120 min (CEST), status 0x80 (DST).
KAIFA_DT = bytes.fromhex("07EA0605050C252D00FF8880")


def test_real_meter_vector():
    value = CosemDateTime.from_bytes(KAIFA_DT)
    assert value.date == CosemDate(2026, 6, 5, 5)
    assert value.time == CosemTime(12, 37, 45, 0)
    assert value.deviation == -120
    assert value.clock_status == ClockStatus.DAYLIGHT_SAVING_ACTIVE
    aware = value.to_datetime()
    assert aware.utcoffset() == dt.timedelta(hours=2)
    assert aware.astimezone(dt.timezone.utc) == dt.datetime(
        2026, 6, 5, 10, 37, 45, tzinfo=dt.timezone.utc
    )
    assert str(value) == "2026-06-05 12:37:45.00 +02:00"
    assert value.to_bytes() == KAIFA_DT


def test_inverted_deviation_for_misbehaving_meters():
    value = CosemDateTime.from_bytes(KAIFA_DT)
    assert value.to_datetime(invert_deviation=True).utcoffset() == dt.timedelta(hours=-2)


def test_wildcards():
    raw = bytes.fromhex("FFFF FF FF FF 0C FF FF FF 8000 FF".replace(" ", ""))
    value = CosemDateTime.from_bytes(raw)
    assert value.date == CosemDate()
    assert value.time == CosemTime(12, None, None, None)
    assert value.deviation is None
    assert value.clock_status is None
    assert not value.is_fully_specified
    assert value.to_bytes() == raw
    with pytest.raises(ValueError):
        value.to_datetime()


def test_naive_when_deviation_unspecified():
    raw = bytes.fromhex("07E6 0B 0C 06 10 36 00 00 8000 00".replace(" ", ""))
    value = CosemDateTime.from_bytes(raw)
    assert value.to_datetime() == dt.datetime(2022, 11, 12, 16, 54, 0)
    assert value.clock_status == ClockStatus(0)


def test_from_datetime_round_trip():
    src = dt.datetime(2024, 2, 29, 23, 59, 58, 120000, tzinfo=dt.timezone(dt.timedelta(hours=1)))
    value = CosemDateTime.from_datetime(src)
    assert value.deviation == -60
    assert value.date.day_of_week == 4  # Thursday
    assert CosemDateTime.from_bytes(value.to_bytes()).to_datetime() == src


def test_date_and_time_alone():
    assert CosemDate.from_bytes(bytes.fromhex("07E80102FF")) == CosemDate(2024, 1, 2, None)
    assert CosemTime.from_bytes(bytes.fromhex("0102030A")).to_time() == dt.time(1, 2, 3, 100000)
    assert str(CosemDate(None, 12, None)) == "*-12-*"


def test_special_month_not_a_concrete_date():
    with pytest.raises(ValueError):
        CosemDate(2024, 0xFE, 1).to_date()


@pytest.mark.parametrize("cls,size", [(CosemDateTime, 12), (CosemDate, 5), (CosemTime, 4)])
def test_wrong_length_rejected(cls, size):
    with pytest.raises(DecodeError):
        cls.from_bytes(bytes(size - 1))
    with pytest.raises(DecodeError):
        cls.from_bytes(bytes(size + 1))


@pytest.mark.parametrize("deviation", [0x7FFF, 721, -721, -0x7FFF])
def test_out_of_range_deviation_is_a_decode_error(deviation):
    import struct

    raw = KAIFA_DT[:9] + struct.pack(">h", deviation) + KAIFA_DT[11:]
    with pytest.raises(DecodeError, match="deviation"):
        CosemDateTime.from_bytes(raw)


@pytest.mark.parametrize("deviation", [-720, 720, 0, -0x8000])
def test_deviation_limits_and_not_specified_decode(deviation):
    import struct

    raw = KAIFA_DT[:9] + struct.pack(">h", deviation) + KAIFA_DT[11:]
    assert CosemDateTime.from_bytes(raw).to_bytes() == raw
