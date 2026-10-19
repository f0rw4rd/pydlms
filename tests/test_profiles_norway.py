"""Kaifa KFM_001 compact lists: the layout follows the list length.

Source: Kaifa "Norwegian HAN spesification - OBIS Codes", KFM_001,
list version 09.11.2018 (published by NEK). Only the 13-value 3-phase
list 2 has a capture (``hdlc_kaifa_ma304h3e``, tests/meters); the other
layouts are documentation-only and built synthetically here.
"""

from __future__ import annotations

import datetime as dt

from pydlms.cosem.data import DlmsData as D
from pydlms.cosem.enums import Unit
from pydlms.cosem.time import CosemDateTime
from pydlms.profiles import get_profile
from pydlms.push import extract_records

PROFILE = get_profile("kaifa-han-no")
HEAD = [D.visible_string("KFM_001"), D.visible_string("6970631400000000")]
STAMP = CosemDateTime.from_datetime(
    dt.datetime(2024, 5, 1, 15, 0, tzinfo=dt.timezone(dt.timedelta(hours=2)))
).to_bytes()
ENERGY = [D.uint32(100), D.uint32(200), D.uint32(300), D.uint32(400)]


def apply(values):
    return PROFILE.apply(extract_records(D.structure(values)))


def obis(records):
    return [str(r.obis) for r in records]


def test_list_1_is_active_power_only():
    (record,) = apply([D.uint32(1234)])
    assert str(record.obis) == "1.0.1.7.0.255" and record.unit == Unit.WATT
    assert record.value == 1234


def test_single_phase_list_2():
    records = apply(
        [*HEAD, D.visible_string("MA105H2E")]
        + [D.uint32(1234), D.uint32(0), D.uint32(0), D.uint32(200), D.uint32(5123), D.uint32(2301)]
    )
    assert obis(records)[3:] == [
        "1.0.1.7.0.255",
        "1.0.2.7.0.255",
        "1.0.3.7.0.255",
        "1.0.4.7.0.255",
        "1.0.31.7.0.255",
        "1.0.32.7.0.255",
    ]
    assert records[-2].value == 5.123 and records[-2].unit == Unit.AMPERE
    assert records[-1].value == 230.1 and records[-1].unit == Unit.VOLT


def test_single_phase_list_3_adds_clock_and_energies():
    list_2 = [*HEAD, D.visible_string("MA105H2E")] + [D.uint32(i) for i in range(6)]
    records = apply(list_2 + [D.octet_string(STAMP), *ENERGY])
    assert len(records) == 14
    assert obis(records)[9:] == [
        "0.0.1.0.0.255",
        "1.0.1.8.0.255",
        "1.0.2.8.0.255",
        "1.0.3.8.0.255",
        "1.0.4.8.0.255",
    ]
    assert str(records[9].value) == "2024-05-01 15:00:00.00 +02:00"
    assert records[10].unit == Unit.WATT_HOUR and records[12].unit == Unit.VAR_HOUR


def test_three_phase_list_3():
    list_2 = [*HEAD, D.visible_string("MA304H3E")] + [D.uint32(i) for i in range(10)]
    records = apply(list_2 + [D.octet_string(STAMP), *ENERGY])
    assert obis(records)[7:13] == [
        "1.0.31.7.0.255",
        "1.0.51.7.0.255",
        "1.0.71.7.0.255",
        "1.0.32.7.0.255",
        "1.0.52.7.0.255",
        "1.0.72.7.0.255",
    ]
    assert obis(records)[13:] == [
        "0.0.1.0.0.255",
        "1.0.1.8.0.255",
        "1.0.2.8.0.255",
        "1.0.3.8.0.255",
        "1.0.4.8.0.255",
    ]


def test_unknown_length_stays_unlabelled():
    records = apply([D.uint32(1), D.uint32(2)])
    assert [r.obis for r in records] == [None, None]
