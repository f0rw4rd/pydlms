"""Wiener Netze customer interface: positional labels by list length.

Source: Wiener Netze, "Smart Meter Kundenschnittstelle" (the DSO's interface
description, wienernetze.at/smart-meter-kundenschnittstelle, read
2026-10-16): push of 0-X:25.9.0.255 attribute 2; Landis+Gyr and Iskraemeco
send the clock and eight registers (9 values), Siemens the serial number
0-0:96.1.1 first (10 values); octet-string(12) clock, unsigned32 values.
The DSO publishes no scaler or unit; scaler 0 with Wh, varh, W and var comes
from two independent MIT-licensed decoders tested on Wiener Netze meters
(bernikr/esphome-wienernetze-smartmeter@0c8f3d6 wienernetze.cpp,
tofuSCHNITZEL/wiener_netze_smartmeter@0c2ea2e meter_data.py). No capture is
vendored: the vectors below are hand-built from those descriptions
"""

from __future__ import annotations

import datetime as dt

from pydlms.cosem.data import DlmsData as D
from pydlms.cosem.enums import Unit
from pydlms.cosem.time import CosemDateTime
from pydlms.obis import ObisCode
from pydlms.profiles import get_profile
from pydlms.push import PushRecord, extract_records

PROFILE = get_profile("wiener-netze")
STAMP = CosemDateTime.from_datetime(
    dt.datetime(2026, 10, 16, 12, 0, tzinfo=dt.timezone(dt.timedelta(hours=2)))
).to_bytes()
REGISTERS = [
    "1.0.1.8.0.255",
    "1.0.2.8.0.255",
    "1.0.3.8.0.255",
    "1.0.4.8.0.255",
    "1.0.1.7.0.255",
    "1.0.2.7.0.255",
    "1.0.3.7.0.255",
    "1.0.4.7.0.255",
]
VALUES = [D.uint32(v) for v in (1234567, 0, 2345, 6789, 512, 0, 30, 0)]


def apply(values):
    return PROFILE.apply(extract_records(D.structure(values)))


def test_landis_gyr_and_iskraemeco_list():
    records = apply([D.octet_string(STAMP), *VALUES])
    assert [str(r.obis) for r in records] == ["0.0.1.0.0.255", *REGISTERS]
    assert records[1].value == 1234567
    assert records[0].datetime is not None


def test_siemens_list_leads_with_the_serial_number():
    records = apply([D.octet_string(b"1SIE0012345678AB"), D.octet_string(STAMP), *VALUES])
    assert [str(r.obis) for r in records] == ["0.0.96.1.1.255", "0.0.1.0.0.255", *REGISTERS]


UNITS = [Unit.WATT_HOUR] * 2 + [Unit.VAR_HOUR] * 2 + [Unit.WATT] * 2 + [Unit.VAR] * 2


def test_registers_are_whole_wh_varh_w_var():
    records = apply([D.octet_string(STAMP), *VALUES])
    assert records[0].scaler == 0 and records[0].unit is None
    assert [(r.scaler, r.unit) for r in records[1:]] == [(0, u) for u in UNITS]
    # +A 1234567 Wh is printed as 1234.567 kWh by both decoders: scaler 0.
    assert records[1].value == 1234567


def test_siemens_serial_has_no_unit():
    records = apply([D.octet_string(b"1SIE0012345678AB"), D.octet_string(STAMP), *VALUES])
    assert records[0].unit is None and records[1].unit is None
    assert [r.unit for r in records[2:]] == UNITS


def test_other_lengths_and_labelled_payloads_are_left_alone():
    short = apply([D.octet_string(STAMP), *VALUES[:7]])
    assert all(r.obis is None for r in short)
    labelled = [PushRecord(ObisCode.parse("0.0.96.1.0.255"), v) for v in VALUES[:1]]
    labelled += [PushRecord(None, v) for v in [D.octet_string(STAMP), *VALUES[1:]]]
    assert len(labelled) == 9
    assert PROFILE.apply(labelled) == labelled
