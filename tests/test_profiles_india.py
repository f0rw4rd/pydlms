"""IS 15959 associations, event codes and event status word.

Sources (public BIS copies):
IS 15959:2011 Part 1 Tables 3, 6, 9, 11, 32-38 with Amendments 1, 2 and 5;
IS 15959 (Part 2):2016 Tables 2, 9, 10, A5-A10 with Amendment 1;
IS 15959 (Part 3):2017 Table 8. Hand-built vectors only (no capture).
"""

from __future__ import annotations

import pytest

from pydlms.cosem.data import DlmsData, decode_data, encode_data
from pydlms.exceptions import DecodeError
from pydlms.profiles import india
from pydlms.profiles.presets import get_preset
from pydlms.security.hls import Mechanism
from pydlms.security.suites import SecurityPolicy

# -- associations -------------------------------------------------------------


@pytest.mark.parametrize(
    "name,sap,mechanism,ciphered,association,setup",
    [
        ("is15959-pc", 16, Mechanism.NONE, False, "0.0.40.0.1.255", None),
        ("is15959-mr", 32, Mechanism.LLS, False, "0.0.40.0.2.255", None),
        ("is15959-us", 48, None, False, "0.0.40.0.3.255", None),  # default HLS 2
        ("is15959-sm-mr", 32, Mechanism.LLS, True, "0.0.40.0.2.255", "0.0.43.0.2.255"),
        ("is15959-sm-us", 48, None, True, "0.0.40.0.3.255", "0.0.43.0.3.255"),
        ("is15959-sm-push", 64, None, True, "0.0.40.0.4.255", "0.0.43.0.4.255"),
        ("is15959-sm-fw", 80, None, True, "0.0.40.0.5.255", "0.0.43.0.5.255"),
        ("is15959-sm-ihd", 96, None, True, "0.0.40.0.6.255", "0.0.43.0.6.255"),
    ],
)
def test_associations(name, sap, mechanism, ciphered, association, setup):
    preset = get_preset(name)
    assert preset is india.ASSOCIATIONS[name]
    assert (preset.client_sap, preset.server_logical) == (sap, 1)
    assert preset.mechanism is mechanism
    assert preset.ciphered is ciphered
    assert preset.association_obis == association
    assert preset.security_setup_obis == setup
    assert preset.security_suite == (0 if ciphered else None)


def test_security_setup_follows_part1_amendment_5_not_the_2011_table():
    # Part 1 Table 6 (2011) said 0.b.43.0.1/2.255; Amd 5 (2021) and Part 2
    # Table 2 say .2 (MR) and .3 (US).
    assert get_preset("is15959-sm-mr").security_setup_obis == "0.0.43.0.2.255"
    assert get_preset("is15959-sm-us").security_setup_obis == "0.0.43.0.3.255"


def test_smart_meter_security_policies():
    assert get_preset("is15959-sm-mr").security_policy is SecurityPolicy.ENCRYPTED
    assert get_preset("is15959-sm-us").security_policy is SecurityPolicy.AUTHENTICATED_ENCRYPTED
    assert get_preset("is15959-sm-fw").security_policy is SecurityPolicy.AUTHENTICATED_ENCRYPTED


@pytest.mark.parametrize("name", ["is15959-us", "is15959-sm-us", "is15959-sm-fw"])
def test_hls_defaults_to_mechanism_2(name):
    # The standard names no id; the Renesas IS 15959-2 reference meter
    # (RelySys/3-Phase-Smart-Meter@0cd9daf AssociationConfiguration.xml,
    # US and FW) and waseeldev/gosem@53a1580 (L&T and AEW US examples) use
    # mechanism 2 with AES-128-ECB of the challenge.
    preset = get_preset(name)
    assert preset.mechanism is None and preset.default_mechanism is Mechanism.HLS
    assert preset.client_kwargs()["mechanism"] is Mechanism.HLS


def test_hls_mechanism_can_be_chosen_by_the_caller():
    preset = get_preset("is15959-sm-us")
    assert preset.client_kwargs(Mechanism.HLS_GMAC) == {
        "client_sap": 48,
        "server_logical": 1,
        "mechanism": Mechanism.HLS_GMAC,
    }
    assert get_preset("is15959-us").client_kwargs(2)["mechanism"] is Mechanism.HLS
    assert get_preset("is15959-sm-mr").client_kwargs()["mechanism"] is Mechanism.LLS


@pytest.mark.parametrize("name", ["is15959-sm-push", "is15959-sm-ihd"])
def test_pre_established_associations_are_not_opened(name):
    assert get_preset(name).pre_established
    with pytest.raises(ValueError, match="pre-established"):
        get_preset(name).client_kwargs()


# -- event codes --------------------------------------------------------------

CATEGORY_CODES = {
    india.EventCategory.VOLTAGE: list(range(1, 13)),
    india.EventCategory.CURRENT: list(range(51, 71)),
    india.EventCategory.POWER: [101, 102],
    india.EventCategory.TRANSACTION: [*range(151, 168), 169, 177, 178],
    india.EventCategory.OTHER: list(range(201, 217)),
    india.EventCategory.NON_ROLLOVER: [251],
    india.EventCategory.CONTROL: [301, 302],
}


def test_every_defined_code_and_no_other():
    expected = {code: cat for cat, codes in CATEGORY_CODES.items() for code in codes}
    assert {code: e.category for code, e in india.EVENTS.items()} == expected


@pytest.mark.parametrize("code", [0, 13, 50, 71, 103, 150, 168, 170, 176, 179, 217, 252, 303])
def test_undefined_codes(code):
    assert india.event(code) is None


@pytest.mark.parametrize(
    "code,kind,text",
    [
        (1, "occurrence", "R-phase voltage missing"),
        (2, "restoration", "R-phase voltage missing cleared"),
        (69, "occurrence", "earth loading"),
        (101, "occurrence", "power failure"),
        (156, "single", "RS-485 device address changed"),
        (165, "single", "ESW filter changed"),
        (207, "occurrence", "single-wire operation (neutral missing)"),
        (216, "restoration", "overload cleared"),
        (251, "single", "meter cover opened"),
        (302, "single", "load connected"),
    ],
)
def test_event_details(code, kind, text):
    event = india.event(code)
    assert (event.code, event.kind, event.description) == (code, kind, text)
    assert event.source


def test_category_obis_codes():
    assert india.EventCategory.VOLTAGE.code_obis == "0.0.96.11.0.255"
    assert india.EventCategory.CONTROL.log_obis == "0.0.99.98.6.255"
    assert india.event(301).category.log_obis == "0.0.99.98.6.255"


# -- event status word --------------------------------------------------------


def _esw(*bits: int) -> bytes:
    raw = bytearray(16)
    for bit in bits:
        raw[bit // 8] |= 0x80 >> (bit % 8)
    return bytes(raw)


def test_esw_objects():
    assert (india.ESW_OBIS, india.ESWF_OBIS, india.ESW_LENGTH) == (
        "0.0.94.91.18.255",
        "0.0.94.91.26.255",
        128,
    )


def test_esw_bit_table():
    assert sorted(india.ESW_BITS) == [*range(13), 51, 81, 82, 83, 84, 85, 86, 87]
    assert india.ESW_BITS[0].events == (1, 2) and india.ESW_BITS[0].meters == "3-phase"
    # Amendment 1 moved 3, 4 and 11 to the common list.
    assert {india.ESW_BITS[b].meters for b in (3, 4, 11)} == {"common"}
    assert india.ESW_BITS[51].events == (69, 70) and india.ESW_BITS[51].meters == "1-phase"
    assert india.ESW_BITS[83].events == (251,)
    assert india.ESW_BITS[84].events == (301, 302)
    assert india.ESW_BITS[85].events == () and "last gasp" in india.ESW_BITS[85].description


def test_decode_esw_from_a_pushed_bit_string():
    # bit 0 (R-phase voltage) and bit 84 (load switch): octet 0 = 0x80,
    # octet 10 = 0x08. A-XDR bit-string: tag 04, length 81 80 (128 bits).
    wire = bytes.fromhex("048180") + _esw(0, 84)
    assert wire.hex() == "048180" + "80" + "00" * 9 + "08" + "00" * 5
    data, consumed = decode_data(wire)
    assert consumed == len(wire)
    bits = india.decode_esw(data)
    assert [b.bit for b in bits] == [0, 84]
    assert bits[0].events == (1, 2)
    assert encode_data(data) == wire


def test_meter_side_filter_layout_decodes_to_assigned_bits():
    # The Renesas IS 15959-2 reference meter (RelySys/3-Phase-Smart-Meter
    # @0cd9daf r_dlms_event.c) sets ESW bit n as octet n // 8, mask
    # 0x80 >> n % 8, and serves the octets as they are; its default ESWF
    # (r_dlms_factory_config.h) has 0x18, 0x10 at octets 0, 1, 0x10 at 6 and
    # 0x7F at 10. Read MSB first that is exactly assigned bits; LSB first
    # it would be 12, 52 and 80, which no table assigns.
    raw = bytearray(16)
    raw[0], raw[1], raw[6], raw[10] = 0x18, 0x10, 0x10, 0x7F
    bits = india.decode_esw(bytes(raw))
    assert [b.bit for b in bits] == [3, 4, 11, 51, *range(81, 88)]
    assert all(b.meters != "unassigned" for b in bits)


def test_decode_esw_from_raw_octets_and_flags():
    assert [b.bit for b in india.decode_esw(_esw(12, 51, 87))] == [12, 51, 87]
    flags = [False] * 128
    flags[85] = True
    assert india.decode_esw(flags)[0].description.startswith("last gasp")
    assert india.decode_esw(bytes(16)) == []


def test_unassigned_bits_are_reported_not_dropped():
    (bit,) = india.decode_esw(_esw(100))
    assert (bit.bit, bit.meters, bit.events) == (100, "unassigned", ())


@pytest.mark.parametrize("value", [bytes(15), bytes(17), [True] * 127, b""])
def test_wrong_esw_length_is_refused(value):
    with pytest.raises(DecodeError, match="128 bits"):
        india.decode_esw(value)


def test_esw_must_be_a_bit_string():
    with pytest.raises(DecodeError, match="bit-string"):
        india.decode_esw(DlmsData.octet_string(bytes(16)))


def test_truncated_bit_string_does_not_decode():
    with pytest.raises(DecodeError):
        decode_data(bytes.fromhex("048180") + bytes(15))
