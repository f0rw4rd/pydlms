"""Values checked against public restatements of the DLMS/COSEM and IEC
62056 clauses (third verification pass, 2026-10-17).

Sources and legal basis:

* GB5 / GB6: DLMS UA 1000-2 Ed. 5 (2005) and Ed. 6 (2007) excerpts (Green
  Book), published by the DLMS UA on dlms.com, read from the Wayback
  Machine: clause 6 (mode E sign-on, Figure 17) and 8.4.2.3 (reserved HDLC
  addresses, Table 2, Figure 21).
* SPODES: PJSC Rosseti corporate standard STO 34.01-5.1-006-2019 "Electricity
  meters. Requirements for the information model of data exchange"
  (version 2), published by Rosseti on rosseti.ru: 7.4.12 (Association LN
  access modes), 7.4.15 / Table 7.19 (IEC HDLC setup, reserved addresses),
  9.8 (SNRM/UA negotiation), 10.3.3 Table 10.3 (HLS GMAC example), 12
  Table 12.1 (HDLC trace).

The values below are typed from the printed text, not from pydlms.
"""

from __future__ import annotations

import pytest

from pydlms.cosem.access import AttributeAccessMode, MethodAccessMode
from pydlms.hdlc.address import HdlcAddress, decode_address, encode_address
from pydlms.hdlc.connection import HdlcParameters, parameter_field, parse_parameter_field
from pydlms.hdlc.framing import FrameType, decode_frame
from tests.test_transports import LGZ_ACK, LGZ_IDENT, _optical

# --- SPODES 7.4.12: Association LN (IC 15 version 1) access rights ---------------------

SPODES_ATTRIBUTE_ACCESS = {
    0: "no_access",
    1: "read_only",
    2: "write_only",
    3: "read_and_write",
    4: "authenticated_read_only",
    5: "authenticated_write_only",
    6: "authenticated_read_and_write",
}
SPODES_METHOD_ACCESS = {0: "no_access", 1: "access", 2: "authenticated_access"}


def test_attribute_access_modes_match_spodes_7_4_12():
    assert {m.value: m.name.lower() for m in AttributeAccessMode} == SPODES_ATTRIBUTE_ACCESS


def test_method_access_modes_match_spodes_7_4_12():
    assert {m.value: m.name.lower() for m in MethodAccessMode} == SPODES_METHOD_ACCESS


# --- GB6 8.4.2.3 Table 2 / Figure 21, SPODES Table 7.19: reserved addresses ------------


def test_four_octet_address_example_of_green_book_ed6_figure_21():
    """Upper 0x1234, lower 0x3FFF (all-station) and client 0x3A, printed
    bit by bit in GB6 Figure 21 (low-order bit = extension bit)."""
    server = HdlcAddress(0x1234, 0x3FFF, 4)
    expected = bytes([0b01001000, 0b01101000, 0b11111110, 0b11111111])
    assert encode_address(server) == expected
    assert decode_address(expected) == server
    assert encode_address(HdlcAddress.client(0x3A)) == bytes([0b01110101])


@pytest.mark.parametrize(
    ("one_octet", "two_octet"),
    [
        (0x00, 0x0000),  # no-station
        (0x01, 0x0001),  # management logical device
        (0x7E, 0x3FFE),  # CALLING physical device
        (0x7F, 0x3FFF),  # all-station (broadcast)
    ],
)
def test_reserved_addresses_fit_each_address_size(one_octet, two_octet):
    """GB6 Table 2 and SPODES Table 7.19: each reserved one-octet value has a
    14-bit counterpart (0x7F <-> 0x3FFF); both are the top of their range."""
    assert HdlcAddress(1, one_octet, 2).lower == one_octet
    assert HdlcAddress(1, two_octet, 4).lower == two_octet
    with pytest.raises(ValueError):
        HdlcAddress(1, 0x80, 2)
    with pytest.raises(ValueError):
        HdlcAddress(1, 0x4000, 4)


# --- SPODES 9.8 and Table 12.1: SNRM/UA parameter field ---------------------------------


def test_default_parameter_field_of_spodes_9_8_decodes_to_the_defaults():
    field = bytes.fromhex("81800C050180060180070101080101")
    params, user_data = parse_parameter_field(field)
    assert params == HdlcParameters(max_info_tx=128, max_info_rx=128, window_tx=1, window_rx=1)
    assert user_data == b""


def test_parameter_field_with_four_octet_windows_matches_spodes_table_12_1():
    """The UA of SPODES Table 12.1 carries the windows on four octets each
    (``07 04 00000001 08 04 00000001``): every parameter has its own length,
    and pydlms builds the same field for the defaults."""
    field = bytes.fromhex("818012050180060180070400000001080400000001")
    assert parse_parameter_field(field)[0] == HdlcParameters()
    assert parameter_field(HdlcParameters()) == field
    proposed = bytes.fromhex("818012050180060180070400000007080400000007")
    assert parse_parameter_field(proposed)[0] == HdlcParameters(window_tx=7, window_rx=7)


# Frames of SPODES Table 12.1 / 12.2 whose HCS and FCS are printed intact
# (several longer frames of the table lost octets in typesetting).
SPODES_TRACE = [
    ("7EA00802212153 09177E", FrameType.DISC, 0x10, 0x10),
    ("7EA0082102211FA0D97E", FrameType.DM, 0x10, 0x10),
    ("7EA0080221219305D17E", FrameType.SNRM, 0x10, 0x10),
    ("7EA00821022173CA707E", FrameType.UA, 0x10, 0x10),
    ("7EA0080221419350B47E", FrameType.SNRM, 0x20, 0x10),
    ("7EA008410221732EE97E", FrameType.UA, 0x20, 0x10),
]


@pytest.mark.parametrize(("hex_frame", "kind", "client", "physical"), SPODES_TRACE)
def test_spodes_table_12_frames_decode(hex_frame, kind, client, physical):
    frame = decode_frame(bytes.fromhex(hex_frame.replace(" ", "")))
    assert frame.kind == kind
    addresses = {frame.dest, frame.src}
    assert HdlcAddress.client(client) in addresses
    assert HdlcAddress(1, physical, 2) in addresses


def test_spodes_table_12_get_request_and_response_decode():
    request = decode_frame(
        bytes.fromhex("7EA01A0221213478A2E6E600C001C1000F0000280000FF0100F9797E")
    )
    assert request.kind == FrameType.I and request.info[3:6] == bytes.fromhex("C001C1")
    response = decode_frame(bytes.fromhex("7EA0192102217247DEE6E700C401C10009060000280000FFB66E7E"))
    assert response.info.endswith(bytes.fromhex("09060000280000FF"))


# --- GB5 Figure 17: mode E switch confirmation sent with its parity bit ----------------


def test_mode_e_confirmation_of_green_book_ed5_figure_17(monkeypatch):
    """GB5 Figure 17 prints the server's confirmation after the switch to
    9600 Bd 8N1 as ``06H B2H 35H B2H 8DH 0AH``: ``ACK 2 5 2 CR LF`` with the
    even parity bit kept in bit 7 (GB8 6.2: "the same structure as the
    acknowledgement/option select message ... still with parity (7E1)")."""
    monkeypatch.setattr("pydlms.transports.serial.time.sleep", lambda s: None)
    t = _optical({b"/?!\r\n": LGZ_IDENT, LGZ_ACK: bytes.fromhex("06B235B28D0A")})
    t.sign_on()
    assert t._serial.rx == b""
    assert t._serial.baudrate == 9600


# --- SPODES 10.3.3 Table 10.3: HLS mechanism 5 (GMAC) example ---------------------------


def test_hls_gmac_example_of_spodes_table_10_3():
    """Same values as the Green Book example in ``tests/crypto/vectors.py``;
    SPODES prints them independently, step by step."""
    pytest.importorskip("cryptography")
    from pydlms.security.hls import hls_gmac

    ek = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    ak = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")
    f_stoc = hls_gmac(ek, ak, bytes.fromhex("4D4D4D0000000001"), 0x00000001, b"P6wRJ21F")
    assert f_stoc == bytes.fromhex("10000000011A52FE7DD3E72748973C1E28")
    f_ctos = hls_gmac(ek, ak, bytes.fromhex("4D4D4D0000BC614E"), 0x01234567, b"K56iVagY")
    assert f_ctos == bytes.fromhex("1001234567FE1466AFB3DBCD4F9389E2B7")
