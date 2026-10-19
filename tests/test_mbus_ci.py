"""M-Bus frames with an M-Bus data header: CI 0x60/0x61/0x7C/0x7D.

Sources: OMS Vol. 2 Issue 5.0.1 Table 1 (CI,
direction, header type), Annex D.2/D.3 (field order), 7.2.4 Table 18
(two-octet configuration field, mode bits 12..8); Annex N N.2.2 (a wired
long-header frame, byte by byte, with its checksum). The DLMS vectors
below are hand-built from that layout: no public DLMS capture with a
header was found.
"""

from __future__ import annotations

import pytest

from pydlms.exceptions import ChecksumError, FramingError
from pydlms.explain import explain
from pydlms.mbus import (
    MbusFrame,
    MbusLongHeader,
    MbusReader,
    MbusShortHeader,
    MbusTransportHeader,
    decode_mbus_frame,
    encode_mbus_frame,
    segment_apdu,
)
from pydlms.push import PushDecoder

# OMS Vol. 2 Annex N, N.2.2 "M-Bus Meter with no encryption" (RSP-UD, CI 72h).
OMS_N22 = bytes.fromhex(
    "68202068 08 FD 72 78563412 9315 33 03 2A 00 0000"
    " 0C14270485 02 046D32371F15 02FD170000 89 16".replace(" ", "")
)

PUSH = bytes.fromhex("0f00000001000902abcd")  # data-notification, octet-string ABCD
GET = bytes.fromhex("c001c100030100010800ff0200")  # get-request-normal 1.0.1.8.0.255 attr 2

LONG_UP = MbusTransportHeader(
    "up", 0x2A, 0x00, 0x0000, identification=0x12345678, manufacturer=0x1593, version=1,
    device_type=2,
)  # fmt: skip
SHORT_UP = MbusTransportHeader("up", 0x2A, 0x00, 0x0000)
LONG_DOWN = MbusTransportHeader(
    "down", 0x2A, 0x00, 0x0000, identification=0x12345678, manufacturer=0x1593, version=1,
    device_type=2,
)  # fmt: skip
SHORT_DOWN = MbusTransportHeader("down", 0x2B, 0x00, 0x0000)

# Hand-built: 68 L L 68 | C A CI | header | STSAP DTSAP | APDU | CS 16, CS the
# sum of C..APDU mod 256 (checked independently in test_vectors_checksum).
VECTORS = [
    (
        0x7C,
        "681B1B6808017C78563412931501022A00000001670F00000001000902ABCD6916",
        MbusFrame(0x08, 0x01, 0x7C, 0x01, 0x67, PUSH, LONG_UP),
    ),
    (
        0x7D,
        "6813136808017D2A00000001670F00000001000902ABCDAB16",
        MbusFrame(0x08, 0x01, 0x7D, 0x01, 0x67, PUSH, SHORT_UP),
    ),
    (
        0x60,
        "681E1E6853016078563412931501022A0000001001C001C100030100010800FF02003E16",
        MbusFrame(0x53, 0x01, 0x60, 0x10, 0x01, GET, LONG_DOWN),
    ),
    (
        0x61,
        "681616685301612B0000001001C001C100030100010800FF02008116",
        MbusFrame(0x53, 0x01, 0x61, 0x10, 0x01, GET, SHORT_DOWN),
    ),
]
IDS = [f"ci{ci:02x}" for ci, _, _ in VECTORS]


def _with_ci(raw: bytes, ci: int) -> bytes:
    """Replace the CI octet of a long frame and recompute the checksum."""
    out = bytearray(raw)
    out[6] = ci
    out[-2] = sum(out[4:-2]) & 0xFF
    return bytes(out)


# --- the OMS example ----------------------------------------------------------


def test_oms_n22_checksum_and_length_rule():
    # L counts C..last data octet; CS is their sum mod 256 (0x89 in the spec).
    assert OMS_N22[1] == len(OMS_N22) - 6 == 0x20
    assert sum(OMS_N22[4:-2]) & 0xFF == OMS_N22[-2] == 0x89


def test_oms_n22_long_header_fields():
    h = MbusLongHeader.parse(OMS_N22[7:19])
    assert h.identification == 0x12345678  # BCD 12345678, LSB first
    assert h.manufacturer == 0x1593
    assert (h.version, h.device_type, h.access_number, h.status) == (0x33, 0x03, 0x2A, 0x00)
    assert h.configuration == 0x0000
    assert MbusLongHeader.build(h) == OMS_N22[7:19]
    assert MbusLongHeader.sizeof() == 12 and MbusShortHeader.sizeof() == 4


def test_oms_n22_m_bus_application_layer_is_not_dlms():
    with pytest.raises(FramingError, match="0x72"):
        decode_mbus_frame(OMS_N22)


def test_oms_n22_header_under_dlms_ci():
    # Same octets with CI 7Ch: the long header parses at the same offsets; the
    # next two octets are then taken as the transport SAPs.
    frame = decode_mbus_frame(_with_ci(OMS_N22, 0x7C))
    assert frame.header is not None and frame.header.long
    assert frame.header.direction == "up"
    assert frame.header.identification_number == "12345678"
    assert (frame.stsap, frame.dtsap) == (0x0C, 0x14)
    assert frame.data == OMS_N22[21:-2]


# --- hand-built vectors per CI --------------------------------------------------


@pytest.mark.parametrize(("ci", "hexstr", "frame"), VECTORS, ids=IDS)
def test_vectors_checksum(ci, hexstr, frame):
    raw = bytes.fromhex(hexstr)
    assert raw[6] == ci
    assert raw[1] == raw[2] == len(raw) - 6
    assert sum(raw[4:-2]) & 0xFF == raw[-2]


@pytest.mark.parametrize(("ci", "hexstr", "frame"), VECTORS, ids=IDS)
def test_vectors_decode(ci, hexstr, frame):
    assert decode_mbus_frame(bytes.fromhex(hexstr)) == frame


@pytest.mark.parametrize(("ci", "hexstr", "frame"), VECTORS, ids=IDS)
def test_vectors_encode(ci, hexstr, frame):
    assert encode_mbus_frame(frame) == bytes.fromhex(hexstr)


@pytest.mark.parametrize(("ci", "hexstr", "frame"), VECTORS, ids=IDS)
def test_header_frames_are_complete(ci, hexstr, frame):
    decoded = decode_mbus_frame(bytes.fromhex(hexstr))
    assert decoded.final and decoded.sequence == 0


def test_header_properties():
    assert LONG_UP.long and not SHORT_UP.long
    assert SHORT_UP.identification_number is None
    assert MbusTransportHeader("up", 0, 0, 0x0500).security_mode == 5
    assert MbusTransportHeader("up", 0, 0, 0x1F00).security_mode == 31
    assert MbusTransportHeader("up", 0, 0, 0xE0FF).security_mode == 0


# --- integrity ----------------------------------------------------------------


@pytest.mark.parametrize(("ci", "hexstr", "frame"), VECTORS, ids=IDS)
def test_every_byte_tamper_rejected(ci, hexstr, frame):
    raw = bytes.fromhex(hexstr)
    for pos in range(len(raw)):
        bad = bytearray(raw)
        bad[pos] ^= 0x01
        with pytest.raises((ChecksumError, FramingError)):
            decode_mbus_frame(bytes(bad))


@pytest.mark.parametrize(("ci", "hexstr", "frame"), VECTORS, ids=IDS)
def test_body_tamper_is_checksum_error(ci, hexstr, frame):
    raw = bytes.fromhex(hexstr)
    for pos in range(4, len(raw) - 2):
        bad = bytearray(raw)
        bad[pos] ^= 0x80
        with pytest.raises(ChecksumError):
            decode_mbus_frame(bytes(bad))


@pytest.mark.parametrize(("ci", "size"), [(0x7C, 12), (0x60, 12), (0x7D, 4), (0x61, 4)])
@pytest.mark.parametrize("keep", [0, 1])
def test_truncated_header(ci, size, keep):
    # Valid L and checksum, but the body ends inside the header or the SAPs
    # (keep=2 would be a valid frame with an empty APDU).
    body = bytes([0x08, 0x01, ci]) + bytes(size + keep)
    raw = bytes([0x68, len(body), len(body), 0x68]) + body + bytes([sum(body) & 0xFF, 0x16])
    with pytest.raises(FramingError, match="header"):
        decode_mbus_frame(raw)


@pytest.mark.parametrize("mode", range(1, 32))
def test_encrypted_configuration_refused(mode):
    raw = bytes.fromhex(VECTORS[0][1])
    bad = bytearray(raw)
    bad[18] = mode  # CF second octet BASMMMMM, mode bits 12..8
    bad[-2] = sum(bad[4:-2]) & 0xFF
    with pytest.raises(FramingError, match=f"security mode {mode}"):
        decode_mbus_frame(bytes(bad))


def test_oms_mode5_configuration_refused():
    # OMS Annex N N.4.2: configuration field 50 05 (mode 5, five blocks).
    raw = bytearray(bytes.fromhex(VECTORS[1][1]))
    raw[9:11] = b"\x50\x05"
    raw[-2] = sum(raw[4:-2]) & 0xFF
    with pytest.raises(FramingError, match="security mode 5"):
        decode_mbus_frame(bytes(raw))


def test_mode_specific_bits_without_mode_accepted():
    # Bits outside MMMMM (e.g. the hop counter/sync bits) do not encrypt.
    raw = bytearray(bytes.fromhex(VECTORS[1][1]))
    raw[9:11] = b"\x00\xe0"
    raw[-2] = sum(raw[4:-2]) & 0xFF
    assert decode_mbus_frame(bytes(raw)).header.configuration == 0xE000


# --- encode validation ----------------------------------------------------------


@pytest.mark.parametrize(
    "frame",
    [
        MbusFrame(0x08, 0x01, 0x7C, 1, 0x67, PUSH),  # header missing
        MbusFrame(0x08, 0x01, 0x10, 1, 0x67, PUSH, SHORT_UP),  # header on 0x10
        MbusFrame(0x08, 0x01, 0x7C, 1, 0x67, PUSH, SHORT_UP),  # short under long CI
        MbusFrame(0x08, 0x01, 0x7D, 1, 0x67, PUSH, LONG_UP),  # long under short CI
        MbusFrame(0x08, 0x01, 0x7C, 1, 0x67, PUSH, LONG_DOWN),  # direction
        MbusFrame(0x53, 0x01, 0x61, 1, 0x67, PUSH, SHORT_UP),  # direction
        MbusFrame(0x08, 0x01, 0x7D, 1, 0x67, PUSH, MbusTransportHeader("up", 0, 0, 0x0500)),
        MbusFrame(0x08, 0x01, 0x72, 1, 0x67, PUSH),  # not a DLMS CI
        MbusFrame(0x08, 0x01, 0x7C, 1, 0x67, bytes(239), LONG_UP),  # L > 255
    ],
)
def test_encode_refuses_inconsistent_frames(frame):
    with pytest.raises(ValueError):
        encode_mbus_frame(frame)


def test_encode_maximum_sizes():
    assert len(encode_mbus_frame(MbusFrame(8, 1, 0x7C, 1, 0x67, bytes(238), LONG_UP))) == 261
    assert len(encode_mbus_frame(MbusFrame(8, 1, 0x7D, 1, 0x67, bytes(246), SHORT_UP))) == 261
    with pytest.raises(ValueError):
        encode_mbus_frame(MbusFrame(8, 1, 0x7D, 1, 0x67, bytes(247), SHORT_UP))


def test_header_direction_validated():
    with pytest.raises(ValueError):
        MbusTransportHeader("sideways", 0, 0, 0)


# --- reader -------------------------------------------------------------------


def test_reader_returns_unsegmented_frames_immediately():
    reader = MbusReader()
    assert reader.feed(bytes.fromhex(VECTORS[0][1])) == [PUSH]
    assert reader.feed(bytes.fromhex(VECTORS[2][1])) == [GET]


def test_reader_mixed_segmented_and_header_stream():
    seg = segment_apdu(b"A" * 300, max_data=200)
    header = bytes.fromhex(VECTORS[1][1])
    reader = MbusReader()
    out = []
    # A header frame arrives inside a segmented message: it is delivered and
    # the half-built message is dropped (it can no longer complete in order).
    out += reader.feed(seg[0])
    out += reader.feed(header)
    out += reader.feed(seg[1])
    assert out == [PUSH]
    # Afterwards complete sequences of both kinds work, byte by byte too.
    stream = b"\xe5" + b"".join(seg) + header + b"".join(seg)
    for b in stream:
        out += reader.feed(bytes([b]))
    assert out == [PUSH, b"A" * 300, PUSH, b"A" * 300]


def test_reader_drops_encrypted_header_frame():
    raw = bytearray(bytes.fromhex(VECTORS[1][1]))
    raw[9:11] = b"\x50\x05"
    raw[-2] = sum(raw[4:-2]) & 0xFF
    reader = MbusReader()
    assert reader.feed(bytes(raw) + bytes.fromhex(VECTORS[1][1])) == [PUSH]
    assert reader.dropped == 1


def test_push_decoder_over_header_frame():
    messages = PushDecoder("mbus").feed(bytes.fromhex(VECTORS[0][1]))
    assert len(messages) == 1
    assert messages[0].records[0].data.value == b"\xab\xcd"


# --- explain ------------------------------------------------------------------


def test_explain_long_header():
    text = explain(bytes.fromhex(VECTORS[0][1]))
    assert "CI=0x7C (long header, up, unsegmented)" in text
    assert "ident 12345678 manufacturer 0x1593 version 1 device type 0x02" in text
    assert "ACC=0x2A STS=0x00 CF=0x0000 (no M-Bus encryption)" in text
    assert "DATA_NOTIFICATION" in text


def test_explain_short_header_and_refusal():
    good = bytes.fromhex(VECTORS[3][1])
    assert "CI=0x61 (short header, down, unsegmented)" in explain(good)
    bad = bytearray(bytes.fromhex(VECTORS[1][1]))
    bad[9:11] = b"\x50\x05"
    bad[-2] = sum(bad[4:-2]) & 0xFF
    assert "security mode 5" in explain(bytes(bad))
