"""IEC 62056-21 command messages ``SOH C D [STX data] ETX BCC``.

The B0/B1 vectors are computed from the clause 6.3 BCC rule (XOR of every
character after SOH up to and including ETX) and match the messages
cB-Sigma's iec6205621 package builds with ``Block("B0", "", false, ETX)``.
The clause text itself was not read (unverified).
"""

from __future__ import annotations

import pytest

from pydlms.exceptions import ChecksumError, FramingError
from pydlms.transports import iec62056_21, serial
from pydlms.transports.iec62056_21 import (
    BREAK,
    SIGN_OFF,
    CommandMessage,
    build_command,
    parse_command,
)

B0 = bytes.fromhex("0142300371")
B1 = bytes.fromhex("0142310370")
# R1 read of 1.8.0: SOH R1 STX 1.8.0() ETX BCC
R1 = b"\x01R1\x021.8.0()\x03" + bytes(
    [0x52 ^ 0x31 ^ 0x02 ^ 0x03 ^ 0x31 ^ 0x2E ^ 0x38 ^ 0x2E ^ 0x30 ^ 0x28 ^ 0x29]
)


def test_serial_reexports_the_moved_names():
    for name in iec62056_21.__all__:
        if hasattr(serial, name):
            assert getattr(serial, name) is getattr(iec62056_21, name)
    assert serial.DataMessage is iec62056_21.DataMessage
    assert serial.parse_identification is iec62056_21.parse_identification


@pytest.mark.parametrize(
    "raw,command,data",
    [
        (B0, "B0", None),
        (B1, "B1", None),
        (R1, "R1", b"1.8.0()"),
        (b"\x01P0\x02\x03\x61", "P0", b""),
    ],
    ids=["B0", "B1", "R1", "P0-empty-data"],
)
def test_known_vectors(raw, command, data):
    assert build_command(command, data) == raw
    assert parse_command(raw) == (command, data)


def test_break_and_sign_off_constants():
    assert BREAK == B0 and SIGN_OFF == B1


@pytest.mark.parametrize("raw", [B0, B1, R1])
def test_construct_round_trip(raw):
    parsed = CommandMessage.parse(raw)
    assert CommandMessage.build({"body": {"value": parsed.body.value}}) == raw


@pytest.mark.parametrize("raw", [B0, B1, R1])
@pytest.mark.parametrize("position", range(1, 5))
def test_any_corrupted_octet_rejected(raw, position):
    corrupted = bytearray(raw)
    corrupted[position] ^= 0x40
    with pytest.raises(FramingError):  # ChecksumError is a FramingError
        parse_command(bytes(corrupted))


@pytest.mark.parametrize("raw", [B0, B1])
def test_bad_bcc_is_a_checksum_error(raw):
    with pytest.raises(ChecksumError, match="BCC"):
        parse_command(raw[:-1] + bytes([raw[-1] ^ 0x01]))


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        B0[:1],
        B0[:3],  # no ETX
        B0[:-1],  # no BCC
        B0 + b"\x00",  # trailing octet
        B0[1:],  # no SOH
        b"\x02B0\x03\x71",  # STX is a data message, not a command
        b"\x01B0\r\n",  # Gurux-style break without ETX/BCC
        b"\x01R1\x021.8.0()",  # data without ETX
        b"\x01B\x00\x03\x41",  # command identifier not printable
    ],
)
def test_malformed_rejected(raw):
    with pytest.raises(FramingError):
        parse_command(raw)


@pytest.mark.parametrize(
    "command,data",
    [("B", None), ("B00", None), ("B\x03", None), ("R1", b"1.8.0\x03"), ("R1", b"\xb5")],
)
def test_build_rejects_bad_fields(command, data):
    with pytest.raises(ValueError):
        build_command(command, data)
