"""IEC 62056-21 mode C data readout (clause 6.3): message parsing and the transport.

The meter side is a scripted fake serial port; the vectors are hand-built from
the clause 6.3 message structure, not captures.
"""

from __future__ import annotations

import pytest

from pydlms.exceptions import ChecksumError, DlmsTimeoutError, FramingError, ProtocolError
from pydlms.transports.serial import (
    DataMessage,
    OpticalTransport,
    ReadoutDataSet,
    ReadoutValue,
    block_check_character,
    parse_data_message,
    read_mode_c,
)
from tests.test_transports import FakePort

BLOCK = (
    b"0.0.0(12345678)\r\n"
    b"1.8.0(001234.5*kWh)2.8.0(000010.0*kWh)\r\n"
    b"F.F(00000000)\r\n"
    b"P.01(2410120000)(00)(15)(1)(1.5)(kWh)\r\n"
    b"0.9.1(123456)\r\n"
)


def message(block: bytes = BLOCK, end: bytes = b"!\r\n") -> bytes:
    body = block + end + b"\x03"
    return b"\x02" + body + bytes([block_check_character(body)])


GOOD = message()


# --- message parsing ---------------------------------------------------------------


def test_bcc_is_xor_after_stx_through_etx():
    # "!" ^ CR ^ LF ^ ETX = 0x21 ^ 0x0D ^ 0x0A ^ 0x03 = 0x25
    assert message(b"") == b"\x02!\r\n\x03\x25"


def test_construct_round_trip():
    parsed = DataMessage.parse(GOOD)
    assert DataMessage.build({"body": {"value": parsed.body.value}}) == GOOD


def test_parse_data_message():
    sets = parse_data_message(GOOD)
    assert sets[0] == ReadoutDataSet("0.0.0", (ReadoutValue("12345678"),))
    assert sets[1].address == "1.8.0" and sets[1].value == "001234.5" and sets[1].unit == "kWh"
    assert sets[2] == ReadoutDataSet("2.8.0", (ReadoutValue("000010.0", "kWh"),))
    profile = sets[4]
    assert profile.address == "P.01"
    assert [v.value for v in profile.values] == ["2410120000", "00", "15", "1", "1.5", "kWh"]
    assert [s.address for s in sets] == ["0.0.0", "1.8.0", "2.8.0", "F.F", "P.01", "0.9.1"]


def test_parse_empty_block_and_addressless_line():
    assert parse_data_message(message(b"")) == ()
    assert parse_data_message(message(b"(42*V)\r\n")) == (
        ReadoutDataSet("", (ReadoutValue("42", "V"),)),
    )


@pytest.mark.parametrize(
    "raw,error",
    [
        (b"", FramingError),
        (GOOD[1:], FramingError),  # no STX
        (GOOD[:-2], FramingError),  # no ETX, no BCC
        (GOOD[:-1], FramingError),  # BCC missing
        (GOOD + b"\x00", FramingError),  # trailing octet
        (GOOD[:-1] + bytes([GOOD[-1] ^ 0x01]), ChecksumError),
        (message(end=b"\r\n"), FramingError),  # no "!" end of block
        (message(b"1.8.0(12\r\n"), FramingError),  # unclosed value
        (message(b"1.8.0 12\r\n"), FramingError),  # no brackets
        (message(b"1.8.0(1)x\r\n"), FramingError),  # trailing junk on a line
        (message(b"1.8.0(1*k*W)\r\n"), FramingError),  # two units
        (message(b"1.8.0(1)\r2.8.0(2)\r\n"), FramingError),  # bare CR
        (message(b"1.8.0(\xb5)\r\n"), FramingError),  # non-ASCII
        (message(b"1.8.0(" + b"9" * 1100 + b")\r\n"), FramingError),  # line too long
        (b"\x02" + b"0" * (64 * 1024) + b"\x03\x00", FramingError),  # message too large
    ],
)
def test_parse_data_message_rejects(raw, error):
    with pytest.raises(error):
        parse_data_message(raw)


@pytest.mark.parametrize("position", range(len(GOOD)))
def test_any_corrupted_octet_rejected(position):
    raw = bytearray(GOOD)
    raw[position] ^= 0x40
    with pytest.raises(FramingError):  # ChecksumError is a FramingError
        parse_data_message(bytes(raw))


# --- transport ---------------------------------------------------------------------


class ModeCPort(FakePort):
    """A mode C meter: the data message only arrives at the agreed baud, 7E1."""

    def __init__(self, ident: bytes, data: bytes, ack: bytes, baud: int, fmt=(7, "E")):
        super().__init__({b"/?!\r\n": ident})
        self.ack, self.data, self.target = ack, data, (baud, *fmt)
        self.pending = b""

    def write(self, data):
        super().write(data)
        if data == self.ack:
            self.pending = self.data

    def apply_settings(self, settings):
        super().apply_settings(settings)
        if (self.baudrate, self.bytesize, self.parity) == self.target and self.pending:
            self.rx += self.pending
            self.pending = b""


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr("pydlms.transports.serial.time.sleep", lambda s: None)


def _transport(port, **kw):
    transport = OpticalTransport("fake", timeout=0.2, **kw)
    transport._serial = port
    return transport


def test_mode_c_readout_switches_baud_after_ack():
    port = ModeCPort(b"/LGZ5ZMD3104100.B23\r\n", GOOD, b"\x06050\r\n", 9600)
    readout = _transport(port).read_mode_c()
    assert port.written == [b"/?!\r\n", b"\x06050\r\n"]
    # Request and option-select ACK both went out at 300 baud 7E1 ...
    assert port.settings == [(300, 7, "E"), (300, 7, "E")]
    # ... and the port stays 7E1 at the announced rate for the data message.
    assert (port.baudrate, port.bytesize, port.parity) == (9600, 7, "E")
    assert readout.identification.manufacturer == "LGZ"
    assert readout.identification.identification == "ZMD3104100.B23"
    assert readout.get("1.8.0").value == "001234.5" and readout.get("1.8.0").unit == "kWh"
    assert readout.get("9.9.9") is None
    assert len(readout.data_sets) == 6


def test_mode_c_without_baud_switch_gets_nothing():
    """The data only arrives after the switch: skipping it is a timeout."""
    port = ModeCPort(b"/LGZ5X\r\n", GOOD, b"\x06050\r\n", 9600)
    transport = _transport(port)
    transport.reconfigure = lambda *a, **k: None
    with pytest.raises(DlmsTimeoutError, match="after 0 octets"):
        transport.read_mode_c()


def test_mode_c_enhanced_identification_and_baud_cap():
    port = ModeCPort(b"/ISK6\\2MT382\r\n", GOOD, b"\x06040\r\n", 4800)
    readout = _transport(port, max_baud=4800).read_mode_c()
    assert port.written[-1] == b"\x06040\r\n"  # 19200 offered, 4800 selected
    assert readout.identification.mode_e and port.baudrate == 4800


def test_mode_c_at_300_baud_and_device_address():
    port = ModeCPort(b"/ABC0X\r\n", GOOD, b"\x06000\r\n", 300)
    port.replies = {b"/?12345678!\r\n": b"/ABC0X\r\n"}
    transport = _transport(port, device_address="12345678")
    assert len(transport.read_mode_c().data_sets) == 6
    assert port.written == [b"/?12345678!\r\n", b"\x06000\r\n"]


def test_mode_c_second_readout_signs_on_at_300_again():
    port = ModeCPort(b"/LGZ5X\r\n", GOOD, b"\x06050\r\n", 9600)
    transport = _transport(port)
    transport.read_mode_c()
    transport.read_mode_c()
    assert port.written == [b"/?!\r\n", b"\x06050\r\n"] * 2
    assert port.settings == [(300, 7, "E")] * 4


@pytest.mark.parametrize(
    "ident", [b"/LGZA\\2X\r\n", b"/LGZ9X\r\n"], ids=["mode-b-letter", "reserved-digit"]
)
def test_mode_c_baud_char_outside_table(ident):
    port = ModeCPort(ident, GOOD, b"", 9600)
    with pytest.raises(ProtocolError, match="baud character"):
        _transport(port).read_mode_c()
    assert port.written == [b"/?!\r\n"]  # no ACK for a rate we cannot select


@pytest.mark.parametrize("ident", [b"LGZ5X\r\n", b"/L5\r\n"])
def test_mode_c_malformed_identification(ident):
    port = ModeCPort(ident, GOOD, b"", 9600)
    with pytest.raises(ProtocolError):
        _transport(port).read_mode_c()


def test_mode_c_identification_line_too_long():
    port = ModeCPort(b"/LGZ5" + b"X" * 200 + b"\r\n", GOOD, b"", 9600)
    with pytest.raises(ProtocolError, match="longer than"):
        _transport(port).read_mode_c()


@pytest.mark.parametrize(
    "data,error,match",
    [
        (GOOD[:-1] + bytes([GOOD[-1] ^ 0x01]), ChecksumError, "BCC"),
        (GOOD[:40], DlmsTimeoutError, "after 40 octets"),  # truncated, no ETX
        (b"\x15", FramingError, "STX"),  # NAK instead of a data message
        (message(b"1.8.0(1\r\n"), FramingError, "malformed"),
    ],
    ids=["bcc", "truncated", "no-stx", "bad-line"],
)
def test_mode_c_bad_data_message(data, error, match):
    port = ModeCPort(b"/LGZ5X\r\n", data, b"\x06050\r\n", 9600)
    with pytest.raises(error, match=match):
        _transport(port).read_mode_c()


def test_mode_c_strips_parity_bit_from_8n1_bridge():
    with_parity = bytes(b | 0x80 if i % 3 == 0 else b for i, b in enumerate(GOOD))
    port = ModeCPort(b"/LGZ5X\r\n", with_parity, b"\x06050\r\n", 9600, fmt=(8, "N"))
    port.bytesize, port.parity = 8, "N"
    transport = _transport(port, sign_on_bytesize=8, sign_on_parity="N")
    assert parse_data_message(GOOD) == transport.read_mode_c().data_sets


def test_read_mode_c_function_opens_and_closes(monkeypatch):
    pytest.importorskip("serial")
    port = ModeCPort(b"/LGZ5X\r\n", GOOD, b"\x06050\r\n", 9600)
    opened = []
    closed = []
    port.close = lambda: closed.append(True)

    def fake_open(url, **kw):
        opened.append((url, kw))
        return port

    monkeypatch.setattr("serial.serial_for_url", fake_open)
    readout = read_mode_c("/dev/ttyUSB0", timeout=0.2)
    assert opened == [
        (
            "/dev/ttyUSB0",
            {"baudrate": 300, "bytesize": 7, "parity": "E", "stopbits": 1, "timeout": 0},
        )
    ]
    assert closed == [True]
    assert readout.get("0.0.0").value == "12345678"


class EchoModeCPort(ModeCPort):
    """Mode C meter behind a half-duplex converter that echoes our lines."""

    def write(self, data):
        self.rx += data
        super().write(data)


def test_mode_c_skips_echo_of_request_and_ack():
    """REVIEW F13: the echo was parsed as the identification."""
    port = EchoModeCPort(b"/LGZ5ZMD3104100.B23\r\n", GOOD, b"\x06050\r\n", 9600)
    readout = _transport(port).read_mode_c()
    assert readout.identification.manufacturer == "LGZ"
    assert len(readout.data_sets) == 6
