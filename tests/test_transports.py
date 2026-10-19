"""Transport tests: TCP/UDP over loopback, serial via pyserial URLs, optical sign-on."""

from __future__ import annotations

import socket
import threading

import pytest

from pydlms.exceptions import DlmsTimeoutError, ProtocolError, TransportError
from pydlms.transports.base import LoopbackTransport
from pydlms.transports.serial import (
    BAUD_CHARS,
    OpticalTransport,
    SerialTransport,
    parse_identification,
)
from pydlms.transports.tcp import TcpTransport, UdpTransport


def _echo_server(kind=socket.SOCK_STREAM):
    sock = socket.socket(socket.AF_INET, kind)
    sock.bind(("127.0.0.1", 0))
    if kind == socket.SOCK_STREAM:
        sock.listen(1)

        def run():
            conn, _ = sock.accept()
            with conn:
                while data := conn.recv(100):
                    conn.sendall(data.upper())

    else:

        def run():
            data, addr = sock.recvfrom(100)
            sock.sendto(data.upper(), addr)

    threading.Thread(target=run, daemon=True).start()
    return sock


def test_tcp_round_trip_and_recv_exact():
    server = _echo_server()
    with TcpTransport(*server.getsockname(), timeout=2) as t:
        t.send(b"hello")
        assert t.recv_exact(5) == b"HELLO"
        with pytest.raises(DlmsTimeoutError):
            t.recv(timeout=0.05)
    server.close()


def test_tcp_connect_refused():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    with pytest.raises(TransportError, match="cannot connect"):
        TcpTransport("127.0.0.1", port, connect_timeout=1).open()


def test_tcp_not_open():
    with pytest.raises(TransportError):
        TcpTransport("127.0.0.1").send(b"x")


def test_tcp_peer_close_detected():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    def run():
        conn, _ = server.accept()
        conn.close()

    threading.Thread(target=run, daemon=True).start()
    with TcpTransport(*server.getsockname(), timeout=2) as t:
        with pytest.raises(TransportError, match="closed"):
            t.recv()
    server.close()


def test_udp_round_trip():
    server = _echo_server(socket.SOCK_DGRAM)
    with UdpTransport(*server.getsockname(), timeout=2) as t:
        t.send(b"dgram")
        assert t.recv_exact(5) == b"DGRAM"
    server.close()


def test_recv_exact_timeout_reports_progress():
    transport = LoopbackTransport()
    transport.inject(b"ab")
    with pytest.raises(DlmsTimeoutError, match="got 2 of 4"):
        transport.recv_exact(4, timeout=0.05)


# --- serial (pyserial URLs, no hardware) -----------------------------------------------


def test_serial_loop_url():
    pytest.importorskip("serial")
    with SerialTransport("loop://", 9600, timeout=1) as t:
        t.send(b"\x7e\x01\x7e")
        assert t.recv_exact(3) == b"\x7e\x01\x7e"
        t.reconfigure(19200)
        assert t.baudrate == 19200


def test_serial_bad_port():
    pytest.importorskip("serial")
    with pytest.raises(TransportError):
        SerialTransport("/dev/does-not-exist-pydlms").open()


def test_serial_socket_url_to_hdlc_simulator():
    """HDLC over a pyserial socket:// URL to the simulator: the serial code path."""
    pytest.importorskip("serial")
    from pydlms.client import DlmsClient
    from pydlms.simulator import example_meter, serve

    server = serve(example_meter(), hdlc=True)
    host, port = server.server_address
    try:
        with DlmsClient.serial(f"socket://{host}:{port}", timeout=3) as meter:
            assert meter.get_register("1.0.1.8.0.255").value == 12345678
    finally:
        server.shutdown()
        server.server_close()


# --- optical sign-on -------------------------------------------------------------------


@pytest.mark.parametrize(
    "line,manufacturer,baud,mode_e,ident",
    [
        (b"/LGZ5\\2ZMD3104100.B23\r\n", "LGZ", 9600, True, "ZMD3104100.B23"),
        (b"/ISK5\\2MT382-1000\r\n", "ISk"[:2] + "K", 9600, True, "MT382-1000"),
        (b"/KFM5KAIFA-METER\r\n", "KFM", 9600, False, "KAIFA-METER"),
        (b"/ABC6\\2X\r\n", "ABC", 19200, True, "X"),
    ],
)
def test_parse_identification(line, manufacturer, baud, mode_e, ident):
    parsed = parse_identification(line)
    assert parsed.manufacturer == manufacturer
    assert parsed.baud == baud and parsed.mode_e == mode_e
    assert parsed.identification == ident


@pytest.mark.parametrize("line", [b"LGZ5\r\n", b"/LG\r\n", b"/LGZ5ident"])
def test_parse_identification_rejects(line):
    with pytest.raises(ProtocolError):
        parse_identification(line)


def test_baud_char_table():
    assert BAUD_CHARS["0"] == 300 and BAUD_CHARS["5"] == 9600 and BAUD_CHARS["6"] == 19200


class FakePort:
    """Stands in for a pyserial port: scripted meter replies, records settings."""

    def __init__(self, replies: dict[bytes, bytes]):
        self.replies = replies
        self.rx = bytearray()
        self.written: list[bytes] = []
        self.settings: list[tuple] = []
        self.baudrate, self.bytesize, self.parity = 300, 7, "E"

    @property
    def in_waiting(self):
        return len(self.rx)

    def read(self, n):
        out = bytes(self.rx[:n])
        del self.rx[:n]
        return out

    def write(self, data):
        self.written.append(data)
        self.rx += self.replies.get(data, b"")

    def flush(self):
        self.settings.append((self.baudrate, self.bytesize, self.parity))

    def apply_settings(self, settings):
        if getattr(self, "refuse", False):
            raise OSError(22, "Invalid argument")
        for key, value in settings.items():
            setattr(self, key, value)

    def close(self):
        pass


def _optical(replies, **kw):
    transport = OpticalTransport("fake", timeout=1, **kw)
    transport._serial = FakePort(replies)
    return transport


def test_optical_sign_on_mode_e(monkeypatch):
    monkeypatch.setattr("pydlms.transports.serial.time.sleep", lambda s: None)
    t = _optical({b"/?!\r\n": b"/LGZ5\\2ZMD3104100\r\n", b"\x06252\r\n": b"\x06252\r\n"})
    ident = t.sign_on()
    port = t._serial
    assert ident.manufacturer == "LGZ" and ident.mode_e
    assert port.written == [b"/?!\r\n", b"\x06252\r\n"]
    assert (port.baudrate, port.bytesize, port.parity) == (9600, 8, "N")
    assert port.settings[0] == (300, 7, "E")  # request sent at 300 7E1


def test_optical_baud_capped(monkeypatch):
    monkeypatch.setattr("pydlms.transports.serial.time.sleep", lambda s: None)
    t = _optical(
        {b"/?12345678!\r\n": b"/ABC6\\2X\r\n", b"\x06242\r\n": b"\x06242\r\n"},
        max_baud=4800,
        device_address="12345678",
    )
    t.sign_on()
    assert t._serial.written[-1] == b"\x06242\r\n"
    assert t._serial.baudrate == 4800


def test_optical_no_answer_times_out(monkeypatch):
    t = _optical({})
    t.timeout = 0.05
    with pytest.raises(DlmsTimeoutError):
        t.sign_on()


# --- REVIEW F13: mode E echo, reaction time, switch confirmation -------------------

LGZ_IDENT = b"/LGZ5\\2ZMD3104407.B32\r\n"
LGZ_ACK = b"\x06252\r\n"


class EchoPort(FakePort):
    """A half-duplex converter: every written line comes back as an echo."""

    def write(self, data):
        self.written.append(data)
        self.rx += data + self.replies.get(data, b"")


def _recording_sleep(monkeypatch, port):
    events = []
    monkeypatch.setattr("pydlms.transports.serial.time.sleep", lambda s: events.append(s))
    original = port.write

    def write(data):
        events.append(data)
        original(data)

    port.write = write
    return events


def test_optical_sign_on_skips_echo_of_the_request(monkeypatch):
    """REVIEW F13 repro: the echo /?!<CR><LF> was parsed as identification."""
    monkeypatch.setattr("pydlms.transports.serial.time.sleep", lambda s: None)
    t = OpticalTransport("fake", timeout=1)
    t._serial = EchoPort({b"/?!\r\n": LGZ_IDENT, LGZ_ACK: LGZ_ACK})
    ident = t.sign_on()
    assert ident.manufacturer == "LGZ"
    assert t._serial.written == [b"/?!\r\n", LGZ_ACK]
    assert t._serial.rx == b""  # echo of the ACK and the confirmation both consumed


@pytest.mark.parametrize(("ident", "ack", "minimum"), [(LGZ_IDENT, LGZ_ACK, 0.2)])
def test_optical_waits_reaction_time_before_ack(monkeypatch, ident, ack, minimum):
    """REVIEW F13 repro: the ACK left at t=0.000 s; IEC 62056-21 tr >= 200 ms."""
    t = _optical({b"/?!\r\n": ident, ack: ack})
    events = _recording_sleep(monkeypatch, t._serial)
    t.sign_on()
    before_ack = events[1 : events.index(ack)]
    assert before_ack and sum(before_ack) >= minimum - 0.01


def test_optical_lower_case_manufacturer_needs_only_20ms(monkeypatch):
    t = _optical({b"/?!\r\n": b"/LGz5\\2X\r\n", LGZ_ACK: LGZ_ACK})
    events = _recording_sleep(monkeypatch, t._serial)
    t.sign_on()
    before_ack = events[1 : events.index(LGZ_ACK)]
    assert 0.01 <= sum(before_ack) < 0.2


def test_optical_reads_switch_confirmation(monkeypatch):
    """REVIEW F13 repro: b'\\x06252\\r\\n' was left for the HDLC reader."""
    monkeypatch.setattr("pydlms.transports.serial.time.sleep", lambda s: None)
    # 7E1 read on an 8N1 port: the parity bit shows up in bit 7.
    confirm = bytes(octet | 0x80 if bin(octet).count("1") % 2 else octet for octet in LGZ_ACK)
    t = _optical({b"/?!\r\n": LGZ_IDENT, LGZ_ACK: confirm})
    t.sign_on()
    assert t._serial.rx == b""


def test_optical_wrong_switch_confirmation_raises(monkeypatch):
    monkeypatch.setattr("pydlms.transports.serial.time.sleep", lambda s: None)
    t = _optical({b"/?!\r\n": LGZ_IDENT, LGZ_ACK: b"\x15"})
    t.switch_confirm_timeout = 0.05
    with pytest.raises(ProtocolError, match="switch"):
        t.sign_on()


def test_optical_missing_switch_confirmation_is_tolerated(monkeypatch):
    monkeypatch.setattr("pydlms.transports.serial.time.sleep", lambda s: None)
    t = _optical({b"/?!\r\n": LGZ_IDENT})
    t.switch_confirm_timeout = 0.05
    t.sign_on()
    assert (t._serial.baudrate, t._serial.bytesize) == (9600, 8)


def test_reconfigure_falls_back_to_reopen(monkeypatch):
    pytest.importorskip("serial")
    t = SerialTransport("fake", 300, bytesize=7, parity="E")
    t._serial = FakePort({})
    t._serial.refuse = True
    reopened = []

    def fake_open(url, **kw):
        reopened.append(kw)
        return FakePort({})

    monkeypatch.setattr("serial.serial_for_url", fake_open)
    t.reconfigure(9600)
    assert reopened == [
        {"baudrate": 9600, "bytesize": 8, "parity": "N", "stopbits": 1, "timeout": 0}
    ]
    assert (t.baudrate, t.bytesize, t.parity) == (9600, 8, "N")


# --- optical reconnect -------------------------------------------------------------


def _scripted_serial_for_url(monkeypatch, replies):
    """Patch pyserial so every open returns a fresh FakePort opened with the
    requested line settings; returns the list of (kwargs, port) opens."""
    pytest.importorskip("serial")
    opens = []

    def fake_open(url, **kw):
        port = FakePort(replies)
        port.baudrate, port.bytesize, port.parity = kw["baudrate"], kw["bytesize"], kw["parity"]
        opens.append((kw, port))
        return port

    monkeypatch.setattr("serial.serial_for_url", fake_open)
    return opens


def test_optical_reopen_signs_on_at_300_baud_7e1(monkeypatch):
    """Wave 0 item 1 repro: after close() the transport kept the mode E rate,
    so a reopened link sent ``/?!`` at 9600 8N1 and the meter never heard it."""
    monkeypatch.setattr("pydlms.transports.serial.time.sleep", lambda s: None)
    opens = _scripted_serial_for_url(monkeypatch, {b"/?!\r\n": LGZ_IDENT, LGZ_ACK: LGZ_ACK})
    t = OpticalTransport("fake", timeout=1)
    t.open()
    assert (opens[0][1].baudrate, opens[0][1].bytesize) == (9600, 8)
    t.close()
    assert (t.baudrate, t.bytesize, t.parity) == (300, 7, "E")
    t.open()
    kw, port = opens[1]
    assert (kw["baudrate"], kw["bytesize"], kw["parity"]) == (300, 7, "E")
    assert port.written[0] == b"/?!\r\n"
    assert port.settings[0] == (300, 7, "E")  # the request left at 300 7E1
    assert (port.baudrate, port.bytesize, port.parity) == (9600, 8, "N")


def test_optical_repeated_sign_on_returns_to_sign_on_rate(monkeypatch):
    """A second sign_on() on an open link at the switched rate first drops
    back to 300 baud in the configured sign-on format."""
    monkeypatch.setattr("pydlms.transports.serial.time.sleep", lambda s: None)
    t = _optical({b"/?!\r\n": LGZ_IDENT, LGZ_ACK: LGZ_ACK})
    t.sign_on()
    t._serial.settings.clear()
    t.sign_on()
    assert t._serial.settings[0] == (300, 7, "E")
    assert (t._serial.baudrate, t._serial.bytesize, t._serial.parity) == (9600, 8, "N")


def test_optical_reopen_keeps_custom_sign_on_format(monkeypatch):
    monkeypatch.setattr("pydlms.transports.serial.time.sleep", lambda s: None)
    opens = _scripted_serial_for_url(monkeypatch, {b"/?!\r\n": LGZ_IDENT, LGZ_ACK: LGZ_ACK})
    t = OpticalTransport("fake", timeout=1, sign_on_bytesize=8, sign_on_parity="N")
    t.open()
    t.close()
    t.open()
    assert (opens[1][0]["baudrate"], opens[1][0]["bytesize"], opens[1][0]["parity"]) == (
        300,
        8,
        "N",
    )


def test_optical_reopen_fallback_does_not_sign_on_again(monkeypatch):
    """Repro: a driver that refuses the in-place 7E1 -> 8N1 switch (Linux
    PTYs, some USB adapters) made reconfigure() reopen through
    OpticalTransport.open(), which signed on again and recursed."""
    monkeypatch.setattr("pydlms.transports.serial.time.sleep", lambda s: None)
    opens = _scripted_serial_for_url(monkeypatch, {b"/?!\r\n": LGZ_IDENT, LGZ_ACK: LGZ_ACK})
    original = FakePort.apply_settings

    def refuse(self, settings):
        self.refuse = True
        original(self, settings)

    monkeypatch.setattr(FakePort, "apply_settings", refuse)
    t = OpticalTransport("fake", timeout=1)
    t.open()
    assert [(kw["baudrate"], kw["bytesize"], kw["parity"]) for kw, _ in opens] == [
        (300, 7, "E"),
        (9600, 8, "N"),
    ]
    assert opens[0][1].written == [b"/?!\r\n", LGZ_ACK]
    assert opens[1][1].written == []  # no second sign-on on the reopened port
    assert (t.baudrate, t.bytesize, t.parity) == (9600, 8, "N")


def _with_even_parity(data: bytes) -> bytes:
    """7E1 characters as an 8N1 bridge hands them over: parity in bit 7."""
    return bytes(octet | 0x80 if bin(octet).count("1") % 2 else octet for octet in data)


def test_optical_identification_with_parity_bit_from_8n1_bridge(monkeypatch):
    """Repro: an 8N1 bridge (sign_on_bytesize=8) delivers the 7E1
    identification with the parity bit in bit 7; the line was parsed
    unmasked and rejected as not an identification message."""
    monkeypatch.setattr("pydlms.transports.serial.time.sleep", lambda s: None)
    t = _optical(
        {b"/?!\r\n": _with_even_parity(LGZ_IDENT), LGZ_ACK: _with_even_parity(LGZ_ACK)},
        sign_on_bytesize=8,
        sign_on_parity="N",
    )
    ident = t.sign_on()
    assert ident.manufacturer == "LGZ" and ident.identification == "ZMD3104407.B32"


def test_serial_open_wraps_termios_errors(monkeypatch):
    # A Linux PTY can refuse a setting (e.g. parity E) with termios.error,
    # which is not an OSError; open() must still raise TransportError.
    termios = pytest.importorskip("termios")
    serial = pytest.importorskip("serial")
    from pydlms.exceptions import TransportError
    from pydlms.transports.serial import SerialTransport

    def refuse(*args, **kwargs):
        raise termios.error(22, "Invalid argument")

    monkeypatch.setattr(serial, "serial_for_url", refuse)
    with pytest.raises(TransportError, match="cannot open"):
        SerialTransport("/dev/ttyFAKE", 2400).open()
