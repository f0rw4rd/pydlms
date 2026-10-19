"""HDLC over a real serial line (socat PTY pair) and IEC 62056-21 mode E.

The meter side runs the simulator's HDLC server on one PTY; the client uses
:meth:`DlmsClient.serial` / :meth:`DlmsClient.optical` on the other, so the
pyserial transport, termios settings, HDLC timing and the optical sign-on
state machine all run against a real tty.
"""

from __future__ import annotations

import threading
import time

import pytest

from pydlms.client import DlmsClient
from pydlms.simulator import HdlcServer, example_meter

pytestmark = pytest.mark.integration
serial = pytest.importorskip("serial")


class _SerialSock:
    """Adapter: the HDLC server expects ``sendall``."""

    def __init__(self, port):
        self.port = port

    def sendall(self, data: bytes) -> None:
        self.port.write(data)
        self.port.flush()


def _meter_thread(path: str, optical: bool, stop: threading.Event, log: list):
    # A PTY passes bytes whatever its line settings, so the fake meter stays
    # at 8N1; the client's 300 7E1 -> 9600 8N1 switch is what is under test.
    port = serial.Serial(path, 9600, timeout=0.05)
    server = HdlcServer(example_meter(), _SerialSock(port))
    try:
        if optical:
            request = b""
            while not request.endswith(b"!\r\n") and not stop.is_set():
                request += port.read(1)
            log.append(request)
            port.write(b"/PYD5\\2SIMULATOR\r\n")
            ack = b""
            while not ack.endswith(b"\r\n") and not stop.is_set():
                ack += port.read(1)
            log.append(ack)
        while not stop.is_set():
            data = port.read(256)
            if data:
                server.feed(data)
    finally:
        port.close()


@pytest.mark.parametrize("optical", [False, True], ids=["serial-hdlc", "optical-mode-e"])
def test_read_over_pty(pty_pair, optical):
    meter_path, client_path = pty_pair
    stop = threading.Event()
    log: list[bytes] = []
    thread = threading.Thread(
        target=_meter_thread, args=(meter_path, optical, stop, log), daemon=True
    )
    thread.start()
    time.sleep(0.1)
    try:
        if optical:
            # Linux PTYs cannot switch 7E1 -> 8N1 (EINVAL), so sign on at 8N1;
            # the 300 -> 9600 baud switch and the protocol bytes are still real.
            client = DlmsClient.optical(client_path, timeout=3)
            transport = client.link.transport
            transport.sign_on_format = (8, "N")  # every sign-on and reconnect
            transport.bytesize, transport.parity = 8, "N"  # the first open
        else:
            client = DlmsClient.serial(client_path, 9600, timeout=3)
        with client as meter:
            assert meter.get_register("1.0.1.8.0.255").value == 12345678
            assert len(meter.read_profile("1.0.99.1.0.255").rows) == 96
        if optical:
            assert log == [b"/?!\r\n", b"\x06252\r\n"]
            assert client.link.transport.identification.manufacturer == "PYD"
    finally:
        stop.set()
        thread.join(2)


def _scripted_iec21_meter(path: str, stop: threading.Event, log: list):
    """Fast-woken mode C meter: B0, NUL strings (ACK), request, option
    select, data message, B1 (ACK). Every received unit goes into ``log``."""
    from pydlms.transports.iec62056_21 import BREAK, SIGN_OFF, block_check_character

    port = serial.Serial(path, 9600, timeout=0.05)
    buffer = bytearray()

    def take(predicate) -> bytes:
        deadline = time.monotonic() + 10
        while not stop.is_set() and time.monotonic() < deadline:
            size = predicate(buffer)
            if size:
                unit = bytes(buffer[:size])
                del buffer[:size]
                log.append(unit)
                return unit
            buffer.extend(port.read(64))
        raise TimeoutError(f"meter waited for more than {bytes(buffer)!r}")

    def exact(expected: bytes):
        return lambda b: len(expected) if b.startswith(expected) else 0

    def nul_string(b):
        size = len(b) - len(b.lstrip(b"\x00"))
        # A string has ended when nothing follows within the 50 ms read.
        return size if size and port.in_waiting == 0 and size == len(b) else 0

    def line(b):
        end = b.find(b"\r\n")
        return end + 2 if end >= 0 else 0

    body = b"1.8.0(001234.5*kWh)\r\n!\r\n\x03"
    try:
        take(exact(BREAK))
        take(nul_string)
        port.write(b"\x06")
        take(line)  # request
        port.write(b"/PYD5SCRIPTED\r\n")
        take(line)  # option select
        port.write(b"\x02" + body + bytes([block_check_character(body)]))
        take(exact(SIGN_OFF))
        port.write(b"\x06")
        port.flush()
    except TimeoutError as exc:
        log.append(exc)
    finally:
        port.close()


def test_break_fast_wake_up_and_sign_off_bytes_over_pty(pty_pair):
    """B0, the fast wake-up NUL string and B1 as they leave a real tty."""
    from pydlms.transports.serial import OpticalTransport

    meter_path, client_path = pty_pair
    stop = threading.Event()
    log: list = []
    thread = threading.Thread(
        target=_scripted_iec21_meter, args=(meter_path, stop, log), daemon=True
    )
    thread.start()
    time.sleep(0.1)
    transport = OpticalTransport(client_path, timeout=3, wake_up="fast", break_before_sign_on=True)
    try:
        readout = transport.read_mode_c()
    finally:
        transport.close()
        stop.set()
        thread.join(5)
    assert readout.get("1.8.0").value == "001234.5"
    assert log == [
        bytes.fromhex("0142300371"),  # B0
        b"\x00" * 16,  # one fast wake-up string: 0.53 s at 300 baud
        b"/?!\r\n",
        b"\x06050\r\n",
        bytes.fromhex("0142310370"),  # B1
    ]
