"""DLMS over a wired M-Bus on a real tty (socat PTY pair).

The simulator's MbusServer answers on one PTY; DlmsClient.mbus polls on
the other, so pyserial, the reply time-out (330 bit periods + 50 ms at
2400 baud, plus the converter margin) and the repetition of a lost or
corrupt answer run in real time. PTYs do not model parity (and a Linux
PTY may refuse PARENB), so both ends run 8N1.
"""

from __future__ import annotations

import threading

import pytest

from pydlms.client import DlmsClient
from pydlms.simulator import MbusServer, example_meter

pytestmark = pytest.mark.integration
serial = pytest.importorskip("serial")


class _SerialSock:
    def __init__(self, port):
        self.port = port

    def sendall(self, data: bytes) -> None:
        self.port.write(data)
        self.port.flush()


def _meter(path: str, stop: threading.Event, servers: list, **options) -> None:
    port = serial.Serial(path, 2400, timeout=0.02)
    server = MbusServer(example_meter(), _SerialSock(port), address=5, **options)
    servers.append(server)
    try:
        while not stop.is_set():
            data = port.read(256)
            if data:
                server.feed(data)
    finally:
        port.close()


@pytest.mark.parametrize(
    "faults",
    [{}, {"drop_ack": {2}, "corrupt_response": {2}, "drop_response": {4}, "max_segment": 64}],
    ids=["clean", "faults"],
)
def test_mbus_over_pty(pty_pair, faults):
    meter_path, client_path = pty_pair
    stop = threading.Event()
    servers: list[MbusServer] = []
    thread = threading.Thread(target=_meter, args=(meter_path, stop, servers), kwargs=faults)
    thread.start()
    try:
        with DlmsClient.mbus(client_path, 5, parity="N", timeout=5) as client:
            assert str(client.get_register("1.0.1.8.0.255")) == "12345678 Wh"
            assert len(client.get_association_view()) > 10
            link = client.link
    finally:
        stop.set()
        thread.join(5)
    server = servers[0]
    assert server.bad_frames == 0
    if faults:
        assert server.duplicates == 1
        assert link.repetitions == 3
