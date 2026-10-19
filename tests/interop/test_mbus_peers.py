"""Wired M-Bus link layer against independent peers (no DLMS in either).

* rscada/libmbus as the M-Bus master talking to pydlms's
  :class:`~pydlms.simulator.MbusServer` (tests/interop/mbus/master.c): its
  SND_NKE, selection, SND_UD and REQ_UD2 telegrams are built by libmbus,
  our answers pass libmbus's ``mbus_frame_verify`` (start, L, C field set,
  checksum, stop) and its variable data header parser for the idle RSP_UD.
  The DLMS segments it receives are reassembled and decoded by pydlms.
* addiva-elektronik/mbus-device as the M-Bus slave for pydlms's
  :class:`~pydlms.mbus_link.MbusLink`: SND_NKE/E5, REQ_UD2/RSP_UD with
  toggling FCB, selection by secondary address, silence for another
  address. It has no DLMS, so a DLMS SND_UD is not acknowledged.

No open wired M-Bus slave that speaks DLMS exists, so
these check the link layer only.

Build:  docker build -t pydlms-interop-mbus tests/interop/mbus
Run:    pytest -m integration tests/interop/test_mbus_peers.py
"""

from __future__ import annotations

import socket
import subprocess
import time

import pytest

from pydlms.apdu.acse import AARE
from pydlms.exceptions import DlmsTimeoutError, TransportError
from pydlms.mbus_link import MbusLink, _secondary_octets
from pydlms.simulator import example_meter, serve_mbus
from pydlms.transports.tcp import TcpTransport
from tests.interop.oracle import require_image

pytestmark = pytest.mark.integration

IMAGE = "pydlms-interop-mbus"
AARQ = "601da109060760857405080101be10040e01000000065f1f0400007e1fffff"
GET = "c001c100030100200700ff0200"  # 1.0.32.7.0.255 attribute 2
SECONDARY = "12345678" + "9344" + "10" + "07"


def _master(host: str, port: int, *args: str) -> list[str]:
    result = subprocess.run(  # noqa: S603,S607 - fixed docker argv, test-only
        ["docker", "run", "--rm", "--network", "host", IMAGE, "master", host, str(port), *args],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.splitlines()


def _apdus(lines: list[str]) -> list[bytes]:
    """Reassemble the DLMS APDUs from the master's RSP lines (CI 0x00..0x1F)."""
    apdus, buffer = [], b""
    for line in lines:
        if not line.startswith("RSP "):
            continue
        _, control, address, ci, data = (line.split() + [""])[:5]
        ci = int(ci, 16)
        if ci > 0x1F:
            continue
        payload = bytes.fromhex(data)
        assert payload[:2] == bytes([1, 16])  # STSAP 1 -> DTSAP 16
        buffer += payload[2:]
        if ci & 0x10:
            apdus.append(buffer)
            buffer = b""
    return apdus


@pytest.fixture
def mbus_server():
    require_image(IMAGE, "tests/interop/mbus")
    servers = []

    def start(**options):
        server = serve_mbus(example_meter(), "127.0.0.1", 0, 5, **options)
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def test_libmbus_master_reads_segmented_response(mbus_server):
    server = mbus_server(max_segment=24, not_ready=2, secondary=_secondary_octets(SECONDARY))
    lines = _master(*server.server_address[:2], "5", AARQ, GET)
    assert lines[:2] == ["ACK SND_NKE", "ACK SND_UD"]
    # Idle answers (CI 72h) parse as a variable data header in libmbus.
    assert "IDLE 1234567893441007" in lines
    aare, response = _apdus(lines)
    assert AARE.from_bytes(aare).result == 0
    assert response.hex() == "c401c1001208fd"  # 230.1 V (long-unsigned 2301)
    log = server.mbus_servers[0].log
    snd = [entry.split()[2] for entry in log if entry.startswith("SND_UD")]
    req = [entry.split()[2] for entry in log if entry.startswith("REQ_UD2")]
    assert snd == ["C=0x73", "C=0x53"]
    # libmbus starts with FCB=1 and toggles after every RSP_UD, as MbusLink does.
    assert req == ["C=0x7B", "C=0x5B"] * (len(req) // 2) + ["C=0x7B"] * (len(req) % 2)
    assert server.mbus_servers[0].bad_frames == 0


def test_libmbus_master_selects_by_secondary_address(mbus_server):
    server = mbus_server(secondary=_secondary_octets(SECONDARY), idle_ack=True, not_ready=1)
    lines = _master(*server.server_address[:2], "0", "--secondary", "12345678FFFFFFFF", AARQ)
    assert lines[:2] == ["ACK select", "ACK SND_UD"]
    assert "ACK REQ_UD2" in lines  # the E5 idle answer
    (aare,) = _apdus(lines)
    assert AARE.from_bytes(aare).result == 0
    assert any(line.startswith("RSP 08 05 ") for line in lines)  # answers with its own address
    assert server.mbus_servers[0].log[0] == "select 78563412ffffffff -> True"


def _logs(cid: str) -> str:
    return subprocess.run(  # noqa: S603,S607 - fixed docker argv, test-only
        ["docker", "logs", cid], capture_output=True, text=True, timeout=30, check=False
    ).stdout


@pytest.fixture(scope="module")
def mbus_device():
    require_image(IMAGE, "tests/interop/mbus")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    cid = subprocess.run(  # noqa: S603,S607 - fixed docker argv, test-only
        ["docker", "run", "-d", "--rm", "--network", "host", IMAGE, "device", "5", str(port)],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    ).stdout.strip()
    try:
        deadline = time.monotonic() + 30
        while "ready" not in _logs(cid):
            assert time.monotonic() < deadline, "mbus-device did not start"
            time.sleep(0.2)
        yield "127.0.0.1", port
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True, timeout=60)  # noqa: S603,S607


def _link(address, **kw) -> MbusLink:
    """A link over TCP; the bridge takes one connection at a time and
    restarts in between, so connecting is retried."""
    link = MbusLink(TcpTransport(*address, timeout=5, connect_timeout=2), reply_timeout=1.0, **kw)
    deadline = time.monotonic() + 10
    while True:
        try:
            link.transport.open()
            return link
        except TransportError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.1)


# The canned RSP_UD of mbus-device (mbus-device.c raw_response, README example).
DEVICE_RSP_UD = bytes.fromhex(
    "681F1F680805727856341224400107550000000313153100DA023B13018B60043718021B16"
)


def test_mbus_link_against_mbus_device(mbus_device):
    link = _link(mbus_device, primary_address=5)
    try:
        link.reset()
        first = link.request_user_data()
        second = link.request_user_data()
        assert first.raw == second.raw == DEVICE_RSP_UD
        assert first.is_rsp_ud and not first.is_dlms
        assert link.fcb_request is True  # toggled twice
        assert link.repetitions == 0
        # No DLMS in mbus-device: a DLMS SND_UD is not acknowledged.
        with pytest.raises(DlmsTimeoutError, match="SND_UD CI 0x10"):
            link.send_apdu(bytes.fromhex(GET))
    finally:
        link.disconnect()


def test_mbus_link_address_and_selection_against_mbus_device(mbus_device):
    link = _link(mbus_device, primary_address=6)
    try:
        with pytest.raises(DlmsTimeoutError, match="SND_NKE to address 6"):
            link.reset()
    finally:
        link.disconnect()
    link = _link(mbus_device, secondary_address="12345678FFFFFFFF")
    try:
        link.select()
        answer = link.request_user_data()
        assert answer.raw == DEVICE_RSP_UD and answer.address == 5
    finally:
        link.disconnect()
    link = _link(mbus_device, secondary_address="87654321FFFFFFFF")
    try:
        with pytest.raises(DlmsTimeoutError, match="selection"):
            link.select()
    finally:
        link.disconnect()
