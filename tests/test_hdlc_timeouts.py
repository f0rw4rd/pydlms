"""HDLC inter-octet and inactivity time-outs.

Behaviour after IEC 62056-46 6.4.4.10.3 (inactivity) and 6.4.4.10.4
(inter-octet) as cB-Sigma ``hdlc/client.go`` and ``hdlc/scanner.go`` read
them (Apache-2.0; clause text not read, *unverified*): a gap longer than the
inter-octet time-out ends a frame being received and what was gathered is
dropped; the server drops the link after its inactivity time-out without
traffic, so the client takes the link as gone a little before (a tenth of
the time-out, at most 2 s). Every timing test uses an injected clock.
"""

from __future__ import annotations

import pytest

from pydlms.client import SERIAL_INTER_OCTET_TIMEOUT, DlmsClient
from pydlms.cosem.data import DlmsData
from pydlms.cosem.interface_classes import ClassId
from pydlms.exceptions import DlmsTimeoutError, LinkLostError, ProtocolError
from pydlms.hdlc.address import HdlcAddress
from pydlms.hdlc.connection import HdlcLink, HdlcState
from pydlms.hdlc.framing import FrameReader, FrameType, HdlcFrame, encode_frame
from pydlms.transports.base import LoopbackTransport
from tests.test_hdlc import E450_FIRST, FakeMeter


class Clock:
    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


# --- FrameReader ------------------------------------------------------------------


def test_stale_partial_frame_is_dropped_after_the_gap():
    reader = FrameReader(inter_octet=0.1)
    assert reader.feed(E450_FIRST[:40], now=10.0) == []
    frames = reader.feed(E450_FIRST, now=10.2)
    assert len(frames) == 1 and frames[0].info == decode_info()
    assert reader.dropped == 1


def decode_info() -> bytes:
    return FrameReader().feed(E450_FIRST)[0].info


def test_partial_frame_within_the_gap_is_kept():
    reader = FrameReader(inter_octet=0.1)
    assert reader.feed(E450_FIRST[:40], now=10.0) == []
    assert reader.feed(E450_FIRST[40:80], now=10.05) == []
    frames = reader.feed(E450_FIRST[80:], now=10.15)  # each gap 0.05 / 0.1
    assert len(frames) == 1
    assert reader.dropped == 0


def test_gap_equal_to_the_timeout_is_not_stale():
    reader = FrameReader(inter_octet=0.1)
    reader.feed(E450_FIRST[:40], now=10.0)
    assert len(reader.feed(E450_FIRST[40:], now=10.1)) == 1


def test_without_inter_octet_any_gap_is_fine():
    reader = FrameReader()
    reader.feed(E450_FIRST[:40], now=10.0)
    assert len(reader.feed(E450_FIRST[40:], now=99999.0)) == 1
    assert reader.dropped == 0


def test_retained_closing_flag_is_not_a_dropped_frame():
    reader = FrameReader(inter_octet=0.1)
    assert len(reader.feed(E450_FIRST, now=10.0)) == 1
    assert len(reader.feed(E450_FIRST, now=20.0)) == 1
    assert reader.dropped == 0


def test_feed_uses_the_injected_clock():
    clock = Clock(10.0)
    reader = FrameReader(inter_octet=0.1, clock=clock)
    reader.feed(E450_FIRST[:40])
    clock.now = 11.0
    assert len(reader.feed(E450_FIRST)) == 1
    assert reader.dropped == 1


def test_stale_split_does_not_resync_onto_garbage():
    """The dropped head must not combine with the next frame's tail."""
    reader = FrameReader(inter_octet=0.1)
    reader.feed(E450_FIRST[:40], now=10.0)
    assert reader.feed(E450_FIRST[40:], now=11.0) == []
    assert reader.dropped == 1


@pytest.mark.parametrize("value", [0, -1.0])
def test_inter_octet_must_be_positive(value):
    with pytest.raises(ValueError):
        FrameReader(inter_octet=value)


# --- HdlcLink: inter-octet --------------------------------------------------------


def test_link_passes_the_inter_octet_timeout_to_its_reader():
    link = HdlcLink(LoopbackTransport(FakeMeter()), inter_octet_timeout=0.25, timeout=0.2)
    assert link._reader.inter_octet == 0.25
    link.connect()  # the reader is rebuilt on connect
    assert link._reader.inter_octet == 0.25
    assert link.request(b"\xc0\x01\x01") == b"\xc0\x01\x01"


def test_link_drops_a_stale_partial_frame():
    clock = Clock()
    transport = LoopbackTransport()
    link = HdlcLink(transport, inter_octet_timeout=0.1, timeout=0.05, clock=clock)
    transport.open()
    push = encode_frame(
        HdlcFrame(HdlcAddress.client(16), HdlcAddress.server(1), FrameType.UI, b"\xe6\xe7\x00\x0f")
    )
    transport.inject(push[:6])
    with pytest.raises(DlmsTimeoutError):  # only the partial frame arrived
        link.receive_push()
    clock.now += 1.0
    transport.inject(push)
    assert link.receive_push() == b"\x0f"
    assert link._reader.dropped == 1


# --- HdlcLink: inactivity ---------------------------------------------------------


def _connected(inactivity, clock, meter=None):
    meter = meter or FakeMeter()
    transport = LoopbackTransport(meter)
    link = HdlcLink(transport, timeout=0.2, inactivity_timeout=inactivity, clock=clock)
    link.connect()
    return link, transport, meter


def test_link_lost_error_is_a_protocol_error():
    assert issubclass(LinkLostError, ProtocolError)


def test_inactivity_ends_the_link_before_the_meter_does():
    clock = Clock(0.0)
    link, transport, meter = _connected(60.0, clock)
    clock.now = 50.0
    assert link.request(b"\xc0\x01\x01") == b"\xc0\x01\x01"  # activity at 50
    clock.now = 50.0 + 58.0 - 0.001  # margin min(60/10, 2) = 2: limit 58
    assert link.request(b"\xc0\x01\x02") == b"\xc0\x01\x02"
    clock.now += 58.0
    sent = len(transport.sent)
    with pytest.raises(LinkLostError, match="inactivity"):
        link.send_apdu(b"\xc0\x01\x03")
    assert link.state == HdlcState.DISCONNECTED
    assert len(transport.sent) == sent  # nothing sent into the dead link
    with pytest.raises(ProtocolError, match="not connected"):
        link.send_apdu(b"\xc0\x01\x03")  # and no silent reconnect
    link.connect()
    assert link.request(b"\xc0\x01\x04") == b"\xc0\x01\x04"


@pytest.mark.parametrize(
    "timeout,limit",
    [
        (120.0, 118.0),  # margin capped at 2 s
        (10.0, 9.0),  # a tenth of the time-out
        (1.0, 0.9),
    ],
)
def test_inactivity_margin(timeout, limit):
    clock = Clock(0.0)
    link, _, _ = _connected(timeout, clock)
    clock.now = limit - 0.01
    link.send_apdu(b"\xc0\x01\x01")
    assert link.receive_apdu() == b"\xc0\x01\x01"
    clock.now += limit
    with pytest.raises(LinkLostError):
        link.send_apdu(b"\xc0\x01\x02")


def test_received_frames_count_as_activity():
    clock = Clock(0.0)
    link, transport, _ = _connected(10.0, clock)
    clock.now = 8.0
    push = encode_frame(
        HdlcFrame(HdlcAddress.client(16), HdlcAddress.server(1), FrameType.UI, b"\xe6\xe7\x00\x0f")
    )
    transport.inject(push)
    assert link.receive_push() == b"\x0f"
    clock.now = 16.5  # 8.5 s after the push, 16.5 s after our last frame
    assert link.request(b"\xc0\x01\x01") == b"\xc0\x01\x01"


def test_no_inactivity_timeout_never_expires():
    clock = Clock(0.0)
    link, _, _ = _connected(None, clock)
    clock.now = 1e9
    assert link.request(b"\xc0\x01\x01") == b"\xc0\x01\x01"


def test_disconnect_after_inactivity_sends_no_disc():
    clock = Clock(0.0)
    link, transport, _ = _connected(10.0, clock)
    clock.now = 100.0
    sent = len(transport.sent)
    link.disconnect()
    assert len(transport.sent) == sent
    assert link.state == HdlcState.DISCONNECTED and not transport.is_open


def test_connected_property_reports_expiry():
    clock = Clock(0.0)
    link, _, _ = _connected(10.0, clock)
    assert link.connected
    clock.now = 100.0
    assert not link.connected
    assert link.state == HdlcState.DISCONNECTED


@pytest.mark.parametrize("kw", [{"inactivity_timeout": 0}, {"inter_octet_timeout": -1}])
def test_timeouts_must_be_positive(kw):
    with pytest.raises(ValueError):
        HdlcLink(LoopbackTransport(), **kw)


# --- client defaults and the HDLC setup helper ---------------------------------------


def test_serial_and_optical_get_a_conservative_inter_octet_default():
    pytest.importorskip("serial")
    serial = DlmsClient.serial("loop://")
    optical = DlmsClient.optical("loop://")
    assert serial.link.inter_octet_timeout == SERIAL_INTER_OCTET_TIMEOUT
    assert optical.link.inter_octet_timeout == SERIAL_INTER_OCTET_TIMEOUT
    assert serial.link.inactivity_timeout is None


def test_serial_timeouts_can_be_overridden():
    pytest.importorskip("serial")
    m = DlmsClient.serial("loop://", inter_octet_timeout=None, inactivity_timeout=120)
    assert m.link.inter_octet_timeout is None
    assert m.link.inactivity_timeout == 120


def test_tcp_hdlc_has_no_inter_octet_timeout():
    m = DlmsClient.tcp("192.0.2.1", hdlc=True)
    assert m.link.inter_octet_timeout is None and m.link.inactivity_timeout is None


@pytest.fixture
def hdlc_meter():
    from pydlms.simulator import example_meter, serve

    sim = example_meter()
    server = serve(sim, hdlc=True)
    yield sim, server.server_address
    server.shutdown()
    server.server_close()


@pytest.mark.parametrize("seconds,applied", [(120, 120), (0, None)])
def test_read_hdlc_inactivity_timeout(hdlc_meter, seconds, applied):
    sim, (host, port) = hdlc_meter
    sim.add_object(
        ClassId.IEC_HDLC_SETUP, "0.0.22.0.0.255", {8: DlmsData.uint16(seconds)}, version=1
    )
    with DlmsClient.tcp(host, port, hdlc=True, timeout=3) as m:
        assert m.read_hdlc_inactivity_timeout() == seconds
        assert m.link.inactivity_timeout == applied


def test_read_hdlc_inactivity_timeout_without_apply(hdlc_meter):
    sim, (host, port) = hdlc_meter
    sim.add_object(ClassId.IEC_HDLC_SETUP, "0.0.22.0.0.255", {8: DlmsData.uint16(30)}, version=1)
    with DlmsClient.tcp(host, port, hdlc=True, timeout=3) as m:
        assert m.read_hdlc_inactivity_timeout(apply=False) == 30
        assert m.link.inactivity_timeout is None


def test_read_hdlc_inactivity_timeout_refuses_a_non_integer(hdlc_meter):
    from pydlms.exceptions import DecodeError

    sim, (host, port) = hdlc_meter
    sim.add_object(
        ClassId.IEC_HDLC_SETUP, "0.0.22.0.0.255", {8: DlmsData.visible_string("x")}, version=1
    )
    with DlmsClient.tcp(host, port, hdlc=True, timeout=3) as m:
        with pytest.raises(DecodeError):
            m.read_hdlc_inactivity_timeout()
        assert m.link.inactivity_timeout is None
