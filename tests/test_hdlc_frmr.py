"""FRMR decoding, SREJ handling and HDLC link-state hygiene.

The FRMR layout is ISO/IEC 13239 5.5.3.4.2 Figure 18a as cited by cB-Sigma
``hdlc/frmr.go`` (Apache-2.0); the vectors below are built by hand from
that bit numbering, not copied. The 13239 text itself was not read.
"""

from __future__ import annotations

import pytest

from pydlms.exceptions import DlmsTimeoutError, FrameRejectError, FramingError, ProtocolError
from pydlms.hdlc.connection import HdlcLink, HdlcState
from pydlms.hdlc.framing import (
    PF_BIT,
    FrameReader,
    FrameType,
    control_i,
    control_rnr,
    control_rr,
)
from pydlms.hdlc.frmr import FRMR_INFO_LEN, FrameReject, FrmrInfoStruct, decode_frmr
from pydlms.transports.base import LoopbackTransport
from tests.test_hdlc import FakeMeter, make_link

# --- the FRMR information field --------------------------------------------------------


def _by_bit_number(control, vs, response, vr, w=0, x=0, y=0, z=0) -> bytes:
    """Build the field from the Figure 18a bit numbers (bit 1 = LSB of
    octet 1), independently of the construct under test."""
    value = control  # bits 1-8
    value |= (vs & 7) << 9  # bits 10-12 (bit 9 is 0)
    value |= int(response) << 12  # bit 13
    value |= (vr & 7) << 13  # bits 14-16
    value |= (w << 16) | (x << 17) | (y << 18) | (z << 19)  # bits 17-20
    return value.to_bytes(3, "little")


VECTORS = [
    # REJ with P (0x19) rejected as undefined (W); server V(S)=3, V(R)=5.
    ("19a601", FrameReject(0x19, vs=3, vr=5, w=True)),
    # An I-frame with an information field too long (Y); V(S)=1, V(R)=1.
    ("3222" + "04", FrameReject(0x32, vs=1, vr=1, y=True)),
    # Invalid N(R) (Z) on RR N(R)=7 P; V(S)=2, V(R)=7.
    ("f1e408", FrameReject(0xF1, vs=2, vr=7, z=True)),
    # A response rejected with W and X; V(S)=7, V(R)=1.
    ("113e03", FrameReject(0x11, vs=7, vr=1, response=True, w=True, x=True)),
    # No reason bit: an unspecified rejection.
    ("100000", FrameReject(0x10, vs=0, vr=0)),
]


@pytest.mark.parametrize(("hexstr", "reject"), VECTORS)
def test_frmr_known_vectors(hexstr, reject):
    raw = bytes.fromhex(hexstr)
    assert raw == _by_bit_number(
        reject.control,
        reject.vs,
        reject.response,
        reject.vr,
        reject.w,
        reject.x,
        reject.y,
        reject.z,
    )
    assert decode_frmr(raw) == reject
    assert reject.to_bytes() == raw


@pytest.mark.parametrize("value", range(0, 1 << 24, 0x10F0B))
def test_frmr_round_trip(value):
    raw = value.to_bytes(3, "big")
    raw = raw[:1] + bytes([raw[1] & 0xFE]) + raw[2:]  # bit 9 is always 0
    assert decode_frmr(raw).to_bytes() == raw
    assert FrmrInfoStruct.build(FrmrInfoStruct.parse(raw)) == raw


@pytest.mark.parametrize("size", range(FRMR_INFO_LEN))
def test_frmr_truncated_raises(size):
    with pytest.raises(FramingError, match="needs 3"):
        decode_frmr(bytes.fromhex("19a601")[:size])


def test_frmr_padding_octets_ignored():
    assert decode_frmr(bytes.fromhex("19a6010000")) == decode_frmr(bytes.fromhex("19a601"))


def test_frmr_reasons_are_readable():
    assert FrameReject(0x10, 0, 0).reasons == ()
    assert "unspecified" in FrameReject(0x10, 0, 0).describe()
    assert FrameReject(0, 0, 0, w=True).reasons == ("control field undefined or not implemented",)
    # X is sent with W and replaces its meaning.
    assert FrameReject(0, 0, 0, w=True, x=True).reasons == (
        "information field not permitted with this frame",
    )
    assert FrameReject(0, 0, 0, y=True, z=True).reasons == (
        "information field too long",
        "invalid N(R)",
    )
    text = decode_frmr(bytes.fromhex("3222f4")).describe()
    assert "reserved bits 0xF" in text and "information field too long" in text
    assert "control 0x32" in text and "V(S)=1 V(R)=1" in text


# --- FRMR and DM end the link ---------------------------------------------------------


def _frmr(meter, info: bytes) -> bytes:
    return meter.frame(FrameType.FRMR | PF_BIT, info)


def test_frmr_mid_request_disconnects():
    """Regression: the link stayed CONNECTED after FRMR."""
    meter = FakeMeter()
    link = make_link(meter)
    link.connect()
    link.transport.responder = lambda data: _frmr(meter, bytes.fromhex("3222" + "04"))
    with pytest.raises(FrameRejectError, match="information field too long") as info:
        link.request(b"\xc0\x01\x01")
    assert info.value.reject == FrameReject(0x32, vs=1, vr=1, y=True)
    assert info.value.info == bytes.fromhex("322204")
    assert link.state == HdlcState.DISCONNECTED
    with pytest.raises(ProtocolError, match="not connected"):
        link.send_apdu(b"\xc0\x01\x02")
    link.transport.responder = meter
    link.connect()  # a new SNRM brings it back
    assert link.request(b"\xc0\x01\x03") == b"\xc0\x01\x03"


@pytest.mark.parametrize("info", [b"", b"\x32", b"\x32\x22"])
def test_frmr_with_unreadable_reason_still_disconnects(info):
    meter = FakeMeter()
    link = make_link(meter)
    link.connect()
    link.transport.responder = lambda data: _frmr(meter, info)
    with pytest.raises(FrameRejectError, match="unreadable") as exc:
        link.request(b"\xc0\x01\x01")
    assert exc.value.reject is None and exc.value.info == info
    assert link.state == HdlcState.DISCONNECTED


def test_frmr_after_a_segment_disconnects():
    meter = FakeMeter(max_info=32)
    link = make_link(meter)
    link.connect()
    link.transport.responder = lambda data: _frmr(meter, bytes.fromhex("100008"))
    with pytest.raises(FrameRejectError, match="invalid N"):
        link.request(bytes(100))
    assert link.state == HdlcState.DISCONNECTED


def test_frmr_answering_snrm_is_a_frame_reject():
    meter = FakeMeter()
    link = HdlcLink(
        LoopbackTransport(lambda data: _frmr(meter, bytes.fromhex("930001"))), timeout=0.1
    )
    with pytest.raises(FrameRejectError, match="control 0x93"):
        link.connect()
    assert link.state == HdlcState.DISCONNECTED


def test_dm_mid_request_disconnects():
    meter = FakeMeter()
    link = make_link(meter)
    link.connect()
    link.transport.responder = lambda data: meter.frame(FrameType.DM | PF_BIT)
    with pytest.raises(ProtocolError, match="DM"):
        link.request(b"\xc0\x01\x01")
    assert link.state == HdlcState.DISCONNECTED


# --- fatal errors end the link ----------------------------------------------------------


def test_timeout_after_recovery_disconnects():
    """Regression: a request that timed out after its RR
    polls left the link CONNECTED with V(S)/V(R) out of step."""
    meter = FakeMeter()
    link = make_link(meter, timeout=0.02, retries=1)
    link.connect()
    link.transport.responder = lambda data: b""
    with pytest.raises(DlmsTimeoutError):
        link.request(b"\xc0\x01\x01")
    assert link.state == HdlcState.DISCONNECTED


def test_segment_ack_timeout_disconnects():
    meter = FakeMeter(max_info=32)
    link = make_link(meter, timeout=0.02, retries=1)
    link.connect()
    link.transport.responder = lambda data: b""
    with pytest.raises(DlmsTimeoutError, match="not acknowledged"):
        link.request(bytes(100))
    assert link.state == HdlcState.DISCONNECTED


def test_exhausted_retransmissions_disconnect():
    meter = FakeMeter()
    link = make_link(meter, timeout=0.02, retries=2)
    link.connect()
    # The meter keeps answering RR N(R)=0: it never got our N(S)=0.
    link.transport.responder = lambda data: meter.frame(control_rr(0))
    with pytest.raises(ProtocolError, match="after 2 retransmissions"):
        link.request(b"\xc0\x01\x01")
    assert link.state == HdlcState.DISCONNECTED


def test_invalid_nr_disconnects():
    meter = FakeMeter()
    link = make_link(meter)
    link.connect()
    link.transport.responder = lambda data: meter.frame(control_rr(5))
    with pytest.raises(ProtocolError, match=r"invalid N\(R\)=5"):
        link.request(b"\xc0\x01\x01")
    assert link.state == HdlcState.DISCONNECTED


def test_push_wait_timeout_keeps_the_link():
    meter = FakeMeter()
    link = make_link(meter, timeout=0.02)
    link.connect()
    with pytest.raises(DlmsTimeoutError):
        link.receive_push()
    assert link.state == HdlcState.CONNECTED


# --- SREJ ----------------------------------------------------------------------------


def control_srej(nr: int) -> int:
    return ((nr & 7) << 5) | PF_BIT | int(FrameType.SREJ)


class SrejOnce:
    """Answers the first I-frame (or the first final one) with SREJ for it,
    as if it arrived corrupted, then lets ``meter`` take the resend."""

    def __init__(self, meter, final_only=False):
        self.meter = meter
        self.final_only = final_only
        self.done = False

    def __call__(self, data):
        for frame in FrameReader().feed(data):
            if (
                not self.done
                and frame.kind == FrameType.I
                and not (self.final_only and frame.segmented)
            ):
                self.done = True
                return self.meter.frame(control_srej(frame.ns))
        return self.meter(data)


def _sent(link):
    return FrameReader().feed(b"".join(link.transport.sent))


def test_srej_for_the_request_resends_it():
    meter = FakeMeter()
    link = make_link(meter)
    link.connect()
    link.transport.sent.clear()
    link.transport.responder = SrejOnce(meter)
    assert link.request(b"\xc0\x01\x01") == b"\xc0\x01\x01"
    assert [(f.kind, f.ns) for f in _sent(link) if f.kind == FrameType.I] == [
        (FrameType.I, 0),
        (FrameType.I, 0),
    ]
    assert meter.received == [b"\xc0\x01\x01"]
    assert link.state == HdlcState.CONNECTED


def test_srej_for_a_segment_resends_it():
    meter = FakeMeter(max_info=32)
    link = make_link(meter)
    link.connect()
    link.transport.sent.clear()
    link.transport.responder = SrejOnce(meter)
    apdu = bytes(range(100))
    assert link.request(apdu) == apdu
    ns = [f.ns for f in _sent(link) if f.kind == FrameType.I]
    assert ns == [0, 0, 1, 2, 3]


def test_srej_for_a_frame_never_sent_is_a_protocol_error():
    meter = FakeMeter()
    link = make_link(meter)
    link.connect()
    # V(S)=1 after the request: SREJ N(R)=1 asks for a frame not sent yet.
    link.transport.responder = lambda data: meter.frame(control_srej(1))
    with pytest.raises(ProtocolError, match="SREJ for N"):
        link.request(b"\xc0\x01\x01")
    assert link.state == HdlcState.DISCONNECTED


def test_srej_for_an_acknowledged_frame_is_a_protocol_error():
    meter = FakeMeter()
    link = make_link(meter)
    link.connect()
    assert link.request(b"\xc0\x01\x01") == b"\xc0\x01\x01"
    # N(S)=0 was acknowledged by the answer; only N(S)=1 is outstanding.
    link.transport.responder = lambda data: meter.frame(control_srej(0))
    with pytest.raises(ProtocolError, match=r"outstanding frame is N\(S\)=1"):
        link.request(b"\xc0\x01\x02")


# --- RNR busy polling ------------------------------------------------------------------


class BusyScript(FakeMeter):
    """Answers the first segment with RNR, then each busy poll with the
    next scripted answer (raw bytes, or None for RR and normal service)."""

    def __init__(self, answers, **kw):
        super().__init__(**kw)
        self.answers = list(answers)
        self.busy = False

    def handle(self, f):
        if f.kind == FrameType.I and f.segmented and not self.busy and self.answers:
            self.busy = True
            self.vr = (self.vr + 1) % 8
            self.rx_apdu += f.info
            return self.frame(control_rnr(self.vr))
        if f.kind == FrameType.RR and self.busy:
            answer = self.answers.pop(0) if self.answers else None
            if answer is None:
                self.busy = False
                return self.frame(control_rr(self.vr))
            return answer
        return super().handle(f)


def _ui(meter, apdu):
    return meter.frame(FrameType.UI | PF_BIT, b"\xe6\xe7\x00" + apdu)


def test_ui_push_during_rnr_is_queued():
    """A push that arrives while the meter is busy used to abort the
    request ("expected RR or RNR to a busy poll, got UI")."""
    meter = BusyScript([], max_info=32)
    push = b"\x0f\x00\x00\x00\x01\x00\x09\x01\xaa"
    meter.answers = [_ui(meter, push) + meter.frame(control_rnr(1)), None]
    link = make_link(meter, busy_interval=0)
    link.connect()
    apdu = bytes(range(100))
    assert link.request(apdu) == apdu
    assert link.receive_push() == push
    assert link.state == HdlcState.CONNECTED


def test_dm_during_rnr_disconnects():
    meter = BusyScript([], max_info=32)
    meter.answers = [meter.frame(FrameType.DM | PF_BIT)]
    link = make_link(meter, busy_interval=0)
    link.connect()
    with pytest.raises(ProtocolError, match="DM"):
        link.request(bytes(100))
    assert link.state == HdlcState.DISCONNECTED


def test_frmr_during_rnr_disconnects():
    meter = BusyScript([], max_info=32)
    meter.answers = [_frmr(meter, bytes.fromhex("110008"))]
    link = make_link(meter, busy_interval=0)
    link.connect()
    with pytest.raises(FrameRejectError, match="invalid N"):
        link.request(bytes(100))
    assert link.state == HdlcState.DISCONNECTED


def test_no_answer_to_a_busy_poll_times_out_and_disconnects():
    meter = BusyScript([], max_info=32)
    meter.answers = [b""]
    link = make_link(meter, busy_interval=0, timeout=0.02)
    link.connect()
    with pytest.raises(DlmsTimeoutError, match="busy poll 1/"):
        link.request(bytes(100))
    assert link.state == HdlcState.DISCONNECTED


def test_i_frame_during_rnr_is_a_protocol_error():
    meter = BusyScript([], max_info=32)
    meter.answers = [meter.frame(control_i(0, 1), b"\xe6\xe7\x00\x01")]
    link = make_link(meter, busy_interval=0)
    link.connect()
    with pytest.raises(ProtocolError, match="busy poll, got HDLC I"):
        link.request(bytes(100))
