"""HDLC sequence checks, loss recovery, stale frames and size bounds.

Regression tests for REVIEW findings F4 (N(R) validation, duplicate
I-frames), F5 (RR poll / retransmission after a lost frame, IEC 62056-46
6.4.4.9.1 via cB-Sigma), F7 (bounded reassembly and waits) and F14 (stale
frames after an SNRM retry or a reconnect).
"""

from __future__ import annotations

import pytest

from pydlms.exceptions import DlmsTimeoutError, FramingError, ProtocolError
from pydlms.hdlc.connection import MAX_APDU_SIZE, HdlcLink
from pydlms.hdlc.framing import FrameReader, FrameType, HdlcFrame, control_i, control_rr
from pydlms.transports.base import LoopbackTransport
from tests.test_hdlc import FakeMeter, make_link


class LossyMeter(FakeMeter):
    """FakeMeter on a lossy line, answering polls like an NRM secondary.

    ``lose_requests``: final request I-frames that never arrive.
    ``lose_answers``: answer I-frames lost on the way back.
    ``lose_acks``: RRs for request segments lost on the way back.
    ``repeat_once``: the first RR during a segmented answer is lost, so the
    meter repeats its last frame (a duplicate for the client).
    """

    def __init__(self, lose_requests=0, lose_answers=0, lose_acks=0, repeat_once=False, **kw):
        super().__init__(**kw)
        self.lose_requests = lose_requests
        self.lose_answers = lose_answers
        self.lose_acks = lose_acks
        self.repeat_once = repeat_once
        self.last_tx = b""
        self.polls = 0

    def handle(self, f):
        if f.kind == FrameType.I:
            if f.ns != self.vr:  # a retransmission we already have
                return self.frame(control_rr(self.vr))
            if not f.segmented and self.lose_requests:
                self.lose_requests -= 1
                return b""
            out = super().handle(f)
            if f.segmented and self.lose_acks:
                self.lose_acks -= 1
                return b""
            return out
        if f.kind == FrameType.RR:
            if self.last_tx and f.nr != self.vs:
                self.polls += 1
                return self.last_tx  # the client missed our last frame
            if self.repeat_once and self.pending_tx:
                self.repeat_once = False
                return self.last_tx
            if not self.pending_tx:
                self.polls += 1
                return self.frame(control_rr(self.vr))
        return super().handle(f)

    def _next_segment(self):
        raw = super()._next_segment()
        if raw:
            self.last_tx = raw
            if self.lose_answers:
                self.lose_answers -= 1
                return b""
        return raw


def sent_frames(link):
    return FrameReader().feed(b"".join(link.transport.sent))


# --- F4: sequence numbers ------------------------------------------------------------


def test_duplicate_i_frame_is_discarded_not_fatal():
    """REVIEW F4 repro: V(R)=1 and the meter repeats its N(S)=0 answer."""
    meter = LossyMeter()
    link = make_link(meter)
    link.connect()
    assert link.request(b"\xc0\x01\x01") == b"\xc0\x01\x01"
    stale = meter.last_tx  # I N(S)=0 N(R)=1
    link.transport.responder = lambda data: stale + meter(data)
    assert link.request(b"\xc0\x01\x02") == b"\xc0\x01\x02"
    assert link.vr == 2


def test_duplicate_segment_after_lost_rr_is_acknowledged_again():
    meter = LossyMeter(max_info=32, repeat_once=True)
    link = make_link(meter)
    link.connect()
    apdu = bytes(range(100))
    assert link.request(apdu) == apdu
    rrs = [f for f in sent_frames(link) if f.kind == FrameType.RR]
    # one RR per segment boundary of the 4-frame answer, plus one re-sent
    # for the duplicate
    assert len(rrs) == 4


def test_invalid_nr_rejected():
    """REVIEW F4 repro: an I-frame with N(R)=5 at V(S)=1 acknowledges frames
    never sent."""
    meter = FakeMeter()
    link = make_link(meter)
    link.connect()
    link.transport.responder = lambda data: bytes.fromhex(
        "7ea0132103b0db05e6e700c401c100090142fe657e"
    )
    with pytest.raises(ProtocolError, match=r"invalid N\(R\)=5"):
        link.request(b"\xc0\x01\x01")


def test_invalid_nr_in_segment_ack_rejected():
    meter = FakeMeter(max_info=32)
    link = make_link(meter)
    link.connect()
    link.transport.responder = lambda data: meter.frame(control_rr(6))
    with pytest.raises(ProtocolError, match=r"invalid N\(R\)"):
        link.request(bytes(100))


# --- F5: recovery ---------------------------------------------------------------------


def test_lost_answer_recovered_by_rr_poll():
    meter = LossyMeter(lose_answers=1)
    link = make_link(meter, timeout=0.05)
    link.connect()
    assert link.request(b"\xc0\x01\x01") == b"\xc0\x01\x01"
    assert meter.polls == 1


def test_lost_request_retransmitted_after_poll():
    meter = LossyMeter(lose_requests=1)
    link = make_link(meter, timeout=0.05)
    link.connect()
    assert link.request(b"\xc0\x01\x01") == b"\xc0\x01\x01"
    i_frames = [f for f in sent_frames(link) if f.kind == FrameType.I]
    assert [f.ns for f in i_frames] == [0, 0]  # the original and the retransmission
    assert meter.received == [b"\xc0\x01\x01"]


def test_lost_segment_ack_recovered_by_rr_poll():
    meter = LossyMeter(max_info=32, lose_acks=2)
    link = make_link(meter, timeout=0.05)
    link.connect()
    apdu = bytes(range(100))
    assert link.request(apdu) == apdu


def test_lost_middle_segment_of_answer_recovered():
    meter = LossyMeter(max_info=32, response_size=100)
    link = make_link(meter, timeout=0.05)
    link.connect()
    original = meter._next_segment
    calls = []

    def lose_second():
        raw = original()
        calls.append(raw)
        return b"" if len(calls) == 2 else raw

    meter._next_segment = lose_second
    assert link.request(b"\xc0\x01") == bytes(100)


def test_no_answer_polls_retries_times_then_times_out():
    """REVIEW F5 repro: no answer used to fail after exactly 1 frame sent."""
    meter = FakeMeter()
    link = make_link(meter, timeout=0.05, retries=3)
    link.connect()
    link.transport.sent.clear()
    link.transport.responder = lambda data: b""
    with pytest.raises(DlmsTimeoutError, match="3 RR polls"):
        link.request(b"\xc0\x01\x01")
    kinds = [f.kind for f in sent_frames(link)]
    assert kinds == [FrameType.I, FrameType.RR, FrameType.RR, FrameType.RR]
    assert all(f.poll_final for f in sent_frames(link))


def test_retries_zero_fails_on_first_timeout():
    meter = FakeMeter()
    link = make_link(meter, timeout=0.05, retries=0)
    link.connect()
    link.transport.sent.clear()
    link.transport.responder = lambda data: b""
    with pytest.raises(DlmsTimeoutError):
        link.request(b"\xc0\x01\x01")
    assert len(link.transport.sent) == 1


def test_push_wait_never_polls():
    meter = FakeMeter()
    link = make_link(meter, timeout=0.05)
    link.connect()
    link.transport.sent.clear()
    with pytest.raises(DlmsTimeoutError):
        link.receive_push()
    assert link.transport.sent == []


# --- F14: stale frames -------------------------------------------------------------


def test_late_ua_before_answer_is_ignored():
    """REVIEW F14 repro: UA (F=1) then the I-frame answer."""
    meter = FakeMeter()
    link = make_link(meter)
    link.connect()
    link.transport.responder = lambda data: meter.frame(FrameType.UA | 0x10) + meter(data)
    assert link.request(b"\xc0\x01\x01") == b"\xc0\x01\x01"


def test_late_ua_from_snrm_retry_is_flushed():
    meter = FakeMeter()
    snrms = []

    def responder(data):
        frames = FrameReader().feed(data)
        if frames[0].kind == FrameType.SNRM:
            snrms.append(data)
            if len(snrms) == 1:
                return b""  # the first UA is late ...
            return meter(data) + meter(data)  # ... and arrives with the second
        return meter(data)

    link = HdlcLink(LoopbackTransport(responder), timeout=0.05, retries=2)
    link.connect()
    assert link.request(b"\xc0\x01\x01") == b"\xc0\x01\x01"


def test_reconnect_discards_frames_of_the_previous_session():
    meter = FakeMeter()
    link = make_link(meter)
    link.connect()
    link.disconnect()
    # An answer of the old session (N(S)=0) still sits in the receive path.
    stale = meter.frame(control_i(0, 1), b"\xe6\xe7\x00\xc4\x01\xc1\x00\x09\x01\x42")
    link._pending.extend(FrameReader().feed(stale))
    link.transport.inject(stale)
    link.connect()
    assert link.request(b"\xc0\x01\x01") == b"\xc0\x01\x01"


def test_snrm_answer_skips_data_frames():
    meter = FakeMeter()
    stale = meter.frame(control_i(3, 0), b"\xe6\xe7\x00\xc4")

    def responder(data):
        return stale + meter(data)

    link = HdlcLink(LoopbackTransport(responder), timeout=0.05, retries=0)
    link.connect()
    assert link.negotiated.max_info_tx == 128


# --- F7: bounds ---------------------------------------------------------------------


def test_reassembly_capped():
    meter = FakeMeter(max_info=32, response_size=500)
    link = make_link(meter, max_apdu_size=200)
    link.connect()
    with pytest.raises(FramingError, match="exceeds 200"):
        link.request(b"\xc0\x01")


def test_default_reassembly_cap_is_max_pdu():
    assert make_link(FakeMeter()).max_apdu_size == MAX_APDU_SIZE == 0xFFFF


def test_segmented_ui_push_capped():
    meter = FakeMeter()
    link = make_link(meter, max_apdu_size=100)
    segment = meter.frame(FrameType.UI, bytes(60), segmented=True)
    link.transport.inject(segment * 3)
    with pytest.raises(FramingError):
        link.receive_apdu()


class FloodTransport(LoopbackTransport):
    """Answers every read with one more RR, forever (a babbling peer)."""

    def __init__(self, frame: bytes):
        super().__init__()
        self.frame = frame
        self.reads = 0

    def _read(self, max_bytes, timeout):
        if self._rx:
            return super()._read(max_bytes, timeout)
        self.reads += 1
        if self.reads > 200_000:
            raise RuntimeError("receive_apdu never gave up")
        return self.frame


def test_rr_flood_does_not_extend_the_wait():
    meter = FakeMeter()
    rr = encode_rr(meter, 0)
    transport = FloodTransport(rr)
    link = HdlcLink(transport, timeout=0.05, retries=0)
    link.state = link.state.CONNECTED
    with pytest.raises(DlmsTimeoutError):
        link.receive_apdu()


def encode_rr(meter, nr):
    from pydlms.hdlc.framing import encode_frame

    return encode_frame(HdlcFrame(meter.client, meter.server, control_rr(nr)))
