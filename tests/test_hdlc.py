"""Tests for HDLC: CRC, addressing, frame codec, reader and the link state machine."""

from __future__ import annotations

import pytest

from pydlms.exceptions import ChecksumError, FramingError, ProtocolError
from pydlms.hdlc.address import HdlcAddress, decode_address, read_address
from pydlms.hdlc.connection import HdlcLink, HdlcParameters, HdlcState
from pydlms.hdlc.crc import crc16_x25, fcs_bytes
from pydlms.hdlc.framing import (
    LLC_RESPONSE,
    FrameReader,
    FrameType,
    HdlcFrame,
    control_i,
    control_rnr,
    control_rr,
    decode_frame,
    encode_frame,
    strip_llc,
)
from pydlms.transports.base import LoopbackTransport

# A real L+G E450 push frame (esphome-libs/dlms_parser hdlc_landis_gyr_e450, Apache-2.0).
E450_FIRST = bytes.fromhex(
    "7ea08bceff0313eee1e6e700e0400001000077db084c475a677370b1778201033000177bca14dd2985"
    "39c05bd0e9250bcb05d33295aad43eda9a14e25ac843c12fc63ca7e5c42a4d53e3f6a0c9c8793c0e1d"
    "011ab0df9b7a48a3361428240d3775a473cd4ac2238ab2594d87c7b037bb5bc130e3070770e04b9e40"
    "7da3cd42314bd87f2e08067d34a7cab7417e"
)


# --- CRC ----------------------------------------------------------------------


def test_crc_check_value():
    # CRC-16/X-25 catalogue check value.
    assert crc16_x25(b"123456789") == 0x906E


def test_fcs_wire_order_snrm():
    # Well-known SNRM 7E A0 07 03 21 93 0F 01 7E.
    assert fcs_bytes(bytes.fromhex("A007032193")) == b"\x0f\x01"


def test_crc_matches_real_frame_hcs():
    assert fcs_bytes(E450_FIRST[1:7]) == E450_FIRST[7:9]


# --- addressing -------------------------------------------------------------


@pytest.mark.parametrize(
    "address,encoded",
    [
        (HdlcAddress.client(16), b"\x21"),
        (HdlcAddress.client(1), b"\x03"),
        (HdlcAddress.server(1), b"\x03"),
        (HdlcAddress.server(1, 17), b"\x02\x23"),
        (HdlcAddress(103, 127, 2), b"\xce\xff"),
        (HdlcAddress.server(1, 0x3FFF, size=4), b"\x00\x02\xfe\xff"),
        (
            HdlcAddress.server(0x1234, 0x0ABC),
            bytes([0x24 << 1, 0x34 << 1, 0x15 << 1, (0x3C << 1) | 1]),
        ),
    ],
)
def test_address_vectors(address, encoded):
    assert address.to_bytes() == encoded
    assert decode_address(encoded) == address


def test_read_address_from_stream():
    addr, nxt = read_address(b"\xce\xff\x03", 0)
    assert addr == HdlcAddress(103, 127, 2)
    assert nxt == 2


@pytest.mark.parametrize(
    "raw", [b"\x02", b"\x03\x03", b"\x02\x02\x03", b"", b"\x02\x02\x02\x02\x03"]
)
def test_bad_addresses_rejected(raw):
    with pytest.raises(FramingError):
        decode_address(raw)


def test_read_address_runs_off_end():
    with pytest.raises(FramingError):
        read_address(b"\x02\x02", 0)
    with pytest.raises(FramingError):
        read_address(b"\x02\x02\x02\x02\x03", 0)


def test_address_range_checks():
    with pytest.raises(ValueError):
        HdlcAddress(0x80)
    with pytest.raises(ValueError):
        HdlcAddress(1, 2, 1)
    with pytest.raises(ValueError):
        HdlcAddress(1, None, 3)


# --- frames -------------------------------------------------------------------


def test_snrm_vector():
    frame = HdlcFrame(HdlcAddress.server(1), HdlcAddress.client(16), FrameType.SNRM | 0x10)
    assert encode_frame(frame) == bytes.fromhex("7EA0070321930F017E")
    decoded = decode_frame(bytes.fromhex("7EA0070321930F017E"))
    assert decoded.kind == FrameType.SNRM and decoded.poll_final and decoded.info == b""


def test_real_e450_frame_round_trip():
    frame = decode_frame(E450_FIRST)
    assert frame.kind == FrameType.UI
    assert frame.src == HdlcAddress.server(1)
    assert frame.info.startswith(LLC_RESPONSE + b"\xe0")
    assert not frame.segmented
    assert encode_frame(frame) == E450_FIRST


def test_i_frame_sequence_fields():
    frame = HdlcFrame(HdlcAddress.server(1), HdlcAddress.client(16), control_i(3, 5), b"\x01")
    decoded = decode_frame(encode_frame(frame))
    assert decoded.kind == FrameType.I
    assert (decoded.ns, decoded.nr) == (3, 5)
    rr = decode_frame(encode_frame(HdlcFrame(frame.dest, frame.src, control_rr(6))))
    assert rr.kind == FrameType.RR and rr.nr == 6


def test_segmentation_bit_round_trip():
    frame = HdlcFrame(HdlcAddress.server(1), HdlcAddress.client(16), control_i(0, 0), b"abc", True)
    raw = encode_frame(frame)
    assert raw[1] & 0x08
    assert decode_frame(raw).segmented


@pytest.mark.parametrize("position", range(1, len(E450_FIRST) - 1))
def test_any_corrupted_byte_rejected(position):
    raw = bytearray(E450_FIRST)
    raw[position] ^= 0x01
    with pytest.raises(FramingError):
        decode_frame(bytes(raw))


def test_bad_fcs_is_checksum_error():
    raw = bytearray(E450_FIRST)
    raw[-2] ^= 0xFF
    with pytest.raises(ChecksumError):
        decode_frame(bytes(raw))


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\x7e\x7e",
        E450_FIRST[:-1],
        E450_FIRST[1:],
        b"\x7e\xb0" + E450_FIRST[2:],  # wrong format type
        E450_FIRST[:-3] + E450_FIRST[-2:],  # truncated, length mismatch
    ],
)
def test_malformed_frames(raw):
    with pytest.raises(FramingError):
        decode_frame(raw)


def test_oversized_frame_rejected():
    with pytest.raises(ValueError):
        encode_frame(HdlcFrame(HdlcAddress.server(1), HdlcAddress.client(16), 0x10, bytes(2100)))


def test_strip_llc():
    assert strip_llc(b"\xe6\xe7\x00\x0f") == b"\x0f"
    assert strip_llc(b"\xe6\xe6\x00\xc0") == b"\xc0"
    assert strip_llc(b"\x0f") == b"\x0f"


# --- reader ---------------------------------------------------------------------


def test_reader_handles_split_noise_and_shared_flags():
    snrm = bytes.fromhex("7EA0070321930F017E")
    reader = FrameReader()
    stream = b"\x10\x40\x01\x41\x16" + snrm + snrm[1:] + E450_FIRST
    frames = []
    for i in range(0, len(stream), 7):
        frames += reader.feed(stream[i : i + 7])
    assert [f.kind for f in frames] == [FrameType.SNRM, FrameType.SNRM, FrameType.UI]


def test_reader_drops_bad_frame_and_recovers():
    bad = bytearray(E450_FIRST)
    bad[20] ^= 0xFF
    reader = FrameReader()
    frames = reader.feed(bytes(bad) + E450_FIRST)
    assert len(frames) == 1
    assert reader.dropped >= 1


def test_reader_strict_raises():
    bad = bytearray(E450_FIRST)
    bad[20] ^= 0xFF
    with pytest.raises(FramingError):
        FrameReader(strict=True).feed(bytes(bad))


# --- parameters -----------------------------------------------------------------


def test_parameters_round_trip_and_vector():
    params = HdlcParameters(max_info_tx=128, max_info_rx=128, window_tx=1, window_rx=1)
    raw = params.to_bytes()
    assert raw == bytes.fromhex(
        "818012 0501 80 0601 80 0704 00000001 0804 00000001".replace(" ", "")
    )
    assert HdlcParameters.from_bytes(raw) == params


def test_parameters_two_octet_lengths():
    raw = bytes.fromhex("81801405020400060204000704000000010804000000 01".replace(" ", ""))
    params = HdlcParameters.from_bytes(raw)
    assert params.max_info_tx == 0x400 and params.max_info_rx == 0x400


@pytest.mark.parametrize(
    "raw", ["8180", "818005050180", "81800305 0580", "828003050180", "8180030500"]
)
def test_parameters_malformed(raw):
    with pytest.raises(FramingError):
        HdlcParameters.from_bytes(bytes.fromhex(raw.replace(" ", "")))


def test_empty_parameters_default():
    assert HdlcParameters.from_bytes(b"") == HdlcParameters()


# --- link state machine against a scripted meter ----------------------------------


class FakeMeter:
    """A minimal HDLC server: UA on SNRM, echoes APDUs, segments responses."""

    def __init__(self, max_info=128, response_size=None, ua_params=None):
        self.reader = FrameReader(strict=True)
        self.client = HdlcAddress.client(16)
        self.server = HdlcAddress.server(1)
        self.vs = 0
        self.vr = 0
        self.max_info = max_info
        self.response_size = response_size
        self.ua_params = ua_params
        self.rx_apdu = bytearray()
        self.received: list[bytes] = []
        self.pending_tx: list[HdlcFrame] = []

    def frame(self, control, info=b"", segmented=False):
        return encode_frame(HdlcFrame(self.client, self.server, control, info, segmented))

    def __call__(self, data: bytes) -> bytes:
        out = b""
        for f in self.reader.feed(data):
            out += self.handle(f)
        return out

    def handle(self, f: HdlcFrame) -> bytes:
        if f.kind == FrameType.SNRM:
            self.vs = self.vr = 0
            params = (
                self.ua_params
                if self.ua_params is not None
                else HdlcParameters(self.max_info, self.max_info).to_bytes()
            )
            return self.frame(FrameType.UA | 0x10, params)
        if f.kind == FrameType.DISC:
            return self.frame(FrameType.UA | 0x10)
        if f.kind == FrameType.I:
            assert f.ns == self.vr
            self.vr = (self.vr + 1) % 8
            self.rx_apdu += f.info
            if f.segmented:
                return self.frame(control_rr(self.vr))
            apdu = strip_llc(bytes(self.rx_apdu))
            self.received.append(apdu)
            self.rx_apdu = bytearray()
            body = b"\xe6\xe7\x00" + (bytes(self.response_size) if self.response_size else apdu)
            chunks = [body[i : i + self.max_info] for i in range(0, len(body), self.max_info)]
            self.pending_tx = [
                HdlcFrame(self.client, self.server, 0, c, i < len(chunks) - 1)
                for i, c in enumerate(chunks)
            ]
            return self._next_segment()
        if f.kind == FrameType.RR:
            return self._next_segment()
        raise AssertionError(f"unexpected {f.kind}")

    def _next_segment(self) -> bytes:
        if not self.pending_tx:
            return b""
        f = self.pending_tx.pop(0)
        f.control = control_i(self.vs, self.vr)
        self.vs = (self.vs + 1) % 8
        return encode_frame(f)


def make_link(meter, **kw):
    kw.setdefault("timeout", 0.2)
    return HdlcLink(LoopbackTransport(meter), **kw)


def test_link_connect_request_disconnect():
    meter = FakeMeter()
    link = make_link(meter)
    link.connect()
    assert link.state == HdlcState.CONNECTED
    assert link.request(b"\xc0\x01\x01") == b"\xc0\x01\x01"
    assert link.request(b"\xc0\x01\x02") == b"\xc0\x01\x02"
    link.disconnect()
    assert link.state == HdlcState.DISCONNECTED
    assert meter.received == [b"\xc0\x01\x01", b"\xc0\x01\x02"]


def test_link_negotiates_smaller_info_length():
    meter = FakeMeter(max_info=64)
    link = make_link(meter, parameters=HdlcParameters(max_info_tx=512, max_info_rx=512))
    link.connect()
    assert link.negotiated.max_info_tx == 64
    assert link.negotiated.max_info_rx == 64


def test_link_segmented_send_and_receive():
    meter = FakeMeter(max_info=32)
    link = make_link(meter)
    link.connect()
    apdu = bytes(range(200))
    assert link.request(apdu) == apdu
    # 203 octets with LLC at 32 per frame -> 7 I-frames from us.
    sent_i = [f for f in FrameReader().feed(b"".join(link.transport.sent)) if f.kind == FrameType.I]
    assert len(sent_i) == 7 and all(f.segmented for f in sent_i[:-1]) and not sent_i[-1].segmented


def test_link_sequence_numbers_wrap():
    meter = FakeMeter()
    link = make_link(meter)
    link.connect()
    for i in range(20):
        assert link.request(bytes([0xC0, i])) == bytes([0xC0, i])
    assert link.vs == 20 % 8


def test_link_ua_without_parameters_uses_defaults():
    link = make_link(FakeMeter(ua_params=b""))
    link.connect()
    assert link.negotiated == HdlcParameters()


def test_link_dm_on_snrm():
    meter = FakeMeter()

    def responder(data):
        return meter.frame(FrameType.DM | 0x10)

    link = HdlcLink(LoopbackTransport(responder), timeout=0.1)
    with pytest.raises(ProtocolError, match="DM"):
        link.connect()


def test_link_timeout_retries_snrm():
    from pydlms.exceptions import DlmsTimeoutError

    transport = LoopbackTransport(lambda data: b"")
    link = HdlcLink(transport, timeout=0.05, retries=2)
    with pytest.raises(DlmsTimeoutError):
        link.connect()
    assert len(transport.sent) == 3


def test_link_out_of_sequence_rejected():
    meter = FakeMeter()
    link = make_link(meter)
    link.connect()

    def bad_responder(data):
        return meter.frame(control_i(5, 1), b"\xe6\xe7\x00\x01")

    link.transport.responder = bad_responder
    with pytest.raises(ProtocolError, match="out-of-sequence"):
        link.request(b"\xc0\x01")


def test_link_requires_connect():
    link = make_link(FakeMeter())
    with pytest.raises(ProtocolError):
        link.send_apdu(b"\x00")


def test_link_receives_ui_push():
    link = make_link(FakeMeter())
    link.transport.inject(E450_FIRST)
    link.state = HdlcState.CONNECTED
    link.client = HdlcAddress.client(103)
    apdu = link.receive_push()
    assert apdu[0] == 0xE0


class BusyMeter(FakeMeter):
    """Answers each segment with RNR (receiver not ready) and stays busy for
    ``busy`` RR polls before answering RR, like a meter whose input buffer
    is full. ``wrong_nr`` makes the RNR acknowledge the wrong frame."""

    def __init__(self, busy, wrong_nr=False, **kw):
        super().__init__(**kw)
        self.busy_for = busy
        self.remaining = 0
        self.polls = 0
        self.wrong_nr = wrong_nr

    def handle(self, f):
        if f.kind == FrameType.I and f.segmented:
            assert self.remaining == 0, "client sent an I-frame while the meter was busy"
            assert f.ns == self.vr
            self.vr = (self.vr + 1) % 8
            self.rx_apdu += f.info
            self.remaining = self.busy_for
            return self.frame(control_rnr((self.vr + self.wrong_nr) % 8))
        if f.kind == FrameType.RR and self.remaining:
            self.polls += 1
            self.remaining -= 1
            return self.frame(control_rnr(self.vr) if self.remaining else control_rr(self.vr))
        return super().handle(f)


def test_link_waits_while_meter_reports_rnr():
    meter = BusyMeter(busy=3, max_info=32)
    link = make_link(meter, busy_interval=0)
    link.connect()
    apdu = bytes(range(100))
    assert link.request(apdu) == apdu
    # 103 octets with LLC -> 4 frames; the 3 segmented ones are each answered
    # RNR and polled until RR (3 polls each).
    assert meter.polls == 3 * 3


def test_link_gives_up_on_a_meter_that_stays_busy():
    from pydlms.exceptions import DlmsTimeoutError

    meter = BusyMeter(busy=100, max_info=32)
    link = make_link(meter, busy_polls=3, busy_interval=0)
    link.connect()
    with pytest.raises(DlmsTimeoutError, match="still busy"):
        link.request(bytes(100))
    assert meter.polls == 3


def test_link_rnr_with_wrong_nr_rejected():
    meter = BusyMeter(busy=1, wrong_nr=True, max_info=32)
    link = make_link(meter, busy_interval=0)
    link.connect()
    with pytest.raises(ProtocolError, match="not acknowledged"):
        link.request(bytes(100))


# --- review F1: UA parameter ranges -------------------------------------------------

# UA with max info tx=0, rx=1 octet 0x80, windows 1 (REVIEW.md F1).
UA_ZERO_TX = bytes.fromhex("7ea01e210373c37a818012050180060100070400000001080400000001f1fd7e")


def test_ua_max_info_zero_means_default():
    """A 0 parameter is "use the default" (IEC 62056-46 6.4.4.4.3.2 via
    cB-Sigma); it must never reach the segmenter as a 0 slice size."""
    params = HdlcParameters.from_bytes(decode_frame(UA_ZERO_TX).info)
    assert (params.max_info_tx, params.max_info_rx) == (0x80, 128)
    link = make_link(FakeMeter(ua_params=decode_frame(UA_ZERO_TX).info))
    link.connect()
    assert link.negotiated.max_info_tx == 128  # the UA's rx (0 = default) is our tx
    assert link.request(bytes(300)) == bytes(300)


@pytest.mark.parametrize(
    "group",
    [
        "050207ef",  # max info tx 2031 > 2030
        "06020800",  # max info rx 2048
        "070400000008",  # window tx 8
        "080400000000ff",  # length 4 but 5 value octets: bad length
    ],
)
def test_ua_parameters_out_of_range_raise_framing_error(group):
    raw = bytes.fromhex(group)
    field = bytes([0x81, 0x80, len(raw)]) + raw
    with pytest.raises(FramingError):
        HdlcParameters.from_bytes(field)


def test_ua_out_of_range_is_framing_error_on_connect():
    params = bytes.fromhex("8180040502ffff")  # max info tx 65535
    link = make_link(FakeMeter(ua_params=params))
    with pytest.raises(FramingError):
        link.connect()


@pytest.mark.parametrize(
    "kw",
    [
        {"max_info_tx": 0},
        {"max_info_rx": 2031},
        {"window_tx": 0},
        {"window_rx": 8},
    ],
)
def test_hdlc_parameters_validated_at_construction(kw):
    with pytest.raises(FramingError):
        HdlcParameters(**kw)


def test_oversized_frame_is_framing_error():
    with pytest.raises(FramingError):
        encode_frame(HdlcFrame(HdlcAddress.server(1), HdlcAddress.client(16), 0x10, bytes(2040)))


# --- review F2: REJ / SREJ / unknown control ------------------------------------------

REJ_FRAME = bytes.fromhex("7ea0072103195d8c7e")


def test_reader_decodes_rej_without_value_error():
    frames = FrameReader().feed(REJ_FRAME)
    assert len(frames) == 1
    assert frames[0].kind == FrameType.REJ
    assert frames[0].nr == 0
    assert "REJ" in frames[0].describe()


def test_reader_trace_does_not_evaluate_describe(caplog):
    """describe() must not run (or raise) unless TRACE logging is on."""
    reader = FrameReader()
    calls = []
    original = HdlcFrame.describe

    def spy(self):
        calls.append(self)
        return original(self)

    HdlcFrame.describe = spy
    try:
        reader.feed(REJ_FRAME)
    finally:
        HdlcFrame.describe = original
    assert calls == []


def test_unknown_unnumbered_control_is_framing_error():
    frame = HdlcFrame(HdlcAddress.client(16), HdlcAddress.server(1), 0x2F)  # XID-like
    with pytest.raises(FramingError):
        _ = frame.kind
    assert "0x2F" in frame.describe()


def test_link_rej_while_waiting_is_protocol_error_not_value_error():
    meter = FakeMeter()
    link = make_link(meter, retries=0)
    link.connect()
    link.transport.responder = lambda data: meter.frame(0x09 | 0x10 | (2 << 5))
    with pytest.raises(ProtocolError):
        link.request(b"\xc0\x01")


def test_link_unknown_frame_while_waiting_is_dlms_error():
    from pydlms.exceptions import DlmsError

    meter = FakeMeter()
    link = make_link(meter, retries=0)
    link.connect()
    link.transport.responder = lambda data: meter.frame(0x2F | 0x10)
    with pytest.raises(DlmsError):
        link.request(b"\xc0\x01")


# --- review F3: source address must be the server we talk to ----------------------

# I-frame N(S)=0 N(R)=1 from server 5 to client 16, carrying a GET response.
FOREIGN_I_FRAME = bytes.fromhex("7ea013210b30134fe6e700c401c100090142fe657e")


def test_link_discards_frame_from_another_server():
    meter = FakeMeter()
    link = make_link(meter, retries=0)
    link.connect()
    link.transport.responder = lambda data: FOREIGN_I_FRAME + meter(data)
    assert link.request(b"\xc0\x01\x01") == b"\xc0\x01\x01"


def test_link_times_out_when_only_another_server_answers():
    from pydlms.exceptions import DlmsTimeoutError

    meter = FakeMeter()
    link = make_link(meter, retries=0)
    link.connect()
    link.transport.responder = lambda data: FOREIGN_I_FRAME
    with pytest.raises(DlmsTimeoutError):
        link.request(b"\xc0\x01\x01")


def _addressed_meter(server: HdlcAddress) -> FakeMeter:
    meter = FakeMeter()
    meter.server = server
    return meter


@pytest.mark.parametrize(
    ("configured", "answering", "accepted"),
    [
        (HdlcAddress.server(1, 17), HdlcAddress.server(1, 17), True),
        (HdlcAddress.server(1, 17), HdlcAddress.server(1, 17, size=4), True),  # 4-octet echo
        (HdlcAddress.server(1, 17), HdlcAddress.server(1, 18), False),
        (HdlcAddress.server(1, 17), HdlcAddress.server(2, 17), False),
        (HdlcAddress.server(1, 17), HdlcAddress.server(1), False),
        (HdlcAddress.server(1), HdlcAddress.server(1, 17), True),  # no physical configured
        (HdlcAddress.server(1, 0x7E), HdlcAddress.server(1, 33), True),  # CALLING
        (HdlcAddress.server(1, 0x3FFE, size=4), HdlcAddress.server(1, 1000), True),
    ],
)
def test_link_server_address_matching(configured, answering, accepted):
    from pydlms.exceptions import DlmsTimeoutError

    meter = _addressed_meter(answering)
    link = HdlcLink(LoopbackTransport(meter), server_address=configured, timeout=0.05, retries=0)
    if accepted:
        link.connect()
        assert link.request(b"\xc0\x01") == b"\xc0\x01"
    else:
        with pytest.raises(DlmsTimeoutError):
            link.connect()


def test_link_drops_non_ui_frames_to_all_stations():
    meter = FakeMeter()
    link = make_link(meter, retries=0)
    link.connect()
    broadcast = encode_frame(
        HdlcFrame(HdlcAddress.client(0x7F), meter.server, control_i(0, 1), LLC_RESPONSE + b"\xc4")
    )
    link.transport.responder = lambda data: broadcast + meter(data)
    assert link.request(b"\xc0\x01\x01") == b"\xc0\x01\x01"


# --- review F6: a UI push during a request is not the response --------------------

PUSH_APDU = bytes.fromhex("0f00000001000902abcd")


def _ui(meter, apdu, segmented=False, llc=True):
    info = (LLC_RESPONSE if llc else b"") + apdu
    return meter.frame(FrameType.UI | 0x10, info, segmented)


def test_link_request_skips_ui_push_and_queues_it():
    meter = FakeMeter()
    link = make_link(meter)
    link.connect()
    link.transport.responder = lambda data: _ui(meter, PUSH_APDU) + meter(data)
    assert link.request(b"\xc0\x01\x01") == b"\xc0\x01\x01"
    assert link.receive_push() == PUSH_APDU


def test_link_request_skips_segmented_ui_push():
    meter = FakeMeter()
    link = make_link(meter)
    link.connect()
    first = meter.frame(FrameType.UI, LLC_RESPONSE + PUSH_APDU[:4], segmented=True)
    rest = meter.frame(FrameType.UI | 0x10, PUSH_APDU[4:])
    link.transport.responder = lambda data: first + meter(data) + rest
    assert link.request(b"\xc0\x01\x01") == b"\xc0\x01\x01"
    assert link.receive_push() == PUSH_APDU


def test_link_receive_push_waits_for_ui_on_connected_link():
    meter = FakeMeter()
    link = make_link(meter)
    link.connect()
    link.transport.inject(_ui(meter, PUSH_APDU))
    assert link.receive_push() == PUSH_APDU


def test_disconnected_link_receive_apdu_still_returns_pushes():
    link = make_link(FakeMeter())
    link.transport.inject(E450_FIRST)
    link.client = HdlcAddress.client(103)
    assert link.receive_apdu()[0] == 0xE0


def test_client_read_push_returns_push_queued_during_request():
    from pydlms.apdu.xdlms import DataNotification
    from pydlms.client import DlmsClient
    from pydlms.cosem.data import DlmsData

    note = DataNotification(7, DlmsData.structure([DlmsData.uint32(42)])).to_bytes()
    meter = FakeMeter()
    link = make_link(meter)
    client = DlmsClient(link, auto_associate=False)
    client.connect()
    link.transport.responder = lambda data: _ui(meter, note) + meter(data)
    assert link.request(b"\xc0\x01\x01") == b"\xc0\x01\x01"
    message = client.read_push(timeout=0.1)
    assert message.notification.long_invoke_id == 7
