"""HDLC modulo-128 numbering (SNRME), opt-in.

IEC 62056-46 defines modulo 8 only; ISO/IEC 13239 extended numbering is set
up with SNRME and gives I and S frames a two-octet control field. Layout and
behaviour reference: cB-Sigma ``hdlc/control.go``, ``station.go``,
``client.go``, ``frmr.go`` (Apache-2.0, read, not copied); the ISO/IEC 13239
clauses they cite are *unverified* here. The encodings themselves are
checked against ITU-T X.25 and IBM SDLC in ``test_hdlc_spec_sources.py``.

The ``ORACLE`` vectors were produced by cB-Sigma/dlms itself at the commit
the interop image pins (26360a13e5d8f1da0fba1758118adaaa00be2ccf): a Go
test in its ``hdlc`` package built each frame with ``Control.set(&f,
Modulo128)`` and ``Frame.Encode``, and each FRMR field with
``FrameReject{Modulo: 128}.Encode``.
"""

from __future__ import annotations

import itertools

import pytest

from pydlms.exceptions import (
    ChecksumError,
    DlmsTimeoutError,
    FrameRejectError,
    FramingError,
    ProtocolError,
)
from pydlms.hdlc import FrameReject, HdlcModeTracker, decode_frmr
from pydlms.hdlc.address import HdlcAddress
from pydlms.hdlc.connection import (
    MAX_WINDOW_128,
    HdlcLink,
    HdlcParameters,
    max_window,
    parse_parameter_field,
)
from pydlms.hdlc.crc import crc16_x25
from pydlms.hdlc.framing import (
    LLC_REQUEST,
    MODULO_128,
    PF_BIT,
    FrameReader,
    FrameType,
    HdlcFrame,
    control_i,
    control_octets,
    control_rej,
    control_rnr,
    control_rr,
    decode_frame,
    encode_frame,
)
from pydlms.hdlc.frmr import FRMR_INFO_LEN_128
from pydlms.simulator import HdlcServer, example_meter, serve
from pydlms.transports.base import LoopbackTransport

SERVER = HdlcAddress.server(1)
CLIENT = HdlcAddress.client(16)
INFO = bytes.fromhex("e6e600c001c1")

#: cB-Sigma/dlms ``hdlc`` (see the module docstring); server 1 -> client 16
#: addresses are 03 21.
ORACLE = {
    "i_1_126_p0": "7ea010032102fc74b1e6e600c001c123cd7e",
    "i_127_5_p1_seg": "7ea80e0321fe0b4c13e6e600016ec67e",
    "rr_5_p1": "7ea0080321010b4cf67e",
    "rnr_127_p1": "7ea008032105ff87207e",
    "snrme_default": "7ea0070321df67897e",
    "snrme_w20": "7ea01e0321dfa5b3818012050180060180070400000014080400000064924a7e",
    "ua_w20": "7ea01e032173c3dc818012050180060180070400000014080400000064924a7e",
}
FRMR_ORACLE = {"frmr128": "02fcc83608", "frmr128b": "9300fe0307"}

AARQ = bytes.fromhex("601da109060760857405080101be10040e01000000065f1f0400001e1dffff")


def bits_lsb(bits: str) -> int:
    """An octet from its bits in transmission order (bit 1 first)."""
    return sum(1 << i for i, b in enumerate(bits) if b == "1")


def seven(value: int) -> str:
    return "".join(str(value >> i & 1) for i in range(7))


def frame128(control, info=b"", segmented=False, dest=SERVER, src=CLIENT):
    return HdlcFrame(dest, src, control, info, segmented, MODULO_128)


# --- control field --------------------------------------------------------------------


@pytest.mark.parametrize(
    "ns,nr,poll", list(itertools.product((0, 1, 63, 64, 126, 127), (0, 1, 5, 126, 127), (0, 1)))
)
def test_extended_control_bit_layout(ns, nr, poll):
    # ISO/IEC 13239 extended control fields as bit strings in transmission
    # order (via cB-Sigma modulo128_test.go): I = 0 N(S) | P/F N(R);
    # RR = 1000 0000 | P/F N(R); RNR = 1010 0000; REJ = 1001 0000.
    second = bits_lsb(str(poll) + seven(nr))
    wire = {
        control_i(ns, nr, bool(poll), MODULO_128): (bits_lsb("0" + seven(ns)), second),
        control_rr(nr, bool(poll), MODULO_128): (bits_lsb("10000000"), second),
        control_rnr(nr, bool(poll), MODULO_128): (bits_lsb("10100000"), second),
        control_rej(nr, bool(poll), MODULO_128): (bits_lsb("10010000"), second),
    }
    for control, octets in wire.items():
        assert control_octets(control, MODULO_128) == bytes(octets)
    frame = frame128(control_i(ns, nr, bool(poll), MODULO_128))
    assert (frame.kind, frame.ns, frame.nr, frame.poll_final) == (FrameType.I, ns, nr, bool(poll))
    assert frame.extended
    for make, kind in (
        (control_rr, FrameType.RR),
        (control_rnr, FrameType.RNR),
        (control_rej, FrameType.REJ),
    ):
        s = frame128(make(nr, bool(poll), MODULO_128))
        assert (s.kind, s.nr, s.poll_final) == (kind, nr, bool(poll))


def test_extended_numbers_are_reduced_modulo_128():
    assert control_i(128, 129, True, MODULO_128) == control_i(0, 1, True, MODULO_128)
    assert control_rr(-1, True, MODULO_128) == control_rr(127, True, MODULO_128)


def test_snrme_control_values():
    assert FrameType.SNRME == bits_lsb("1111" + "0" + "011") == 0xCF
    assert FrameType.SNRME | PF_BIT == bits_lsb("1111" + "1" + "011") == 0xDF
    frame = decode_frame(bytes.fromhex(ORACLE["snrme_default"]))
    assert frame.kind == FrameType.SNRME and frame.poll_final
    # Every other byte value the modulo-8 decoder knew keeps its kind.
    assert {k.name for k in FrameType} >= {"SNRM", "SNRME", "UA", "DM", "FRMR", "UI"}


@pytest.mark.parametrize("kind", [FrameType.SNRM, FrameType.UA, FrameType.DM, FrameType.UI])
def test_unnumbered_frames_keep_one_octet(kind):
    for pf in (0, PF_BIT):
        mod8 = encode_frame(HdlcFrame(SERVER, CLIENT, kind | pf, INFO))
        mod128 = encode_frame(frame128(kind | pf, INFO))
        assert mod8 == mod128
        assert decode_frame(mod8, modulus=MODULO_128) == frame128(kind | pf, INFO)


@pytest.mark.parametrize("bad", [0x100, -1, 0x1FF03])
def test_control_that_does_not_fit_raises(bad):
    modulus = 8 if bad == 0x100 else MODULO_128
    with pytest.raises(FramingError):
        encode_frame(HdlcFrame(SERVER, CLIENT, bad, b"", False, modulus))


@pytest.mark.parametrize("modulus", [0, 7, 16, 127, 256])
def test_unsupported_modulus_is_a_value_error(modulus):
    with pytest.raises(ValueError, match="modulo 8 or 128"):
        HdlcFrame(SERVER, CLIENT, 0, modulus=modulus)
    with pytest.raises(ValueError):
        control_i(0, 0, True, modulus)
    with pytest.raises(ValueError):
        decode_frame(bytes.fromhex(ORACLE["rr_5_p1"]), modulus=modulus)
    with pytest.raises(ValueError):
        FrameReader(modulus=modulus)


# --- frames: oracle vectors, round trip, malformed -------------------------------------


@pytest.mark.parametrize(
    "name,frame",
    [
        ("i_1_126_p0", frame128(control_i(1, 126, False, MODULO_128), INFO)),
        (
            "i_127_5_p1_seg",
            frame128(control_i(127, 5, True, MODULO_128), LLC_REQUEST + b"\x01", True),
        ),
        ("rr_5_p1", frame128(control_rr(5, True, MODULO_128))),
        ("rnr_127_p1", frame128(control_rnr(127, True, MODULO_128))),
        ("snrme_default", frame128(FrameType.SNRME | PF_BIT)),
        (
            "snrme_w20",
            frame128(
                FrameType.SNRME | PF_BIT,
                HdlcParameters(128, 128, 20, 100, modulus=MODULO_128).to_bytes(),
            ),
        ),
    ],
)
def test_oracle_vectors(name, frame):
    raw = bytes.fromhex(ORACLE[name])
    assert encode_frame(frame) == raw
    assert decode_frame(raw, modulus=MODULO_128) == frame


def test_oracle_vector_checksums_by_hand():
    # The HCS covers both control octets: rebuild the I-frame without the
    # construct path.
    header = bytes.fromhex("a010032102fc")
    hcs = crc16_x25(header).to_bytes(2, "little")
    body = header + hcs + INFO
    raw = b"\x7e" + body + crc16_x25(body).to_bytes(2, "little") + b"\x7e"
    assert raw.hex() == ORACLE["i_1_126_p0"]


def test_ua_oracle_parameters_need_modulo_128():
    frame = decode_frame(bytes.fromhex(ORACLE["ua_w20"]), modulus=MODULO_128)
    params, _ = parse_parameter_field(frame.info, MODULO_128)
    assert (params.window_tx, params.window_rx) == (20, 100)
    with pytest.raises(FramingError, match="outside 1..7"):
        parse_parameter_field(frame.info)


@pytest.mark.parametrize(
    "ns,nr,poll,segmented,size",
    [
        (0, 0, True, False, 0),
        (1, 2, False, True, 5),
        (127, 127, True, False, 200),
        (64, 3, 1, 0, 1),
    ],
)
def test_round_trip_and_stream(ns, nr, poll, segmented, size):
    info = bytes(range(size % 256)) * (1 + size // 256)
    frame = frame128(control_i(ns, nr, bool(poll), MODULO_128), info[:size], bool(segmented))
    raw = encode_frame(frame)
    assert decode_frame(raw, modulus=MODULO_128) == frame
    rr = frame128(control_rr(nr, bool(poll), MODULO_128))
    stream = b"\x00\x7e" + raw + encode_frame(rr)
    reader = FrameReader(modulus=MODULO_128)
    assert reader.feed(stream[:7]) == []
    assert reader.feed(stream[7:]) == [frame, rr]


def test_modulo_128_frame_read_as_modulo_8_fails_the_hcs():
    raw = bytes.fromhex(ORACLE["i_1_126_p0"])
    with pytest.raises(ChecksumError):
        decode_frame(raw)
    reader = FrameReader()
    assert reader.feed(raw) == []
    assert reader.dropped == 1


def test_modulo_8_i_frame_read_as_modulo_128_fails_the_hcs():
    raw = encode_frame(HdlcFrame(SERVER, CLIENT, control_i(1, 2), INFO))
    with pytest.raises(ChecksumError):
        decode_frame(raw, modulus=MODULO_128)


@pytest.mark.parametrize("name", ["i_1_126_p0", "rr_5_p1"])
def test_every_byte_tampered_is_rejected(name):
    raw = bytes.fromhex(ORACLE[name])
    for index in range(1, len(raw) - 1):
        tampered = bytearray(raw)
        tampered[index] ^= 0x01
        with pytest.raises(FramingError):
            decode_frame(bytes(tampered), modulus=MODULO_128)


def test_truncated_extended_control_is_a_framing_error():
    # An S frame whose length leaves room for one control octet only: the
    # second octet would have to come out of the FCS.
    header = bytes.fromhex("a007032101")
    body = header + crc16_x25(header).to_bytes(2, "little")
    raw = b"\x7e" + body + b"\x7e"
    assert decode_frame(raw).kind == FrameType.RR  # fine as modulo 8
    with pytest.raises(FramingError):
        decode_frame(raw, modulus=MODULO_128)


def test_unchecked_decode_repairs_a_two_octet_header():
    raw = bytearray(bytes.fromhex(ORACLE["i_1_126_p0"]))
    raw[-3] ^= 0xFF  # FCS
    raw[7] ^= 0xFF  # HCS
    frame = decode_frame(bytes(raw), verify_checksums=False, modulus=MODULO_128)
    assert (frame.ns, frame.nr, frame.info) == (1, 126, INFO)


def test_describe_and_octets():
    frame = decode_frame(bytes.fromhex(ORACLE["i_1_126_p0"]), modulus=MODULO_128)
    assert frame.control_octets == bytes.fromhex("02fc")
    assert frame.describe().startswith("I N(S)=1 N(R)=126 ")


# --- FRMR -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,reject",
    [
        ("frmr128", FrameReject(0xFC02, 100, 27, z=True, modulus=MODULO_128)),
        (
            "frmr128b",
            FrameReject(0x93, 127, 1, True, w=True, x=True, y=True, modulus=MODULO_128),
        ),
    ],
)
def test_frmr_128_oracle_vectors(name, reject):
    info = bytes.fromhex(FRMR_ORACLE[name])
    assert reject.to_bytes() == info
    assert FrameReject.from_bytes(info, MODULO_128) == reject
    assert decode_frmr(info + b"\x00\x00", MODULO_128) == reject  # padding


@pytest.mark.parametrize("vs,vr", [(0, 0), (1, 126), (127, 127), (64, 63)])
def test_frmr_128_round_trip(vs, vr):
    for control in (0x00, 0x93, 0xFFFE, 0x0B01):
        for flags in itertools.product((False, True), repeat=5):
            reject = FrameReject(control, vs, vr, *flags, modulus=MODULO_128)
            assert FrameReject.from_bytes(reject.to_bytes(), MODULO_128) == reject


@pytest.mark.parametrize("size", range(FRMR_INFO_LEN_128))
def test_frmr_128_truncated_raises(size):
    with pytest.raises(FramingError, match="modulo 128 needs 5"):
        FrameReject.from_bytes(bytes.fromhex(FRMR_ORACLE["frmr128"])[:size], MODULO_128)


def test_frmr_128_describe_shows_both_control_octets():
    reject = FrameReject.from_bytes(bytes.fromhex(FRMR_ORACLE["frmr128"]), MODULO_128)
    text = reject.describe()
    assert "invalid N(R)" in text and "control 02 FC" in text and "V(S)=100 V(R)=27" in text


def test_frmr_default_layout_is_still_three_octets():
    assert FrameReject(0x93, 1, 2, w=True).to_bytes() == bytes.fromhex("93 42 01")
    assert FrameReject.from_bytes(bytes.fromhex("934401")).modulus == 8


# --- parameters -------------------------------------------------------------------------


def test_window_limits_follow_the_modulus():
    assert (max_window(), max_window(MODULO_128), MAX_WINDOW_128) == (7, 127, 127)
    HdlcParameters(window_tx=127, window_rx=127, modulus=MODULO_128)
    for kw in ({"window_tx": 128}, {"window_rx": 0}):
        with pytest.raises(FramingError, match="outside 1..127"):
            HdlcParameters(**kw, modulus=MODULO_128)
    with pytest.raises(FramingError, match="outside 1..7"):
        HdlcParameters(window_tx=8)


def test_modulus_is_not_part_of_the_parameters_bytes_or_equality():
    a = HdlcParameters(512, 256, 3, 7)
    b = HdlcParameters(512, 256, 3, 7, modulus=MODULO_128)
    assert a == b and repr(a) == repr(b) and a.to_bytes() == b.to_bytes()


# --- capture mode tracking --------------------------------------------------------------


def _u(kind, src=CLIENT, dest=SERVER, info=b""):
    return encode_frame(HdlcFrame(dest, src, kind | PF_BIT, info))


def _i128(ns, nr, info, to_client=False):
    dest, src = (CLIENT, SERVER) if to_client else (SERVER, CLIENT)
    return encode_frame(frame128(control_i(ns, nr, True, MODULO_128), info, dest=dest, src=src))


def test_tracker_follows_snrme_and_snrm():
    tracker = HdlcModeTracker()
    reader = FrameReader(tracker=tracker)
    stream = (
        _u(FrameType.SNRME)
        + _u(FrameType.UA, SERVER, CLIENT)
        + _i128(0, 0, INFO)
        + _u(FrameType.DISC)
        + _u(FrameType.UA, SERVER, CLIENT)
        + _u(FrameType.SNRM)
        + _u(FrameType.UA, SERVER, CLIENT)
        + encode_frame(HdlcFrame(SERVER, CLIENT, control_i(0, 0), INFO))
    )
    frames = reader.feed(stream)
    assert reader.dropped == 0
    assert [f.kind for f in frames][2] == FrameType.I and frames[2].extended
    assert not frames[-1].extended and tracker.modulus == 8


@pytest.mark.parametrize("refusal", [FrameType.DM, FrameType.FRMR])
def test_tracker_ignores_a_refused_snrme(refusal):
    tracker = HdlcModeTracker()
    reader = FrameReader(tracker=tracker)
    reader.feed(
        _u(FrameType.SNRME) + _u(refusal, SERVER, CLIENT) + _u(FrameType.UA, SERVER, CLIENT)
    )
    assert tracker.modulus == 8


# --- the link against the simulator -----------------------------------------------------


class _Sock:
    def __init__(self):
        self.out = bytearray()

    def sendall(self, data):
        self.out += data


class Peer:
    """LoopbackTransport responder: the simulator's HdlcServer, with a hook
    that may answer a frame (decoded in the server's numbering) itself."""

    def __init__(self, window=None, modulo128=True, **kw):
        window = window or (127 if modulo128 else 7)
        self.sock = _Sock()
        self.server = HdlcServer(
            example_meter(), self.sock, window=window, modulo128=modulo128, **kw
        )
        self.hook = None

    def __call__(self, data):
        if self.hook is not None:
            for frame in FrameReader(modulus=self.server.modulus).feed(data):
                answer = self.hook(frame)
                if answer is not None:
                    return answer
        self.server.feed(data)
        out = bytes(self.sock.out)
        self.sock.out.clear()
        return out


def make_link(peer, window=20, max_info=5, **kw):
    kw.setdefault("timeout", 0.05)
    kw.setdefault("modulus", MODULO_128)
    params = HdlcParameters(
        max_info_tx=max_info, max_info_rx=128, window_tx=window, modulus=MODULO_128
    )
    return HdlcLink(LoopbackTransport(peer), parameters=params, **kw)


def sent(link, modulus=None):
    """Frames the link sent: in ``modulus`` numbering, or (None) following
    the SNRME/SNRM the link sent and the meter's UA."""
    if modulus is None:
        reader = FrameReader(tracker=HdlcModeTracker())
        # Only our side is in ``sent``: take the mode-setting as answered.
        frames = []
        for data in link.transport.sent:
            frames += reader.feed(data)
            if frames and frames[-1].kind in (FrameType.SNRME, FrameType.SNRM):
                reader.tracker.observe(HdlcFrame(CLIENT, SERVER, FrameType.UA))
        return frames
    return FrameReader(modulus=modulus).feed(b"".join(link.transport.sent))


def test_link_sets_up_modulo_128_with_snrme():
    peer = Peer(window=100)
    link = make_link(peer)
    assert link.modulus == 8  # until a UA answers SNRME
    link.connect()
    first = decode_frame(link.transport.sent[0])
    assert first.kind == FrameType.SNRME and first.poll_final
    assert first.info == HdlcParameters(5, 128, 20, 1, modulus=MODULO_128).to_bytes()
    assert link.modulus == MODULO_128 and peer.server.modulus == MODULO_128
    assert link.negotiated.window_tx == 20
    assert peer.server.window_rx == 20


def test_link_sends_windows_with_two_octet_controls():
    peer = Peer(window=100)
    link = make_link(peer, window=20, max_info=5)
    link.connect()
    link.transport.sent.clear()
    assert link.request(AARQ)[0] == 0x61  # AARE; 34 octets with LLC = 7 frames
    frames = [f for f in sent(link, MODULO_128) if f.kind == FrameType.I]
    assert [(f.ns, f.poll_final, f.extended) for f in frames] == [
        (k, k == 6, True) for k in range(7)
    ]
    assert peer.server.window_overruns == 0 and peer.server.max_burst == 7


def test_sequence_numbers_wrap_at_128():
    peer = Peer(window=7)
    link = make_link(peer, window=7, max_info=5)
    link.connect()
    for _ in range(20):  # 140 I-frames out, 20 in
        assert link.request(AARQ)[0] == 0x61
    assert link.vs == (20 * 7) % 128 == 12
    assert link.vr == 20
    assert peer.server.vr == link.vs and peer.server.window_overruns == 0


def test_window_127_in_one_burst():
    peer = Peer(window=127)
    link = make_link(peer, window=127, max_info=1)
    link.connect()
    apdu = AARQ + bytes(200)  # 233 octets with LLC at 1 per frame
    link.transport.sent.clear()
    link.send_apdu(apdu)
    frames = [f for f in sent(link, MODULO_128) if f.kind == FrameType.I]
    assert [f.ns for f in frames[:128]] == list(range(127)) + [127]
    assert [f.poll_final for f in frames[:127]] == [False] * 126 + [True]
    assert peer.server.max_burst == 127 and peer.server.window_overruns == 0


def test_lost_frame_go_back_n_in_modulo_128():
    peer = Peer(window=20, reject={3})
    link = make_link(peer, window=20, max_info=5)
    link.connect()
    link.transport.sent.clear()
    assert link.request(AARQ)[0] == 0x61
    ns = [f.ns for f in sent(link, MODULO_128) if f.kind == FrameType.I]
    assert ns == list(range(7)) + list(range(2, 7))  # resent from N(R)=2


def test_frmr_on_a_modulo_128_link_has_five_octets():
    peer = Peer()
    link = make_link(peer)
    link.connect()
    info = FrameReject(0x0002, 0, 0, z=True, modulus=MODULO_128).to_bytes()

    def hook(frame):
        if frame.kind == FrameType.I:
            return encode_frame(HdlcFrame(CLIENT, SERVER, FrameType.FRMR | PF_BIT, info))
        return None

    peer.hook = hook
    with pytest.raises(FrameRejectError, match="invalid N\\(R\\)") as caught:
        link.request(AARQ)
    assert caught.value.reject is not None and caught.value.reject.modulus == MODULO_128
    assert not link.connected


def test_invalid_nr_in_modulo_128_ends_the_link():
    peer = Peer()
    link = make_link(peer, max_info=128)
    link.connect()
    peer.hook = lambda frame: encode_frame(
        frame128(control_rr(100, True, MODULO_128), dest=CLIENT, src=SERVER)
    )
    with pytest.raises(ProtocolError, match="invalid N\\(R\\)=100"):
        link.request(AARQ)
    assert not link.connected


def test_duplicate_i_frame_across_the_wrap_is_dropped():
    peer = Peer()
    link = make_link(peer, max_info=128)
    link.connect()
    link.vs, link.vr = 3, 0
    peer.server.vr, peer.server.vs = 3, 0
    response = []

    def hook(frame):
        if frame.kind != FrameType.I:
            return None
        peer.hook = None
        peer.server.feed(encode_frame(frame))
        answer = bytes(peer.sock.out)
        peer.sock.out.clear()
        response.append(answer)
        # A repeat of N(S)=127 (V(R)-1 across the wrap) comes first.
        duplicate = frame128(control_i(127, 4, False, MODULO_128), b"x", dest=CLIENT, src=SERVER)
        return encode_frame(duplicate) + answer

    peer.hook = hook
    assert link.request(AARQ)[0] == 0x61
    assert link.vr == 1


# --- fallback ---------------------------------------------------------------------------


def test_fallback_to_snrm_on_dm():
    peer = Peer(window=7, modulo128=False)
    link = make_link(peer, window=20)
    link.connect()
    kinds = [f.kind for f in sent(link)]
    assert kinds == [FrameType.SNRME, FrameType.SNRM]
    snrm = decode_frame(link.transport.sent[1])
    assert snrm.info == HdlcParameters(5, 128, 7, 1).to_bytes()  # windows capped to 7
    assert link.modulus == 8 and link.negotiated.window_tx == 7
    assert link.request(AARQ)[0] == 0x61
    assert all(not f.extended for f in sent(link) if f.kind == FrameType.I)


def _refuse_snrme(answer):
    def hook(frame):
        if frame.kind == FrameType.SNRME:
            return answer
        return None

    return hook


def test_fallback_to_snrm_on_frmr():
    peer = Peer(modulo128=False)
    # A peer without SNRME rejects it in the modulo-8 layout: W, control DF.
    frmr = encode_frame(
        HdlcFrame(
            CLIENT, SERVER, FrameType.FRMR | PF_BIT, FrameReject(0xDF, 0, 0, w=True).to_bytes()
        )
    )
    peer.hook = _refuse_snrme(frmr)
    link = make_link(peer, window=3)
    link.connect()
    assert link.modulus == 8 and link.negotiated.window_tx == 3


def test_fallback_to_snrm_on_silence():
    peer = Peer(modulo128=False)
    peer.hook = _refuse_snrme(b"")
    link = make_link(peer, retries=1)
    link.connect()
    kinds = [f.kind for f in sent(link)]
    assert kinds == [FrameType.SNRME, FrameType.SNRME, FrameType.SNRM]
    assert link.modulus == 8


def test_no_fallback_dm_is_a_protocol_error():
    link = make_link(Peer(modulo128=False), modulus_fallback=False)
    with pytest.raises(ProtocolError, match="answered SNRME with DM"):
        link.connect()
    assert [f.kind for f in sent(link)] == [FrameType.SNRME]
    assert not link.connected


def test_no_fallback_frmr_is_a_frame_reject():
    peer = Peer(modulo128=False)
    frmr = FrameReject(0xDF, 0, 0, w=True).to_bytes()
    peer.hook = _refuse_snrme(
        encode_frame(HdlcFrame(CLIENT, SERVER, FrameType.FRMR | PF_BIT, frmr))
    )
    link = make_link(peer, modulus_fallback=False)
    with pytest.raises(FrameRejectError, match="control 0xDF"):
        link.connect()


def test_no_fallback_silence_times_out():
    peer = Peer(modulo128=False)
    peer.hook = _refuse_snrme(b"")
    link = make_link(peer, modulus_fallback=False, retries=0)
    with pytest.raises(DlmsTimeoutError, match="no UA after 1 SNRME attempts"):
        link.connect()


def test_reconnect_resets_the_numbering():
    peer = Peer()
    link = make_link(peer)
    link.connect()
    assert link.modulus == MODULO_128
    link.disconnect()
    peer.server.modulo128 = False
    link.connect()
    assert link.modulus == 8 and peer.server.modulus == 8


def test_link_argument_validation():
    with pytest.raises(ValueError, match="modulo 8 or 128"):
        HdlcLink(LoopbackTransport(), modulus=16)
    params = HdlcParameters(window_tx=20, modulus=MODULO_128)
    with pytest.raises(ValueError, match="needs modulo-128"):
        HdlcLink(LoopbackTransport(), parameters=params)
    link = HdlcLink(LoopbackTransport())
    assert (link.proposed_modulus, link.modulus, link.modulus_fallback) == (8, 8, True)


# --- simulator ---------------------------------------------------------------------------


def test_simulator_window_limits():
    HdlcServer(example_meter(), _Sock(), window=127, modulo128=True)
    with pytest.raises(ValueError, match="outside 1..127"):
        HdlcServer(example_meter(), _Sock(), window=128, modulo128=True)
    with pytest.raises(ValueError, match="outside 1..7"):
        HdlcServer(example_meter(), _Sock(), window=8)
    with pytest.raises(ValueError, match="outside 1..127"):
        serve(example_meter(), hdlc=True, hdlc_window=0, hdlc_modulo128=True)
