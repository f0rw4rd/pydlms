"""HDLC sequence arithmetic (F7) and the transmit window > 1 (F8).

Behaviour reference: cB-Sigma ``hdlc/client.go`` ``transfer`` (Apache-2.0,
read, not copied), which cites IEC 62056-46 6.4.4.4.3.4-6 for the window
and 6.4.4.9.1 for recovery; those clause numbers are *unverified* here.
"""

from __future__ import annotations

import contextlib
import itertools
import socketserver
import threading

import pytest

from pydlms.client import DlmsClient
from pydlms.cosem.data import DlmsData
from pydlms.cosem.interface_classes import ClassId
from pydlms.exceptions import DlmsTimeoutError, ProtocolError
from pydlms.hdlc.address import HdlcAddress
from pydlms.hdlc.connection import HdlcLink, HdlcParameters, HdlcState
from pydlms.hdlc.framing import (
    LLC_REQUEST,
    PF_BIT,
    SEQ_MODULUS,
    FrameReader,
    FrameType,
    HdlcFrame,
    control_i,
    control_rnr,
    control_rr,
    encode_frame,
    seq_add,
    seq_diff,
    strip_llc,
)
from pydlms.simulator import HdlcServer, example_meter
from pydlms.transports.base import LoopbackTransport

# --- F7: modulo-aware arithmetic -------------------------------------------------------


def test_seq_add_wraps_modulo_8():
    assert SEQ_MODULUS == 8
    assert seq_add(7) == 0
    assert seq_add(6, 3) == 1
    assert seq_add(0, -1) == 7
    assert seq_add(100, 28, modulus=128) == 0


def test_seq_diff_counts_frames_between():
    assert seq_diff(3, 1) == 2
    assert seq_diff(1, 6) == 3  # 6, 7, 0
    assert seq_diff(5, 5) == 0
    assert seq_diff(2, 126, modulus=128) == 4


@pytest.mark.parametrize("ns,nr,poll", list(itertools.product(range(8), range(8), (False, True))))
def test_control_octets_match_the_modulo_8_layout(ns, nr, poll):
    # The pre-refactor encoding: three-bit fields masked with & 7.
    pf = 0x10 if poll else 0
    assert control_i(ns, nr, poll) == ((nr & 7) << 5) | pf | ((ns & 7) << 1)
    assert control_rr(nr, poll) == ((nr & 7) << 5) | pf | 0x01
    assert control_rnr(nr, poll) == ((nr & 7) << 5) | pf | 0x05
    frame = HdlcFrame(HdlcAddress.server(1), HdlcAddress.client(16), control_i(ns, nr, poll))
    assert (frame.ns, frame.nr, frame.poll_final) == (ns, nr, poll)
    assert PF_BIT == 0x10


def test_control_i_reduces_out_of_range_numbers():
    assert control_i(-1, 9) == control_i(7, 1)


# --- F8: the simulator's windowed HDLC server -----------------------------------------


class _Sock:
    def __init__(self):
        self.out = bytearray()

    def sendall(self, data):
        self.out += data

    def frames(self):
        frames = FrameReader().feed(bytes(self.out))
        self.out.clear()
        return frames


SERVER = HdlcAddress.server(1)
CLIENT = HdlcAddress.client(16)


def _client_frame(control, info=b"", segmented=False):
    return encode_frame(HdlcFrame(SERVER, CLIENT, control, info, segmented))


def _sim_server(window=3, proposed=7, **kw):
    sock = _Sock()
    server = HdlcServer(example_meter(), sock, window=window, **kw)
    server.feed(
        _client_frame(FrameType.SNRM | PF_BIT, HdlcParameters(window_tx=proposed).to_bytes())
    )
    (ua,) = sock.frames()
    return server, sock, HdlcParameters.from_bytes(ua.info)


def _segments(server, chunks, poll_every, start=0, stop=None):
    """Feed I-frames ``start..stop`` of ``chunks`` (the last unsegmented),
    P=1 on every ``poll_every``-th frame and on the last."""
    for k, chunk in enumerate(chunks[:stop]):
        last = k == len(chunks) - 1
        poll = last or (k + 1) % poll_every == 0
        if k >= start:
            server.feed(_client_frame(control_i(k, 0, poll), chunk, segmented=not last))


#: A lowest-level-security LN AARQ (the common public-client request).
AARQ = bytes.fromhex("601da109060760857405080101be10040e01000000065f1f0400001e1dffff")


def _aarq_chunks(size=5):
    payload = LLC_REQUEST + AARQ
    return [payload[i : i + size] for i in range(0, len(payload), size)]


@pytest.mark.parametrize("window,proposed,expected", [(1, 7, 1), (3, 7, 3), (7, 2, 2)])
def test_simulator_offers_its_window_in_the_ua(window, proposed, expected):
    _, _, ua = _sim_server(window, proposed)
    assert ua.window_rx == expected
    assert ua.window_tx == 1


def test_simulator_default_ua_is_unchanged():
    sock = _Sock()
    HdlcServer(example_meter(), sock).feed(_client_frame(FrameType.SNRM | PF_BIT))
    (ua,) = sock.frames()
    assert ua.info == HdlcParameters(128, 128).to_bytes()


def test_simulator_acks_only_on_poll():
    server, sock, _ = _sim_server(window=3)
    chunks = _aarq_chunks()
    assert len(chunks) == 7
    _segments(server, chunks, poll_every=3, stop=2)
    assert sock.frames() == []  # no poll yet, no answer
    _segments(server, chunks, poll_every=3, start=2, stop=3)  # P on frame 3
    (rr,) = sock.frames()
    assert rr.kind == FrameType.RR and rr.nr == 3 and rr.poll_final


def test_simulator_answers_a_windowed_request():
    server, sock, _ = _sim_server(window=3)
    chunks = _aarq_chunks()
    _segments(server, chunks, poll_every=3)
    frames = sock.frames()
    kinds = [f.kind for f in frames]
    assert kinds == [FrameType.RR, FrameType.RR, FrameType.I]  # P on frames 3, 6, 7
    assert [f.nr for f in frames] == [3, 6, 7]
    response = frames[-1]
    assert strip_llc(response.info)[0] == 0x61  # AARE
    assert server.window_overruns == 0


def test_simulator_counts_a_window_overrun():
    server, sock, _ = _sim_server(window=2)
    chunks = _aarq_chunks()
    _segments(server, chunks, poll_every=3, stop=3)
    assert server.window_overruns == 1


@pytest.mark.parametrize("fault,kind", [("drop", FrameType.RR), ("reject", FrameType.REJ)])
def test_simulator_fault_injection_reports_the_gap_at_the_poll(fault, kind):
    server, sock, _ = _sim_server(window=3, **{fault: {2}})
    chunks = _aarq_chunks()
    _segments(server, chunks, poll_every=3, stop=3)
    (answer,) = sock.frames()
    assert answer.kind == kind and answer.nr == 1 and answer.poll_final
    # Go-back-N: the client resends from N(R)=1.
    _segments(server, chunks, poll_every=3, start=1)
    frames = sock.frames()
    assert frames[-1].kind == FrameType.I
    assert strip_llc(frames[-1].info)[0] == 0x61


def test_simulator_answers_an_idle_poll_with_rr():
    server, sock, _ = _sim_server(window=3, drop={1})
    # The only frame of a one-frame request is lost: the client polls.
    server.feed(_client_frame(control_i(0, 0), LLC_REQUEST + b"\xc0\x01\x01"))
    assert sock.frames() == []
    server.feed(_client_frame(control_rr(0)))
    (rr,) = sock.frames()
    assert rr.kind == FrameType.RR and rr.nr == 0 and rr.poll_final


# --- F8: the client's transmit window -------------------------------------------------


class SimPeer:
    """A LoopbackTransport responder backed by the simulator's HdlcServer."""

    def __init__(self, window=3, meter=None, **kw):
        self.sock = _Sock()
        self.server = HdlcServer(meter or example_meter(), self.sock, window=window, **kw)
        self.hook = None  # optional (frame) -> bytes | None, before the server

    def __call__(self, data):
        for frame in FrameReader().feed(data):
            answer = self.hook(frame) if self.hook else None
            if answer is not None:
                self.sock.out += answer
                continue
            self.server.feed(encode_frame(frame))
        out = bytes(self.sock.out)
        self.sock.out.clear()
        return out


def _peer_frame(control):
    return encode_frame(HdlcFrame(CLIENT, SERVER, control))


def control_rej(nr, poll=True):
    return (seq_add(nr, 0) << 5) | (PF_BIT if poll else 0) | FrameType.REJ


def control_srej(nr, poll=True):
    return (seq_add(nr, 0) << 5) | (PF_BIT if poll else 0) | FrameType.SREJ


def windowed_link(peer, window=3, max_info=5, **kw):
    kw.setdefault("timeout", 0.05)
    link = HdlcLink(
        LoopbackTransport(peer),
        parameters=HdlcParameters(max_info_tx=max_info, max_info_rx=128, window_tx=window),
        **kw,
    )
    link.connect()
    link.transport.sent.clear()
    return link


def sent_i(link):
    """(N(S), P, segmented) of every I-frame the link sent."""
    frames = FrameReader().feed(b"".join(link.transport.sent))
    return [(f.ns, f.poll_final, f.segmented) for f in frames if f.kind == FrameType.I]


def sent_kinds(link):
    return [f.kind for f in FrameReader().feed(b"".join(link.transport.sent))]


def _is_aare(apdu):
    return apdu[0] == 0x61


def test_window_3_sends_7_segments_with_p_on_frames_3_and_6():
    peer = SimPeer(window=3)
    link = windowed_link(peer, window=3)
    assert link.negotiated.window_tx == 3
    assert _is_aare(link.request(AARQ))  # 34 octets with LLC: 7 frames of 5
    assert sent_i(link) == [
        (0, False, True),
        (1, False, True),
        (2, True, True),
        (3, False, True),
        (4, False, True),
        (5, True, True),
        (6, True, False),
    ]
    assert sent_kinds(link) == [FrameType.I] * 7  # no RR polls needed
    assert not link._unacked  # the response's N(R) acknowledged the last frame
    assert peer.server.window_overruns == 0


def test_window_defaults_to_one():
    assert HdlcParameters().window_tx == 1
    peer = SimPeer(window=7)
    link = HdlcLink(LoopbackTransport(peer), parameters=HdlcParameters(max_info_tx=5))
    link.connect()
    assert link.negotiated.window_tx == 1
    link.transport.sent.clear()
    assert _is_aare(link.request(AARQ))
    assert all(poll for _, poll, _ in sent_i(link))


def test_window_is_capped_by_the_meter():
    peer = SimPeer(window=2)
    link = windowed_link(peer, window=7)
    assert link.negotiated.window_tx == 2
    assert _is_aare(link.request(AARQ))
    assert [p for _, p, _ in sent_i(link)] == [False, True] * 3 + [True]
    assert peer.server.window_overruns == 0


def test_rr_without_final_mid_window_only_acknowledges():
    peer = SimPeer(window=3)
    link = windowed_link(peer)

    def hook(frame):
        if frame.kind == FrameType.I and frame.ns == 0 and not frame.poll_final:
            peer.server.feed(encode_frame(frame))
            return _peer_frame(control_rr(1, poll=False))  # partial ack, F=0
        return None

    peer.hook = hook
    assert _is_aare(link.request(AARQ))
    assert [ns for ns, _, _ in sent_i(link)] == [0, 1, 2, 3, 4, 5, 6]


def test_rr_final_with_a_partial_ack_resends_from_nr():
    # The meter lost frame 2 (N(S)=1) and answers the poll with RR N(R)=1.
    peer = SimPeer(window=3, drop={2})
    link = windowed_link(peer)
    assert _is_aare(link.request(AARQ))
    assert sent_i(link) == [
        (0, False, True),
        (1, False, True),
        (2, True, True),
        (1, False, True),  # go-back-N from N(R)=1, P on the last again
        (2, True, True),
        (3, False, True),
        (4, False, True),
        (5, True, True),
        (6, True, False),
    ]


def test_rej_resends_from_nr():
    peer = SimPeer(window=3, reject={5})  # N(S)=4 arrives damaged
    link = windowed_link(peer)
    assert _is_aare(link.request(AARQ))
    assert [ns for ns, _, _ in sent_i(link)] == [0, 1, 2, 3, 4, 5, 4, 5, 6]


def test_lost_poll_frame_is_recovered_by_an_rr_poll_not_a_blind_resend():
    peer = SimPeer(window=3, drop={3})  # the P frame of the first window
    link = windowed_link(peer)
    assert _is_aare(link.request(AARQ))
    kinds = sent_kinds(link)
    assert kinds[:5] == [FrameType.I, FrameType.I, FrameType.I, FrameType.RR, FrameType.I]
    assert [ns for ns, _, _ in sent_i(link)] == [0, 1, 2, 2, 3, 4, 5, 6]
    assert sent_i(link)[3] == (2, True, True)


def test_lost_final_frame_is_resent_after_a_poll():
    peer = SimPeer(window=3, drop={7})  # the final, unsegmented frame
    link = windowed_link(peer)
    assert _is_aare(link.request(AARQ))
    assert sent_kinds(link)[-2:] == [FrameType.RR, FrameType.I]
    assert sent_i(link)[-1] == (6, True, False)


def test_nr_beyond_the_window_raises_and_disconnects():
    peer = SimPeer(window=3)
    link = windowed_link(peer)
    # After N(S)=0..2 the valid N(R) are 0..3; 5 acknowledges frames never sent.
    peer.hook = lambda f: _peer_frame(control_rr(5)) if f.poll_final else b""
    with pytest.raises(ProtocolError, match=r"invalid N\(R\)=5"):
        link.request(AARQ)
    assert link.state == HdlcState.DISCONNECTED
    assert len(sent_i(link)) == 3


def test_nr_behind_the_window_raises():
    peer = SimPeer(window=3)
    link = windowed_link(peer)
    assert _is_aare(link.request(AARQ))  # V(S)=7 now
    # Outstanding N(S)=7,0,1: valid N(R) 7,0,1,2; 6 is behind the window.
    peer.hook = lambda f: _peer_frame(control_rr(6)) if f.poll_final else b""
    with pytest.raises(ProtocolError, match=r"invalid N\(R\)=6"):
        link.request(AARQ)


def test_ns_wraps_past_7():
    peer = SimPeer(window=3)
    link = windowed_link(peer)
    assert _is_aare(link.request(AARQ))
    link.transport.sent.clear()
    assert _is_aare(link.request(AARQ))
    assert [ns for ns, _, _ in sent_i(link)] == [7, 0, 1, 2, 3, 4, 5]
    assert [p for _, p, _ in sent_i(link)] == [False, False, True, False, False, True, True]
    assert link.vs == 6  # 14 frames sent, modulo 8


def test_wrap_with_a_reject_across_zero():
    peer = SimPeer(window=3)
    link = windowed_link(peer)
    assert _is_aare(link.request(AARQ))  # V(S)=7
    peer.server.reject = {peer.server.received + 2}  # N(S)=0 damaged
    link.transport.sent.clear()
    assert _is_aare(link.request(AARQ))
    assert [ns for ns, _, _ in sent_i(link)] == [7, 0, 1, 0, 1, 2, 3, 4, 5]


def test_meter_that_keeps_rejecting_ends_the_link():
    peer = SimPeer(window=3)
    link = windowed_link(peer, retries=2)
    peer.hook = lambda f: _peer_frame(control_rej(0)) if f.poll_final else b""
    with pytest.raises(ProtocolError, match="keeps rejecting"):
        link.request(AARQ)
    assert link.state == HdlcState.DISCONNECTED
    # The first window and two go-back-N resends of it.
    assert [ns for ns, _, _ in sent_i(link)] == [0, 1, 2] * 3


def test_unanswered_window_times_out_after_bounded_polls():
    peer = SimPeer(window=3)
    link = windowed_link(peer, retries=2)
    peer.hook = lambda f: b""
    with pytest.raises(DlmsTimeoutError, match="not acknowledged after 2 RR polls"):
        link.request(AARQ)
    assert sent_kinds(link) == [FrameType.I] * 3 + [FrameType.RR] * 2
    assert link.state == HdlcState.DISCONNECTED


def test_srej_in_a_window_resends_only_that_frame():
    peer = SimPeer(window=3)
    link = windowed_link(peer)
    done = []

    def hook(frame):
        if frame.kind == FrameType.I and frame.ns == 1 and not done:
            done.append(1)
            return b""  # lost; the meter asks for it selectively at the poll
        if frame.kind == FrameType.I and frame.ns == 2 and len(done) == 1:
            done.append(2)
            return _peer_frame(control_srej(1))
        return None

    peer.hook = hook
    # The SREJ also acknowledges N(S)=0; only N(S)=1 is sent again (P=1).
    # The simulator is go-back-N, so it then asks for N(S)=2 with RR.
    assert _is_aare(link.request(AARQ))
    assert [(ns, p) for ns, p, _ in sent_i(link)][:5] == [
        (0, False),
        (1, False),
        (2, True),
        (1, True),
        (2, True),
    ]


def test_rnr_in_a_window_waits_then_resends_from_nr():
    peer = SimPeer(window=3)
    link = windowed_link(peer, busy_interval=0)
    seen = set()

    def hook(frame):
        # Busy after the first frame: N(S)=1 and 2 are discarded once and the
        # poll is answered RNR N(R)=1; the busy poll then gets RR N(R)=1
        # from the simulator.
        if frame.kind == FrameType.I and frame.ns in (1, 2) and frame.ns not in seen:
            seen.add(frame.ns)
            return _peer_frame(control_rnr(1)) if frame.poll_final else b""
        return None

    peer.hook = hook
    assert _is_aare(link.request(AARQ))
    assert sent_kinds(link)[:5] == [FrameType.I] * 3 + [FrameType.RR, FrameType.I]
    assert [ns for ns, _, _ in sent_i(link)] == [0, 1, 2, 1, 2, 3, 4, 5, 6]


# --- F8 end to end: DlmsClient over the windowed simulator ----------------------------


@contextlib.contextmanager
def windowed_meter(window, **faults):
    """The example meter behind HdlcServer(window, faults) on loopback TCP
    (``simulator.serve`` builds its HdlcServer with the defaults)."""
    sim = example_meter()
    servers: list[HdlcServer] = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            server = HdlcServer(sim, self.request, window=window, **faults)
            servers.append(server)
            try:
                while data := self.request.recv(4096):
                    server.feed(data)
            except OSError:
                return

    class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True
        daemon_threads = True

    tcp = Server(("127.0.0.1", 0), Handler)
    threading.Thread(target=tcp.serve_forever, args=(0.05,), daemon=True).start()
    try:
        yield sim, tcp.server_address, servers
    finally:
        tcp.shutdown()
        tcp.server_close()


@pytest.mark.parametrize("window", [1, 3, 7])
def test_large_set_through_the_window(window):
    big = DlmsData.octet_string(bytes(range(256)) * 8)  # 2 KiB: SET with blocks
    with windowed_meter(window) as (sim, address, servers):
        params = HdlcParameters(max_info_tx=64, max_info_rx=64, window_tx=window)
        with DlmsClient.tcp(*address, hdlc=True, timeout=3, hdlc_parameters=params) as m:
            assert m.link.negotiated.window_tx == window
            m.set("0.0.42.0.0.255", ClassId.DATA, 2, big)
            assert m.get("0.0.42.0.0.255").value == big.value
        assert servers[0].window_overruns == 0
        assert any(r[:2] == b"\xc1\x03" for r in sim.requests)  # set-with-datablock


@pytest.mark.parametrize(
    "faults", [{"drop": {5, 23}}, {"reject": {5, 23}}, {"drop": {3}, "reject": {12}}]
)
def test_large_set_survives_lost_and_rejected_frames(faults):
    big = DlmsData.octet_string(bytes(range(256)) * 4)
    with windowed_meter(3, **faults) as (sim, address, servers):
        params = HdlcParameters(max_info_tx=32, max_info_rx=64, window_tx=3)
        with DlmsClient.tcp(*address, hdlc=True, timeout=0.3, hdlc_parameters=params) as m:
            m.set("0.0.42.0.0.255", ClassId.DATA, 2, big)
            assert m.get("0.0.42.0.0.255").value == big.value
        assert servers[0].window_overruns == 0
        # Every injected fault fired (the frame counter got past it).
        assert servers[0].received > max(max(ks) for ks in faults.values())


def test_hdlc_parameters_need_hdlc():
    with pytest.raises(ValueError, match="hdlc=True"):
        DlmsClient.tcp("192.0.2.1", hdlc_parameters=HdlcParameters(window_tx=3))


def test_cli_hdlc_window_flag(capsys):
    from pydlms.cli import main

    with windowed_meter(7) as (_, (host, port), servers):
        url = f"tcp+hdlc://{host}:{port}"
        argv = ["read", url, "--hdlc-window", "4", "--obis", "1.0.32.7.0.255", "--register"]
        assert main(argv) == 0
        assert servers[0].window_rx == 4
    assert capsys.readouterr().out.split("  ")[:3] == ["1.0.32.7.0.255", "230.1", "V"]


@pytest.mark.parametrize("value", ["0", "8"])
def test_cli_hdlc_window_range(value):
    from pydlms.cli import main

    with pytest.raises(SystemExit):
        main(["read", "tcp+hdlc://192.0.2.1", "--hdlc-window", value, "--obis", "1.0.1.8.0.255"])


def test_cli_hdlc_window_needs_hdlc():
    from pydlms.cli import main

    with pytest.raises(SystemExit, match="HDLC endpoint"):
        main(["read", "tcp://192.0.2.1", "--hdlc-window", "3", "--obis", "1.0.1.8.0.255"])


# --- simulator.serve(hdlc_window=...) and `simulate --hdlc-window` ---------------------


def test_serve_hdlc_window_end_to_end():
    from pydlms.simulator import serve

    big = DlmsData.octet_string(bytes(range(256)) * 8)
    tcp = serve(example_meter(), hdlc=True, hdlc_window=3)
    try:
        params = HdlcParameters(max_info_tx=64, max_info_rx=64, window_tx=3)
        address = tcp.server_address[:2]
        with DlmsClient.tcp(*address, hdlc=True, timeout=3, hdlc_parameters=params) as m:
            assert m.link.negotiated.window_tx == 3
            m.set("0.0.42.0.0.255", ClassId.DATA, 2, big)
            assert m.get("0.0.42.0.0.255").value == big.value
        (server,) = tcp.hdlc_servers
        assert server.window_rx == 3
        assert server.window_overruns == 0
        assert server.max_burst > 1  # several I-frames per poll
    finally:
        tcp.shutdown()
        tcp.server_close()


def test_serve_hdlc_window_validated():
    from pydlms.simulator import serve

    with pytest.raises(ValueError, match="outside 1..7"):
        serve(example_meter(), hdlc=True, hdlc_window=8)


def test_simulate_cli_passes_hdlc_window(monkeypatch):
    import pydlms.simulator as simulator
    from pydlms.cli import main

    seen = []
    monkeypatch.setattr(simulator, "main", lambda argv: seen.append(argv))
    assert main(["simulate", "--hdlc", "--hdlc-window", "4"]) == 0
    assert seen[0][-2:] == ["--hdlc-window", "4"]
    args = simulator._parser().parse_args(seen[0])
    assert (args.hdlc, args.hdlc_window) == (True, 4)
