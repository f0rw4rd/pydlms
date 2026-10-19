"""Pin the modulo-8 HDLC bytes before and after modulo-128 (SNRME) support.

Modulo 128 is opt-in and must not change a single default byte. The
corpus below is every modulo-8 I/RR/RNR control (all N(S), N(R), P/F)
framed with 1-, 2- and 4-octet addresses, segmented and not, decoded back
to (kind, N(S), N(R), P/F); the U frames with and without parameters;
every FRMR field the 3-octet layout can express; and complete client
transcripts against the simulator (windows 1, 3, 7, segmented requests).
The digests were taken from the code before modulo 128 existed
(commit 38b397a) and are only ever compared, never regenerated.
"""

from __future__ import annotations

import hashlib
import itertools

from pydlms.hdlc.address import HdlcAddress
from pydlms.hdlc.connection import HdlcLink, HdlcParameters, parameter_field
from pydlms.hdlc.framing import (
    PF_BIT,
    FrameType,
    HdlcFrame,
    control_i,
    control_rnr,
    control_rr,
    decode_frame,
    encode_frame,
)
from pydlms.hdlc.frmr import FrameReject
from pydlms.simulator import HdlcServer, example_meter
from pydlms.transports.base import LoopbackTransport

FRAME_DIGEST = "04c966daaef90993ee61dd042b3f0d82edab2da4d1aadcedf5f1303896968897"
TRANSCRIPT_DIGEST = "d0432a893fbb81d31c14e90f5b1d0b20696b8207a0fbcc5b27202afcb1285bfa"

AARQ = bytes.fromhex("601da109060760857405080101be10040e01000000065f1f0400001e1dffff")
GET = bytes.fromhex("c001c100030100010800ff0200")


def _frame_corpus() -> list[bytes]:
    out = []
    addresses = [
        (HdlcAddress.server(1), HdlcAddress.client(16)),
        (HdlcAddress(1, 0x11, 2), HdlcAddress.client(1)),
        (HdlcAddress(0x12, 0x3456, 4), HdlcAddress.client(0x30)),
    ]
    for dest, src in addresses:
        for ns, nr, poll in itertools.product(range(8), range(8), (False, True)):
            for control, info in (
                (control_i(ns, nr, poll), b"\xe6\xe6\x00\xc0\x01\xc1"),
                (control_rr(nr, poll), b""),
                (control_rnr(nr, poll), b""),
            ):
                for segmented in (False, True):
                    raw = encode_frame(HdlcFrame(dest, src, control, info, segmented))
                    f = decode_frame(raw)
                    out.append(raw + bytes([f.kind.value, f.ns, f.nr, f.poll_final]))
        for kind in (
            FrameType.SNRM,
            FrameType.UA,
            FrameType.DISC,
            FrameType.DM,
            FrameType.UI,
            FrameType.FRMR,
        ):
            for pf in (0, PF_BIT):
                for info in (
                    b"",
                    parameter_field(HdlcParameters()),
                    parameter_field(HdlcParameters(1024, 512, 7, 3), b"ud"),
                ):
                    out.append(encode_frame(HdlcFrame(dest, src, kind | pf, info)))
    for control in range(256):
        for vs, vr in itertools.product(range(8), range(8)):
            reject = FrameReject(
                control,
                vs,
                vr,
                bool(control & 1),
                True,
                bool(control & 2),
                bool(control & 4),
                bool(control & 8),
            )
            out.append(reject.to_bytes())
    return out


class _Sock:
    def __init__(self):
        self.out = bytearray()

    def sendall(self, data):
        self.out += data


def _transcript(window: int, max_info: int) -> list[bytes]:
    sock = _Sock()
    server = HdlcServer(example_meter(), sock, window=window)
    log: list[bytes] = []

    def responder(data):
        log.append(b"TX" + data)
        server.feed(data)
        out = bytes(sock.out)
        sock.out.clear()
        log.append(b"RX" + out)
        return out

    link = HdlcLink(
        LoopbackTransport(responder),
        parameters=HdlcParameters(max_info_tx=max_info, max_info_rx=128, window_tx=window),
        timeout=0.05,
    )
    link.connect()
    link.request(AARQ)
    link.request(GET)
    link.disconnect()
    return log


def test_modulo_8_frames_are_byte_identical():
    corpus = _frame_corpus()
    assert len(corpus) == 18796
    assert hashlib.sha256(b"|".join(corpus)).hexdigest() == FRAME_DIGEST


def test_modulo_8_link_transcripts_are_byte_identical():
    log: list[bytes] = []
    for window, max_info in ((1, 128), (1, 5), (3, 5), (7, 7)):
        log += _transcript(window, max_info)
    assert len(log) == 80
    assert hashlib.sha256(b"|".join(log)).hexdigest() == TRANSCRIPT_DIGEST
