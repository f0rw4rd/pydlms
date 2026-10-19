"""HDLC modulo 128 (SNRME) against cB-Sigma/dlms's secondary station
(``hdlc.Station``, Go, Apache-2.0).

The go-dlms image's ``hdlc`` mode (``tests/interop/go-dlms/adapter/hdlc.go``)
serves the library's station on TCP in front of its DLMS server sessions;
``-modulo128`` sets ``Station.Modulo128`` (SNRME taken, two-octet I and S
control fields, windows up to 127), without it SNRME is answered with DM.
pydlms is driven over it with ``hdlc_modulus=128``: an independent
implementation of the extended control field, the windows above 7 and the
sequence wrap, and of the fallback to SNRM.

Image: ``docker build -t pydlms-interop-go-dlms tests/interop/go-dlms``;
``PYDLMS_GO_DLMS_IMAGE`` selects another tag.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import time

import pytest

from pydlms.client import DlmsClient
from pydlms.cosem.data import DlmsData
from pydlms.cosem.interface_classes import ClassId
from pydlms.debug import FrameRecorder
from pydlms.exceptions import ProtocolError
from pydlms.hdlc.connection import HdlcParameters
from pydlms.hdlc.framing import MODULO_128, FrameReader, FrameType, HdlcModeTracker
from pydlms.recording import deframe
from tests.interop.oracle import require_image

pytestmark = pytest.mark.integration

IMAGE = os.environ.get("PYDLMS_GO_DLMS_IMAGE", "pydlms-interop-go-dlms")
BIG = "0.0.128.0.0.255"  # octet-string of 1500 octets in the adapter


def _docker(*args: str) -> str:
    return subprocess.run(  # noqa: S603,S607 - fixed argv, test-only
        ["docker", *args], capture_output=True, text=True, check=True, timeout=60
    ).stdout.strip()


def _logs(cid: str) -> str:
    out = subprocess.run(  # noqa: S603,S607
        ["docker", "logs", cid], capture_output=True, text=True, timeout=30
    )
    return out.stdout + out.stderr


@contextlib.contextmanager
def station(*flags: str):
    """Run ``godlms hdlc *flags``; yield ``(port, logs)``."""
    require_image(IMAGE, "tests/interop/go-dlms")
    cid = _docker("run", "-d", "--rm", "-p", "127.0.0.1::4059", IMAGE, "hdlc", *flags)
    try:
        deadline = time.monotonic() + 60
        while "godlms hdlc listening" not in (logs := _logs(cid)):
            if "unknown command" in logs:
                pytest.skip(f"{IMAGE} has no hdlc mode: rebuild tests/interop/go-dlms")
            if time.monotonic() > deadline:
                pytest.fail(f"hdlc station did not come up:\n{logs[-2000:]}")
            time.sleep(0.2)
        port = int(_docker("port", cid, "4059").splitlines()[0].rsplit(":", 1)[1])
        yield port, lambda: _logs(cid)
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True, timeout=60)  # noqa: S603,S607


def _client(port, recorder, **kw):
    meter = DlmsClient.tcp("127.0.0.1", port, hdlc=True, timeout=5, **kw)
    meter.link.transport.recorder = recorder
    return meter


def _frames(recorder):
    """(direction, frame) of a recording, numbering followed from SNRME/UA."""
    tracker = HdlcModeTracker()
    readers = {d: FrameReader(tracker=tracker) for d in ("TX", "RX")}
    out = []
    for direction, data in recorder.frames:
        if direction in readers:
            out += [(direction, f) for f in readers[direction].feed(data)]
    assert all(r.dropped == 0 for r in readers.values())
    return out


def _longest_burst(frames, direction):
    """Most I-frames in a row from ``direction`` with P/F only on the last."""
    best = run = 0
    for d, f in frames:
        if d != direction:
            continue
        if f.kind == FrameType.I:
            run += 1
            best = max(best, run)
            if f.poll_final:
                run = 0
        elif f.kind != FrameType.UI:
            run = 0
    return best


def test_modulo_128_against_the_station():
    params = HdlcParameters(32, 128, window_tx=20, window_rx=20, modulus=MODULO_128)
    recorder = FrameRecorder()
    data = DlmsData.octet_string(bytes(range(256)) * 4)
    with station("-modulo128", "-window", "20", "-max-info", "128") as (port, _):
        with _client(port, recorder, hdlc_parameters=params, hdlc_modulus=128) as meter:
            link = meter.link
            assert link.modulus == MODULO_128
            assert (link.negotiated.window_tx, link.negotiated.window_rx) == (20, 20)
            assert meter.get("1.0.1.8.0.255", ClassId.REGISTER).value == 12345678
            assert len(meter.get(BIG).value) == 1500
            for _ in range(5):  # about 33 I-frames each: N(S) wraps past 127
                meter.set(BIG, ClassId.DATA, 2, data)
            assert meter.get(BIG).value == data.value
            assert link.vs < 64 and link.vr > 7
    frames = _frames(recorder)
    assert frames[0][1].kind == FrameType.SNRME
    i_frames = [f for _, f in frames if f.kind == FrameType.I]
    assert all(f.extended for f in i_frames)
    sent_ns = [f.ns for d, f in frames if d == "TX" and f.kind == FrameType.I]
    assert 127 in sent_ns and 0 in sent_ns[sent_ns.index(127) :]  # the wrap
    # Windows above modulo 8's 7 frames, both ways.
    assert _longest_burst(frames, "TX") > 7
    assert _longest_burst(frames, "RX") > 7
    # The recording reads back through the SNRME/UA auto-detection.
    apdus = deframe(recorder.frames)
    assert [(d, a[0]) for d, a in apdus[:2]] == [("TX", 0x60), ("RX", 0x61)]  # AARQ, AARE
    # five SETs, each in data blocks (the server limits the PDU size)
    assert [a[0] for d, a in apdus if d == "TX"].count(0xC1) >= 5


def test_fallback_to_snrm_when_the_station_lacks_modulo_128():
    params = HdlcParameters(32, 128, window_tx=20, modulus=MODULO_128)
    recorder = FrameRecorder()
    with station("-window", "7") as (port, logs):
        with _client(port, recorder, hdlc_parameters=params, hdlc_modulus=128) as meter:
            assert meter.link.modulus == 8
            assert meter.link.negotiated.window_tx == 7  # capped for the SNRM
            assert meter.get("1.0.1.8.0.255", ClassId.REGISTER).value == 12345678
            assert len(meter.get(BIG).value) == 1500
    kinds = [f.kind for _, f in _frames(recorder)]
    assert kinds[:4] == [FrameType.SNRME, FrameType.DM, FrameType.SNRM, FrameType.UA]
    assert not any(f.extended for _, f in _frames(recorder))


def test_no_fallback_fails_against_a_modulo_8_station():
    with station() as (port, _):
        meter = DlmsClient.tcp(
            "127.0.0.1",
            port,
            hdlc=True,
            timeout=5,
            hdlc_modulus=128,
            hdlc_modulus_fallback=False,
            auto_associate=False,
        )
        with pytest.raises(ProtocolError, match="answered SNRME with DM"):
            meter.connect()
        meter.link.transport.close()
