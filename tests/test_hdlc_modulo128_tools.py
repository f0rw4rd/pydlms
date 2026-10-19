"""Modulo-128 HDLC (SNRME) through the client, CLI and analysis tools.

The link, codec and simulator tests are in ``test_hdlc_modulo128``; this
file drives the opt-in from ``DlmsClient`` (``hdlc_modulus``), ``pydlms
read --hdlc-modulo`` and ``pydlms simulate --hdlc-modulo``, and checks that
``pydlms decode``, recordings and redaction read modulo-128 frames.
"""

from __future__ import annotations

import contextlib

import pytest

from pydlms.client import DlmsClient
from pydlms.cosem.data import DlmsData
from pydlms.cosem.interface_classes import ClassId
from pydlms.explain import explain
from pydlms.hdlc.connection import HdlcLink, HdlcParameters
from pydlms.hdlc.framing import MODULO_128, FrameType
from pydlms.recording import deframe, session_apdus
from pydlms.simulator import example_meter, serve
from pydlms.transports.base import LoopbackTransport
from tests.test_hdlc_modulo128 import AARQ, CLIENT, ORACLE, SERVER, Peer, _u


@contextlib.contextmanager
def served(**kw):
    tcp = serve(example_meter(), hdlc=True, **kw)
    try:
        yield tcp
    finally:
        tcp.shutdown()
        tcp.server_close()


def test_client_end_to_end_with_large_windows():
    big = DlmsData.octet_string(bytes(range(256)) * 8)
    with served(hdlc_window=50, hdlc_modulo128=True) as tcp:
        params = HdlcParameters(64, 64, window_tx=40, modulus=MODULO_128)
        address = tcp.server_address[:2]
        with DlmsClient.tcp(
            *address, hdlc=True, timeout=3, hdlc_parameters=params, hdlc_modulus=128
        ) as meter:
            assert meter.link.modulus == MODULO_128
            assert meter.link.negotiated.window_tx == 40
            meter.set("0.0.42.0.0.255", ClassId.DATA, 2, big)
            assert meter.get("0.0.42.0.0.255").value == big.value
        (server,) = tcp.hdlc_servers
        assert server.modulus == MODULO_128 and server.window_overruns == 0
        assert server.max_burst > 7  # more than a modulo-8 window


def test_client_falls_back_against_a_modulo_8_simulator():
    with served() as tcp:
        with DlmsClient.tcp(*tcp.server_address[:2], hdlc=True, timeout=3, hdlc_modulus=128) as m:
            assert m.link.modulus == 8
            assert m.get("1.0.32.7.0.255", ClassId.REGISTER).value


def test_client_modulus_needs_hdlc():
    with pytest.raises(ValueError, match="hdlc_modulus requires hdlc=True"):
        DlmsClient.tcp("192.0.2.1", hdlc_modulus=128)


def test_cli_hdlc_modulo(capsys):
    from pydlms.cli import main

    with served(hdlc_window=30, hdlc_modulo128=True) as tcp:
        host, port = tcp.server_address[:2]
        url = f"tcp+hdlc://{host}:{port}"
        argv = ["read", url, "--hdlc-modulo", "128", "--hdlc-window", "30"]
        assert main([*argv, "--obis", "1.0.32.7.0.255", "--register"]) == 0
        (server,) = tcp.hdlc_servers
        assert (server.modulus, server.window_rx) == (MODULO_128, 30)
    assert capsys.readouterr().out.split("  ")[:3] == ["1.0.32.7.0.255", "230.1", "V"]


def test_cli_no_fallback_fails_against_a_modulo_8_meter(capsys):
    from pydlms.cli import main

    with served() as tcp:
        host, port = tcp.server_address[:2]
        argv = ["read", f"tcp+hdlc://{host}:{port}", "--hdlc-modulo", "128"]
        argv += ["--no-hdlc-modulo-fallback", "--timeout", "1", "--obis", "1.0.32.7.0.255"]
        assert main(argv) != 0
    assert "answered SNRME with DM" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv,message",
    [
        (["tcp+hdlc://192.0.2.1", "--hdlc-window", "8"], "needs --hdlc-modulo 128"),
        (["tcp://192.0.2.1", "--hdlc-modulo", "128"], "HDLC endpoint"),
        (["tcp+hdlc://192.0.2.1", "--no-hdlc-modulo-fallback"], "needs --hdlc-modulo 128"),
    ],
)
def test_cli_hdlc_modulo_usage_errors(argv, message):
    from pydlms.cli import main

    with pytest.raises(SystemExit, match=message):
        main(["read", *argv, "--obis", "1.0.1.8.0.255"])


def test_simulate_cli_passes_hdlc_modulo(monkeypatch):
    import pydlms.simulator as simulator
    from pydlms.cli import main

    seen = []
    monkeypatch.setattr(simulator, "main", lambda argv: seen.append(argv))
    assert main(["simulate", "--hdlc", "--hdlc-modulo", "128", "--hdlc-window", "50"]) == 0
    args = simulator._parser().parse_args(seen[0])
    assert (args.hdlc, args.hdlc_modulo, args.hdlc_window) == (True, 128, 50)
    simulator.check_hdlc_options(args)
    for bad, message in (
        (["--hdlc-window", "50"], "1-7"),
        (["--hdlc-modulo", "128"], "needs --hdlc"),
    ):
        args = simulator._parser().parse_args(["--hdlc", *bad] if "1-7" in message else bad)
        with pytest.raises(SystemExit, match=message):
            simulator.check_hdlc_options(args)


# --- explain, recordings, redaction ------------------------------------------------------


def _session():
    """TX/RX records of a modulo-128 session against the simulator."""
    peer = Peer(window=20)
    records = []

    def responder(data):
        records.append(("TX", data))
        out = peer(data)
        if out:
            records.append(("RX", out))
        return out

    link = HdlcLink(
        LoopbackTransport(responder),
        parameters=HdlcParameters(5, 128, 20, modulus=MODULO_128),
        timeout=0.05,
        modulus=MODULO_128,
    )
    link.connect()
    response = link.request(AARQ)
    return records, response


def test_recording_follows_snrme():
    records, response = _session()
    apdus = deframe(records)
    assert apdus == [("TX", AARQ), ("RX", response)]
    assert session_apdus(records) == apdus


def test_recording_without_the_snrme_needs_the_modulus():
    records, response = _session()
    data_phase = records[2:]  # drop SNRME and UA
    assert deframe(data_phase) == []  # read as modulo 8: every HCS fails
    assert deframe(data_phase, hdlc_modulus=128) == [("TX", AARQ), ("RX", response)]


def test_explain_shows_the_extended_control_field():
    raw = bytes.fromhex(ORACLE["i_1_126_p0"])
    text = explain(raw, hdlc_modulus=128)
    assert "control   02 FC  I (modulo 128)" in text
    assert "HCS       74 B1  ok" in text
    snrme = _u(FrameType.SNRME) + _u(FrameType.UA, SERVER, CLIENT)
    assert "I (modulo 128)" in explain([snrme, raw])
    assert "dropped" in explain(raw)


def test_cli_decode_hdlc_modulo(capsys):
    from pydlms.cli import main

    assert main(["decode", "--hdlc-modulo", "128", ORACLE["i_1_126_p0"]]) == 0
    assert "(modulo 128)" in capsys.readouterr().out


def test_redaction_finds_modulo_128_frames():
    from pydlms.redact import _frame_at

    raw = bytes.fromhex(ORACLE["i_1_126_p0"])
    frame, end = _frame_at(raw, 0)
    assert frame is not None and frame.extended and end == len(raw)
