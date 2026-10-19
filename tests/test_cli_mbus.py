"""CLI endpoints for wired M-Bus: ``mbus://<device>`` and ``mbus+tcp://host:port``."""

from __future__ import annotations

import pytest

from pydlms.cli import build_client, build_parser, main, parse_endpoint
from pydlms.mbus_link import MbusLink
from pydlms.simulator import example_meter, serve_mbus
from pydlms.transports.serial import SerialTransport
from pydlms.transports.tcp import TcpTransport


def client(*argv: str):
    return build_client(build_parser().parse_args(["clock", *argv]))


def test_parse_mbus_endpoints():
    assert parse_endpoint("mbus:///dev/ttyUSB0?address=5") == (
        "mbus",
        {"port": "/dev/ttyUSB0", "address": "5"},
    )
    assert parse_endpoint("mbus+tcp://gw:10001?address=5") == (
        "mbus+tcp",
        {"host": "gw", "port": 10001, "address": "5"},
    )
    with pytest.raises(SystemExit, match="host and a port"):
        parse_endpoint("mbus+tcp://gw?address=5")


def test_mbus_serial_client_options():
    c = client("mbus:///dev/ttyUSB0?address=5&baud=9600", "--server", "1", "--client", "16")
    assert isinstance(c.link, MbusLink)
    transport = c.link.transport
    assert isinstance(transport, SerialTransport)
    assert (transport.port, transport.baudrate, transport.parity) == ("/dev/ttyUSB0", 9600, "E")
    assert (c.link.address, c.link.client_sap, c.link.server_sap) == (5, 16, 1)
    c = client("mbus:///dev/ttyUSB0?secondary=12345678FFFFFFFF&parity=n")
    assert c.link.address == 0xFD and c.link.transport.parity == "N"
    assert c.link.transport.baudrate == 2400


def test_mbus_tcp_client_options():
    c = client("mbus+tcp://192.0.2.1:10001?address=254")
    assert isinstance(c.link.transport, TcpTransport)
    assert (c.link.transport.host, c.link.transport.port, c.link.address) == (
        "192.0.2.1",
        10001,
        254,
    )


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["mbus:///dev/x?address=251"], "invalid connection options"),
        (["mbus:///dev/x?address=five"], "not a number"),
        (["mbus:///dev/x?address=1&secondary=12345678FFFFFFFF"], "not both"),
        (["mbus:///dev/x?parity=X"], "parity"),
        (["mbus://?address=1"], "needs a device"),
        (["mbus:///dev/x", "--physical", "17"], "--physical"),
        (["mbus:///dev/x", "--address-size", "2"], "HDLC endpoint"),
        (["mbus:///dev/x", "--client-wport", "5"], "wrapper endpoint"),
        (["mbus+tcp://h:1", "--hdlc-window", "3"], "HDLC endpoint"),
    ],
)
def test_mbus_usage_errors(argv, message):
    with pytest.raises(SystemExit, match=message):
        client(*argv)


def test_read_over_mbus_tcp(capsys):
    server = serve_mbus(example_meter(), address=5)
    host, port = server.server_address[:2]
    try:
        endpoint = f"mbus+tcp://{host}:{port}?address=5"
        assert main(["read", endpoint, "--obis", "1.0.32.7.0.255", "--register"]) == 0
        assert capsys.readouterr().out.split("  ")[:3] == ["1.0.32.7.0.255", "230.1", "V"]
        assert main(["list", endpoint]) == 0
        assert "Profile generic" in capsys.readouterr().out
    finally:
        server.shutdown()
        server.server_close()


def test_record_and_decode_mbus_session(tmp_path, capsys):
    """``--record`` of a polled M-Bus session (E5, short frames, long frames
    split over several reads) decodes again with ``decode --file``."""
    server = serve_mbus(example_meter(), address=5, max_segment=32)
    host, port = server.server_address[:2]
    record = tmp_path / "mbus.hex"
    try:
        endpoint = f"mbus+tcp://{host}:{port}?address=5"
        argv = ["--record", str(record), "read", endpoint, "--obis", "1.0.32.7.0.255", "--register"]
        assert main(argv) == 0
    finally:
        server.shutdown()
        server.server_close()
    capsys.readouterr()
    assert main(["decode", "--file", str(record)]) == 0
    out = capsys.readouterr().out
    assert "short frame C=0x40 (SND_NKE) A=0x05" in out
    assert "short frame C=0x7B (REQ_UD2 FCB=1)" in out
    assert "E5 (single character acknowledgement)" in out
    assert "CI=0x00 (segment 0) STSAP=1 DTSAP=16" in out  # the AARE in 32-octet segments
    assert "== APDU AARE (0x61)" in out and "== APDU GET_RESPONSE (0xC4)" in out
    assert main(["decode", "--file", str(record), "--xml"]) == 0
    assert "<GetResponseNormal>" in capsys.readouterr().out


def test_explain_names_link_telegrams():
    from pydlms.explain import detect_framing, explain
    from pydlms.mbus_link import control_name, encode_long_frame, starts_with_mbus_telegram

    assert detect_framing(b"\xe5") == "mbus"
    assert detect_framing(bytes.fromhex("107BFD7816")) == "mbus"
    assert detect_framing(bytes.fromhex("107BFD7716")) == "apdu"  # bad checksum
    assert not starts_with_mbus_telegram(b"\xe5\x00")
    idle = encode_long_frame(0x08, 5, 0x72, bytes(12))
    text = explain([bytes.fromhex("105B056016"), idle])
    assert "REQ_UD2 FCB=0" in text
    assert "C=0x08 (RSP_UD ACD=0 DFC=0) A=0x05 CI=0x72 (no DLMS data)" in text
    assert control_name(0x4B) == "REQ_UD2 FCV=0"
    assert control_name(0x01) == "NACK ACD=0 DFC=0"
    assert control_name(0x38) == "RSP_UD ACD=1 DFC=1"
