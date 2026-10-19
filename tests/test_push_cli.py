"""``pydlms push --capture-objects FILE`` and ``--from-meter URL``."""

from __future__ import annotations

import pytest

from pydlms.apdu.xdlms import DataNotification
from pydlms.cli import build_parser, main
from pydlms.cosem.data import DlmsData as D
from pydlms.simulator import example_meter, serve
from tests.test_push_setup import PUSH_SETUP, TEXT


def test_cli_parses_capture_options():
    ns = build_parser().parse_args(["push", "-", "--capture-objects", "f.txt"])
    assert ns.capture_objects == "f.txt" and ns.from_meter is None
    ns = build_parser().parse_args(
        ["push", "-", "--from-meter", "tcp://h:1", "--meter-client", "17"]
    )
    assert ns.from_meter == "tcp://h:1" and ns.meter_client == 17
    assert ns.push_setup == PUSH_SETUP
    with pytest.raises(SystemExit):
        build_parser().parse_args(
            ["push", "-", "--from-meter", "tcp://h", "--capture-objects", "f"]
        )


def raw_push() -> str:
    body = D.structure(
        [D.octet_string(bytes(6)), D.visible_string("PYD1"), D.uint32(42), D.uint32(7)]
    )
    return DataNotification(1, body).to_bytes().hex()


def run_push(monkeypatch, capsys, *extra):
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO(raw_push() + "\n"))
    assert main(["push", "-", "--framing", "raw", *extra]) == 0
    return capsys.readouterr().out


def test_cli_capture_objects_file(monkeypatch, capsys, tmp_path):
    path = tmp_path / "objects.txt"
    path.write_text(TEXT + "3 1.0.1.7.0.255 2\n")
    out = run_push(monkeypatch, capsys, "--capture-objects", str(path))
    assert "1.0.1.8.0.255" in out and "42" in out


def test_cli_capture_objects_bad_file(capsys, tmp_path):
    path = tmp_path / "bad.txt"
    path.write_text("3 oops\n")
    assert main(["push", "-", "--capture-objects", str(path)]) != 0
    assert "line 1" in capsys.readouterr().err


def test_cli_from_meter(monkeypatch, capsys):
    server = serve(example_meter())
    try:
        host, port = server.server_address
        out = run_push(monkeypatch, capsys, "--from-meter", f"tcp://{host}:{port}")
    finally:
        server.shutdown()
        server.server_close()
    assert "0.0.96.1.0.255  PYD1" in out
    assert "1.0.1.8.0.255  42" in out
