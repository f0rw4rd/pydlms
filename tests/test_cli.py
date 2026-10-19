"""CLI tests: against the simulator over loopback TCP, and offline decode."""

from __future__ import annotations

import json

import pytest

from pydlms.cli import main, parse_endpoint
from pydlms.simulator import ClientProfile, example_meter, serve
from tests.meter_fixtures import load


@pytest.fixture(scope="module")
def endpoint():
    sim = example_meter()
    sim.clients[17] = ClientProfile(mechanism=1, secret=b"12345678")
    server = serve(sim)
    host, port = server.server_address
    yield f"tcp://{host}:{port}"
    server.shutdown()
    server.server_close()


def test_parse_endpoint():
    assert parse_endpoint("tcp://10.0.0.1") == ("tcp", {"host": "10.0.0.1", "port": 4059})
    assert parse_endpoint("tcp+hdlc://m:5000")[1]["port"] == 5000
    assert parse_endpoint("serial:///dev/ttyUSB0?baud=2400") == (
        "serial",
        {"port": "/dev/ttyUSB0", "baud": "2400"},
    )
    assert parse_endpoint("/dev/ttyS1") == ("serial", {"port": "/dev/ttyS1"})
    assert parse_endpoint("udp://10.0.0.2") == ("udp", {"host": "10.0.0.2", "port": 4059})
    assert parse_endpoint("udp://m:4060") == ("udp", {"host": "m", "port": 4060})
    assert parse_endpoint("optical:///dev/ttyUSB1?baud=9600") == (
        "optical",
        {"port": "/dev/ttyUSB1", "baud": "9600"},
    )
    assert parse_endpoint("optical://?port=COM3") == ("optical", {"port": "COM3"})
    with pytest.raises(SystemExit):
        parse_endpoint("ftp://x")
    with pytest.raises(SystemExit, match="no host"):
        parse_endpoint("udp://:4059")


def test_read_register(endpoint, capsys):
    assert main(["read", endpoint, "--obis", "1.0.32.7.0.255", "--register"]) == 0
    assert capsys.readouterr().out.split("  ")[:3] == ["1.0.32.7.0.255", "230.1", "V"]


def test_read_json_and_lls(endpoint, capsys):
    code = main(
        [
            "--json",
            "read",
            endpoint,
            "--client",
            "17",
            "--auth",
            "lls",
            "--password",
            "12345678",
            "--obis",
            "0.0.96.1.0.255",
        ]
    )
    assert code == 0
    assert json.loads(capsys.readouterr().out)[0]["value"] == "PYD0000000001"


def test_list_clock_profile(endpoint, capsys):
    assert main(["list", endpoint]) == 0
    assert "Profile generic" in capsys.readouterr().out
    assert main(["clock", endpoint]) == 0
    assert "2024-05-01 12:00:00.00 +02:00" in capsys.readouterr().out
    assert main(["profile", endpoint, "--obis", "1.0.99.1.0.255", "--last", "2"]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 2 and "2024-05-01 23:45:00" in lines[-1]


def test_profile_typed_with_scalers(endpoint, capsys):
    args = ["profile", endpoint, "--obis", "1.0.99.1.0.255", "--last", "1"]
    assert main(["--json", *args, "--scalers"]) == 0
    (row,) = json.loads(capsys.readouterr().out)
    assert row == {
        "0.0.1.0.0.255/2": "2024-05-01 23:45:00.00 +00:00",
        "1.0.1.8.0.255/2": "1665 Wh",
    }
    assert main(["--json", *args, "--typed"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["1.0.1.8.0.255/2"] == 1665


def test_list_shows_access_rights(endpoint, capsys):
    assert main(["--json", "list", endpoint]) == 0
    rows = {r["obis"]: r for r in json.loads(capsys.readouterr().out)}
    assert rows["1.0.1.8.0.255"]["access"] == "r=1-3 w=2-3 x=1"
    assert rows["0.0.96.1.0.255"]["access"] == "r=1-2 w=2 x=-"


def test_errors_are_reported_with_hint(endpoint, capsys):
    assert main(["read", endpoint, "--obis", "9.9.9.9.9.9"]) == 2
    err = capsys.readouterr().err
    assert "OBJECT_UNDEFINED" in err and "-v" in err


def test_verbose_trace_and_record(endpoint, tmp_path, capsys):
    record = tmp_path / "session.hex"
    from pydlms.debug import disable_debug

    try:
        assert (
            main(["-vv", "--record", str(record), "read", endpoint, "--obis", "1.0.1.8.0.255"]) == 0
        )
    finally:
        disable_debug()
    err = capsys.readouterr().err
    assert "TX" in err and "AARQ" in err.upper() or "APDU TX" in err
    lines = record.read_text().splitlines()
    assert lines[0].startswith("# pydlms recording v1")
    assert lines[1].startswith("TX 0001")  # wrapper header of the AARQ
    assert any(line.startswith("RX ") for line in lines)
    assert any(line.startswith("TX-APDU c001") for line in lines)  # plaintext GET
    # The recording replays through the decoder: frames, or the plaintext APDUs.
    assert main(["decode", "--file", str(record)]) == 0
    out = capsys.readouterr().out
    assert "AARE" in out and "TCP/UDP wrapper" in out
    assert main(["decode", "--file", str(record), "--apdus"]) == 0
    out = capsys.readouterr().out
    assert "GetRequestNormal" in out and "TCP/UDP wrapper" not in out


def test_log_layers_limits_output_to_the_chosen_layer(endpoint, capsys):
    from pydlms.debug import disable_debug

    read = ["read", endpoint, "--obis", "1.0.1.8.0.255", "--register"]
    try:
        assert main(["-v", *read]) == 0
        everything = _logger_names(capsys.readouterr().err)
        disable_debug()
        assert main(["-v", "--log-layers", "wrapper", *read]) == 0
        only_wrapper = _logger_names(capsys.readouterr().err)
    finally:
        disable_debug()
    # Without the filter the association and transport layers log as well,
    # so the second run proves the filter, not a quiet stack.
    assert {"pydlms.wrapper", "pydlms.association", "pydlms.transport"} <= everything
    assert only_wrapper == {"pydlms.wrapper"}


def _logger_names(err: str) -> set[str]:
    """Logger names from enable_debug's ``time name level message`` lines."""
    names = set()
    for line in err.splitlines():
        parts = line.split()
        if len(parts) > 2 and parts[1].startswith("pydlms."):
            names.add(parts[1])
    return names


def test_decode_command_with_keys(capsys):
    pytest.importorskip("cryptography")
    fx = load("hdlc_landis_gyr_e450")
    assert (
        main(
            [
                "decode",
                fx.raw.hex(),
                "--key",
                fx.encryption_key.hex(),
                "--auth-key",
                fx.authentication_key.hex(),
            ]
        )
        == 0
    )
    assert "tag verified" in capsys.readouterr().out


def test_decode_requires_input():
    with pytest.raises(SystemExit):
        main(["decode"])


def test_push_from_stdin(monkeypatch, capsys):
    pytest.importorskip("cryptography")
    import io

    fx = load("mbus_netz_noe_p1")
    monkeypatch.setattr("sys.stdin", io.StringIO(fx.raw.hex() + "\n"))
    assert (
        main(
            [
                "push",
                "-",
                "--framing",
                "mbus",
                "--key",
                fx.encryption_key.hex(),
                "--profile",
                "netz-noe-p1",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "0.0.96.1.0.255  181220000009" in out
    assert "1.0.32.7.0.255  233.7  V" in out


@pytest.mark.parametrize(("hdlc", "scheme"), [(False, "tcp"), (True, "tcp+hdlc")])
def test_simulate_command_serves_until_interrupted(hdlc, scheme, capsys):
    """``pydlms simulate`` in a child process: read through it, then SIGINT."""
    import os
    import re
    import signal
    import subprocess
    import sys
    from pathlib import Path

    code = "import sys; from pydlms.cli import main; sys.exit(main(sys.argv[1:]))"
    argv = [sys.executable, "-c", code, "simulate", "--port", "0"]
    if hdlc:
        argv.append("--hdlc")
    root = str(Path(__file__).resolve().parent.parent)
    env = {**os.environ, "PYTHONPATH": root}
    proc = subprocess.Popen(argv, stderr=subprocess.PIPE, text=True, env=env)  # nosec
    try:
        line = proc.stderr.readline()
        match = re.search(r"listening on ([\d.]+):(\d+) \((\w+)\)", line)
        assert match, line
        assert match.group(3) == ("HDLC" if hdlc else "wrapper")
        url = f"{scheme}://{match.group(1)}:{match.group(2)}"
        assert main(["read", url, "--obis", "1.0.32.7.0.255", "--register"]) == 0
        assert capsys.readouterr().out.split("  ")[:3] == ["1.0.32.7.0.255", "230.1", "V"]
        proc.send_signal(signal.SIGINT)
        assert proc.wait(timeout=10) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        proc.stderr.close()


def test_simulate_replay_answers_like_the_recorded_meter(endpoint, tmp_path, capsys):
    """Record a read, then ``pydlms simulate --replay`` serves the same answer."""
    import os
    import re
    import signal
    import subprocess
    import sys
    from pathlib import Path

    record = tmp_path / "session.hex"
    read = ["read", "--obis", "1.0.32.7.0.255", "--register"]
    assert main(["--record", str(record), read[0], endpoint, *read[1:]]) == 0
    recorded = capsys.readouterr().out
    code = "import sys; from pydlms.cli import main; sys.exit(main(sys.argv[1:]))"
    argv = [sys.executable, "-c", code, "simulate", "--port", "0", "--replay", str(record)]
    root = str(Path(__file__).resolve().parent.parent)
    env = {**os.environ, "PYTHONPATH": root}
    proc = subprocess.Popen(argv, stderr=subprocess.PIPE, text=True, env=env)  # nosec
    try:
        line = proc.stderr.readline()
        match = re.search(r"listening on ([\d.]+):(\d+)", line)
        assert match, line
        url = f"tcp://{match.group(1)}:{match.group(2)}"
        assert main([read[0], url, *read[1:]]) == 0
        assert capsys.readouterr().out == recorded
        proc.send_signal(signal.SIGINT)
        assert proc.wait(timeout=10) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        proc.stderr.close()


def test_decode_xml_edit_encode_and_replay(endpoint, tmp_path, capsys):
    """record -> decode --xml -> edit -> encode --recording -> replay."""
    from pydlms.cosem.interface_classes import ClassId
    from pydlms.recording import load_recording
    from pydlms.replay import ReplayMeter

    record = tmp_path / "session.hex"
    obis = "0.0.96.1.0.255"
    assert main(["--record", str(record), "read", endpoint, "--obis", obis]) == 0
    capsys.readouterr()
    assert main(["decode", "--file", str(record), "--xml"]) == 0
    from_frames = capsys.readouterr().out
    assert main(["decode", "--file", str(record), "--xml", "--apdus"]) == 0
    xml = capsys.readouterr().out
    assert xml.startswith("<pydlms-session") and "<AARQ>" in from_frames
    assert '<visible-string value="PYD0000000001" />' in xml
    edited = tmp_path / "edited.xml"
    edited.write_text(xml.replace("PYD0000000001", "EDITED"))
    assert main(["encode", str(edited), "--recording"]) == 0
    replayed = tmp_path / "edited.hex"
    replayed.write_text(capsys.readouterr().out)
    assert all(
        line.split()[0] in ("TX-APDU", "RX-APDU") for line in replayed.read_text().split("\n")[:-1]
    )
    replay = ReplayMeter(load_recording(replayed))
    server = serve(replay)
    try:
        from pydlms.client import DlmsClient

        with DlmsClient.tcp(*server.server_address, timeout=5) as meter:
            assert meter.get(obis, ClassId.DATA, 2).value == "EDITED"
    finally:
        server.shutdown()
        server.server_close()
    assert main(["encode", str(edited)]) == 0
    assert capsys.readouterr().out.split("\n")[1].startswith("c001")  # bare hex lines


def test_gurux_dialect_edit_encode_and_replay(endpoint, tmp_path, capsys):
    """The same loop through the Gurux translator dialect."""
    from pydlms.cosem.interface_classes import ClassId
    from pydlms.recording import load_recording
    from pydlms.replay import ReplayMeter

    record = tmp_path / "session.hex"
    obis = "0.0.96.1.0.255"
    assert main(["--record", str(record), "read", endpoint, "--obis", obis]) == 0
    capsys.readouterr()
    assert main(["decode", "--file", str(record), "--xml", "--apdus", "--dialect", "gurux"]) == 0
    xml = capsys.readouterr().out
    assert xml.startswith('<pydlms-session version="1" dialect="gurux">')
    assert '<String Value="PYD0000000001" />' in xml and "<GetRequestNormal>" in xml
    edited = tmp_path / "edited.xml"
    edited.write_text(xml.replace("PYD0000000001", "EDITED"))
    assert main(["encode", str(edited), "--recording"]) == 0
    replayed = tmp_path / "edited.hex"
    replayed.write_text(capsys.readouterr().out)
    server = serve(ReplayMeter(load_recording(replayed)))
    try:
        from pydlms.client import DlmsClient

        with DlmsClient.tcp(*server.server_address, timeout=5) as meter:
            assert meter.get(obis, ClassId.DATA, 2).value == "EDITED"
    finally:
        server.shutdown()
        server.server_close()


def test_simulator_options_build_a_replay_meter(tmp_path):
    from pydlms.replay import ReplayMeter
    from pydlms.security.hls import Mechanism
    from pydlms.simulator import _parser, meter_from_args

    record = tmp_path / "session.hex"
    record.write_text("TX-APDU c001c100030100010800ff0200\nRX-APDU c401c1000600000001\n")
    key = "00" * 16
    args = _parser().parse_args(
        ["--replay", str(record), "--key", key, "--client", "1:5", "--client", "32:1:pw"]
    )
    meter = meter_from_args(args)
    assert isinstance(meter, ReplayMeter)
    assert meter.encryption_key == bytes(16)
    assert meter.clients[1] == ClientProfile(Mechanism.HLS_GMAC, ciphered=True)
    assert meter.clients[32] == ClientProfile(Mechanism.LLS, secret=b"pw", ciphered=True)
    plain = meter_from_args(_parser().parse_args([]))
    assert not isinstance(plain, ReplayMeter) and plain.encryption_key is None


def test_bad_hex_rejected():
    with pytest.raises(SystemExit):
        main(["decode", "zz"])


def test_version(capsys):
    with pytest.raises(SystemExit):
        main(["--version"])
    assert "pydlms" in capsys.readouterr().out


def test_all_auth_levels_via_cli(tmp_path, capsys):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization

    from pydlms.security import ec
    from pydlms.security.hls import Mechanism

    sim = example_meter(encryption_key=bytes(range(16)), authentication_key=bytes(range(16, 32)))
    client_key = ec.generate_private_key(1)
    sim.signing_key = ec.generate_private_key(1)
    sim.clients.update(
        {
            20: ClientProfile(Mechanism.HLS, b"secret"),
            24: ClientProfile(Mechanism.HLS_MD5, b"secret"),
            25: ClientProfile(Mechanism.HLS_SHA1, b"secret"),
            21: ClientProfile(Mechanism.HLS_SHA256, b"secret"),
            22: ClientProfile(Mechanism.HLS_ECDSA, client_public_key=client_key.public_key()),
            23: ClientProfile(Mechanism.HLS_GMAC, ciphered=True),
        }
    )
    signing = tmp_path / "client.pem"
    signing.write_bytes(
        client_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    server_pub = tmp_path / "server.pem"
    server_pub.write_bytes(
        sim.signing_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    server = serve(sim)
    url = "tcp://{}:{}".format(*server.server_address)
    title = ["--system-title", "5059444C4D533031"]
    try:
        for extra in (
            ["--client", "20", "--auth", "hls", "--password", "secret"],
            ["--client", "24", "--auth", "md5", "--password", "secret"],
            ["--client", "25", "--auth", "sha1", "--password", "secret"],
            ["--client", "21", "--auth", "sha256", "--password", "secret", *title],
            [
                "--client",
                "22",
                "--auth",
                "ecdsa",
                "--signing-key",
                str(signing),
                "--server-key",
                str(server_pub),
                *title,
            ],
            [
                "--client",
                "23",
                "--auth",
                "gmac",
                "--key",
                bytes(range(16)).hex(),
                "--auth-key",
                bytes(range(16, 32)).hex(),
            ],
        ):
            assert main(["read", url, "--obis", "1.0.1.8.0.255", "--register", *extra]) == 0
            assert "12345678" in capsys.readouterr().out
    finally:
        server.shutdown()
        server.server_close()


def test_invocation_counter_options(tmp_path, capsys):
    pytest.importorskip("cryptography")
    from pydlms.security.hls import Mechanism

    key, ak = bytes(range(16)), bytes(range(16, 32))
    sim = example_meter(encryption_key=key, authentication_key=ak)
    sim.clients[1] = ClientProfile(Mechanism.HLS_GMAC, ciphered=True)
    sim.set_ic_location("0.0.43.1.0.255", last=900)
    server = serve(sim)
    url = "tcp://{}:{}".format(*server.server_address)
    store = tmp_path / "ic.json"
    base = [
        "read",
        url,
        "--obis",
        "1.0.1.8.0.255",
        "--register",
        "--client",
        "1",
        "--auth",
        "gmac",
        "--key",
        key.hex(),
        "--auth-key",
        ak.hex(),
    ]
    try:
        assert main(base) == 2  # stale counter 0
        assert "INVOCATION_COUNTER_ERROR" in capsys.readouterr().err
        assert main([*base, "--discover-ic", "--ic-store", str(store)]) == 0
        assert main([*base, "--ic-store", str(store)]) == 0  # continues from the store
        assert main([*base, "--ic-retry"]) == 0
    finally:
        server.shutdown()
        server.server_close()
