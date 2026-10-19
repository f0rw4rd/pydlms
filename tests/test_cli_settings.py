"""CLI flags for addressing and association settings: each
flag reaches the built client, and bad values or wrong endpoints exit with
a usage message before any I/O."""

from __future__ import annotations

import pytest

from pydlms.apdu.xdlms import Conformance
from pydlms.cli import build_client, build_parser, main
from pydlms.hdlc.address import HdlcAddress
from pydlms.simulator import ClientProfile, example_meter, serve

KEY = "000102030405060708090A0B0C0D0E0F"


def _client(*argv: str):
    return build_client(build_parser().parse_args(["clock", *argv]))


def _settings(*argv: str):
    return _client(*argv).association.settings


def _exits(match: str, *argv: str) -> None:
    with pytest.raises(SystemExit, match=match):
        _client(*argv)


def _usage_error(*argv: str) -> None:
    """argparse refuses the value itself (exit status 2)."""
    with pytest.raises(SystemExit) as info:
        build_parser().parse_args(["clock", *argv])
    assert info.value.code == 2


# -- defaults ----------------------------------------------------------------------


def test_defaults_leave_settings_untouched():
    settings = _settings("tcp://192.0.2.1")
    assert settings.max_receive_pdu_size == 0xFFFF
    assert settings.conformance is None
    assert settings.protection == "glo"
    assert not settings.use_dedicated_key
    assert settings.expected_server_system_title is None
    assert settings.gbt_window == 1
    assert not settings.invocation_counter_retry
    assert not settings.require_verified_release
    client = _client("tcp://192.0.2.1", "--client", "1")
    assert client.link.client_wport == 1
    assert _client("tcp+hdlc://192.0.2.1").link.server == HdlcAddress(1, None, 1)


# -- --address-size ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["--address-size", "1"], HdlcAddress(1, None, 1)),
        (["--address-size", "2", "--physical", "17"], HdlcAddress(1, 17, 2)),
        (["--address-size", "4", "--physical", "17"], HdlcAddress(1, 17, 4)),
    ],
)
def test_address_size(argv, expected):
    assert _client("tcp+hdlc://192.0.2.1", *argv).link.server == expected


def test_address_size_on_serial_and_optical():
    pytest.importorskip("serial")
    for endpoint in ("serial://loop://", "optical://loop://"):
        client = _client(endpoint, "--address-size", "4", "--physical", "300")
        assert client.link.server == HdlcAddress(1, 300, 4)


@pytest.mark.parametrize("value", ["3", "0", "x"])
def test_address_size_choices(value):
    _usage_error("tcp+hdlc://192.0.2.1", "--address-size", value)


@pytest.mark.parametrize("endpoint", ["tcp://192.0.2.1", "udp://192.0.2.1"])
def test_address_size_needs_hdlc(endpoint):
    _exits("--address-size needs an HDLC endpoint", endpoint, "--address-size", "4")


@pytest.mark.parametrize(
    ("argv", "match"),
    [
        (["--address-size", "1", "--physical", "17"], "no lower part"),
        (["--address-size", "4"], "needs a physical"),
        (["--address-size", "2", "--physical", "200"], "out of range"),
    ],
)
def test_address_size_does_not_fit(argv, match):
    _exits(f"invalid connection options: .*{match}", "tcp+hdlc://192.0.2.1", *argv)


def test_address_size_end_to_end(capsys):
    server = serve(example_meter(), hdlc=True)
    try:
        host, port = server.server_address[:2]
        argv = ["clock", f"tcp+hdlc://{host}:{port}", "--address-size", "4", "--physical", "9"]
        assert main([*argv, "--timeout", "3"]) == 0
    finally:
        server.shutdown()
        server.server_close()
    assert capsys.readouterr().out.strip()


# -- --physical-from-serial ------------------------------------------------------------


def test_physical_from_serial():
    client = _client("tcp+hdlc://192.0.2.1", "--physical-from-serial", "12345678:landis+gyr")
    assert client.link.server == HdlcAddress(1, 6678, 4)


@pytest.mark.parametrize(
    ("argv", "match"),
    [
        (["--physical-from-serial", "12345678"], "SERIAL:VENDOR"),
        (["--physical-from-serial", ":emh"], "SERIAL:VENDOR"),
        (["--physical-from-serial", "1234:"], "SERIAL:VENDOR"),
        (["--physical-from-serial", "1234:acme"], "no rule for vendor 'acme'.*landis"),
        (["--physical-from-serial", "abc:emh"], "no digits"),
        (["--physical-from-serial", "1:emh", "--physical", "17"], "not both"),
        (["--physical-from-serial", "12345678:emh", "--address-size", "2"], "out of range"),
    ],
)
def test_physical_from_serial_errors(argv, match):
    _exits(match, "tcp+hdlc://192.0.2.1", *argv)


def test_physical_from_serial_needs_hdlc():
    _exits("needs an HDLC endpoint", "tcp://192.0.2.1", "--physical-from-serial", "1:emh")


# -- --client-wport ---------------------------------------------------------------------


@pytest.mark.parametrize("endpoint", ["tcp://192.0.2.1", "udp://192.0.2.1"])
def test_client_wport(endpoint):
    assert _client(endpoint, "--client-wport", "4660").link.client_wport == 0x1234


@pytest.mark.parametrize("value", ["-1", "65536"])
def test_client_wport_range(value):
    _exits("client_wport", "tcp://192.0.2.1", "--client-wport", value)


def test_client_wport_not_a_number():
    _usage_error("tcp://192.0.2.1", "--client-wport", "x")


def test_client_wport_needs_wrapper():
    _exits("--client-wport needs a wrapper endpoint", "tcp+hdlc://192.0.2.1", "--client-wport", "1")


def test_client_wport_end_to_end(capsys):
    sim = example_meter()
    sim.clients[0x30] = ClientProfile()
    server = serve(sim)
    try:
        host, port = server.server_address[:2]
        assert (
            main(["clock", f"tcp://{host}:{port}", "--client-wport", "48", "--timeout", "3"]) == 0
        )
    finally:
        server.shutdown()
        server.server_close()
    assert capsys.readouterr().out.strip()


# -- association settings -------------------------------------------------------------


@pytest.mark.parametrize("value", ["13", "512", "65535"])
def test_max_pdu(value):
    assert _settings("tcp://192.0.2.1", "--max-pdu", value).max_receive_pdu_size == int(value)


@pytest.mark.parametrize("value", ["12", "0", "65536"])
def test_max_pdu_range(value):
    _exits("--max-pdu must be 13-65535", "tcp://192.0.2.1", "--max-pdu", value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("007E1F", Conformance(0x007E1F)),
        ("0x7e1f", Conformance(0x007E1F)),
        ("get", Conformance.GET),
        (
            "GET, set,selective-access",
            Conformance.GET | Conformance.SET | Conformance.SELECTIVE_ACCESS,
        ),
    ],
)
def test_conformance(value, expected):
    assert _settings("tcp://192.0.2.1", "--conformance", value).conformance == expected


@pytest.mark.parametrize(
    ("value", "match"),
    [
        ("1000000", "wider than the 24-bit"),
        ("0", "at least one bit"),
        ("get,frobnicate", "unknown bit 'frobnicate'"),
        ("", "unknown bit"),
    ],
)
def test_conformance_errors(value, match):
    _exits(match, "tcp://192.0.2.1", "--conformance", value)


@pytest.mark.parametrize(
    "value",
    [
        "glo",
        "general-glo",
        "general-ciphering",
        "general-signing",
        "glo+signing",
        "general-ciphering+signing",
    ],
)
def test_protection(value):
    pytest.importorskip("cryptography")
    assert _settings("tcp://192.0.2.1", "--key", KEY, "--protection", value).protection == value


def test_protection_choices():
    _usage_error("tcp://192.0.2.1", "--protection", "rot13")


def test_protection_and_dedicated_key_need_a_key():
    _exits("--protection needs ciphering", "tcp://192.0.2.1", "--protection", "general-glo")
    _exits("--dedicated-key needs ciphering", "tcp://192.0.2.1", "--dedicated-key")


def test_dedicated_key():
    pytest.importorskip("cryptography")
    assert _settings("tcp://192.0.2.1", "--key", KEY, "--dedicated-key").use_dedicated_key


def test_client_title_alias():
    settings = _settings("tcp://192.0.2.1", "--client-title", "50:59:44:4C:4D:53:30:31")
    assert settings.client_system_title == b"PYDLMS01"


def test_client_title_reaches_the_security_context():
    pytest.importorskip("cryptography")
    settings = _settings("tcp://192.0.2.1", "--key", KEY, "--client-title", "4142434445464748")
    assert settings.security.client_system_title == b"ABCDEFGH"


@pytest.mark.parametrize("flag", ["--client-title", "--system-title", "--expect-server-title"])
@pytest.mark.parametrize("value", ["41424344454647", "414243444546474849", "zz"])
def test_titles_must_be_eight_octets(flag, value):
    with pytest.raises(SystemExit, match="8 octets|not a hex string"):
        _client("tcp://192.0.2.1", flag, value)


def test_expect_server_title():
    settings = _settings("tcp://192.0.2.1", "--expect-server-title", "4142434445464748")
    assert settings.expected_server_system_title == b"ABCDEFGH"


@pytest.mark.parametrize("value", ["1", "63"])
def test_gbt_window(value):
    assert _settings("tcp://192.0.2.1", "--gbt-window", value).gbt_window == int(value)


@pytest.mark.parametrize("value", ["0", "64"])
def test_gbt_window_range(value):
    _exits("--gbt-window must be 1-63", "tcp://192.0.2.1", "--gbt-window", value)


@pytest.mark.parametrize("flag", ["--ic-retry", "--invocation-counter-retry"])
def test_invocation_counter_retry(flag):
    assert _settings("tcp://192.0.2.1", flag).invocation_counter_retry


def test_require_verified_release():
    assert _settings("tcp://192.0.2.1", "--require-verified-release").require_verified_release


def test_every_flag_on_udp():
    pytest.importorskip("cryptography")
    settings = _settings(
        "udp://192.0.2.1",
        "--key",
        KEY,
        "--max-pdu",
        "1024",
        "--conformance",
        "get,set",
        "--protection",
        "general-glo",
        "--dedicated-key",
        "--expect-server-title",
        "4142434445464748",
        "--gbt-window",
        "8",
        "--invocation-counter-retry",
        "--require-verified-release",
    )
    assert (settings.max_receive_pdu_size, settings.gbt_window) == (1024, 8)
    assert settings.conformance == Conformance.GET | Conformance.SET
    assert settings.protection == "general-glo" and settings.use_dedicated_key
    assert settings.expected_server_system_title == b"ABCDEFGH"
    assert settings.invocation_counter_retry and settings.require_verified_release
