"""Recording redaction (pydlms.redact, ``pydlms redact``)."""

from __future__ import annotations

import pytest

from pydlms import cli
from pydlms.apdu.acse import AARE, AARQ
from pydlms.apdu.tags import Tag
from pydlms.client import DlmsClient
from pydlms.cosem.data import DlmsData
from pydlms.cosem.interface_classes import ClassId
from pydlms.debug import FrameRecorder
from pydlms.exceptions import DecodeError
from pydlms.hdlc.address import HdlcAddress
from pydlms.hdlc.framing import FrameReader, HdlcFrame, control_i, decode_frame, encode_frame
from pydlms.recording import deframe, parse_recording, session_apdus
from pydlms.redact import PHYSICAL_PLACEHOLDER, placeholder, redact_recording, redact_records
from pydlms.security.hls import Mechanism
from pydlms.simulator import ClientProfile, _parser, example_meter, meter_from_args, serve
from pydlms.wrapper import decode_wrapper, encode_wrapper

SERIAL = b"PYD0000000001"  # example meter 0.0.96.1.0.255
LDN = b"PYD1000000000001"  # example meter 0.0.42.0.0.255
SERVER_TITLE = b"PYD\x00\x00\x00\x00\x01"  # example meter system title
CLIENT_TITLE = b"PYDCLNT1"
PASSWORD = b"S3cr3tPw"
SERVER_TITLE_SET = b"PYDS3T42"  # served by a security setup object
EK = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
AK = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")


def _meter(**kw):
    sim = example_meter(**kw)
    sim.clients[32] = ClientProfile(Mechanism.LLS, secret=PASSWORD)
    sim.add_object(
        ClassId.SECURITY_SETUP,
        "0.0.43.0.0.255",
        {
            2: DlmsData.enum(0),
            3: DlmsData.enum(0),
            4: DlmsData.octet_string(CLIENT_TITLE),
            5: DlmsData.octet_string(SERVER_TITLE_SET),
        },
        version=1,
        base_name=0x5000,
    )
    return sim


def _script(meter: DlmsClient) -> dict:
    return {
        "serial": meter.get("0.0.96.1.0.255").value,
        "ldn": meter.get("0.0.42.0.0.255").value,
        "title": meter.get("0.0.43.0.0.255", ClassId.SECURITY_SETUP, 5).value,
        "energy": meter.get_register("1.0.1.8.0.255"),
        "clock": meter.get_clock(),
    }


def _record(sim, hdlc=False, script=_script, **kw):
    server = serve(sim, hdlc=hdlc)
    recorder = FrameRecorder()
    meter = DlmsClient.tcp(*server.server_address, hdlc=hdlc, timeout=5, **kw)
    meter.link.transport.recorder = recorder
    try:
        with meter:
            result = script(meter)
    finally:
        server.shutdown()
        server.server_close()
    return recorder.dump(), result


def _lls(**kw):
    return {"client_sap": 32, "mechanism": Mechanism.LLS, "password": PASSWORD, **kw}


def _all_bytes(text: str) -> bytes:
    return b"".join(data for _, data in parse_recording(text))


def _assert_parses(text: str) -> None:
    """Every raw frame of the output parses with its checksums verified."""
    records = parse_recording(text)
    for direction in ("TX", "RX"):
        stream = b"".join(d for r, d in records if r == direction)
        if stream[:1] == b"\x7e":
            reader = FrameReader(strict=True)
            frames = reader.feed(stream)
            assert reader.dropped == 0
            assert sum(len(encode_frame(f)) for f in frames) == len(stream)
        elif stream:
            pos = 0
            while pos < len(stream):
                length = int.from_bytes(stream[pos + 6 : pos + 8], "big")
                decode_wrapper(stream[pos : pos + 8 + length])
                pos += 8 + length
    deframe(records)  # reassembles without a checksum error


@pytest.mark.parametrize("hdlc", [False, True], ids=["wrapper", "hdlc"])
@pytest.mark.parametrize("test_keys", [False, True], ids=["default", "test-keys"])
def test_identifiers_and_password_are_gone(hdlc, test_keys):
    original, _ = _record(_meter(), hdlc, **_lls())
    whole = _all_bytes(original)
    for secret in (SERIAL, LDN, PASSWORD, SERVER_TITLE_SET):
        assert secret in whole  # the test would prove nothing otherwise
    text, log = redact_recording(original, test_keys=test_keys)
    out = _all_bytes(text)
    for secret in (SERIAL, LDN[3:], PASSWORD, SERVER_TITLE_SET):
        assert secret not in out, secret
    assert b"PYD" + placeholder(13) in out  # the manufacturer flag stays
    assert placeholder(len(SERIAL)) in out
    _assert_parses(text)
    summary = str(log)
    assert "serial" in summary and "system title" in summary
    for secret in (SERIAL, LDN, PASSWORD, SERVER_TITLE_SET):
        assert secret.decode() not in summary and secret.hex() not in summary.lower()
    raw_acse = [a for d, a in deframe(parse_recording(text)) if a[0] in (Tag.AARQ, Tag.AARE)]
    if test_keys:
        aarq = AARQ.from_bytes(next(a for a in raw_acse if a[0] == Tag.AARQ))
        assert aarq.calling_authentication_value == placeholder(len(PASSWORD))
    else:
        assert raw_acse == []
        assert "AARQ/AARE" in summary


def test_drop_raw_auth_overrides_test_keys():
    original, _ = _record(_meter(), **_lls())
    text, _ = redact_recording(original, test_keys=True, drop_raw_auth=True)
    assert not [a for _, a in deframe(parse_recording(text)) if a[0] in (Tag.AARQ, Tag.AARE)]
    # The plaintext AARE line stays (replay reads the session parameters from it).
    plain = [a for d, a in parse_recording(text) if d == "RX-APDU" and a[0] == Tag.AARE]
    assert len(plain) == 1


def test_ciphered_session_titles_and_challenges():
    pytest.importorskip("cryptography")
    from pydlms.security.context import SecurityContext

    sim = _meter(encryption_key=EK, authentication_key=AK)
    sim.clients[1] = ClientProfile(Mechanism.HLS_GMAC, ciphered=True)
    ctx = SecurityContext(EK, AK, client_system_title=CLIENT_TITLE)
    original, result = _record(sim, client_sap=1, mechanism=Mechanism.HLS_GMAC, security=ctx)
    acse = [a for _, a in deframe(parse_recording(original)) if a[0] in (Tag.AARQ, Tag.AARE)]
    ctos = AARQ.from_bytes(acse[0]).calling_authentication_value
    stoc = AARE.from_bytes(acse[1]).responding_authentication_value
    assert ctos and stoc
    for test_keys in (False, True):
        text, log = redact_recording(original, test_keys=test_keys)
        out = _all_bytes(text)
        for secret in (CLIENT_TITLE, SERVER_TITLE, ctos, stoc, SERIAL, LDN[3:]):
            assert secret not in out, (test_keys, secret)
        _assert_parses(text)
        raw = [a for _, a in deframe(parse_recording(text))]
        ciphered = [a for a in raw if a[0] in (Tag.GLO_GET_REQUEST, Tag.GLO_GET_RESPONSE)]
        assert bool(ciphered) == test_keys
        if not test_keys:
            assert "ciphered" in str(log)
    # The plaintext lines still replay the session (keys given at replay time).
    text, _ = redact_recording(original)
    _replay_and_check(
        text,
        result,
        keys=["--key", EK.hex(), "--auth-key", AK.hex(), "--client", "1:5"],
        client_sap=1,
        mechanism=Mechanism.HLS_GMAC,
        security=SecurityContext(EK, AK, client_system_title=b"PYDREPL1"),
    )


def _replay_and_check(text, result, keys=(), **kw):
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        path = f"{tmp}/session.hex"
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        # The same construction `pydlms simulate --replay FILE` runs.
        replay = meter_from_args(_parser().parse_args(["--replay", path, *keys]))
    server = serve(replay)
    client = DlmsClient.tcp(*server.server_address, timeout=5, **kw)
    try:
        with client:
            again = _script(client)
    finally:
        server.shutdown()
        server.server_close()
    assert replay.misses == []
    assert again["serial"] == placeholder(len(SERIAL)).decode()
    assert again["ldn"] == b"PYD" + placeholder(13)
    assert again["title"] == b"PYD" + placeholder(5)
    assert again["energy"] == result["energy"]
    assert again["clock"] == result["clock"]


@pytest.mark.parametrize("hdlc", [False, True], ids=["wrapper", "hdlc"])
@pytest.mark.parametrize("raw_only", [False, True], ids=["apdu-lines", "raw-only"])
def test_redacted_plaintext_recording_replays(hdlc, raw_only):
    original, result = _record(_meter(), hdlc)
    if raw_only:
        original = "\n".join(
            line for line in original.splitlines() if line.split(" ")[0] in ("TX", "RX")
        )
    text, _ = redact_recording(original)
    _replay_and_check(text, result)


def test_idempotent():
    original, _ = _record(_meter(), True, **_lls())
    for kw in ({}, {"test_keys": True}):
        once, _ = redact_recording(original, **kw)
        twice, log = redact_recording(once, **kw)
        assert twice == once
        assert log.replaced == {} and log.dropped == {}


def test_block_transfer_value_is_redacted():
    long_serial = b"SN-" + bytes(range(0x41, 0x5B)) * 12  # 315 octets, several blocks
    sim = _meter(max_pdu=64)
    sim.objects[(ClassId.DATA, sim_obis("0.0.96.1.0.255"))][2] = DlmsData.visible_string(
        long_serial.decode()
    )

    def script(meter):
        return {"serial": meter.get("0.0.96.1.0.255").value}

    original, _ = _record(sim, True, script=script)
    assert b"\xc4\x02" in _all_bytes(original)  # really a GET-with-datablock
    text, _ = redact_recording(original)
    out = _all_bytes(text)
    assert long_serial[:12] not in out and long_serial[-12:] not in out
    _assert_parses(text)
    replay = meter_from_args(_parser().parse_args(["--replay", _tmp(text)]))
    server = serve(replay)
    try:
        with DlmsClient.tcp(*server.server_address, timeout=5) as client:
            assert client.get("0.0.96.1.0.255").value == placeholder(len(long_serial)).decode()
    finally:
        server.shutdown()
        server.server_close()


def sim_obis(text):
    from pydlms.obis import ObisCode

    return ObisCode.parse(text)


def _tmp(text: str) -> str:
    import os
    import tempfile

    handle, path = tempfile.mkstemp(suffix=".hex")
    with os.fdopen(handle, "w", encoding="utf-8") as out:
        out.write(text)
    return path


def test_short_name_session():
    original, result = _record(_meter(), logical_names=False, **_lls())
    text, _ = redact_recording(original)
    out = _all_bytes(text)
    for secret in (SERIAL, LDN[3:], PASSWORD, SERVER_TITLE_SET):
        assert secret not in out
    assert placeholder(len(SERIAL)) in out


def test_unclassified_short_name_read_is_dropped():
    # A ReadResponse whose request names an address no object list explains.
    records = [
        ("TX-APDU", bytes.fromhex("0501020100")),
        ("RX-APDU", bytes.fromhex("0c01000a0d") + SERIAL),
    ]
    out, log = redact_records(records)
    assert out == [("TX-APDU", records[0][1])]
    assert "Short-Name" in str(log)


def test_sweep_and_also_values():
    # The serial also shows up where no rule looks (a profile cell here).
    request = bytes.fromhex("c00181000100006001 00ff0200".replace(" ", ""))
    response = bytes.fromhex("c40181000a0d") + SERIAL
    other_req = bytes.fromhex("c00182000100006002 00ff0200".replace(" ", ""))
    other = bytes.fromhex("c40182000a0d") + SERIAL
    extra = bytes.fromhex("c40182000906") + b"Alice!"
    records = [
        ("TX-APDU", request),
        ("RX-APDU", response),
        ("TX-APDU", other_req),
        ("RX-APDU", other),
        ("TX-APDU", other_req),
        ("RX-APDU", extra),
    ]
    out, log = redact_records(records, also=[b"Alice!"])
    joined = b"".join(d for _, d in out)
    assert SERIAL not in joined and b"Alice!" not in joined
    assert "elsewhere" in str(log)


def test_physical_address_is_replaced():
    server = HdlcAddress.server(1, 4321)  # L+G style: serial % 10000 + 1000
    client = HdlcAddress.client(16)
    get = bytes.fromhex("e6e600c001c10001000001 0000ff0200".replace(" ", ""))
    frames = [
        ("TX", encode_frame(HdlcFrame(server, client, control_i(0, 0), get))),
        (
            "RX",
            encode_frame(
                HdlcFrame(
                    client, server, control_i(0, 1), bytes.fromhex("e6e700c401c1000600000001")
                )
            ),
        ),
    ]
    out, log = redact_records(frames)
    for direction, data in out:
        frame = decode_frame(data)
        address = frame.dest if direction == "TX" else frame.src
        assert address.lower == PHYSICAL_PLACEHOLDER and address.size == 4
    assert "physical address" in str(log)


def test_dedicated_key_in_plain_initiate_request():
    key = bytes(range(0x30, 0x40))
    initiate = b"\x01\x01\x10" + key + b"\x00\x00\x06\x5f\x1f\x04\x00\x00\x7e\x1f\x04\xb0"
    aarq = AARQ(user_information=initiate).to_bytes()
    out, log = redact_records([("TX", encode_wrapper(16, 1, aarq))], test_keys=True)
    assert key not in out[0][1]
    assert "dedicated key" in str(log)


# -- malformed input ----------------------------------------------------------------


def test_not_hex_is_refused():
    with pytest.raises(DecodeError):
        redact_recording("TX zz\n")


def test_mbus_recording_is_refused():
    with pytest.raises(DecodeError, match="M-Bus"):
        redact_records([("RX", bytes.fromhex("6803036808"))])


def test_damaged_and_truncated_frames_are_dropped():
    good = encode_frame(
        HdlcFrame(
            HdlcAddress.server(1),
            HdlcAddress.client(16),
            control_i(0, 0),
            bytes.fromhex("e6e600c001c10001000001 0000ff0200".replace(" ", "")),
        )
    )
    bad = bytearray(good)
    bad[-3] ^= 0xFF  # FCS
    records = [("TX", good), ("TX", bytes(bad)), ("TX", good[:7])]
    out, log = redact_records(records)
    assert out == [("TX", good)]
    assert "unframed" in str(log)


def test_truncated_wrapper_tail_is_dropped():
    pdu = encode_wrapper(16, 1, bytes.fromhex("c001c10001000001 0000ff0200".replace(" ", "")))
    out, log = redact_records([("TX", pdu + pdu[:5])])
    assert out == [("TX", pdu)]
    assert "unframed" in str(log)


@pytest.mark.parametrize(
    "line",
    [
        "6103a10100",  # AARE that does not parse
        "60",  # truncated AARQ
        "c40181000a0d50",  # truncated serial response
        "ff00",  # no APDU tag
        "0f0000000100",  # a push in a client session: content unknown
        "da0000000100",  # ACCESS: layout not walked by redact
    ],
)
def test_unparseable_sensitive_lines_are_dropped(line):
    records = [
        ("TX-APDU", bytes.fromhex("c00181000100006001 00ff0200".replace(" ", ""))),
        ("RX-APDU", bytes.fromhex(line)),
    ]
    out, log = redact_records(records)
    assert ("RX-APDU", bytes.fromhex(line)) not in out
    assert log.dropped


def test_incomplete_segmented_apdu_is_dropped():
    first = encode_frame(
        HdlcFrame(
            HdlcAddress.client(16),
            HdlcAddress.server(1),
            control_i(0, 1),
            bytes.fromhex("e6e700c40181000a0d") + SERIAL[:4],
            segmented=True,
        )
    )
    out, log = redact_records([("RX", first)])
    assert out == []
    assert log.dropped


def test_empty_recording():
    text, log = redact_recording("# nothing\n")
    assert parse_recording(text) == []
    assert str(log) == "nothing to redact"


# -- CLI ----------------------------------------------------------------------------------


def test_cli_writes_output_and_logs_counts(tmp_path, capsys):
    original, _ = _record(_meter(), **_lls())
    source = tmp_path / "session.hex"
    source.write_text(original)
    target = tmp_path / "redacted.hex"
    assert cli.main(["redact", str(source), "-o", str(target), "--also", "S3cr"]) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "serial" in captured.err
    assert SERIAL.decode() not in captured.err and "S3cr" not in captured.err
    text = target.read_text()
    assert SERIAL not in _all_bytes(text) and b"S3cr" not in _all_bytes(text)
    assert session_apdus(parse_recording(text))


def test_cli_stdout(tmp_path, capsys):
    source = tmp_path / "s.hex"
    source.write_text("TX-APDU c00181000100006001 00ff0200\nRX-APDU c40181000a0d" + SERIAL.hex())
    assert cli.main(["redact", str(source)]) == 0
    out = capsys.readouterr().out
    assert SERIAL.hex() not in out and placeholder(len(SERIAL)).hex() in out
