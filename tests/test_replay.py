"""Session recordings (plaintext APDU lines) and the replay meter."""

from __future__ import annotations

import pytest

from pydlms.apdu import xdlms
from pydlms.apdu.acse import AARE
from pydlms.apdu.tags import Tag
from pydlms.client import DlmsClient
from pydlms.cosem.data import DlmsData
from pydlms.cosem.enums import DataAccessResult
from pydlms.cosem.interface_classes import ClassId
from pydlms.debug import FrameRecorder
from pydlms.exceptions import DecodeError, ServiceError
from pydlms.obis import ObisCode
from pydlms.recording import deframe, parse_recording, session_apdus
from pydlms.replay import ReplayMeter
from pydlms.security.hls import Mechanism
from pydlms.simulator import ClientProfile, example_meter, serve
from pydlms.wrapper import encode_wrapper

EK = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
AK = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")
CLIENT_TITLE = b"PYDCLNT1"
ENERGY = "1.0.1.8.0.255"


def _session(sim, hdlc=False, **kw):
    """Run a few reads against ``sim`` with a recorder; return (recorder, results)."""
    server = serve(sim, hdlc=hdlc)
    recorder = FrameRecorder()
    meter = DlmsClient.tcp(*server.server_address, hdlc=hdlc, timeout=5, **kw)
    meter.link.transport.recorder = recorder
    try:
        with meter:
            results = (
                meter.get_register(ENERGY),
                meter.read_profile("1.0.99.1.0.255"),  # block transfer
                meter.get_clock(),
            )
    finally:
        server.shutdown()
        server.server_close()
    return recorder, results


def _replay(meter, hdlc=False, **kw):
    server = serve(meter, hdlc=hdlc)
    client = DlmsClient.tcp(*server.server_address, hdlc=hdlc, timeout=5, **kw)
    return server, client


def _security():
    pytest.importorskip("cryptography")
    from pydlms.security.context import SecurityContext

    return SecurityContext(EK, AK, client_system_title=CLIENT_TITLE)


@pytest.mark.parametrize("hdlc", [False, True], ids=["wrapper", "hdlc"])
@pytest.mark.parametrize("raw_only", [False, True], ids=["apdu-lines", "raw-only"])
def test_plaintext_session_replays(hdlc, raw_only):
    recorder, results = _session(example_meter(max_pdu=256), hdlc)
    records = parse_recording(recorder.dump())
    if raw_only:  # a recording made before the APDU lines existed
        records = [r for r in records if r[0] in ("TX", "RX")]
    replay = ReplayMeter(records)
    server, client = _replay(replay, hdlc)
    try:
        with client:
            assert client.get_register(ENERGY) == results[0]
            assert client.read_profile("1.0.99.1.0.255") == results[1]
            assert client.get_clock() == results[2]
    finally:
        server.shutdown()
        server.server_close()
    assert replay.misses == []


def test_recorded_aare_sets_session_parameters():
    sim = example_meter(max_pdu=300, system_title=b"KFM\x00\x00\x00\x12\x34")
    recorder, _ = _session(sim)
    replay = ReplayMeter(parse_recording(recorder.dump()))
    assert replay.max_pdu == 300
    assert replay.recorded_aare is not None
    assert (
        replay.conformance
        == xdlms.InitiateResponse.from_bytes(replay.recorded_aare.user_information).conformance
    )
    # The title is only sent for ciphered/HLS associations; public: default kept.
    assert ReplayMeter(parse_recording(recorder.dump()), max_pdu=512).max_pdu == 512


def _gmac_meter():
    sim = example_meter(encryption_key=EK, authentication_key=AK, max_pdu=256)
    sim.clients[1] = ClientProfile(Mechanism.HLS_GMAC, ciphered=True)
    return sim


def test_ciphered_hls_gmac_session_replays_from_plaintext_lines():
    sim = _gmac_meter()
    recorder, results = _session(
        sim, client_sap=1, mechanism=Mechanism.HLS_GMAC, security=_security()
    )
    lines = recorder.frames
    raw = [data for d, data in lines if d in ("TX", "RX")]
    plain = [(d, data) for d, data in lines if d in ("TX-APDU", "RX-APDU")]
    # On the wire every service APDU is ciphered; the plaintext lines are not.
    assert any(data[8:9] == bytes([Tag.GLO_GET_REQUEST]) for data in raw)
    assert all(data[0] in (Tag.GET_REQUEST, Tag.GET_RESPONSE, Tag.AARE) for _, data in plain)
    # No HLS pass 3/4 and no StoC in the plaintext lines.
    hls_reply = xdlms.MethodDescriptor(15, ObisCode.parse("0.0.40.0.0.255"), 1).to_bytes()
    assert not any(hls_reply in data for _, data in plain)
    aare = AARE.from_bytes(next(data for d, data in plain if data[0] == Tag.AARE))
    assert aare.responding_authentication_value is None
    assert aare.responding_ap_title == sim.system_title

    replay = ReplayMeter(parse_recording(recorder.dump()), encryption_key=EK, authentication_key=AK)
    replay.clients[1] = ClientProfile(Mechanism.HLS_GMAC, ciphered=True)
    assert replay.system_title == sim.system_title
    server, client = _replay(
        replay, client_sap=1, mechanism=Mechanism.HLS_GMAC, security=_security()
    )
    try:
        with client:
            assert client.get_register(ENERGY) == results[0]
            assert client.read_profile("1.0.99.1.0.255") == results[1]
            assert client.get_clock() == results[2]
    finally:
        server.shutdown()
        server.server_close()
    assert replay.misses == []


def test_ciphered_raw_only_recording_is_refused():
    recorder, _ = _session(
        _gmac_meter(), client_sap=1, mechanism=Mechanism.HLS_GMAC, security=_security()
    )
    raw = [r for r in recorder.frames if r[0] in ("TX", "RX")]
    with pytest.raises(DecodeError, match="ciphered .* without its plaintext"):
        ReplayMeter(raw)


def _get(invoke: int, obis: str = ENERGY) -> bytes:
    attribute = xdlms.AttributeDescriptor(ClassId.REGISTER, ObisCode.parse(obis), 2)
    return xdlms.GetRequestNormal(invoke, attribute).to_bytes()


def _value(invoke: int, value: int) -> bytes:
    return xdlms.GetResponseNormal(
        invoke, xdlms.GetDataResult(data=DlmsData.uint32(value))
    ).to_bytes()


def _associated(meter):
    from pydlms.simulator import _Session

    return _Session(associated=True)


def test_repeated_requests_replay_in_order_then_repeat_the_last():
    records = [
        ("TX-APDU", _get(0xC1)),
        ("RX-APDU", _value(0xC1, 1)),
        ("TX-APDU", _get(0xC2)),
        ("RX-APDU", _value(0xC2, 2)),
    ]
    meter = ReplayMeter(records)
    session = _associated(meter)
    answers = [xdlms.decode_apdu(meter.handle(_get(0xC5), session)) for _ in range(3)]
    assert [a.result.data.value for a in answers] == [1, 2, 2]
    assert {a.invoke_id for a in answers} == {0xC5}  # patched to the request's


def test_unrecorded_requests_are_misses():
    meter = ReplayMeter([("TX-APDU", _get(0xC1)), ("RX-APDU", _value(0xC1, 1))])
    session = _associated(meter)
    answer = xdlms.decode_apdu(meter.handle(_get(0xC3, "1.0.2.8.0.255"), session))
    assert answer.result.error == DataAccessResult.OBJECT_UNDEFINED
    action = xdlms.ActionRequestNormal(
        0xC4, xdlms.MethodDescriptor(70, ObisCode.parse("0.0.96.3.10.255"), 1)
    ).to_bytes()
    answer = xdlms.decode_apdu(meter.handle(action, session))
    assert isinstance(answer, xdlms.ExceptionResponse)
    assert meter.misses == [_get(0xC3, "1.0.2.8.0.255"), action]


def test_miss_surfaces_as_service_error_end_to_end():
    recorder, _ = _session(example_meter())
    replay = ReplayMeter(parse_recording(recorder.dump()))
    server, client = _replay(replay)
    try:
        with client, pytest.raises(ServiceError, match="OBJECT_UNDEFINED"):
            client.get("0.0.96.1.0.255", ClassId.DATA, 2)
    finally:
        server.shutdown()
        server.server_close()


def test_recording_without_pairs_is_refused():
    with pytest.raises(DecodeError, match="no request/response pairs"):
        ReplayMeter([("RX-APDU", _value(0xC1, 1))])


# --- recording format ---------------------------------------------------------------


def test_parse_recording_directions_comments_and_errors():
    text = "# header\n\nTX 7e a0\nrx-apdu c4:01\nc001\n"
    assert parse_recording(text) == [
        ("TX", b"\x7e\xa0"),
        ("RX-APDU", b"\xc4\x01"),
        (None, b"\xc0\x01"),
    ]
    with pytest.raises(DecodeError, match="line 2"):
        parse_recording("TX 00\nRX zz")


def test_deframe_rejoins_wrapper_pdus_split_across_reads():
    pdu = encode_wrapper(16, 1, _get(0xC1))
    reply = encode_wrapper(1, 16, _value(0xC1, 7))
    records = [("TX", pdu), ("RX", reply[:5]), ("RX", reply[5:12]), ("RX", reply[12:])]
    assert deframe(records) == [("TX", _get(0xC1)), ("RX", _value(0xC1, 7))]


def test_session_apdus_prefers_plaintext_lines():
    pdu = encode_wrapper(16, 1, b"\xdb\x00")  # ciphered on the wire
    records = [("TX", pdu), ("TX-APDU", _get(0xC1)), ("RX-APDU", _value(0xC1, 7))]
    assert session_apdus(records) == [("TX", _get(0xC1)), ("RX", _value(0xC1, 7))]
    assert session_apdus(records[:1]) == [("TX", b"\xdb\x00")]
