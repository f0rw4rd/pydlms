"""APDU <-> XML (pydlms.apduxml): lossless round trips, deciphering, redaction."""

from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

from pydlms.apdu import sn, xdlms
from pydlms.apdu.acse import AARE, AARQ, RLRE, RLRQ, ApplicationContext
from pydlms.apdu.gbt import GbtBlock, encode_gbt
from pydlms.apduxml import (
    XmlWriter,
    apdu_to_xml,
    session_to_xml,
    xml_to_apdu,
    xml_to_session,
)
from pydlms.client import DlmsClient
from pydlms.cosem.data import CompactArray, DlmsData, TypeDescription
from pydlms.cosem.enums import ActionResult, DataAccessResult, DataType
from pydlms.cosem.interface_classes import ClassId
from pydlms.debug import FrameRecorder
from pydlms.exceptions import DecodeError
from pydlms.obis import ObisCode
from pydlms.recording import deframe, session_apdus
from pydlms.security.hls import Mechanism
from pydlms.simulator import ClientProfile, example_meter, serve
from tests.meter_fixtures import all_names, load

EK = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
AK = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")
ENERGY = ObisCode.parse("1.0.1.8.0.255")
CLOCK = ObisCode.parse("0.0.1.0.0.255")


def _root(text: str) -> ET.Element:
    return ET.fromstring(text)  # noqa: S314 - our own output


def _session(sim, **kw):
    server = serve(sim)
    recorder = FrameRecorder()
    meter = DlmsClient.tcp(*server.server_address, timeout=5, **kw)
    meter.link.transport.recorder = recorder
    try:
        with meter:
            meter.get_register("1.0.1.8.0.255")
            meter.read_profile("1.0.99.1.0.255", xdlms.entry_descriptor(1, 40))
            meter.set("0.0.96.1.0.255", ClassId.DATA, 2, DlmsData.visible_string("X\x00Y"))
            meter.action("0.0.96.3.10.255", ClassId.DISCONNECT_CONTROL, 1, DlmsData.int8(0))
            meter.get_many([("1.0.1.8.0.255", 3, 2), ("1.0.2.8.0.255", 3, 2)])
            meter.action("0.0.42.0.0.255", ClassId.DATA, 1, DlmsData.int8(0))
            meter.get_association_view()
    finally:
        server.shutdown()
        server.server_close()
    return recorder.frames


def _service_meter(**kw):
    sim = example_meter(max_pdu=256, **kw)
    sim.add_method(  # return data larger than one APDU: action-response-with-pblock
        ClassId.DATA, "0.0.42.0.0.255", 1, lambda s, p: DlmsData.octet_string(bytes(600))
    )
    return sim


_SESSION = session_apdus(_session(_service_meter()))


@pytest.mark.parametrize(("direction", "apdu"), _SESSION, ids=lambda v: str(v)[:24])
def test_every_service_apdu_round_trips_exactly(direction, apdu):
    text = apdu_to_xml(apdu)
    assert _root(text).tag not in ("Raw", "Ciphered")
    assert xml_to_apdu(text) == apdu


def _att(obis=ENERGY, attr=2):
    return xdlms.AttributeDescriptor(ClassId.REGISTER, obis, attr)


def _method(obis=CLOCK, method=1):
    return xdlms.MethodDescriptor(ClassId.CLOCK, obis, method)


_ODD_DATA = DlmsData.structure(
    [
        DlmsData.null(),
        DlmsData.boolean(False),
        DlmsData(DataType.BIT_STRING, [True, False, True, True, False]),
        DlmsData(DataType.FLOAT32, 1.5),
        DlmsData(DataType.FLOAT64, -0.1),
        DlmsData(DataType.LONG64, -(2**63)),
        DlmsData(DataType.LONG64_UNSIGNED, 2**64 - 1),
        DlmsData(DataType.UTF8_STRING, "Zähler €"),
        DlmsData.visible_string("line\nbreak\x00"),
        DlmsData.octet_string(b"--a--"),  # '--' must not break the XML comment
        DlmsData(DataType.DATE_TIME, bytes.fromhex("07E8010101000000FF800000")),
        DlmsData(DataType.DATE, bytes.fromhex("07E80101FF")),
        DlmsData(DataType.TIME, bytes.fromhex("0C000000")),
        DlmsData(DataType.BCD, 0x12),
        DlmsData.array([DlmsData.uint16(1), DlmsData.uint16(2)]),
        DlmsData(
            DataType.COMPACT_ARRAY,
            CompactArray(
                TypeDescription(DataType.LONG_UNSIGNED), [DlmsData.uint16(5), DlmsData.uint16(6)]
            ),
        ),
    ]
)

_HAND_BUILT = [
    xdlms.GetRequestNormal(0xC1, _att(), xdlms.SelectiveAccess(2, DlmsData.uint32(1))),
    xdlms.GetRequestNext(0xC1, 7),
    xdlms.GetRequestWithList(0xC2, [(_att(), None), (_att(attr=3), None)]),
    xdlms.GetResponseNormal(0xC1, xdlms.GetDataResult(data=_ODD_DATA)),
    xdlms.GetResponseNormal(0xC1, xdlms.GetDataResult(error=DataAccessResult.READ_WRITE_DENIED)),
    xdlms.GetResponseWithDatablock(0xC1, False, 2, raw_data=b"\x01\x02"),
    xdlms.GetResponseWithDatablock(0xC1, True, 3, error=DataAccessResult.LONG_GET_ABORTED),
    xdlms.GetResponseWithList(
        0xC1,
        [
            xdlms.GetDataResult(data=DlmsData.uint8(1)),
            xdlms.GetDataResult(error=DataAccessResult(4)),
        ],
    ),
    xdlms.SetRequestNormal(0xC1, _att(), DlmsData.uint32(9)),
    xdlms.SetRequestWithFirstDatablock(0xC1, _att(), False, 1, b"\x06\x00"),
    xdlms.SetRequestWithDatablock(0xC1, True, 2, b"\x00\x09"),
    xdlms.SetRequestWithList(
        0xC1, [(_att(), None, DlmsData.uint8(1)), (_att(attr=3), None, DlmsData.null())]
    ),
    xdlms.SetResponseNormal(0xC1, DataAccessResult.SUCCESS),
    xdlms.SetResponseDatablock(0xC1, 1),
    xdlms.SetResponseLastDatablock(0xC1, DataAccessResult.SUCCESS, 2),
    xdlms.SetResponseWithList(0xC1, [DataAccessResult.SUCCESS, DataAccessResult.TYPE_UNMATCHED]),
    xdlms.ActionRequestNormal(0xC1, _method(), DlmsData.int16(-30)),
    xdlms.ActionRequestNormal(0xC1, _method()),
    xdlms.ActionRequestNextPblock(0xC1, 1),
    xdlms.ActionRequestWithList(0xC1, [(_method(), DlmsData.int8(0)), (_method(method=2), None)]),
    xdlms.ActionRequestWithFirstPblock(0xC1, _method(), False, 1, b"\x0f"),
    xdlms.ActionRequestWithPblock(0xC1, True, 2, b"\x00"),
    xdlms.ActionResponseNormal(0xC1, ActionResult.SUCCESS),
    xdlms.ActionResponseNormal(
        0xC1, ActionResult.SUCCESS, xdlms.GetDataResult(data=DlmsData.uint8(1))
    ),
    xdlms.ActionResponseWithPblock(0xC1, False, 1, b"\x09\x02"),
    xdlms.ActionResponseWithList(
        0xC1, [(ActionResult.SUCCESS, None), (ActionResult.TYPE_UNMATCHED, None)]
    ),
    xdlms.ActionResponseNextPblock(0xC1, 1),
    xdlms.DataNotification(0x10, DlmsData.structure([DlmsData.uint32(1)])),
    xdlms.DataNotification(
        1, DlmsData.uint8(1), bytes.fromhex("07E8010101000000FF800000"), date_time_tagged=True
    ),
    xdlms.EventNotificationRequest(_att(), DlmsData.uint16(42), bytes(12)),
    xdlms.ExceptionResponse(1, 6, 1234),
    xdlms.ExceptionResponse(2, 2),
    xdlms.ConfirmedServiceError(1, 6, 1),
    xdlms.InitiateRequest(xdlms.Conformance.default_ln(), 0xFFFF),
    xdlms.InitiateResponse(xdlms.Conformance.default_ln(), 1024),
    sn.ReadRequest([sn.VariableName(0xFA08), sn.BlockNumberAccess(2)]),
    sn.ReadRequest([sn.ParameterizedAccess(0x3008, 1, DlmsData.uint8(1))]),
    sn.ReadResponse(
        [
            sn.ReadResult(data=DlmsData.uint8(1)),
            sn.ReadResult(error=DataAccessResult.OBJECT_UNDEFINED),
            sn.ReadResult(block_last=True, block_number=1, raw_data=b"\x01"),
        ]
    ),
    sn.WriteRequest([sn.VariableName(0x3010)], [DlmsData.uint32(5)]),
    sn.UnconfirmedWriteRequest([sn.VariableName(0x3010)], [DlmsData.uint32(5)]),
    sn.WriteResponse([DataAccessResult.SUCCESS, DataAccessResult.HARDWARE_FAULT]),
    sn.InformationReportRequest(bytes(12), [0x3008, 0x3010], [DlmsData.uint8(1), DlmsData.null()]),
    AARQ(
        ApplicationContext.LN, xdlms.InitiateRequest(xdlms.Conformance.default_ln(), 512).to_bytes()
    ),
    AARE(ApplicationContext.LN, 1, 1, 13),
    RLRQ(0),
    RLRE(0, b""),
]


@pytest.mark.parametrize("obj", _HAND_BUILT, ids=lambda o: type(o).__name__)
def test_hand_built_apdus_round_trip_exactly(obj):
    apdu = obj.to_bytes()
    text = apdu_to_xml(apdu)
    assert _root(text).tag == type(obj).__name__
    assert xml_to_apdu(text) == apdu


#: APDUs added after the frozen Gurux corpus (``tests/gurux_xml_corpus.py``
#: draws on ``_HAND_BUILT``, so these stay out of it).
_LATER = [
    xdlms.SetResponseLastDatablockWithList(0xC1, [DataAccessResult.TYPE_UNMATCHED], 7),
    sn.WriteResponse([sn.WriteBlockNumber(3), DataAccessResult.HARDWARE_FAULT]),
    sn.ReadRequest([sn.ReadDataBlockAccess(True, 1, b"\xaa\xbb")]),
    sn.WriteRequest([sn.WriteDataBlockAccess(False, 2)], [DlmsData.octet_string(b"\x01\x02")]),
    sn.ReadResponse([sn.ReadResult(block_number=2)]),
    xdlms.SetRequestWithListAndFirstDatablock(
        0xC1,
        [(_att(), None), (_att(attr=3), xdlms.SelectiveAccess(1, DlmsData.null()))],
        False,
        1,
        b"\x02\x11",
    ),
    xdlms.ActionRequestWithListAndFirstPblock(
        0xC1,
        [xdlms.MethodDescriptor(70, ObisCode.parse("0.0.96.3.10.255"), 1)],
        True,
        1,
        b"\x01\x0f\x00",
    ),
]


@pytest.mark.parametrize("obj", _LATER, ids=lambda o: type(o).__name__)
@pytest.mark.parametrize("dialect", ["pydlms", "gurux"])
def test_later_apdus_round_trip_exactly(obj, dialect):
    apdu = obj.to_bytes()
    text = apdu_to_xml(apdu, dialect=dialect)
    if dialect == "pydlms":
        assert _root(text).tag == type(obj).__name__
    assert xml_to_apdu(text) == apdu


def test_gbt_block_round_trips():
    apdu = encode_gbt(GbtBlock(True, False, 1, 2, 1, b"\xc4\x01\xc1\x00\x09\x00"))
    text = apdu_to_xml(apdu)
    assert _root(text).tag == "GbtBlock"
    assert xml_to_apdu(text) == apdu


def test_data_values_are_readable():
    text = apdu_to_xml(
        xdlms.GetResponseNormal(0xC1, xdlms.GetDataResult(data=_ODD_DATA)).to_bytes()
    )
    assert '<utf8-string value="Zähler €" />' in text
    assert '<bit-string value="10110" />' in text
    assert '<visible-string hex="6c696e650a627265616b00" />' in text  # control chars
    assert "<!-- 2024-01-01" in text  # date-time hint
    assert "- -a- -" in text  # '--' escaped inside the comment only
    assert '<octet-string value="2d2d612d2d">' in text


def test_obis_names_and_conformance_bits_as_comments():
    text = apdu_to_xml(xdlms.GetRequestNormal(0xC1, _att()).to_bytes())
    assert '<instance-id value="1.0.1.8.0.255">' in text
    assert "Active energy import" in text
    initiate = xdlms.InitiateResponse(xdlms.Conformance.GET | xdlms.Conformance.SET, 512)
    assert "<!-- SET, GET -->" in apdu_to_xml(initiate.to_bytes()) or "<!-- GET, SET -->" in (
        apdu_to_xml(initiate.to_bytes())
    )


def test_editing_a_field_changes_the_encoding():
    text = apdu_to_xml(xdlms.GetRequestNormal(0xC1, _att()).to_bytes())
    edited = text.replace('<attribute-id value="2" />', '<attribute-id value="3" />')
    assert xml_to_apdu(edited) == xdlms.GetRequestNormal(0xC1, _att(attr=3)).to_bytes()
    edited = text.replace("1.0.1.8.0.255", "1.0.2.8.0.255")
    assert xml_to_apdu(edited) == (
        xdlms.GetRequestNormal(0xC1, _att(ObisCode.parse("1.0.2.8.0.255"))).to_bytes()
    )


def test_unknown_and_lossy_apdus_fall_back_to_raw():
    unknown = b"\xff\x01\x02"
    root = _root(apdu_to_xml(unknown))
    assert root.tag == "Raw" and xml_to_apdu(apdu_to_xml(unknown)) == unknown
    # last-block is a BOOLEAN sent as 02: the decoded form re-encodes it as
    # 01, so the bytes are kept instead.
    lossy = bytes.fromhex("c402c10200000001000100")
    root = _root(apdu_to_xml(lossy))
    assert root.tag == "Raw"
    assert root.find("decoded/GetResponseWithDatablock") is not None
    assert xml_to_apdu(apdu_to_xml(lossy)) == lossy


@pytest.mark.parametrize("dialect", ["pydlms", "gurux"])
@pytest.mark.parametrize(
    "raw",
    [
        "c401c10163",  # GET data-access-result 99
        "c501c163",  # SET data-access-result 99
        "c505c1020063",  # SET with-list
        "c701c16300",  # ACTION action-result 99
        "c703c1020000" + "6300",  # ACTION with-list
        "0c010163",  # SN ReadResponse data-access-error 99
        "0d02000163",  # SN WriteResponse
    ],
)
def test_undefined_result_codes_round_trip_without_raw(raw, dialect):
    # Undefined codes decode to the bare integer, so the XML holds them.
    apdu = bytes.fromhex(raw)
    text = apdu_to_xml(apdu, dialect=dialect)
    assert _root(text).tag != "Raw"
    assert xml_to_apdu(text) == apdu


def test_secrets_are_redacted_unless_asked_for():
    aarq = AARQ(
        ApplicationContext.LN,
        xdlms.InitiateRequest(
            xdlms.Conformance.default_ln(), 512, dedicated_key=bytes(range(16))
        ).to_bytes(),
        mechanism=1,
        calling_authentication_value=b"12345678",
    ).to_bytes()
    text = apdu_to_xml(aarq)
    assert (
        b"12345678".hex() not in text
        and bytes(range(16)).hex() not in text.split("user-information")[2]
    )
    assert text.count("redacted=") == 2  # LLS password and the dedicated key
    with pytest.raises(DecodeError, match="redacted"):
        xml_to_apdu(text)
    shown = apdu_to_xml(aarq, secrets=True)
    assert "redacted" not in shown and xml_to_apdu(shown) == aarq


def test_hls_pass_3_and_4_are_redacted():
    hls = xdlms.MethodDescriptor(15, ObisCode.parse("0.0.40.0.0.255"), 1)
    request = xdlms.ActionRequestNormal(0xC1, hls, DlmsData.octet_string(b"F(StoC)")).to_bytes()
    reply = xdlms.ActionResponseNormal(
        0xC1, ActionResult.SUCCESS, xdlms.GetDataResult(data=DlmsData.octet_string(b"F(CtoS)"))
    ).to_bytes()
    text = session_to_xml([("TX", request), ("RX", reply)])
    assert b"F(StoC)".hex() not in text and b"F(CtoS)".hex() not in text
    assert text.count("redacted=") == 2


def test_session_document_round_trips():
    text = session_to_xml(_SESSION)
    root = _root(text)
    assert root.tag == "pydlms-session" and root.get("version") == "1"
    assert [a.get("direction") for a in root] == [d for d, _ in _SESSION]
    assert xml_to_session(text) == _SESSION
    # A bare APDU element is a one-record session.
    assert xml_to_session(apdu_to_xml(_SESSION[1][1])) == [(None, _SESSION[1][1])]


def test_ciphered_session_deciphers_both_directions():
    pytest.importorskip("cryptography")
    from pydlms.security.context import SecurityContext

    sim = _service_meter(encryption_key=EK, authentication_key=AK)
    sim.clients[1] = ClientProfile(Mechanism.HLS_GMAC, ciphered=True)
    frames = _session(
        sim,
        client_sap=1,
        mechanism=Mechanism.HLS_GMAC,
        security=SecurityContext(EK, AK, client_system_title=b"PYDCLNT1"),
    )
    wire = deframe([f for f in frames if f[0] in ("TX", "RX")])
    text = session_to_xml(wire, EK, AK)
    root = _root(text)
    ciphered = root.findall("apdu/Ciphered")
    assert len(ciphered) == len(wire) - 4  # all but AARQ, AARE, RLRQ, RLRE
    assert all(c.find("plaintext") is not None for c in ciphered), text
    assert "not deciphered" not in text
    # glo-initiate inside the AARQ/AARE user-information too.
    assert root.find("apdu/AARQ/user-information/decoded/Ciphered/plaintext/InitiateRequest")
    with pytest.raises(DecodeError, match="redacted"):  # CtoS in the AARQ
        xml_to_session(text)
    assert xml_to_session(session_to_xml(wire, EK, AK, secrets=True)) == wire
    without_keys = session_to_xml(wire)
    assert "no key given" in without_keys and "<plaintext>" not in without_keys
    # f(StoC)/f(CtoS) of HLS pass 3/4 stay hidden even after deciphering.
    assert text.count("redacted=") >= 3  # CtoS, StoC, f(StoC), f(CtoS)


def test_malformed_xml_is_a_decode_error():
    with pytest.raises(DecodeError, match="well-formed"):
        xml_to_apdu("<GetRequestNormal>")
    with pytest.raises(DecodeError, match="not an APDU element"):
        xml_to_apdu("<Nonsense />")
    with pytest.raises(DecodeError, match="lacks"):
        xml_to_apdu("<GetRequestNext><invoke-id value='0xC1' /></GetRequestNext>")
    with pytest.raises(DecodeError, match="not a COSEM data type"):
        xml_to_apdu(
            "<SetRequestNormal><invoke-id value='1'/><attribute><class-id value='1'/>"
            "<instance-id value='0.0.1.0.0.255'/><attribute-id value='2'/></attribute>"
            "<value><bogus value='1'/></value></SetRequestNormal>"
        )
    with pytest.raises(DecodeError):
        xml_to_session("<pydlms-session><apdu /></pydlms-session>")


@pytest.mark.parametrize("name", all_names())
def test_real_meter_captures_round_trip(name):
    """Every APDU of the vendored captures survives XML byte for byte, and
    ciphered ones show their plaintext with the published keys."""
    pytest.importorskip("cryptography")
    fixture = load(name)
    framing = {"hdlc": "hdlc", "mbus": "mbus"}.get(fixture.transport, "apdu")
    apdus = deframe([(None, fixture.raw)], framing, verify_checksums=False)  # zmf100 FCS
    assert apdus
    for _, apdu in apdus:
        writer = XmlWriter(fixture.encryption_key, fixture.authentication_key)
        element = writer.apdu(apdu)
        text = ET.tostring(element, encoding="unicode")
        assert xml_to_apdu(text) == apdu
        if element.tag == "Ciphered" and fixture.encryption_key:
            assert element.find("plaintext") is not None, text


def test_documented_example_is_the_exact_output():
    expected = (
        "<GetRequestNormal>\n"
        '  <invoke-id value="0xC1" />\n'
        "  <attribute>\n"
        '    <class-id value="3" />\n'
        '    <instance-id value="1.0.1.8.0.255">\n'
        "      <!-- Active energy import (+A) total -->\n"
        "    </instance-id>\n"
        '    <attribute-id value="2" />\n'
        "  </attribute>\n"
        "</GetRequestNormal>\n"
    )
    apdu = bytes.fromhex("c001c100030100010800ff0200")
    assert apdu_to_xml(apdu) == expected
    assert xml_to_apdu(expected) == apdu


@pytest.mark.parametrize("dialect", ["pydlms", "gurux"])
def test_dont_care_data_round_trips(dialect):
    # GET-Response-Normal carrying structure { dont-care, unsigned 5 }.
    apdu = bytes.fromhex("c401c1000202ff1105")
    text = apdu_to_xml(apdu, dialect=dialect)
    if dialect == "pydlms":
        assert "<dont-care" in text
    else:  # Gurux has no element for dont-care
        assert _root(text).tag == "Raw"
    assert xml_to_apdu(text) == apdu
