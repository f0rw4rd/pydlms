"""xDLMS ACCESS service codec (``D9`` / ``DA``, conformance bit 17).

Known-good vector: the ACCESS request of IEC 62056-5-3:2023 Table F.10, as
transcribed in cB-Sigma dlms (Apache-2.0) ``cosem/iec6205653_vectors_test.go``
at 26360a1 (``vecAccessRequest``); the standard's table itself was not read
here. The annex I.2 general-ciphering example wraps the same request; its
decryption (and that of the response) is in
``tests/crypto/test_access_annex_i2.py``.

The same exchange, request *and* response, is printed in plain as Table 21
of DLMS UA 1000-2 Ed. 9 Excerpt 14.2 (public, 2019-05-08; also Ed. 8.3
Excerpt 14.2). Its response has two
zero octets (empty date-time, absent request echo) after the long invoke
id, which is the layout pydlms decodes.
"""

from __future__ import annotations

import pytest

from pydlms.apdu import xdlms
from pydlms.apdu.xdlms import (
    AccessKind,
    AccessRequest,
    AccessRequestAction,
    AccessRequestGet,
    AccessRequestGetWithSelection,
    AccessRequestSet,
    AccessRequestSetWithSelection,
    AccessResponse,
    AccessResponseAction,
    AccessResponseGet,
    AccessResponseSet,
    AttributeDescriptor,
    MethodDescriptor,
    ProcessingOption,
    SelectiveAccess,
    decode_apdu,
    entry_descriptor,
    long_invoke_id,
)
from pydlms.cosem.data import DlmsData
from pydlms.cosem.enums import ActionResult, DataAccessResult
from pydlms.exceptions import DecodeError
from pydlms.obis import ObisCode

# IEC 62056-5-3:2023 Table F.10 (via cB-Sigma vecAccessRequest): get
# 1/0.0.96.1.0.255/2, get 8/0.0.1.0.0.255/2, set 20/0.0.13.0.0.255/7 and /8
# (passive season profile and week profile table), confirmed, normal priority.
F10_REQUEST = bytes.fromhex(
    "D9" "40000000" "00" "04"
    "01" "0001" "0000600100FF" "02"
    "01" "0008" "0000010000FF" "02"
    "02" "0014" "00000D0000FF" "07"
    "02" "0014" "00000D0000FF" "08"
    "04" "00" "00"
    "0104" "0203090100090CFFFFFFFFFFFFFF00000000000901FF"
    "0203090101090CFFFFFFFFFFFFFF00000000000901FF"
    "0203090102090CFFFFFFFFFFFFFF00000000000901FF"
    "0203090103090CFFFFFFFFFFFFFF00000000000901FF"
    "0104" "020809010011FF11FF11FF11FF11FF11FF11FF"
    "0208090101" "1102" "110111011101110111011101"
    "0208090102" "11FF11FF11FF11FF11FF11FF11FF"
    "02080901031101110211021102110211021102"
)  # fmt: skip

# The annex I.2 response, deciphered (tests/crypto/test_access_annex_i2.py),
# less the one zero octet too many it carries there: the serial number and
# clock read, both sets succeeded.
I2_RESPONSE = bytes.fromhex(
    "DA" "40000000" "00" "00" "04"
    "09083030303030303031" "090C07DC030C07161E0000FF8880" "00" "00"
    "04" "0100" "0100" "0200" "0200"
)  # fmt: skip

SERIAL = ObisCode.parse("0.0.96.1.0.255")
CLOCK = ObisCode.parse("0.0.1.0.0.255")
CALENDAR = ObisCode.parse("0.0.13.0.0.255")


def test_table_f10_request_decodes_and_re_encodes_byte_identical():
    req = decode_apdu(F10_REQUEST)
    assert isinstance(req, AccessRequest)
    assert req.long_invoke_id == 0x40000000
    assert (req.invoke_id, req.confirmed, req.high_priority) == (0, True, False)
    assert req.processing_option == ProcessingOption.CONTINUE_ON_ERROR
    assert req.self_descriptive is False
    assert req.date_time is None and req.timestamp is None
    assert req.specifications == [
        AccessRequestGet(AttributeDescriptor(1, SERIAL, 2)),
        AccessRequestGet(AttributeDescriptor(8, CLOCK, 2)),
        AccessRequestSet(AttributeDescriptor(20, CALENDAR, 7)),
        AccessRequestSet(AttributeDescriptor(20, CALENDAR, 8)),
    ]
    assert req.data[:2] == [DlmsData.null(), DlmsData.null()]
    seasons = req.data[2]
    assert len(seasons.value) == 4 and seasons.value[0].value[0] == DlmsData.octet_string(b"\x00")
    assert len(req.data[3].value) == 4
    assert req.to_bytes() == F10_REQUEST


def test_annex_i2_response_decodes_and_re_encodes():
    resp = decode_apdu(I2_RESPONSE)
    assert isinstance(resp, AccessResponse)
    assert resp.long_invoke_id == 0x40000000 and resp.specifications is None
    assert resp.data[0] == DlmsData.octet_string(b"00000001")
    assert resp.data[1].value == bytes.fromhex("07DC030C07161E0000FF8880")
    assert resp.data[2:] == [DlmsData.null(), DlmsData.null()]
    assert resp.results == [
        AccessResponseGet(DataAccessResult.SUCCESS),
        AccessResponseGet(DataAccessResult.SUCCESS),
        AccessResponseSet(DataAccessResult.SUCCESS),
        AccessResponseSet(DataAccessResult.SUCCESS),
    ]
    assert resp.to_bytes() == I2_RESPONSE


# DLMS UA 1000-2 Ed. 9 Excerpt 14.2 Table 21, "Complete Access-Request APDU
# (encoded)" and "Complete Access-Response APDU (encoded)", as printed.
GB9_TABLE21_REQUEST = bytes.fromhex(
    "D94000000000040100010000600100FF020100080000010000FF020200140000"
    "0D0000FF0702001400000D0000FF0804000001040203090100090CFFFFFFFFFF"
    "FFFF00000000000901FF0203090101090CFFFFFFFFFFFFFF00000000000901FF"
    "0203090102090CFFFFFFFFFFFFFF00000000000901FF0203090103090CFFFFFF"
    "FFFFFFFF00000000000901FF0104020809010011FF11FF11FF11FF11FF11FF11"
    "FF02080901011102110111011101110111011101020809010211FF11FF11FF11"
    "FF11FF11FF11FF02080901031101110211021102110211021102"
)
GB9_TABLE21_RESPONSE = bytes.fromhex(
    "DA4000000000000409083030303030303031090C07DC030C07161E0000FF88800000040100010002000200"
)


def test_green_book_table_21_is_the_same_exchange():
    """The public Green Book example settles both layouts: its request is
    Table F.10 byte for byte, its response is the annex I.2 response less
    the extra zero octet, and both decode and re-encode unchanged."""
    assert len(GB9_TABLE21_REQUEST) == 218 and len(GB9_TABLE21_RESPONSE) == 43
    assert GB9_TABLE21_REQUEST == F10_REQUEST
    assert GB9_TABLE21_RESPONSE == I2_RESPONSE
    for raw in (GB9_TABLE21_REQUEST, GB9_TABLE21_RESPONSE):
        assert decode_apdu(raw).to_bytes() == raw


def _every_kind() -> AccessRequest:
    att = AttributeDescriptor(3, ObisCode.parse("1.0.1.8.0.255"), 2)
    profile = AttributeDescriptor(7, ObisCode.parse("1.0.99.1.0.255"), 2)
    return AccessRequest(
        long_invoke_id(0x123456, processing_option=ProcessingOption.BREAK_ON_ERROR),
        bytes.fromhex("07E80501030C000000FF8880"),
        [
            AccessRequestGet(att),
            AccessRequestSet(AttributeDescriptor(1, SERIAL, 2)),
            AccessRequestAction(MethodDescriptor(70, ObisCode.parse("0.0.96.3.10.255"), 1)),
            AccessRequestGetWithSelection(profile, entry_descriptor(1, 2)),
            AccessRequestSetWithSelection(profile, SelectiveAccess(2, DlmsData.null())),
        ],
        [
            DlmsData.null(),
            DlmsData.visible_string("x"),
            DlmsData.int8(0),
            DlmsData.null(),
            DlmsData.array([]),
        ],
    )


def test_every_specification_kind_round_trips():
    req = _every_kind()
    raw = req.to_bytes()
    assert decode_apdu(raw) == req
    assert [s.kind for s in req.specifications] == list(AccessKind)
    assert req.invoke_id == 0x123456 and req.processing_option == ProcessingOption.BREAK_ON_ERROR
    assert req.timestamp is not None and req.timestamp.date.year == 2024
    # with-selection: descriptor, then a non-OPTIONAL selector + Data
    sel = AccessRequestSetWithSelection(
        AttributeDescriptor(7, CLOCK, 2), SelectiveAccess(2, DlmsData.null())
    )
    assert sel.to_bytes() == bytes.fromhex("0500070000010000FF020200")


def test_response_with_echo_and_every_result_kind_round_trips():
    req = _every_kind()
    resp = AccessResponse(
        req.long_invoke_id,
        None,
        list(req.specifications),
        [DlmsData.uint32(7), DlmsData.null(), DlmsData.null(), DlmsData.null(), DlmsData.null()],
        [
            AccessResponseGet(DataAccessResult.SUCCESS),
            AccessResponseSet(DataAccessResult.READ_WRITE_DENIED),
            AccessResponseAction(ActionResult.OTHER_REASON),
            AccessResponseGet(0x77),  # undefined code kept as int
            AccessResponseSet(DataAccessResult.SUCCESS),
        ],
    )
    raw = resp.to_bytes()
    assert raw[6] == 0x01  # echo present: tag, 4 id, 1 empty date-time
    back = decode_apdu(raw)
    assert back == resp
    assert back.results[3].result == 0x77 and not isinstance(
        back.results[3].result, DataAccessResult
    )
    assert isinstance(back.results[2].result, ActionResult)


def test_empty_lists_and_empty_date_time():
    raw = bytes.fromhex("D9C0000001000000")
    req = decode_apdu(raw)
    assert req == AccessRequest(0xC0000001, None, [], [])
    assert req.to_bytes() == raw
    assert AccessRequest(0xC0000001, b"", [], []).to_bytes() == raw
    resp = bytes.fromhex("DAC00000010001000000")
    assert decode_apdu(resp).specifications == []
    assert decode_apdu(resp).to_bytes() == resp


def test_builder_refuses_mismatched_counts_and_bad_ids():
    att = AccessRequestGet(AttributeDescriptor(1, SERIAL, 2))
    with pytest.raises(ValueError, match="1 specifications but 0 data"):
        AccessRequest(1, None, [att], []).to_bytes()
    with pytest.raises(ValueError, match="32-bit"):
        AccessRequest(1 << 32, None, [], []).to_bytes()
    with pytest.raises(ValueError, match="1 data but 0 results"):
        AccessResponse(1, None, None, [DlmsData.null()], []).to_bytes()
    with pytest.raises(ValueError, match="echoes 0"):
        AccessResponse(
            1, None, [], [DlmsData.null()], [AccessResponseGet(DataAccessResult.SUCCESS)]
        ).to_bytes()


@pytest.mark.parametrize(
    "raw,match",
    [
        # specification count 1, data count 2
        ("D9 40000000 00 01 01 0001 0000600100FF 02 02 00 00", "1 specifications but 2 data"),
        ("D9 40000000 00 01 06 0001 0000600100FF 02 01 00", "choice 6 is not 1..5"),
        ("D9 40000000 00 01 00 0001 0000600100FF 02 01 00", "choice 0 is not 1..5"),
        # 0x7F specifications announced, far fewer octets left
        ("D9 40000000 00 7F 01 0001 0000600100FF 02 01 00", "127 elements announced"),
        ("D9 40000000 00 01 01 0001 0000600100FF 02 82FFFF 00", "65535 elements announced"),
        ("D9 40000000 00 00 00 00", "trailing"),
        ("DA 40000000 00 00 01 00 02 0100 0100", "1 data but 2 results"),
        ("DA 40000000 00 02 00 00", "OPTIONAL presence flag"),
        ("DA 40000000 00 01 00 01 00 01 0100", "echoes 0 specifications for 1 results"),
        ("DA 40000000 00 00 01 00 01 0400", "choice 4 is not 1..3"),
        ("DA 40000000 00 00 01 00 01 0000", "choice 0 is not 1..3"),
        ("DA 40000000 00 00 00 7F 0100", "127 elements announced"),
        # date-time longer than what is left
        ("D9 40000000 0C 0102", "truncated"),
    ],
)
def test_malformed_access_apdus_raise(raw, match):
    with pytest.raises(DecodeError, match=match):
        decode_apdu(bytes.fromhex(raw.replace(" ", "")))


@pytest.mark.parametrize("apdu", [F10_REQUEST, I2_RESPONSE], ids=["request", "response"])
def test_every_truncation_raises_decode_error(apdu):
    for end in range(len(apdu)):
        with pytest.raises(DecodeError):
            decode_apdu(apdu[:end])


def test_non_strict_decode_ignores_trailing_octets():
    assert decode_apdu(I2_RESPONSE + b"\x00", strict=False).to_bytes() == I2_RESPONSE
    with pytest.raises(DecodeError, match="trailing"):
        decode_apdu(I2_RESPONSE + b"\x00")


def test_specification_and_result_names():
    assert str(AccessRequestGet(AttributeDescriptor(1, SERIAL, 2))) == "get 1/0.0.96.1.0.255/2"
    assert (
        str(AccessRequestAction(MethodDescriptor(70, SERIAL, 1))) == "action 70/0.0.96.1.0.255/m1"
    )
    assert AccessResponseAction.kind == AccessKind.ACTION
    assert xdlms.AccessResponseAction(ActionResult.SUCCESS).to_bytes() == b"\x03\x00"


# --- XML dialects and explain ------------------------------------------------------------


def _access_apdus() -> list[bytes]:
    req = _every_kind()
    echo = AccessResponse(
        req.long_invoke_id,
        req.date_time,
        list(req.specifications),
        [DlmsData.null()] * 5,
        [AccessResponseGet(DataAccessResult.OBJECT_UNDEFINED)] * 2
        + [AccessResponseAction(ActionResult.OTHER_REASON)]
        + [AccessResponseSet(DataAccessResult.SUCCESS)] * 2,
    )
    return [F10_REQUEST, I2_RESPONSE, req.to_bytes(), echo.to_bytes()]


@pytest.mark.parametrize("raw", _access_apdus(), ids=["f10", "i2", "kinds", "echo"])
def test_both_xml_dialects_round_trip(raw):
    from pydlms.apduxml import apdu_to_xml, xml_to_apdu
    from pydlms.gurux_xml import GuruxXmlWriter, gurux_xml_to_apdu, to_text

    text = apdu_to_xml(raw)
    assert xml_to_apdu(text) == raw
    gurux = to_text(GuruxXmlWriter().apdu(raw))
    assert gurux.startswith("<Access")
    assert gurux_xml_to_apdu(gurux) == raw
    assert xml_to_apdu(gurux) == raw  # the shared root is told apart by its children


def test_pydlms_dialect_names_each_specification_by_its_class():
    from pydlms.apduxml import apdu_to_xml

    text = apdu_to_xml(_every_kind().to_bytes())
    for name in (
        "access-request-get",
        "access-request-set",
        "access-request-action",
        "access-request-get-with-selection",
        "access-request-set-with-selection",
    ):
        assert f"<{name} " in text
    assert '<long-invoke-id value="0xE0123456" />' in text


def test_gurux_dialect_prints_the_gurux_element_names():
    from pydlms.gurux_xml import apdu_to_gurux_xml

    text = apdu_to_gurux_xml(F10_REQUEST)
    assert '<LongInvokeIdAndPriority Value="40000000" />' in text
    assert "<_AccessRequestSpecification>" in text and "<AccessRequestListOfData" in text
    assert "ContinueOnError, Invoke ID: 0" in text
    text = apdu_to_gurux_xml(I2_RESPONSE)
    assert "<AccessResponseListOfData" in text and '<Result Value="Success" />' in text


@pytest.mark.parametrize(
    "xml,match",
    [
        (
            '<AccessRequest><LongInvokeIdAndPriority Value="01"/><AccessRequestBody>'
            '<AccessRequestSpecification Qty="01"><_AccessRequestSpecification><AccessRequestGet>'
            '<AttributeDescriptor><ClassId Value="0001"/><InstanceId Value="0000600100FF"/>'
            '<AttributeId Value="02"/></AttributeDescriptor></AccessRequestGet>'
            "</_AccessRequestSpecification></AccessRequestSpecification>"
            '<AccessRequestListOfData Qty="00"/></AccessRequestBody></AccessRequest>',
            "counts differ",
        ),
        (
            '<AccessRequest><LongInvokeIdAndPriority Value="01"/><AccessRequestBody>'
            "<AccessRequestSpecification><_AccessRequestSpecification><AccessRequestFoo/>"
            "</_AccessRequestSpecification></AccessRequestSpecification>"
            "<AccessRequestListOfData><None/></AccessRequestListOfData>"
            "</AccessRequestBody></AccessRequest>",
            "not an access-request-specification",
        ),
        (
            '<AccessResponse><LongInvokeIdAndPriority Value="01"/><AccessResponseBody>'
            "<AccessResponseListOfData/><AccessResponseSpecification>"
            '<AccessResponseFoo><Result Value="Success"/></AccessResponseFoo>'
            "</AccessResponseSpecification></AccessResponseBody></AccessResponse>",
            "not an access-response-specification",
        ),
    ],
)
def test_gurux_reader_refuses_inconsistent_access_xml(xml, match):
    from pydlms.gurux_xml import gurux_xml_to_apdu

    with pytest.raises(DecodeError, match=match):
        gurux_xml_to_apdu(xml)


def test_explain_spells_out_the_long_invoke_id_and_lists():
    from pydlms.explain import explain

    text = explain(_every_kind().to_bytes())
    assert (
        "long_invoke_id: 0xE0123456 (id 1193046, high priority, confirmed, break on error)" in text
    )
    assert "[2] action 70/0.0.96.3.10.255/m1" in text
    text = explain(I2_RESPONSE)
    assert "0x40000000 (id 0, normal priority, confirmed, continue on error)" in text
    assert "[2] set SUCCESS" in text and '"00000001"' in text
