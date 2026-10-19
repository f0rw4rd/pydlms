"""Gurux translator XML dialect (pydlms.gurux_xml) against frozen GXDLMSTranslator output.

``tests/fixtures/gurux_xml/translator.json`` holds, for every APDU of
``tests/gurux_xml_corpus.py``, what ``GXDLMSTranslator.PduToXml`` printed (or
the error it raised) and whether Gurux's own ``XmlToPdu`` turned that XML back
into the APDU. ``python -m tests.gurux_xml_corpus`` regenerates it; the live
comparison is ``tests/integration/test_gurux_xml.py``.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET

import pytest

from pydlms.apdu import xdlms
from pydlms.apdu.acse import AARQ, ApplicationContext
from pydlms.apduxml import apdu_to_xml, session_to_xml, xml_to_apdu, xml_to_session
from pydlms.cosem.data import DlmsData
from pydlms.cosem.enums import DataType
from pydlms.exceptions import DecodeError
from pydlms.gurux_xml import (
    GuruxXmlWriter,
    apdu_to_gurux_xml,
    data_element,
    element_data,
    gurux_element_to_apdu,
    gurux_xml_to_apdu,
    is_gurux_element,
    to_text,
)
from pydlms.obis import ObisCode
from tests.gurux_xml_corpus import AK, EK, FIXTURE

ROWS = json.loads(FIXTURE.read_text(encoding="utf-8"))
TRANSLATED = [row for row in ROWS if "xml" in row]

#: APDUs the dialect cannot hold exactly; pydlms writes <Raw> (bytes kept).
RAW = {
    "session-15-TX": "visible-string with a NUL (not representable in XML)",
    "hand-03-GetResponseNormal": "visible-string with a NUL",
    "data-visible-nul": "visible-string with a NUL",
    "data-compact-array": "compact array of arrays: Gurux has no form for it",
    **{f"exception-{v}-6": "invocation-counter-error without its counter" for v in (0, 1, 2)},
    # Gurux numbers ServiceError sequentially and calls [8] "task"; in the
    # Green Book [8] is unused and task is [9].
    **{f"cse-8-{v}": "ServiceError choice [8] is not defined" for v in range(8)},
    "capture-hdlc_landis_gyr_zmf100-0": "vendor push body pydlms does not decode",
    "capture-raw_egd_example-0": "vendor push body pydlms does not decode",
    "capture-raw_sagemcom_xt211-0": "vendor push body pydlms does not decode",
    "sn-read-block-number": "ReadResponse block-number [3]: Gurux has no form (it raises)",
    "sn-write-block-number": "WriteResponse block-number [2]: Gurux reads it as Ok",
    "set-list-first-datablock": "SET choice 5: Gurux prints UNKNOWN(49413) and the invoke-id",
    "action-list-first-pblock": "ACTION choice 5: Gurux prints only the invoke-id",
    "set-response-last-list-truncated": "truncated APDU: strict decoding rejects it",
}
#: Where pydlms's element differs from Gurux's (comments aside), and why.
DIFFERS = {
    **dict.fromkeys(RAW, "Raw: see RAW"),
    "hand-07-GetResponseWithList": "Gurux drops error results; pydlms writes DataAccessError",
    "get-list-error": "Gurux drops error results",
    "hand-09-SetRequestWithFirstDatablock": "Gurux repeats the descriptor and adds <Value>",
    "hand-19-ActionRequestWithList": "Gurux prints an empty list",
    "action-list": "Gurux prints an empty list",
    "hand-30-ExceptionResponse": "Gurux drops the invocation counter",
    "exception-ic": "Gurux drops the invocation counter",
    "hand-39-UnconfirmedWriteRequest": "Gurux has no form (writes <Data=...>, not XML)",
    "ciphered-glo-initiate": "Gurux has no form for a bare glo-initiate-request",
    "aarq-ae-qualifier": "Gurux prints 'Invalid certificate.' as text",
    "data-visible-markup": "Gurux writes \" as ' and does not escape & and <",
    "data-visible-control": "Gurux writes tab and CR literally (XML turns them into spaces)",
    "data-visible-latin1": "Gurux hex-dumps non-ASCII text as 'E9 FF'",
    "set-selective": "Gurux misreads the access selection as the value",
    "set-first-selective": "Gurux prints nothing for it",
    "set-list-selective": "Gurux drops the access selection",
    "get-list-selective": "Gurux drops the access selection",
    "initiate-no-response": "Gurux writes response-allowed FALSE as a QoS of 0",
    "ciphered-general-ciphering": "Gurux shows an empty transaction-id as 16 zeros",
    "ciphered-general-signing": "Gurux shows an empty transaction-id as 16 zeros",
    "sn-read-data-block": "Gurux drops the raw-data of read-data-block-access",
    "sn-read-data-block-first": "Gurux drops the raw-data of read-data-block-access",
    "access-response-echo": "Gurux skips the echo flag only and reads the echo as data",
}
#: Gurux XML that no longer holds the APDU, so reading it cannot give the bytes back.
LOSSY = {
    "session-15-TX",  # the NUL and what follows it are gone
    "hand-03-GetResponseNormal",
    "data-visible-nul",
    "data-visible-markup",
    "data-visible-control",
    "data-visible-latin1",
    "hand-07-GetResponseWithList",  # error results dropped
    "get-list-error",
    "hand-19-ActionRequestWithList",  # list contents dropped
    "action-list",
    "hand-30-ExceptionResponse",  # invocation counter dropped
    "exception-ic",
    "set-selective",
    "set-first-selective",
    "set-list-selective",
    "get-list-selective",
    "initiate-no-response",  # indistinguishable from a QoS of 0
    "ciphered-general-ciphering",  # empty transaction-id shown as 16 zeros
    "ciphered-general-signing",
    "sn-read-data-block",  # raw-data dropped
    "sn-read-data-block-first",
    "sn-write-block-number",  # printed as an Ok result
    "set-list-first-datablock",  # descriptors and the block dropped
    "action-list-first-pblock",
    "access-response-echo",  # echoed specifications read as data
}


def _keys(row) -> tuple[bytes | None, bytes | None]:
    if "keys" not in row:
        return None, None
    ek, ak = (bytes.fromhex(k) for k in row["keys"])
    return ek, ak or None


def _lines(text: str) -> list[str]:
    """Element lines without comments and indentation."""
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    return [line.strip() for line in text.splitlines() if line.strip()]


def _ids(row) -> str:
    return row["name"]


def test_fixture_covers_the_corpus():
    from tests.gurux_xml_corpus import build

    assert [r["name"] for r in build()] == [r["name"] for r in ROWS]
    assert len(TRANSLATED) >= 340


@pytest.mark.parametrize("row", ROWS, ids=_ids)
def test_every_apdu_round_trips_through_the_gurux_dialect(row):
    apdu = bytes.fromhex(row["apdu"])
    el = GuruxXmlWriter(*_keys(row), secrets=True).apdu(apdu)
    assert (el.tag == "Raw") == (row["name"] in RAW)
    assert gurux_xml_to_apdu(to_text(el)) == apdu
    assert xml_to_apdu(apdu_to_xml(apdu, dialect="gurux", secrets=True)) == apdu


@pytest.mark.parametrize("row", TRANSLATED, ids=_ids)
def test_output_matches_gurux_line_for_line(row):
    ours = to_text(GuruxXmlWriter(*_keys(row), secrets=True).apdu(bytes.fromhex(row["apdu"])))
    if row["name"] in DIFFERS:
        assert _lines(ours) != _lines(row["xml"]), "no longer differs: drop it from DIFFERS"
    else:
        assert _lines(ours) == _lines(row["xml"])


@pytest.mark.parametrize("row", TRANSLATED, ids=_ids)
def test_gurux_output_reads_back_to_the_apdu(row):
    apdu = bytes.fromhex(row["apdu"])
    try:
        back = xml_to_apdu(row["xml"])
    except DecodeError:
        back = None
    if row["name"] in LOSSY:
        assert back != apdu, "Gurux's XML is complete now: drop it from LOSSY"
    else:
        assert back == apdu


def test_known_lists_name_corpus_entries():
    names = {r["name"] for r in ROWS}
    assert set(RAW) <= names and set(DIFFERS) <= names and names >= LOSSY


def test_where_gurux_round_trips_its_own_xml_ours_encodes_identically():
    # Gurux can only reread what it encodes; there pydlms's text must be its text,
    # so Gurux reads pydlms's XML exactly as it reads its own.
    for row in TRANSLATED:
        if row.get("self_round_trip") and row["name"] not in DIFFERS:
            ours = to_text(
                GuruxXmlWriter(*_keys(row), secrets=True).apdu(bytes.fromhex(row["apdu"]))
            )
            assert _lines(ours) == _lines(row["xml"]), row["name"]


# --- hand-written vectors ------------------------------------------------------------

ENERGY = ObisCode.parse("1.0.1.8.0.255")


def test_get_request_text():
    apdu = xdlms.GetRequestNormal(0xC1, xdlms.AttributeDescriptor(3, ENERGY, 2)).to_bytes()
    assert apdu_to_gurux_xml(apdu) == (
        "<GetRequest>\n"
        "  <GetRequestNormal>\n"
        "    <!-- Priority: High, ServiceClass: Confirmed, Invoke ID: 1 -->\n"
        '    <InvokeIdAndPriority Value="C1" />\n'
        "    <AttributeDescriptor>\n"
        '      <ClassId Value="0003" />\n'
        "      <!-- 1.0.1.8.0.255 Active energy import (+A) total -->\n"
        '      <InstanceId Value="0100010800FF" />\n'
        '      <AttributeId Value="02" />\n'
        "    </AttributeDescriptor>\n"
        "  </GetRequestNormal>\n"
        "</GetRequest>\n"
    )


def test_strings_use_character_references():
    apdu = xdlms.GetResponseNormal(
        0xC1, xdlms.GetDataResult(data=DlmsData.visible_string('a\tb\n<&>"é'))
    ).to_bytes()
    text = apdu_to_gurux_xml(apdu)
    assert '<String Value="a&#9;b&#10;&lt;&amp;&gt;&quot;é" />' in text
    assert gurux_xml_to_apdu(text) == apdu


def test_editing_a_value_changes_the_encoding():
    apdu = xdlms.GetRequestNormal(0xC1, xdlms.AttributeDescriptor(3, ENERGY, 2)).to_bytes()
    edited = apdu_to_gurux_xml(apdu).replace(
        '<AttributeId Value="02" />', '<AttributeId Value="03" />'
    )
    assert gurux_xml_to_apdu(edited) == apdu[:-2] + b"\x03\x00"


def test_dialect_detection():
    initiate = xdlms.InitiateRequest(xdlms.Conformance.default_ln(), 512).to_bytes()
    pydlms_el = ET.fromstring(apdu_to_xml(initiate))  # noqa: S314 - our own output
    gurux_el = ET.fromstring(apdu_to_gurux_xml(initiate))  # noqa: S314
    assert pydlms_el.tag == gurux_el.tag == "InitiateRequest"
    assert not is_gurux_element(pydlms_el) and is_gurux_element(gurux_el)
    assert xml_to_apdu(apdu_to_xml(initiate)) == xml_to_apdu(apdu_to_gurux_xml(initiate))


def test_gurux_quirks_are_repaired_on_read():
    # <Data="..."> is what Gurux prints for an APDU it cannot translate, and it
    # leaves & and < unescaped inside Value attributes.
    assert gurux_xml_to_apdu('<Data="16 01 02" />') == bytes.fromhex("160102")
    text = (
        '<GetResponse><GetResponseNormal><InvokeIdAndPriority Value="C1" />'
        '<Result><Data><String Value="a&<b" /></Data></Result></GetResponseNormal></GetResponse>'
    )
    assert gurux_xml_to_apdu(text) == bytes.fromhex("c401c1000a0461263c62")
    assert gurux_xml_to_apdu("<!-- a -- b --><ReleaseRequest />") == bytes.fromhex("6200")


def test_concatenated_gurux_elements_read_as_a_session():
    one = xdlms.GetRequestNormal(0xC1, xdlms.AttributeDescriptor(3, ENERGY, 2)).to_bytes()
    two = xdlms.GetResponseNormal(0xC1, xdlms.GetDataResult(data=DlmsData.uint32(7))).to_bytes()
    text = '<?xml version="1.0"?>' + apdu_to_gurux_xml(one) + apdu_to_gurux_xml(two)
    assert xml_to_session(text) == [(None, one), (None, two)]


def test_session_round_trips_in_the_gurux_dialect():
    from tests.test_apduxml import _SESSION

    text = session_to_xml(_SESSION, dialect="gurux")
    assert text.startswith('<pydlms-session version="1" dialect="gurux">')
    assert xml_to_session(text) == [(d, a) for d, a in _SESSION]


def test_secrets_are_redacted_unless_asked_for():
    aarq = AARQ(
        ApplicationContext.LN,
        xdlms.InitiateRequest(
            xdlms.Conformance.default_ln(), 512, dedicated_key=bytes(range(16))
        ).to_bytes(),
        mechanism=1,
        calling_authentication_value=b"12345678",
    ).to_bytes()
    text = apdu_to_gurux_xml(aarq)
    assert b"12345678".hex().upper() not in text and bytes(range(16)).hex().upper() not in text
    assert text.count('Value="redacted"') == 2
    with pytest.raises(DecodeError, match="redacted"):
        gurux_xml_to_apdu(text)
    assert gurux_xml_to_apdu(apdu_to_gurux_xml(aarq, secrets=True)) == aarq


def test_hls_pass_3_and_4_are_redacted():
    from pydlms.apduxml import _HLS_METHOD

    class_id, obis, method_id = _HLS_METHOD
    request = xdlms.ActionRequestNormal(
        0xC1, xdlms.MethodDescriptor(class_id, obis, method_id), DlmsData.octet_string(b"S" * 16)
    ).to_bytes()
    response = xdlms.ActionResponseNormal(
        0xC1, xdlms.ActionResult.SUCCESS, xdlms.GetDataResult(data=DlmsData.octet_string(b"C" * 16))
    ).to_bytes()
    writer = GuruxXmlWriter()
    texts = [to_text(writer.apdu(request)), to_text(writer.apdu(response))]
    for text in texts:
        assert "5353" not in text and "4343" not in text and 'Value="redacted"' in text
        with pytest.raises(DecodeError, match="redacted"):
            gurux_xml_to_apdu(text)


def test_ciphered_apdus_keep_the_ciphertext_and_show_the_plaintext_as_a_comment():
    pytest.importorskip("cryptography")
    from pydlms.security import ciphering
    from pydlms.security.context import SecurityContext

    plain = xdlms.GetRequestNormal(0xC1, xdlms.AttributeDescriptor(3, ENERGY, 2)).to_bytes()
    apdu = ciphering.wrap(SecurityContext(EK, AK, client_system_title=b"ABCDEFGH"), plain)
    writer = GuruxXmlWriter(EK, AK, system_title=b"ABCDEFGH")
    el = writer.apdu(apdu)
    assert el.tag == "glo_GetRequest" and gurux_element_to_apdu(el) == apdu
    comment = "".join(c.text for c in el if c.tag is ET.Comment)
    assert "tag verified" in comment and '<InstanceId Value="0100010800FF" />' in comment
    assert "<!--" not in comment  # the nested element's own comments are escaped
    text = to_text(el)
    assert text.rstrip().endswith(f'<glo_GetRequest Value="{apdu[2:].hex().upper()}" />')
    assert gurux_xml_to_apdu(text) == apdu


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ("<GetRequest />", "exactly one element"),
        ("<GetRequest><GetRequestNormal /></GetRequest>", "InvokeIdAndPriority"),
        ('<ReadRequest Qty="01"><VariableName Value="zz" /></ReadRequest>', "not hex"),
        ('<ReadRequest Qty="01"><Nope /></ReadRequest>', "variable-access"),
        (
            '<GetResponse><GetResponseNormal><InvokeIdAndPriority Value="C1" /><Result><Data>'
            '<Array Qty="02"><UInt8 Value="01" /></Array></Data></Result></GetResponseNormal>'
            "</GetResponse>",
            "holds 1 elements",
        ),
        (
            '<GetResponse><GetResponseNormal><InvokeIdAndPriority Value="C1" /><Result><Data>'
            '<UInt8 Value="100" /></Data></Result></GetResponseNormal></GetResponse>',
            "not a valid UNSIGNED",
        ),
        (
            '<GetResponse><GetResponseNormal><InvokeIdAndPriority Value="C1" /><Result><Data>'
            '<Boolean Value="yes" /></Data></Result></GetResponseNormal></GetResponse>',
            "not a valid BOOLEAN",
        ),
        (
            '<InitiateResponse><NegotiatedDlmsVersionNumber Value="06" /><NegotiatedConformance>'
            '<ConformanceBit Name="Teleport" /></NegotiatedConformance>'
            '<NegotiatedMaxPduSize Value="0200" /><VaaName Value="0007" /></InitiateResponse>',
            "conformance bit",
        ),
        (
            '<SetResponse><SetResponseNormal><InvokeIdAndPriority Value="C1" />'
            '<Result Value="Sorry" /></SetResponseNormal></SetResponse>',
            "unknown value",
        ),
        (
            '<AssociationRequest><ApplicationContextName Value="XX" /></AssociationRequest>',
            "context",
        ),
        ("<GetRequest><GetRequest", "well-formed"),
    ],
)
def test_malformed_gurux_xml_is_rejected(text, match):
    with pytest.raises(DecodeError, match=match):
        gurux_xml_to_apdu(text)


def test_unknown_dialect_is_rejected():
    with pytest.raises(ValueError, match="dialect"):
        apdu_to_xml(b"\xc0\x01", dialect="dlms-ua")


def test_information_report_bare_time_round_trips():
    # Gurux's own flagless current-time form (18 0C <12> ...).
    apdu = bytes.fromhex("180C07E6010103000000FF800000" + "0102FA00011105")
    text = apdu_to_gurux_xml(apdu)
    assert 'Bare="true"' in text
    assert gurux_xml_to_apdu(text) == apdu
    assert xml_to_apdu(apdu_to_xml(apdu)) == apdu


@pytest.mark.parametrize(
    "tag,name,value,hexed",
    [
        (DataType.DELTA_INTEGER, "Delta-Int8", -5, "FB"),
        (DataType.DELTA_LONG, "Delta-Int16", -2, "FFFE"),
        (DataType.DELTA_DOUBLE_LONG, "Delta-Int32", 256, "00000100"),
        (DataType.DELTA_UNSIGNED, "Delta-UInt8", 255, "FF"),
        (DataType.DELTA_LONG_UNSIGNED, "Delta-UInt16", 0xFFFE, "FFFE"),
        (DataType.DELTA_DOUBLE_LONG_UNSIGNED, "Delta-UInt32", 1, "00000001"),
    ],
)
def test_delta_data_round_trip(tag, name, value, hexed):
    el = data_element(DlmsData(tag, value))
    assert el.tag == name
    assert el.get("Value") == hexed
    assert element_data(el) == DlmsData(tag, value)
