"""Encodings checked against national adoptions published by the Bureau of
Indian Standards (Public.Resource.Org, CC0 on archive.org).

Sources and the clause list:

* IS/IEC 62056-53:2006 (identical to IEC 62056-53 Ed. 2.0, 2006), the
  COSEM application layer: 8.1 COSEMpdu tags, 8.3 useful types
  (Invoke-Id-And-Priority, Data-Access-Result, Action-Result,
  TypeDescription), 8.5 conformance block, 8.6.1 with-list APDUs,
  7.4.1.8 long data transfer, annex B.2 HDLC profile.
* IS 11418 (Part 3):1986 (ISO 7809:1984), HDLC classes of procedures,
  Table 1 optional functions.

The values below are typed from the printed text, not from pydlms.
"""

from __future__ import annotations

import pytest

from pydlms.apdu import xdlms
from pydlms.apdu.tags import Tag
from pydlms.apdu.xdlms import Conformance, invoke_id_byte
from pydlms.cosem.data import DlmsData, TypeDescription, encode_type_description
from pydlms.cosem.enums import ActionResult, DataAccessResult, DataType
from pydlms.hdlc.address import HdlcAddress
from pydlms.hdlc.framing import SEQ_MODULUS, FrameType
from pydlms.obis import ObisCode

# IEC 62056-53:2006 8.1 COSEMpdu: context tag numbers. [n] IMPLICIT with
# n < 31 is the one-octet tag n (A-XDR keeps the context number as the
# octet); 192.. are written out as such.
COSEM_PDU_TAGS = {
    "INITIATE_REQUEST": 1,
    "READ_REQUEST": 5,
    "WRITE_REQUEST": 6,
    "INITIATE_RESPONSE": 8,
    "READ_RESPONSE": 12,
    "WRITE_RESPONSE": 13,
    "CONFIRMED_SERVICE_ERROR": 14,
    "UNCONFIRMED_WRITE_REQUEST": 22,
    "INFORMATION_REPORT_REQUEST": 24,
    "GET_REQUEST": 192,
    "SET_REQUEST": 193,
    "EVENT_NOTIFICATION_REQUEST": 194,
    "ACTION_REQUEST": 195,
    "GET_RESPONSE": 196,
    "SET_RESPONSE": 197,
    "ACTION_RESPONSE": 199,
    "GLO_GET_REQUEST": 200,
    "GLO_SET_REQUEST": 201,
    "GLO_EVENT_NOTIFICATION_REQUEST": 202,
    "GLO_ACTION_REQUEST": 203,
    "GLO_GET_RESPONSE": 204,
    "GLO_SET_RESPONSE": 205,
    "GLO_ACTION_RESPONSE": 207,
    "DED_GET_REQUEST": 208,
    "DED_SET_REQUEST": 209,
    "DED_EVENT_NOTIFICATION_REQUEST": 210,
    "DED_ACTION_REQUEST": 211,
    "DED_GET_RESPONSE": 212,
    "DED_SET_RESPONSE": 213,
    "DED_ACTION_RESPONSE": 215,
    "EXCEPTION_RESPONSE": 216,
}


@pytest.mark.parametrize(("name", "number"), sorted(COSEM_PDU_TAGS.items()))
def test_cosem_pdu_tags_match_iec_62056_53_8_1(name, number):
    assert Tag[name] == number


def test_acse_application_tags_match_8_2():
    # [APPLICATION 0..3] == 60 H .. 63 H, as the ASN.1 comments print them.
    assert (Tag.AARQ, Tag.AARE, Tag.RLRQ, Tag.RLRE) == (0x60, 0x61, 0x62, 0x63)


# IEC 62056-53:2006 8.5: Conformance ::= [APPLICATION 31] BIT STRING (24),
# bit n named as printed (ASN.1 bit 0 is the first, most significant bit).
CONFORMANCE_BITS = {
    3: "READ",
    4: "WRITE",
    5: "UNCONFIRMED_WRITE",
    8: "ATTRIBUTE0_SUPPORTED_WITH_SET",
    9: "PRIORITY_MGMT_SUPPORTED",
    10: "ATTRIBUTE0_SUPPORTED_WITH_GET",
    11: "BLOCK_TRANSFER_WITH_GET_OR_READ",  # 2006: block-transfer-with-get
    12: "BLOCK_TRANSFER_WITH_SET_OR_WRITE",  # 2006: block-transfer-with-set
    13: "BLOCK_TRANSFER_WITH_ACTION",
    14: "MULTIPLE_REFERENCES",
    15: "INFORMATION_REPORT",
    18: "PARAMETERIZED_ACCESS",
    19: "GET",
    20: "SET",
    21: "SELECTIVE_ACCESS",
    22: "EVENT_NOTIFICATION",
    23: "ACTION",
}


@pytest.mark.parametrize(("bit", "name"), sorted(CONFORMANCE_BITS.items()))
def test_conformance_bits_match_8_5(bit, name):
    assert Conformance[name] == 0x800000 >> bit


def test_invoke_id_and_priority_matches_8_3():
    # invoke_id (0..3), reserved (4..5), service_class (6) 1 = confirmed,
    # priority (7) 1 = high; bit 0 is the low-order bit (0xC1 = high,
    # confirmed, id 1, the value every LN capture shows).
    assert invoke_id_byte(1, high_priority=True, confirmed=True) == 0xC1
    assert invoke_id_byte(0, high_priority=False, confirmed=True) == 1 << 6
    assert invoke_id_byte(0, high_priority=True, confirmed=False) == 1 << 7
    assert invoke_id_byte(15, high_priority=False, confirmed=False) == 0x0F


DATA_ACCESS_RESULT = {
    "SUCCESS": 0,
    "HARDWARE_FAULT": 1,
    "TEMPORARY_FAILURE": 2,
    "READ_WRITE_DENIED": 3,
    "OBJECT_UNDEFINED": 4,
    "OBJECT_CLASS_INCONSISTENT": 9,
    "OBJECT_UNAVAILABLE": 11,
    "TYPE_UNMATCHED": 12,
    "SCOPE_OF_ACCESS_VIOLATED": 13,
    "DATA_BLOCK_UNAVAILABLE": 14,
    "LONG_GET_ABORTED": 15,
    "NO_LONG_GET_IN_PROGRESS": 16,
    "LONG_SET_ABORTED": 17,
    "NO_LONG_SET_IN_PROGRESS": 18,
    "OTHER_REASON": 250,
}
ACTION_RESULT = {
    **{k: v for k, v in DATA_ACCESS_RESULT.items() if v <= 14 or v == 250},
    "LONG_ACTION_ABORTED": 15,
    "NO_LONG_ACTION_IN_PROGRESS": 16,
}


def test_result_enums_match_8_3():
    for name, value in DATA_ACCESS_RESULT.items():
        assert DataAccessResult[name] == value
    for name, value in ACTION_RESULT.items():
        assert ActionResult[name] == value


def test_compact_array_type_description_array_has_unsigned16_count():
    # 8.3 TypeDescription: array [1] IMPLICIT SEQUENCE { number-of-elements
    # Unsigned16, type-description TypeDescription }.
    desc = TypeDescription(DataType.ARRAY, array_of=(3, TypeDescription(DataType.UNSIGNED)))
    assert encode_type_description(desc) == bytes([1, 0x00, 0x03, 17])


def _descriptor() -> xdlms.AttributeDescriptor:
    return xdlms.AttributeDescriptor(1, ObisCode.parse("0.0.96.1.0.255"), 2)


def test_set_with_list_blocks_carry_the_value_list_sequence_of_data():
    """7.4.1.8.2/.3: the data "shall be encoded, as if they would fit into
    one APDU" and cut into DataBlock-SA raw-data; the reference list goes
    only in the first block. In one APDU (8.6.1 Set-Request-With-List) the
    data is ``value-list SEQUENCE OF Data``, the tail after the references."""
    values = [DlmsData.uint8(5), DlmsData.octet_string(b"AB")]
    refs = b"\x02" + (_descriptor().to_bytes() + b"\x00") * 2
    raw = xdlms.encode_data_list(values)
    assert raw == bytes.fromhex("02 11 05 09 02 41 42".replace(" ", ""))
    single = xdlms.SetRequestWithList(
        invoke_id=0xC1, items=[(_descriptor(), None, v) for v in values]
    ).to_bytes()
    assert single == b"\xc1\x04\xc1" + refs + raw
    first = xdlms.SetRequestWithListAndFirstDatablock(
        invoke_id=0xC1,
        items=[(_descriptor(), None)] * 2,
        last_block=True,
        block_number=1,
        raw_data=raw,
    ).to_bytes()
    # DataBlock-SA: last-block BOOLEAN, block-number Unsigned32, raw-data.
    assert first == b"\xc1\x05\xc1" + refs + b"\x01\x00\x00\x00\x01\x07" + raw


def test_action_with_list_pblocks_carry_the_parameter_sequence_of_data():
    """7.4.1.8.4 and 8.6.1 Action-Request-With-List: method-invocation-
    parameters SEQUENCE OF Data, null-data for a method without one."""
    method = xdlms.MethodDescriptor(70, ObisCode.parse("0.0.96.3.10.255"), 1)
    single = xdlms.ActionRequestWithList(
        invoke_id=0xC1, items=[(method, DlmsData.int8(0)), (method, None)]
    )
    raw = xdlms.encode_data_list([DlmsData.int8(0), DlmsData.null()])
    assert single.to_bytes().endswith(raw)


# --- annex B.2: the HDLC profile ----------------------------------------------


def test_profile_class_is_unc_with_ui_modulo_8():
    """B.2.2.2: "the selected HDLC class of procedure is UNC, extended with UI
    frames". ISO 7809:1984 2.2.2.1 gives the UNC basic repertoire (I, RR,
    RNR, SNRM, DISC; UA, DM, FRMR) with an unextended control field, and
    Table 1 option 4 adds UI; extended numbering is option 10, REJ and SREJ
    options 2 and 3, none of them selected."""
    assert SEQ_MODULUS == 8
    unc_plus_ui = {"I", "RR", "RNR", "SNRM", "DISC", "UA", "DM", "FRMR", "UI"}
    assert unc_plus_ui <= set(FrameType.__members__)


def test_one_octet_all_station_and_no_station_addresses():
    """ISO 3309:1984 5.2 / 5.3: all-station ``11111111``, no-station
    ``00000000``; with the 4.1 extension bit (low-order, 1 = last octet) the
    one-octet field carries 0x7F and 0x00."""
    assert HdlcAddress(0x7F).to_bytes() == b"\xff"
    assert HdlcAddress(0x00).to_bytes() == b"\x01"
