"""Short-Name service APDU tests."""

from __future__ import annotations

import pytest

from pydlms.apdu import sn
from pydlms.cosem.data import DlmsData
from pydlms.cosem.enums import DataAccessResult
from pydlms.exceptions import DecodeError
from pydlms.sn_methods import method_address


def test_attribute_address():
    assert sn.attribute_address(0xFA00, 2) == 0xFA08
    assert sn.attribute_address(0x1000, 1) == 0x1000
    assert sn.attribute_address(0xFFF8, 3) == 0x0008  # wraps at 16 bits


def test_read_request_vector():
    raw = sn.ReadRequest([sn.VariableName(0xFA08)]).to_bytes()
    assert raw == bytes.fromhex("050102FA08")


ROUND_TRIP = [
    sn.ReadRequest([sn.VariableName(0x1008), sn.BlockNumberAccess(2)]),
    sn.ReadRequest([sn.ParameterizedAccess(0x3008, 2, DlmsData.uint8(1))]),
    sn.ReadRequest([sn.ReadDataBlockAccess(False, 1, b"\x01\x04\x30")]),
    sn.ReadRequest([sn.ReadDataBlockAccess(True, 0xFFFF, b"")]),
    sn.WriteRequest([sn.WriteDataBlockAccess(False, 2)], [DlmsData.octet_string(b"\xaa")]),
    sn.ReadResponse(
        [
            sn.ReadResult(data=DlmsData.uint16(5)),
            sn.ReadResult(error=DataAccessResult.OBJECT_UNDEFINED),
            sn.ReadResult(block_last=False, block_number=1, raw_data=b"abc"),
            sn.ReadResult(block_number=4),
        ]
    ),
    sn.WriteRequest([sn.VariableName(0x1008)], [DlmsData.uint8(3)]),
    sn.UnconfirmedWriteRequest([sn.VariableName(0x1008)], [DlmsData.uint8(3)]),
    sn.WriteResponse([DataAccessResult.SUCCESS, DataAccessResult.READ_WRITE_DENIED]),
    sn.WriteResponse([sn.WriteBlockNumber(5), DataAccessResult.SUCCESS]),
    sn.InformationReportRequest(bytes(12), [0x1008], [DlmsData.uint8(1)]),
    sn.InformationReportRequest(None, [0x1008], [DlmsData.uint8(1)]),
    sn.InformationReportRequest(bytes(12), [0x1008], [DlmsData.uint8(1)], current_time_bare=True),
]


@pytest.mark.parametrize("apdu", ROUND_TRIP, ids=lambda a: type(a).__name__)
def test_round_trip(apdu):
    raw = apdu.to_bytes()
    assert sn.decode_sn_apdu(raw).to_bytes() == raw


@pytest.mark.parametrize("apdu", ROUND_TRIP, ids=lambda a: type(a).__name__)
def test_truncations_rejected(apdu):
    raw = apdu.to_bytes()
    for cut in range(1, len(raw)):
        with pytest.raises(DecodeError):
            sn.decode_sn_apdu(raw[:cut])


@pytest.mark.parametrize("raw", ["0501 09 0000", "0C0109", "0D0105", "C0", ""])
def test_malformed(raw):
    with pytest.raises(DecodeError):
        sn.decode_sn_apdu(bytes.fromhex(raw.replace(" ", "")))


def test_method_addresses():
    # Association SN reply_to_HLS_authentication (method 8) lives at 0xFA58.
    assert method_address(0xFA00, 12, 8) == 0xFA58
    with pytest.raises(NotImplementedError):
        method_address(0x1000, 9999, 1)


@pytest.mark.parametrize(
    ("class_id", "version", "method", "offset"),
    [
        (64, 0, 1, 0x28),  # Security setup v0: 5 attributes
        (64, 0, 2, 0x30),
        (64, 1, 2, 0x38),  # v1 adds certificates: methods from 0x30
        (64, None, 2, 0x38),
        (72, 0, 1, 0x60),  # M-Bus client v0
        (72, 1, 1, 0x70),
        (72, 2, 1, 0x70),  # newer than known: the highest known version
        (3, 7, 1, 0x28),  # unversioned entry: any version
    ],
)
def test_method_addresses_follow_the_class_version(class_id, version, method, offset):
    assert method_address(0x1000, class_id, method, version) == 0x1000 + offset


# --- InformationReport current-time: spec and Gurux forms ---------------------------
#
# Green Book: current-time GeneralizedTime OPTIONAL, so the A-XDR form is a
# usage flag, then the octet string: 18 01 0C <12>. Gurux.DLMS (GXDLMS.cs,
# "Data is send in octet string. Remove data type.") omits the flag: 18 0C <12>.

DT = "07E6010103000000FF800000"
REPORT_TAIL = "0102FA00011105"  # one name 0xFA00, one value unsigned 5


def test_information_report_spec_time_form():
    report = sn.decode_sn_apdu(bytes.fromhex("18010C" + DT + REPORT_TAIL))
    assert report.current_time == bytes.fromhex(DT)
    assert not report.current_time_bare
    assert report.names == [0xFA00] and report.values == [DlmsData.uint8(5)]


def test_information_report_gurux_time_form_is_accepted_and_kept():
    raw = bytes.fromhex("180C" + DT + REPORT_TAIL)
    report = sn.decode_sn_apdu(raw)
    assert report.current_time == bytes.fromhex(DT)
    assert report.current_time_bare
    assert report.timestamp is not None and report.timestamp.date.year == 2022
    assert report.names == [0xFA00] and report.values == [DlmsData.uint8(5)]
    assert report.to_bytes() == raw


def test_information_report_encodes_the_spec_form_by_default():
    report = sn.InformationReportRequest(bytes.fromhex(DT), [0xFA00], [DlmsData.uint8(5)])
    assert report.to_bytes() == bytes.fromhex("18010C" + DT + REPORT_TAIL)


@pytest.mark.parametrize(
    "raw",
    [
        "180C" + DT[:-2],  # bare form cut inside the date-time
        "180B" + DT[:-2] + REPORT_TAIL,  # bare length other than 12
        "1802" + DT + REPORT_TAIL,  # neither a flag nor a bare 12-octet time
    ],
)
def test_information_report_bad_time_forms_rejected(raw):
    with pytest.raises(DecodeError):
        sn.decode_sn_apdu(bytes.fromhex(raw))


def test_write_response_block_number_is_kept():
    # Green Book WriteResponse: CHOICE { success [0], data-access-error [1],
    # block-number [2] Unsigned16 }.
    raw = bytes.fromhex("0D02020005" + "00")
    response = sn.decode_sn_apdu(raw)
    assert response.results == [sn.WriteBlockNumber(5), DataAccessResult.SUCCESS]
    assert response.to_bytes() == raw


@pytest.mark.parametrize("raw", ["0C0101AA", "0D0101AA"])
def test_undefined_sn_result_codes_are_kept(raw):
    response = sn.decode_sn_apdu(bytes.fromhex(raw))
    assert response.to_bytes().hex().upper() == raw
    assert "OTHER_REASON" not in repr(response)


# --- read-/write-data-block-access [6]/[7] ------------------------------------------


def test_read_data_block_access_review_vector():
    # This raised "unsupported choice 6".
    request = sn.decode_sn_apdu(bytes.fromhex("05010601000102aabb"))
    assert request.items == [sn.ReadDataBlockAccess(True, 1, b"\xaa\xbb")]


def test_write_data_block_access_vector():
    # GuruxDLMS.c svr_handleReadDataBlockAccess: WriteRequest, one
    # write-data-block-access, then one octet-string holding the part.
    raw = bytes.fromhex("0601 07 00 0002 01 09 03 010203".replace(" ", ""))
    request = sn.decode_sn_apdu(raw)
    assert request.items == [sn.WriteDataBlockAccess(False, 2)]
    assert request.values == [DlmsData.octet_string(b"\x01\x02\x03")]
    assert request.to_bytes() == raw


@pytest.mark.parametrize(
    "raw",
    [
        "050106020001 02aabb",  # last-block 2 is not an A-XDR BOOLEAN
        "050106ff0001 00",
        "06010702000101 0900",
        "05010601000105aabb",  # raw-data length beyond the APDU
        "0501060100",  # header cut inside the block number
        "06010701",
    ],
)
def test_data_block_access_malformed(raw):
    with pytest.raises(DecodeError):
        sn.decode_sn_apdu(bytes.fromhex(raw.replace(" ", "")))


@pytest.mark.parametrize("number", [-1, 0x10000])
def test_data_block_number_is_unsigned16(number):
    with pytest.raises(ValueError):
        sn.ReadDataBlockAccess(True, number, b"")
    with pytest.raises(ValueError):
        sn.WriteDataBlockAccess(True, number)


@pytest.mark.parametrize("raw", ["0584ffffffff02fa08", "0D820100 00", "0C8105 0300"])
def test_counts_beyond_the_apdu_are_refused_before_decoding(raw):
    with pytest.raises(DecodeError, match="announced"):
        sn.decode_sn_apdu(bytes.fromhex(raw.replace(" ", "")))
