"""xDLMS LN service APDU tests: vectors, round trips, malformed input."""

from __future__ import annotations

import pytest

from pydlms.apdu import xdlms
from pydlms.apdu.gbt import GbtBlock, GbtReassembler, decode_gbt, encode_gbt, split_gbt
from pydlms.apdu.tags import DED_TAG, GLO_TAG, PLAIN_FOR_CIPHERED, Tag, is_ciphered, tag_name
from pydlms.cosem.data import DlmsData
from pydlms.cosem.enums import ActionResult, DataAccessResult
from pydlms.exceptions import DecodeError, ProtocolError
from pydlms.obis import ObisCode

LDN = ObisCode(0, 0, 43, 1, 0, 255)
CLOCK = ObisCode(0, 0, 1, 0, 0, 255)
ATTR = xdlms.AttributeDescriptor(1, LDN, 2)
METHOD = xdlms.MethodDescriptor(70, ObisCode(0, 0, 96, 3, 10, 255), 1)


def test_get_request_normal_vector():
    # dlms-cosem 0747b15 tests/test_get.py: class 1, 0.0.43.1.0.255, attr 2.
    raw = bytes.fromhex("C001C100010000 2B0100FF0200".replace(" ", ""))
    request = xdlms.GetRequestNormal(0xC1, ATTR)
    assert request.to_bytes() == raw
    assert xdlms.decode_apdu(raw) == request


def test_greenbook_ciphering_plaintext_is_get_clock():
    request = xdlms.decode_apdu(bytes.fromhex("C0010000080000010000FF0200"))
    assert request.attribute == xdlms.AttributeDescriptor(8, CLOCK, 2)


def test_invoke_id_byte():
    assert xdlms.invoke_id_byte(1) == 0xC1
    assert xdlms.invoke_id_byte(1, confirmed=False) == 0x81
    assert xdlms.invoke_id_byte(0, high_priority=False) == 0x40
    with pytest.raises(ValueError):
        xdlms.invoke_id_byte(16)


ROUND_TRIP = [
    xdlms.GetRequestNormal(0xC1, ATTR, xdlms.entry_descriptor(1, 10)),
    xdlms.GetRequestNext(0xC1, 7),
    xdlms.GetRequestWithList(0xC2, [(ATTR, None), (xdlms.AttributeDescriptor(8, CLOCK, 2), None)]),
    xdlms.GetResponseNormal(0xC1, xdlms.GetDataResult(data=DlmsData.uint32(5))),
    xdlms.GetResponseNormal(0xC1, xdlms.GetDataResult(error=DataAccessResult.READ_WRITE_DENIED)),
    xdlms.GetResponseWithDatablock(0xC1, False, 1, raw_data=bytes(300)),
    xdlms.GetResponseWithDatablock(0xC1, True, 2, error=DataAccessResult.DATA_BLOCK_UNAVAILABLE),
    xdlms.GetResponseWithList(
        0xC1,
        [
            xdlms.GetDataResult(data=DlmsData.uint8(1)),
            xdlms.GetDataResult(error=DataAccessResult.OBJECT_UNDEFINED),
        ],
    ),
    xdlms.SetRequestNormal(0xC1, ATTR, DlmsData.visible_string("x")),
    xdlms.SetRequestWithFirstDatablock(0xC1, ATTR, False, 1, b"abc"),
    xdlms.SetRequestWithDatablock(0xC1, True, 2, b"def"),
    xdlms.SetRequestWithList(0xC1, [(ATTR, None, DlmsData.uint8(1))]),
    xdlms.SetRequestWithListAndFirstDatablock(
        0xC1, [(ATTR, None), (ATTR, xdlms.SelectiveAccess(1, DlmsData.null()))], False, 1, b"\x02"
    ),
    xdlms.SetResponseNormal(0xC1, DataAccessResult.SUCCESS),
    xdlms.SetResponseDatablock(0xC1, 3),
    xdlms.SetResponseLastDatablock(0xC1, DataAccessResult.SUCCESS, 4),
    xdlms.SetResponseWithList(0xC1, [DataAccessResult.SUCCESS, DataAccessResult.TYPE_UNMATCHED]),
    xdlms.SetResponseLastDatablockWithList(0xC1, [DataAccessResult.SUCCESS], 5),
    xdlms.ActionRequestNormal(0xC1, METHOD, DlmsData.int8(0)),
    xdlms.ActionRequestNormal(0xC1, METHOD),
    xdlms.ActionRequestNextPblock(0xC1, 2),
    xdlms.ActionRequestWithList(0xC1, [(METHOD, DlmsData.int8(0))]),
    xdlms.ActionRequestWithFirstPblock(0xC1, METHOD, False, 1, b"\x01"),
    xdlms.ActionRequestWithPblock(0xC1, True, 2, b"\x02"),
    xdlms.ActionRequestWithListAndFirstPblock(0xC1, [METHOD, METHOD], True, 1, b"\x02\x0f"),
    xdlms.ActionResponseNormal(0xC1, ActionResult.SUCCESS),
    xdlms.ActionResponseNormal(
        0xC1, ActionResult.SUCCESS, xdlms.GetDataResult(data=DlmsData.octet_string(b"x"))
    ),
    xdlms.ActionResponseWithPblock(0xC1, True, 1, b"zz"),
    xdlms.ActionResponseWithList(0xC1, [(ActionResult.SUCCESS, None)]),
    xdlms.ActionResponseNextPblock(0xC1, 5),
    xdlms.DataNotification(0x80000001, DlmsData.structure([DlmsData.uint8(1)])),
    xdlms.DataNotification(1, DlmsData.uint8(1), bytes(12)),
    xdlms.DataNotification(1, DlmsData.uint8(1), bytes(12), date_time_tagged=True),
    xdlms.EventNotificationRequest(xdlms.AttributeDescriptor(1, LDN, 2), DlmsData.uint8(3)),
    xdlms.ExceptionResponse(1, 2),
    xdlms.ExceptionResponse(1, 6, 1234),
    xdlms.ConfirmedServiceError(1, 6, 1),
    xdlms.InitiateRequest(),
    xdlms.InitiateRequest(dedicated_key=bytes(16), quality_of_service=1),
    xdlms.InitiateResponse(xdlms.Conformance.default_ln(), 1024),
]


@pytest.mark.parametrize("apdu", ROUND_TRIP, ids=lambda a: type(a).__name__)
def test_round_trip(apdu):
    raw = apdu.to_bytes()
    assert xdlms.decode_apdu(raw) == apdu
    assert xdlms.decode_apdu(raw).to_bytes() == raw


@pytest.mark.parametrize("apdu", ROUND_TRIP, ids=lambda a: type(a).__name__)
def test_every_truncation_rejected(apdu):
    raw = apdu.to_bytes()
    for cut in range(1, len(raw)):
        with pytest.raises(DecodeError):
            xdlms.decode_apdu(raw[:cut])


def test_trailing_bytes_rejected_in_strict_mode():
    raw = xdlms.GetRequestNext(0xC1, 1).to_bytes() + b"\x00"
    with pytest.raises(DecodeError):
        xdlms.decode_apdu(raw)
    assert xdlms.decode_apdu(raw, strict=False) == xdlms.GetRequestNext(0xC1, 1)


@pytest.mark.parametrize(
    "raw", ["C009C1", "C409C1", "C109C1", "C509C1", "C309C1", "C709C1", "AB", ""]
)
def test_unknown_choices_rejected(raw):
    with pytest.raises(DecodeError):
        xdlms.decode_apdu(bytes.fromhex(raw))


@pytest.mark.parametrize(
    "raw",
    [
        "C401C101AA",  # GET-Response-Normal, data-access-result 170
        "C402C1010000000101AA",  # DataBlock-G with data-access-result 170
        "C501C1AA",  # SET-Response-Normal
        "C503C1AA00000002",  # SET-Response-Last-Datablock
        "C505C10200AA",  # SET-Response-With-List
        "C504C10200AA00000003",  # SET-Response-Last-Datablock-With-List
        "C701C1AA00",  # ACTION-Response-Normal, action-result 170
        "C703C1020000AA00",  # ACTION-Response-With-List
        "C701C100010105",  # return data with data-access-result 5 (undefined)
    ],
)
def test_undefined_result_codes_are_kept(raw):
    # A vendor-specific or newer-edition code must reach the caller as sent,
    # not collapse to other-reason (250).
    response = xdlms.decode_apdu(bytes.fromhex(raw))
    assert response.to_bytes().hex().upper() == raw
    assert "250" not in repr(response) and "OTHER_REASON" not in repr(response)


def test_undefined_access_result_is_a_plain_int():
    response = xdlms.decode_apdu(bytes.fromhex("C401C101AA"))
    assert response.result.error == 0xAA
    assert not isinstance(response.result.error, DataAccessResult)
    assert xdlms.decode_apdu(bytes.fromhex("C401C10104")).result.error is (
        DataAccessResult.OBJECT_UNDEFINED
    )


def test_conformance_bits():
    conf = xdlms.Conformance.from_bytes(bytes.fromhex("5F1F0400007E1F"))[0]
    assert xdlms.Conformance.GET in conf and xdlms.Conformance.ACTION in conf
    assert xdlms.Conformance.GENERAL_PROTECTION not in conf
    assert int(xdlms.Conformance.GENERAL_PROTECTION) == 0x400000
    assert int(xdlms.Conformance.ACTION) == 0x000001
    with pytest.raises(DecodeError):
        xdlms.Conformance.from_bytes(bytes.fromhex("5F1F0300"))
    assert "GET" in conf.names()


def test_entry_and_range_descriptors():
    entry = xdlms.entry_descriptor(1, 5)
    assert entry.to_bytes() == bytes.fromhex(
        "01020204060000000106000000051200011200 00".replace(" ", "")
    )
    import datetime as dt

    rng = xdlms.range_descriptor(
        xdlms.date_time_value(dt.datetime(2024, 1, 1)),
        xdlms.date_time_value(dt.datetime(2024, 1, 2)),
    )
    raw = rng.to_bytes()
    assert raw[:4] == bytes.fromhex("01010204")
    # restricting object = clock attr 2.
    assert bytes.fromhex("020412000809060000010000FF0F02120000") in raw


def test_data_notification_kaifa_tagged_datetime():
    raw = bytes.fromhex("0F00337AEF090C07EA0605050C252D00FF888002021100 1100".replace(" ", ""))
    note = xdlms.decode_apdu(raw)
    assert note.long_invoke_id == 0x00337AEF
    assert note.date_time_tagged
    assert str(note.timestamp) == "2026-06-05 12:37:45.00 +02:00"
    assert note.to_bytes() == raw


def test_data_notification_without_datetime():
    note = xdlms.decode_apdu(bytes.fromhex("0F4000000000 1101".replace(" ", "")))
    assert note.date_time is None and note.timestamp is None


# Green Book ExceptionResponse: of the service-error CHOICE only
# invocation-counter-error [6] carries content (IMPLICIT Unsigned32); every
# other alternative is IMPLICIT NULL.


def test_exception_counter_only_for_invocation_counter_error():
    assert xdlms.decode_apdu(bytes.fromhex("d80106000004d2")) == xdlms.ExceptionResponse(1, 6, 1234)
    # service-not-supported with four stray octets is not a counter.
    with pytest.raises(DecodeError, match="trailing"):
        xdlms.decode_apdu(bytes.fromhex("d8010200000001"))
    lenient = xdlms.decode_apdu(bytes.fromhex("d8010200000001"), strict=False)
    assert lenient == xdlms.ExceptionResponse(1, 2)


@pytest.mark.parametrize("raw", ["d80106", "d801060000"])
def test_exception_invocation_counter_error_needs_its_counter(raw):
    with pytest.raises(DecodeError):
        xdlms.decode_apdu(bytes.fromhex(raw))
    assert xdlms.decode_apdu(bytes.fromhex(raw), strict=False) == xdlms.ExceptionResponse(1, 6)


def test_exception_trailing_octets_rejected():
    with pytest.raises(DecodeError, match="trailing"):
        xdlms.decode_apdu(bytes.fromhex("d801020000"))


def test_exception_describe():
    assert "INVOCATION_COUNTER_ERROR" in xdlms.ExceptionResponse(1, 6, 9).describe()
    assert "9" in xdlms.ExceptionResponse(1, 6, 9).describe()


# --- tags ---------------------------------------------------------------------------------


def test_tag_tables():
    assert GLO_TAG[Tag.GET_REQUEST] == 0xC8
    assert GLO_TAG[Tag.INITIATE_REQUEST] == 0x21
    assert DED_TAG[Tag.GET_RESPONSE] == 0xD4
    assert DED_TAG[Tag.INITIATE_RESPONSE] == 0x48
    assert PLAIN_FOR_CIPHERED[0xCF] == (Tag.ACTION_RESPONSE, False)
    assert PLAIN_FOR_CIPHERED[0xD7] == (Tag.ACTION_RESPONSE, True)
    assert is_ciphered(0xDB) and is_ciphered(0xC8) and not is_ciphered(0xC0)
    assert tag_name(0xE0) == "GENERAL_BLOCK_TRANSFER" and tag_name(0x99) == "0x99"


# --- general block transfer -----------------------------------------------------------------


def test_gbt_real_e450_headers():
    # Block headers seen in the L+G E450 push (esphome-libs/dlms_parser).
    block = decode_gbt(bytes.fromhex("E0400001000077") + bytes(0x77))
    assert (block.last, block.streaming, block.window, block.block_number) == (False, True, 0, 1)
    last = decode_gbt(bytes.fromhex("E0C00003000 01F".replace(" ", "")) + bytes(0x1F))
    assert last.last and last.block_number == 3


def test_gbt_split_and_reassemble():
    apdu = bytes(range(250))
    blocks = split_gbt(apdu, 64)
    assert len(blocks) == 4
    gbt = GbtReassembler()
    out = [gbt.add(decode_gbt(b)) for b in blocks]
    assert out[:3] == [None, None, None] and out[3] == apdu
    assert not gbt.in_progress


def test_gbt_out_of_sequence():
    gbt = GbtReassembler()
    blocks = split_gbt(bytes(100), 30)
    gbt.add(decode_gbt(blocks[0]))
    with pytest.raises(ProtocolError):
        gbt.add(decode_gbt(blocks[2]))


def test_gbt_state_is_reset_after_an_out_of_sequence_block():
    gbt = GbtReassembler()
    blocks = split_gbt(bytes(100), 30)
    gbt.add(decode_gbt(blocks[0]))
    with pytest.raises(ProtocolError):
        gbt.add(decode_gbt(blocks[2]))
    assert not gbt.in_progress
    # The stale partial APDU must not leak into the next transfer.
    fresh = split_gbt(b"xyz", 2)
    assert gbt.add(decode_gbt(fresh[0])) is None
    assert gbt.add(decode_gbt(fresh[1])) == b"xyz"


def test_gbt_reassembly_is_capped():
    gbt = GbtReassembler(max_size=64)
    blocks = split_gbt(bytes(100), 30)
    gbt.add(decode_gbt(blocks[0]))
    gbt.add(decode_gbt(blocks[1]))
    with pytest.raises(ProtocolError, match="64"):
        gbt.add(decode_gbt(blocks[2]))
    assert not gbt.in_progress
    assert GbtReassembler(max_size=100).add(decode_gbt(split_gbt(bytes(100), 100)[0])) == bytes(100)


def test_gbt_default_cap():
    from pydlms.apdu.gbt import MAX_GBT_APDU

    assert GbtReassembler().max_size == MAX_GBT_APDU


def test_gbt_restart_on_block_one():
    gbt = GbtReassembler()
    gbt.add(decode_gbt(split_gbt(bytes(100), 30)[0]))
    assert gbt.add(decode_gbt(split_gbt(b"abc", 30)[0])) == b"abc"


@pytest.mark.parametrize(
    "raw", ["E0", "E040000100", "E04000010000 05 0102".replace(" ", ""), "C0400001000000"]
)
def test_gbt_malformed(raw):
    with pytest.raises(DecodeError):
        decode_gbt(bytes.fromhex(raw))


def test_gbt_encode_round_trip():
    block = GbtBlock(True, False, 1, 9, 8, b"xyz")
    assert decode_gbt(encode_gbt(block)) == block
    with pytest.raises(ValueError):
        split_gbt(b"x", 0)


# Green Book ConfirmedServiceError: service choices initiateError [1] to
# terminateUpLoad [19] (tag 0 is reserved); ServiceError alternatives [0] to
# [7], task [9] and other-error [10] ([8] change-scope is not used by DLMS).


@pytest.mark.parametrize("raw", ["0e010000", "0e010700", "0e010900", "0e010a00", "0e130601"])
def test_confirmed_service_error_defined_choices(raw):
    error = xdlms.decode_apdu(bytes.fromhex(raw))
    assert error.to_bytes().hex() == raw


@pytest.mark.parametrize("raw", ["0e010800", "0e010b00", "0e01ff00", "0e000601", "0e140601"])
def test_confirmed_service_error_undefined_choices_rejected(raw):
    with pytest.raises(DecodeError, match="choice"):
        xdlms.decode_apdu(bytes.fromhex(raw))
    lenient = xdlms.decode_apdu(bytes.fromhex(raw), strict=False)
    assert lenient.to_bytes().hex() == raw


def test_set_response_last_datablock_with_list_keeps_its_block_number():
    # Green Book Set-Response-Last-Datablock-With-List: invoke-id, result
    # SEQUENCE OF Data-Access-Result, block-number Unsigned32.
    raw = bytes.fromhex("c504c102000000000005")
    response = xdlms.decode_apdu(raw)
    assert response == xdlms.SetResponseLastDatablockWithList(
        0xC1, [DataAccessResult.SUCCESS, DataAccessResult.SUCCESS], 5
    )
    assert response.to_bytes() == raw


def test_set_response_last_datablock_with_list_truncated_before_the_block_number():
    # Two results, then the Unsigned32 block-number is missing.
    with pytest.raises(DecodeError, match="truncated"):
        xdlms.decode_apdu(bytes.fromhex("c504c1020000"))


# jDLMS SetRequestWithListAndFirstDatablock / ActionRequestWithListAndFirstPblock:
# invoke-id, SEQUENCE OF descriptor, DataBlock-SA {last-block, block-number
# Unsigned32, raw-data}. Hand-built from that layout; the jDLMS ``apdu`` oracle
# decodes both to the same fields (tests/interop/test_jdlms.py).
CHOICE5_VECTORS = {
    "c105c10100010000010000ff0200000000000103011105": xdlms.SetRequestWithListAndFirstDatablock(
        0xC1,
        [(xdlms.AttributeDescriptor(1, ObisCode.parse("0.0.1.0.0.255"), 2), None)],
        False,
        1,
        bytes.fromhex("011105"),
    ),
    "c305c1010046000060030aff01000000000103011100": xdlms.ActionRequestWithListAndFirstPblock(
        0xC1,
        [xdlms.MethodDescriptor(70, ObisCode.parse("0.0.96.3.10.255"), 1)],
        False,
        1,
        bytes.fromhex("011100"),
    ),
}


@pytest.mark.parametrize("raw", sorted(CHOICE5_VECTORS))
def test_with_list_and_first_block_vectors(raw):
    apdu = CHOICE5_VECTORS[raw]
    assert apdu.to_bytes().hex() == raw
    assert xdlms.decode_apdu(bytes.fromhex(raw)) == apdu


@pytest.mark.parametrize(
    "raw",
    [
        "c105c18401000000" + "00" * 8,  # 2^24 descriptors announced in 12 octets
        "c105c10200010000010000ff020000000000010100",  # second descriptor missing
        "c305c1830100000000000000",
        "c305c1020046000060030aff01000000000100",  # second method missing
    ],
)
def test_with_list_and_first_block_counts_are_checked(raw):
    with pytest.raises(DecodeError):
        xdlms.decode_apdu(bytes.fromhex(raw))


def test_data_list_round_trip_and_checks():
    values = [DlmsData.uint8(5), DlmsData.null(), DlmsData.octet_string(b"ab")]
    raw = xdlms.encode_data_list(values)
    assert raw.hex() == "031105000902" + b"ab".hex()
    assert xdlms.decode_data_list(raw) == values
    for bad in (raw[:-1], raw + b"\x00", b"\x05\x00", b"\x84\xff\xff\xff\xff"):
        with pytest.raises(DecodeError):
            xdlms.decode_data_list(bad)


# Green Book Cosem-Attribute-Descriptor / Cosem-Method-Descriptor: class-id
# Unsigned16, attribute-id / method-id Integer8 (negative ids are
# manufacturer-specific). Gurux tools show the id as an unsigned byte, so
# 128..255 is a likely user input; it must fail with a clear ValueError.


@pytest.mark.parametrize("bad", [128, 200, 255, -129])
@pytest.mark.parametrize("cls", [xdlms.AttributeDescriptor, xdlms.MethodDescriptor])
def test_descriptor_id_outside_integer8_is_a_value_error(cls, bad):
    with pytest.raises(ValueError, match=r"-128\.\.127") as info:
        cls(1, LDN, bad).to_bytes()
    assert not isinstance(info.value, xdlms.construct.ConstructError)
    if bad > 127:
        assert str(bad - 256) in str(info.value)


@pytest.mark.parametrize("cls", [xdlms.AttributeDescriptor, xdlms.MethodDescriptor])
def test_descriptor_class_id_outside_unsigned16_is_a_value_error(cls):
    with pytest.raises(ValueError, match="class id"):
        cls(0x10000, LDN, 2).to_bytes()


def test_negative_ids_still_round_trip():
    raw = bytes.fromhex("c001c100010000010000ffff00")
    request = xdlms.decode_apdu(raw)
    assert request.attribute.attribute_id == -1
    assert request.to_bytes() == raw


def test_initiate_request_repr_hides_the_dedicated_key():
    from pydlms.apdu.xdlms import InitiateRequest

    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    req = InitiateRequest(dedicated_key=key)
    assert key.hex() not in repr(req).lower()
    assert repr(key) not in repr(req)
    assert InitiateRequest.from_bytes(req.to_bytes()).dedicated_key == key
