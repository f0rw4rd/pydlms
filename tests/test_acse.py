"""ACSE (AARQ/AARE/RLRQ/RLRE) tests.

Known-good vectors are the Green Book v10 examples as quoted in dlms-cosem
0747b15 (MIT) tests/test_asce: LN no security, LLS "12345678", accepted
AARE, rejected AARE (dlms-version-too-low), HLS-GMAC AARQ/AARE, and the
ciphered LLS AARQ with a glo-initiateRequest.
"""

from __future__ import annotations

import pytest

from pydlms.apdu.acse import (
    AARE,
    AARQ,
    RLRE,
    RLRQ,
    AcseServiceUserDiagnostic,
    ApplicationContext,
    decode_acse,
    parse_ber,
)
from pydlms.apdu.xdlms import ConfirmedServiceError, Conformance, InitiateRequest, decode_apdu
from pydlms.exceptions import DecodeError

INITIATE = bytes.fromhex("01000000065F1F0400007E1F04B0")
AARQ_LN = bytes.fromhex("601DA109060760857405080101BE10040E" + INITIATE.hex())
AARQ_LLS = bytes.fromhex(
    "6036A1090607608574050801018A0207808B0760857405080201AC0A80083132333435363738BE10040E"
    + INITIATE.hex()
)
AARE_OK = bytes.fromhex(
    "6129A109060760857405080101A203020100A305A103020100BE10040E0800065F1F040000501F01F40007"
)
AARE_REJECTED = bytes.fromhex("611FA109060760857405080101A203020101A305A103020101BE0604040E010601")
AARE_HLS = bytes.fromhex(
    "6142A109060760857405080101A203020100A305A10302010E88020780890760857405080205"
    "AA0A8008503677524A323146BE10040E0800065F1F040000501F01F40007"
)
AARQ_CIPHERED_LLS = bytes.fromhex(
    "6066A109060760857405080103A60A04084D4D4D0000BC614E8A0207808B0760857405080201"
    "AC0A80083132333435363738BE34043221303001234567801302FF8A7874133D414CED25B425"
    "34D28DB0047720606B175BD52211BE6841DB204D39EE6FDB8E356855"
)


def test_initiate_request_vector():
    assert InitiateRequest(Conformance(0x007E1F), 0x04B0).to_bytes() == INITIATE


def test_aarq_ln_no_security():
    aarq = AARQ(user_information=INITIATE)
    assert aarq.to_bytes() == AARQ_LN
    assert AARQ.from_bytes(AARQ_LN) == aarq


def test_aarq_lls():
    aarq = AARQ(user_information=INITIATE, mechanism=1, calling_authentication_value=b"12345678")
    assert aarq.to_bytes() == AARQ_LLS
    parsed = AARQ.from_bytes(AARQ_LLS)
    assert parsed.mechanism == 1 and parsed.calling_authentication_value == b"12345678"


def test_aarq_ciphered_lls_round_trip():
    parsed = AARQ.from_bytes(AARQ_CIPHERED_LLS)
    assert parsed.application_context == ApplicationContext.LN_CIPHERED
    assert parsed.calling_ap_title == bytes.fromhex("4D4D4D0000BC614E")
    assert parsed.user_information[0] == 0x21  # glo-initiateRequest
    assert parsed.to_bytes() == AARQ_CIPHERED_LLS


def test_aare_accepted():
    aare = AARE.from_bytes(AARE_OK)
    assert aare.accepted
    assert aare.application_context == ApplicationContext.LN
    assert aare.to_bytes() == AARE_OK
    initiate = decode_apdu(aare.user_information)
    assert initiate.max_receive_pdu_size == 500
    assert initiate.vaa_name == 0x0007


def test_aare_rejected_with_service_error():
    aare = AARE.from_bytes(AARE_REJECTED)
    assert not aare.accepted
    assert aare.diagnostic == AcseServiceUserDiagnostic.NO_REASON_GIVEN
    error = decode_apdu(aare.user_information)
    assert isinstance(error, ConfirmedServiceError)
    assert "dlms-version-too-low" in error.describe()
    assert aare.to_bytes() == AARE_REJECTED


def test_aare_hls():
    aare = AARE.from_bytes(AARE_HLS)
    assert aare.accepted
    assert aare.diagnostic_name() == "AUTHENTICATION_REQUIRED"
    assert aare.mechanism == 5
    assert aare.responding_authentication_value == b"P6wRJ21F"
    assert aare.to_bytes() == AARE_HLS


def test_ciphered_aarq_decrypts_with_greenbook_keys():
    pytest.importorskip("cryptography")
    from pydlms.security.ciphering import unwrap
    from pydlms.security.context import SecurityContext
    from tests.crypto.vectors import GB_AK, GB_EK

    aarq = AARQ.from_bytes(AARQ_CIPHERED_LLS)
    ctx = SecurityContext(GB_EK, GB_AK, server_system_title=aarq.calling_ap_title)
    plain = unwrap(ctx, aarq.user_information).plaintext
    request = InitiateRequest.from_bytes(plain)
    assert request.dedicated_key == bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    assert request.max_receive_pdu_size == 0x04B0


def test_release_vectors():
    assert RLRQ(0).to_bytes() == bytes.fromhex("6203800100")
    assert RLRQ.from_bytes(bytes.fromhex("6203800100")).reason == 0
    assert RLRE(0).to_bytes() == bytes.fromhex("6303800100")
    rlre = RLRE.from_bytes(bytes.fromhex("6300"))
    assert rlre.reason is None
    with_info = RLRQ(0, b"\x01\x02").to_bytes()
    assert RLRQ.from_bytes(with_info).user_information == b"\x01\x02"


def test_decode_dispatch():
    assert isinstance(decode_acse(AARQ_LN), AARQ)
    assert isinstance(decode_acse(AARE_OK), AARE)
    assert isinstance(decode_acse(bytes.fromhex("6203800100")), RLRQ)
    assert isinstance(decode_acse(bytes.fromhex("6303800100")), RLRE)
    with pytest.raises(DecodeError):
        decode_acse(b"\x64\x00")
    with pytest.raises(DecodeError):
        decode_acse(b"")


@pytest.mark.parametrize("cut", range(1, len(AARE_OK)))
def test_truncated_aare_rejected(cut):
    with pytest.raises(DecodeError):
        AARE.from_bytes(AARE_OK[:cut])


@pytest.mark.parametrize(
    "raw",
    [
        "6100",  # no context / result
        "6105A1030601FF",  # bad OID
        "610BA109060760857405080109",  # unknown context id 9
        "6107A2050201000000",  # inner overrun handled
        "61049F010100",  # multi-octet tag
    ],
)
def test_malformed_aare(raw):
    with pytest.raises(DecodeError):
        AARE.from_bytes(bytes.fromhex(raw))


def test_parse_ber_long_length():
    value = bytes(200)
    assert parse_ber(b"\x04\x81\xc8" + value) == [(0x04, value)]
    with pytest.raises(DecodeError):
        parse_ber(b"\x04\x85\x00")
