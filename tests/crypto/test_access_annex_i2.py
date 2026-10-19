"""The ACCESS exchange inside the IEC 62056-5-3:2023 annex I.2 example.

The general-ciphering request and response of annex I.2 (one-pass
Diffie-Hellman), as transcribed in cB-Sigma dlms (Apache-2.0)
``cosem/iec6205653_vectors_test.go`` at 26360a1, carry the Table F.10 ACCESS
request and its response. Their GCM tags are not reproducible (cB-Sigma
finding F-171, ``test_general_divergence.py``), so the ciphertext is opened
with the counter stream alone, as cB-Sigma's ``openCT`` does; what is
checked here is that the request is the Table F.10 ACCESS request pydlms
decodes and re-encodes byte for byte, and that the response is an ACCESS
response with one zero octet more than the request's layout allows (see
:data:`I2_RESPONSE_AS_PRINTED`).
"""

from __future__ import annotations

import pytest

from pydlms.apdu.xdlms import (
    AccessRequest,
    AccessResponse,
    AccessResponseGet,
    AccessResponseSet,
    decode_apdu,
)
from pydlms.cosem.enums import DataAccessResult
from pydlms.exceptions import DecodeError
from pydlms.security import gcm
from tests.crypto.vectors import (
    I2_EK_GC_C,
    I2_EK_GC_S,
    I2_REQUEST_CONTENT,
    I2_REQUEST_ORIGINATOR,
    I2_RESPONSE_CONTENT,
    I2_RESPONSE_ORIGINATOR,
)
from tests.test_access_service import F10_REQUEST, I2_RESPONSE


def _open(key: bytes, originator: bytes, content: bytes) -> bytes:
    assert content[0] == 0x31  # authenticated and encrypted, suite 1
    ic = int.from_bytes(content[1:5], "big")
    return gcm.ctr_transform(key, gcm.make_iv(originator, ic), content[5:-12])


def test_annex_i2_request_is_the_table_f10_access_request():
    plain = _open(I2_EK_GC_C, I2_REQUEST_ORIGINATOR, I2_REQUEST_CONTENT)
    assert plain == F10_REQUEST
    request = decode_apdu(plain)
    assert isinstance(request, AccessRequest)
    assert len(request.specifications) == 4
    assert request.to_bytes() == plain


#: What the annex I.2 response deciphers to: ``DA``, the request's long
#: invoke id, then THREE zero octets before the data count 04, where the
#: request in the same annex (and the layout Gurux, jDLMS and cB-Sigma
#: implement) has two: an empty date-time and the absent request echo. With
#: either zero octet left out it is :data:`I2_RESPONSE`. No reader decodes
#: the annex form (Gurux, cB-Sigma and pydlms read a data count of 0, four
#: results and then the data as results); no guess is made at the extra octet.
#: The annex text was not read here, so this may be a transcription or an
#: annex error; it is recorded as a finding.
I2_RESPONSE_AS_PRINTED = I2_RESPONSE[:7] + b"\x00" + I2_RESPONSE[7:]


def test_annex_i2_response_is_an_access_response_with_one_zero_too_many():
    plain = _open(I2_EK_GC_S, I2_RESPONSE_ORIGINATOR, I2_RESPONSE_CONTENT)
    assert plain == I2_RESPONSE_AS_PRINTED
    with pytest.raises(DecodeError, match="choice 9 is not 1..3"):
        decode_apdu(plain)
    response = decode_apdu(plain[:7] + plain[8:])
    assert isinstance(response, AccessResponse)
    assert response.invoke_id == decode_apdu(F10_REQUEST).invoke_id
    assert [type(r) for r in response.results] == [
        AccessResponseGet,
        AccessResponseGet,
        AccessResponseSet,
        AccessResponseSet,
    ]
    assert {r.result for r in response.results} == {DataAccessResult.SUCCESS}
    assert response.to_bytes() == I2_RESPONSE


def test_a_wrong_key_does_not_give_an_access_apdu():
    plain = _open(I2_EK_GC_S, I2_REQUEST_ORIGINATOR, I2_REQUEST_CONTENT)
    assert plain[0] != 0xD9
