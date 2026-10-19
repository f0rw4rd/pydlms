"""IEC 62056-5-3:2023 annex E.7 and E.8: the ciphered initiate APDUs of a release.

Source: the annex E.2/E.5/E.7/E.8 bytes as transcribed in cB-Sigma dlms
26360a1 (see :mod:`tests.crypto.vectors`). Both directions use system title
4D4D4D0000BC614E and IC 0x01234567 with SC 0x30 (authenticated and
encrypted: the InitiateRequest carries a dedicated key). The association
level (our RLRQ equals E.7, E.8 verifies the release) is in
``test_release.py``.
"""

from __future__ import annotations

import pytest

from pydlms.apdu.acse import RLRE, RLRQ
from pydlms.exceptions import DecodeError, SecurityError
from pydlms.security.ciphering import unwrap, wrap
from pydlms.security.context import SecurityContext
from pydlms.security.suites import SecurityControl
from tests.crypto.vectors import (
    E2_INITIATE_REQUEST,
    E5_INITIATE_RESPONSE,
    E7_RLRQ,
    E8_RLRE,
    E_IC,
    E_SYSTEM_TITLE,
    GB_AK,
    GB_EK,
)

AE = SecurityControl.from_byte(0x30)
CASES = [
    pytest.param(E7_RLRQ, RLRQ, E2_INITIATE_REQUEST, id="E.7-RLRQ"),
    pytest.param(E8_RLRE, RLRE, E5_INITIATE_RESPONSE, id="E.8-RLRE"),
]


def _sender() -> SecurityContext:
    return SecurityContext(
        GB_EK, GB_AK, client_system_title=E_SYSTEM_TITLE, invocation_counter=E_IC
    )


def _receiver() -> SecurityContext:
    return SecurityContext(GB_EK, GB_AK, b"RECEIVER", server_system_title=E_SYSTEM_TITLE)


@pytest.mark.parametrize(("apdu", "acse", "plain"), CASES)
def test_ciphering_reproduces_the_annex(apdu, acse, plain):
    user_info = acse.from_bytes(apdu).user_information
    assert wrap(_sender(), plain, sc=AE) == user_info
    assert acse(0, user_info).to_bytes() == apdu


@pytest.mark.parametrize(("apdu", "acse", "plain"), CASES)
def test_annex_user_information_opens(apdu, acse, plain):
    result = unwrap(_receiver(), acse.from_bytes(apdu).user_information)
    assert result.authenticated and result.invocation_counter == E_IC
    assert result.security_control.authenticated and result.security_control.encrypted
    assert result.plaintext == plain


@pytest.mark.parametrize(("apdu", "acse", "plain"), CASES)
def test_every_tampered_byte_is_refused(apdu, acse, plain):
    """Flipping the low bit of any octet of the envelope (tag, length, SC, IC, ciphertext or
    GCM tag) yields no plaintext. The envelope tag is outside the GCM input;
    a flip lands on an undefined tag here (0x20, 0x29), and the association
    additionally checks that the plaintext matches the envelope."""
    user_info = acse.from_bytes(apdu).user_information
    for position in range(len(user_info)):
        tampered = bytearray(user_info)
        tampered[position] ^= 0x01
        with pytest.raises((SecurityError, DecodeError)):
            unwrap(_receiver(), bytes(tampered))
