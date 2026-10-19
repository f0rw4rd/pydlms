"""The V.44 decoder as the ``SecurityContext`` decompressor, end to end.

A get-response is compressed with the test-support encoder
(``tests/v44_encoder.py``), carried in a suite-1 general-glo APDU, and
opened by ``unwrap`` with ``decompressor=v44_decompressor()``. The gating
helpers come from ``test_decompressor.py``; the recording hook proves the
V.44 decoder never sees an APDU whose tag failed.
"""

from __future__ import annotations

import pytest

from pydlms.exceptions import AuthenticationError, DecodeError
from pydlms.security.ciphering import unwrap
from pydlms.security.suites import SecurityControl, SecurityPolicy
from pydlms.security.v44 import v44_decompressor
from tests.crypto.test_decompressor import SC_COMPRESSED, Hook, general_glo, receiver
from tests.v44_encoder import compress

#: get-response-normal, invoke-id 0xC1, data: an array of 12 identical
#: structures {date-time octet-string, uint32}: repetitive like a profile.
ROW = bytes.fromhex("0202090C07EA0A1005000000000080000006000186A0")
GET_RESPONSE = bytes.fromhex("C401C100010C") + ROW * 12
COMPRESSED = compress(GET_RESPONSE)


def test_compressed_apdu_is_smaller():
    assert len(COMPRESSED) < len(GET_RESPONSE) // 3


def test_general_glo_v44_end_to_end():
    hook = Hook(v44_decompressor())
    result = unwrap(receiver(hook=hook), general_glo(SC_COMPRESSED, COMPRESSED))
    assert result.plaintext == GET_RESPONSE
    assert result.security_control.compressed and result.authenticated
    assert hook.calls == [COMPRESSED]


def test_auth_only_v44():
    sc = SecurityControl(1, authenticated=True, compressed=True)
    ctx = receiver(hook=v44_decompressor(), policy=SecurityPolicy.AUTHENTICATED)
    assert unwrap(ctx, general_glo(sc, COMPRESSED)).plaintext == GET_RESPONSE


_APDU = general_glo(SC_COMPRESSED, COMPRESSED)


@pytest.mark.parametrize("position", range(2, len(_APDU)))
def test_every_octet_tampered_fails_before_decompression(position):
    """Title, length, SC, IC, ciphertext and tag: each flip fails before V.44 runs."""
    hook = Hook(v44_decompressor())
    tampered = bytearray(_APDU)
    tampered[position] ^= 0x01
    with pytest.raises((AuthenticationError, DecodeError)):
        unwrap(receiver(hook=hook), bytes(tampered))
    assert hook.calls == []


def test_malformed_v44_becomes_decode_error():
    """A verified APDU whose V.44 data is truncated: the hook's DecodeError is wrapped."""
    hook = Hook(v44_decompressor())
    with pytest.raises(DecodeError, match="decompressor failed: V.44"):
        unwrap(receiver(hook=hook), general_glo(SC_COMPRESSED, COMPRESSED[:-2]))
    assert len(hook.calls) == 1


def test_v44_stops_at_its_own_limit():
    hook = Hook(v44_decompressor(max_output=len(GET_RESPONSE) - 1))
    with pytest.raises(DecodeError, match="exceeds the limit"):
        unwrap(receiver(hook=hook), general_glo(SC_COMPRESSED, COMPRESSED))
    exact = Hook(v44_decompressor(max_output=len(GET_RESPONSE)))
    assert unwrap(receiver(hook=exact), _APDU).plaintext == GET_RESPONSE


def test_unwrap_limit_still_applies():
    with pytest.raises(DecodeError, match="exceeds"):
        unwrap(receiver(hook=v44_decompressor()), _APDU, max_decompressed=len(GET_RESPONSE) - 1)
