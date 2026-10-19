"""AES key wrap known-answer tests.

Every vector is copied byte-exact from RFC 3394 section 4
(https://www.rfc-editor.org/rfc/rfc3394.txt); the subsection is cited at
each constant. Suite 0/1 wrap under a 128-bit KEK, suite 2 under a 256-bit
KEK, so both KEK sizes are pinned. Each case runs through the
SoftwareProvider and the HandleProvider (KEK behind a handle).
"""

from __future__ import annotations

import pytest

from pydlms.cosem.data import encode_data
from pydlms.exceptions import AuthenticationError
from pydlms.security.keywrap import KeyId, key_transfer_data, unwrap_key, wrap_key

# RFC 3394 section 4.1: wrap 128 bits of key data with a 128-bit KEK.
KEK_128 = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
KEY_128 = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
WRAPPED_4_1 = bytes.fromhex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")

# RFC 3394 sections 4.3 and 4.6 share this 256-bit KEK.
KEK_256 = bytes.fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
# RFC 3394 section 4.3: wrap 128 bits of key data with a 256-bit KEK.
WRAPPED_4_3 = bytes.fromhex("64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7")
# RFC 3394 section 4.6: wrap 256 bits of key data with a 256-bit KEK.
KEY_256 = bytes.fromhex("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
WRAPPED_4_6 = bytes.fromhex(
    "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"
)

VECTORS = {
    "4.1": (KEK_128, KEY_128, WRAPPED_4_1),
    "4.3": (KEK_256, KEY_128, WRAPPED_4_3),
    "4.6": (KEK_256, KEY_256, WRAPPED_4_6),
}


@pytest.mark.parametrize("section", sorted(VECTORS))
def test_rfc3394_wrap(section, crypto):
    kek, key, wrapped = VECTORS[section]
    assert wrap_key(crypto.ref(kek), key, provider=crypto.provider) == wrapped


@pytest.mark.parametrize("section", sorted(VECTORS))
def test_rfc3394_unwrap(section, crypto):
    kek, key, wrapped = VECTORS[section]
    assert unwrap_key(crypto.ref(kek), wrapped, provider=crypto.provider) == key


@pytest.mark.parametrize("position", range(len(WRAPPED_4_1)))
def test_unwrap_tamper_128_kek(position, crypto):
    wrapped = bytearray(WRAPPED_4_1)
    wrapped[position] ^= 0x80
    with pytest.raises(AuthenticationError):
        unwrap_key(crypto.ref(KEK_128), bytes(wrapped), provider=crypto.provider)


@pytest.mark.parametrize("position", range(len(WRAPPED_4_6)))
def test_unwrap_tamper_256_kek(position, crypto):
    wrapped = bytearray(WRAPPED_4_6)
    wrapped[position] ^= 0x01
    with pytest.raises(AuthenticationError):
        unwrap_key(crypto.ref(KEK_256), bytes(wrapped), provider=crypto.provider)


def test_unwrap_wrong_kek_rejected(crypto):
    p = crypto.provider
    with pytest.raises(AuthenticationError):
        unwrap_key(crypto.ref(KEK_128), WRAPPED_4_3, provider=p)
    with pytest.raises(AuthenticationError):
        unwrap_key(crypto.ref(bytes(32)), WRAPPED_4_6, provider=p)


def test_key_transfer_parameter(crypto):
    data = key_transfer_data(
        crypto.ref(KEK_128), {KeyId.GLOBAL_UNICAST_ENCRYPTION: KEY_128}, provider=crypto.provider
    )
    expected = bytes.fromhex("0101020216000918") + WRAPPED_4_1
    assert encode_data(data) == expected
