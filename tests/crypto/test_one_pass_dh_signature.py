"""One-pass Diffie-Hellman: what the ephemeral-key signature covers.

Known answer: IEC 62056-5-3:2023 annex I.2 (data in ``vectors.py``). The
client signs its ephemeral public key as the bare point ``X || Y``; the
signature does not verify over ``01 || X || Y`` (the key-agreement scheme id
prepended, the form Gurux.DLMS.Net produces, GXSecure.cs
GetEphemeralPublicKeyData @ 6f263019). pydlms signs ``X || Y`` and accepts
both forms inbound so Gurux peers keep working; the Gurux server does not
verify this signature on general-ciphering at all (by reading, GXSecure.cs
@ 6f263019), and ``tests/integration/test_gurux_suite1.py`` shows it accepts
ours.
"""

from __future__ import annotations

import pytest

from pydlms.exceptions import AuthenticationError
from pydlms.security import ec
from pydlms.security.ciphering import unwrap
from pydlms.security.general import (
    ONE_PASS_DH,
    KeyInfo,
    verify_ephemeral_signature,
    wrap_general_ciphering,
)
from tests.crypto.test_general import SERVER, pair
from tests.crypto.vectors import (
    GB_PLAINTEXT,
    I2_CLIENT_SIGNING_PRIVATE,
    I2_CLIENT_SIGNING_PUBLIC,
    I2_EPHEMERAL_PRIVATE,
    I2_KEY_CIPHERED_DATA,
)

POINT, SIGNATURE = I2_KEY_CIPHERED_DATA[:64], I2_KEY_CIPHERED_DATA[64:]


def _public(scalar: int):
    from cryptography.hazmat.primitives.asymmetric import ec as hazmat_ec

    return hazmat_ec.derive_private_key(scalar, hazmat_ec.SECP256R1()).public_key()


def test_transcription_is_consistent():
    """The example's public keys follow from its private keys."""
    assert ec.public_key_bytes(_public(I2_CLIENT_SIGNING_PRIVATE)) == I2_CLIENT_SIGNING_PUBLIC
    assert ec.public_key_bytes(_public(I2_EPHEMERAL_PRIVATE)) == POINT


def test_annex_i2_signature_covers_the_bare_point():
    signer = ec.load_public_key(1, I2_CLIENT_SIGNING_PUBLIC)
    ec.ecdsa_verify(signer, POINT, SIGNATURE)
    with pytest.raises(AuthenticationError):
        ec.ecdsa_verify(signer, bytes([ONE_PASS_DH]) + POINT, SIGNATURE)
    verify_ephemeral_signature(signer, POINT, SIGNATURE)


@pytest.mark.parametrize("position", range(128))
def test_annex_i2_every_byte_flip_rejected(position):
    signer = ec.load_public_key(1, I2_CLIENT_SIGNING_PUBLIC)
    data = bytearray(I2_KEY_CIPHERED_DATA)
    data[position] ^= 0x01
    with pytest.raises(AuthenticationError):
        verify_ephemeral_signature(signer, bytes(data[:64]), bytes(data[64:]))


def test_gurux_form_with_scheme_prefix_is_accepted():
    key = ec.generate_private_key(1)
    point = ec.public_key_bytes(ec.generate_private_key(1))
    gurux = ec.ecdsa_sign(key, bytes([ONE_PASS_DH]) + point)
    verify_ephemeral_signature(key.public_key(), point, gurux)
    other_prefix = ec.ecdsa_sign(key, b"\x00" + point)
    with pytest.raises(AuthenticationError):
        verify_ephemeral_signature(key.public_key(), point, other_prefix)
    with pytest.raises(AuthenticationError):
        verify_ephemeral_signature(ec.generate_private_key(1).public_key(), point, gurux)


def test_outbound_signs_the_bare_point():
    client, server = pair()
    apdu = wrap_general_ciphering(client, GB_PLAINTEXT, SERVER, KeyInfo("agreed"))
    at = 1 + 1 + 9 + 9 + 1 + 1 + 4 + 2
    point, signature = apdu[at : at + 64], apdu[at + 64 : at + 128]
    ec.ecdsa_verify(client.signing_key.public_key(), point, signature)
    assert unwrap(server, apdu).plaintext == GB_PLAINTEXT
