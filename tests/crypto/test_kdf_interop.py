"""Suite-1 and suite-2 KDF known-answer vectors from an independent implementation.

Source: the Gurux.DLMS.Net server (commit 6f263019, debug build) logged the
ECDH shared secret Z and its KDF output while accepting pydlms one-pass
Diffie-Hellman general-ciphering requests in
``tests/integration/test_gurux_suite1.py`` (originator system title
``GXClient``, recipient ``4752580000000001``). pydlms must derive the same
key from the same Z; the full 32-octet SHA-256 output is checked against the
SP 800-56A definition as well.

No DLMS UA published vector exists for this KDF;
these cross-implementation vectors are the strongest anchor available.
"""

from __future__ import annotations

import hashlib

import pytest

from pydlms.security import ec
from pydlms.security.suites import SecuritySuite

ORIGINATOR = b"GXClient"
RECIPIENT = bytes.fromhex("4752580000000001")
ALGORITHM_ID_AES_GCM_128 = bytes.fromhex("60857405080300")

VECTORS = [
    (
        "89683B903644A9889C201D2B691424D78C78BBB1A4AE9BA2170E0DC5BA68F494",
        "96BBE3113B781DE9E7282CCE019FA0A3F7A129E4CEB4374CB2D39335D91E6CDF",
    ),
    (
        "59B6EC4A0026C281559FCEA8F476FB48DD7F020502C36B8A4646A0C0FEBB61BF",
        "DBA652DEFD13F2704B0D009E6A6A201188A199E81D84582AC426D13643D10268",
    ),
]


@pytest.mark.parametrize("z,gurux_output", VECTORS)
def test_suite1_kdf_matches_gurux(z, gurux_output):
    z_bytes = bytes.fromhex(z)
    expected = bytes.fromhex(gurux_output)
    key = ec.kdf(SecuritySuite.ECDH_ECDSA_AES_GCM_128_SHA256, z_bytes, ORIGINATOR, RECIPIENT)
    assert key == expected[:16]  # AES-128 content key
    # The whole hash output, from the SP 800-56A single-step definition.
    assert (
        hashlib.sha256(
            b"\x00\x00\x00\x01" + z_bytes + ALGORITHM_ID_AES_GCM_128 + ORIGINATOR + RECIPIENT
        ).digest()
        == expected
    )


# ECDH + KDF end to end, suite 1 and suite 2. Source: the Gurux.DLMS.Net
# library (commit 6f263019) via ``tests/integration/gurux_client`` in ``kdf``
# mode: GXEcdsa.GenerateSecret and GXSecure.GenerateKDF (AlgorithmId
# AesGcm128 / AesGcm256), party U ``GXClient``, party V 4752580000000001.
# Gurux's Cipher1 truncates the suite-2 key to 16 octets, but GenerateKDF
# itself returns the full SHA-384 output; the content key is its first 32.
# The private scalars are test-only values.
ECDH_VECTORS = [
    (
        1,
        0x5A5B5C5D5E5F60616263646566676869707172737475767778797A7B7C7D7E7F,
        0x0F0E0D0C0B0A09080706050403020100F0E0D0C0B0A0908070605040302010F,
        "31BB27DEF23FE1D2D1C730CC29E02BA8CD7002D59CB3063773362B4452E0020F",
        "D7D1785981A83BE61A88E38042CA61B4989B1BF3A51AFDCA16D511F210D5EF4C",
    ),
    (
        2,
        0x6A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F90919293949596,
        0x1F1E1D1C1B1A19181716151413121110F0E0D0C0B0A09080706050403020100F0E0D0C0B0A0908070605040302,
        "BF2AF6F76B2C973F3DEC33DF807AD91ABB4B9BB02E21F98DDEC05BB86732211B"
        "5A3642005216B4342330368B4FEFF41C",
        "04CBF2BFB2776434343FC2605252C55B9E7E09E8679110F73658C621122879C5"
        "3F14B617670955D0B8E657260D81D636",
    ),
]


@pytest.mark.parametrize("suite,own,peer,z,gurux_output", ECDH_VECTORS)
def test_ecdh_and_kdf_match_gurux(suite, own, peer, z, gurux_output):
    from cryptography.hazmat.primitives.asymmetric import ec as cec

    curve = cec.SECP256R1() if suite == 1 else cec.SECP384R1()
    own_key = cec.derive_private_key(own, curve)
    peer_key = cec.derive_private_key(peer, curve)
    shared = ec.ecdh_shared_secret(own_key, peer_key.public_key())
    assert shared == bytes.fromhex(z)
    # ECDH is symmetric: the other party derives the same Z.
    assert ec.ecdh_shared_secret(peer_key, own_key.public_key()) == shared
    key = ec.kdf(suite, shared, ORIGINATOR, RECIPIENT)
    assert len(key) == (16 if suite == 1 else 32)
    assert key == bytes.fromhex(gurux_output)[: len(key)]


def test_party_order_matters():
    z = bytes.fromhex(VECTORS[0][0])
    swapped = ec.kdf(SecuritySuite.ECDH_ECDSA_AES_GCM_128_SHA256, z, RECIPIENT, ORIGINATOR)
    assert swapped != bytes.fromhex(VECTORS[0][1])[:16]
