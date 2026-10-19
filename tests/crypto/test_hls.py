"""HLS mechanism vectors and negative tests.

The GMAC, AES (mechanism 2) and ECDSA cases run through the SoftwareProvider
and the HandleProvider (``crypto`` fixture) with identical expectations.
"""

from __future__ import annotations

import hashlib

import pytest

from pydlms.exceptions import AuthenticationError, DecodeError
from pydlms.security import ec, hls
from pydlms.security.suites import SecuritySuite
from tests.crypto.vectors import (
    GB_AK,
    GB_EK,
    GB_HLS_CLIENT_TITLE,
    GB_HLS_CTOS,
    GB_HLS_F_CTOS,
    GB_HLS_F_STOC,
    GB_HLS_SERVER_TITLE,
    GB_HLS_STOC,
)


def test_gmac_client_response_greenbook(crypto):
    # Client: own system title and own IC (1) over StoC.
    ek, ak = crypto.ref(GB_EK), crypto.ref(GB_AK)
    out = hls.hls_gmac(ek, ak, GB_HLS_CLIENT_TITLE, 1, GB_HLS_STOC, provider=crypto.provider)
    assert out == GB_HLS_F_STOC
    assert len(out) == 17


def _verify(crypto, response, ek=GB_EK, ak=GB_AK, title=GB_HLS_SERVER_TITLE, suite=None):
    return hls.verify_hls_gmac(
        crypto.ref(ek),
        crypto.ref(ak),
        title,
        GB_HLS_CTOS,
        response,
        suite=suite,
        provider=crypto.provider,
    )


def test_gmac_server_response_verifies(crypto):
    assert _verify(crypto, GB_HLS_F_CTOS) == 0x01234567


@pytest.mark.parametrize("position", range(17))
def test_gmac_tampered_server_response_rejected(position, crypto):
    bad = bytearray(GB_HLS_F_CTOS)
    bad[position] ^= 0x01
    with pytest.raises((AuthenticationError, DecodeError)):
        _verify(crypto, bytes(bad))


def test_gmac_response_of_another_suite_rejected(crypto):
    _verify(crypto, GB_HLS_F_CTOS, suite=0)
    with pytest.raises(AuthenticationError, match="suite 1"):
        _verify(crypto, GB_HLS_F_CTOS, suite=1)


def test_gmac_wrong_key_or_title_rejected(crypto):
    with pytest.raises(AuthenticationError):
        _verify(crypto, GB_HLS_F_CTOS, ek=bytes(16))
    with pytest.raises(AuthenticationError):
        _verify(crypto, GB_HLS_F_CTOS, ak=bytes(16))
    with pytest.raises(AuthenticationError):
        _verify(crypto, GB_HLS_F_CTOS, title=GB_HLS_CLIENT_TITLE)
    with pytest.raises(DecodeError):
        _verify(crypto, GB_HLS_F_CTOS[:-1])


def test_md5_and_sha1_are_challenge_then_secret():
    secret = b"secret"
    challenge = b"0123456789ABCDEF"
    assert hls.hls_md5(challenge, secret) == hashlib.md5(challenge + secret).digest()  # noqa: S324
    assert hls.hls_sha1(challenge, secret) == hashlib.sha1(challenge + secret).digest()  # noqa: S324
    assert hls.hash_response(hls.Mechanism.HLS_MD5, challenge, secret) == hls.hls_md5(
        challenge, secret
    )
    with pytest.raises(ValueError):
        hls.hash_response(hls.Mechanism.HLS_GMAC, challenge, secret)


def test_md5_wrong_secret_differs():
    c = b"challenge-bytes!"
    assert hls.hls_md5(c, b"right") != hls.hls_md5(c, b"wrong")


def test_sha256_argument_order_is_mirrored():
    secret, stc, sts = b"S" * 16, b"C" * 8, b"V" * 8
    stoc, ctos = b"s" * 16, b"c" * 16
    client = hls.hls_sha256(secret, stc, sts, stoc, ctos)
    assert client == hashlib.sha256(secret + stc + sts + stoc + ctos).digest()
    server = hls.hls_sha256(secret, sts, stc, ctos, stoc)
    assert server == hashlib.sha256(secret + sts + stc + ctos + stoc).digest()
    assert client != server


def test_ecdsa_mechanism_round_trip_and_tamper(crypto):
    suite = SecuritySuite.ECDH_ECDSA_AES_GCM_128_SHA256
    client_key = ec.generate_private_key(suite)
    stc, sts, stoc, ctos = b"C" * 8, b"V" * 8, b"s" * 16, b"c" * 16
    sig = hls.hls_ecdsa_sign(
        crypto.ref(client_key), stc, sts, stoc, ctos, provider=crypto.provider, suite=suite
    )
    # Server verifies the client: client's title and received challenge first.
    hls.hls_ecdsa_verify(client_key.public_key(), stc, sts, stoc, ctos, sig)
    with pytest.raises(AuthenticationError):
        hls.hls_ecdsa_verify(client_key.public_key(), sts, stc, stoc, ctos, sig)


def test_challenge_generation():
    a = hls.generate_challenge()
    assert len(a) == 16 and a != hls.generate_challenge()
    with pytest.raises(ValueError):
        hls.generate_challenge(7)
    with pytest.raises(ValueError):
        hls.generate_challenge(65)


def test_mechanism_oid():
    assert hls.mechanism_oid(hls.Mechanism.HLS_GMAC) == bytes.fromhex("60857405080205")
    assert hls.Mechanism.HLS_GMAC.is_hls and not hls.Mechanism.LLS.is_hls


def test_manufacturer_aes_fips197_kat(crypto):
    # FIPS-197 Appendix C.1: AES-128 of 00112233..FF under key 000102..0F.
    key = crypto.ref(bytes.fromhex("000102030405060708090A0B0C0D0E0F"))
    challenge = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    out = hls.hls_manufacturer_aes(challenge, key, provider=crypto.provider)
    assert out == bytes.fromhex("69C4E0D86A7B0430D8CDB78070B4C55A")
    # Two blocks: each one encrypted on its own (ECB).
    two = hls.hls_manufacturer_aes(challenge * 2, key, provider=crypto.provider)
    assert two == out * 2


def test_manufacturer_aes_padding_rules():
    key = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    # Short secret and challenge are zero padded; output is block aligned.
    short = hls.hls_manufacturer_aes(b"\x00\x11", b"\x00\x01")
    assert len(short) == 16
    assert short == hls.hls_manufacturer_aes(b"\x00\x11" + bytes(14), b"\x00\x01" + bytes(14))
    assert len(hls.hls_manufacturer_aes(bytes(17), key)) == 32
    assert hls.hls_manufacturer_aes(bytes(16), key) != hls.hls_manufacturer_aes(
        bytes(16), bytes(16)
    )
