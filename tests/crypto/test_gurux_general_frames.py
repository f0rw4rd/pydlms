"""Inbound general-ciphering (0xDD) and general-signing (0xDF) APDUs built by
an independent implementation.

Source: the Gurux.DLMS.Net client library (commit 6f263019) built by
``tests/integration/gurux_client/Dockerfile``, run with the fixed test keys
below (originator ``GXClient``, recipient ``4752580000000001``, suite 1,
SC 0x30, invocation counter 77). Gurux generated its ephemeral key and both
ECDSA signatures (the static-unified frame has neither); pydlms must derive the same agreed key, verify the
ephemeral-key signature and the APDU signature, and decrypt. The live
variant with fresh keys is ``tests/integration/test_gurux_client.py``.

Regenerate: run that image with ``MODE f"{GURUX_SIGNING:064x}"`` and the
public X||Y hex of ``RECIPIENT_KA`` and ``RECIPIENT_SIGNING``; strip the
8-octet wrapper header.
"""

from __future__ import annotations

import pytest

from pydlms.apdu.xdlms import GetRequestNormal, decode_apdu
from pydlms.exceptions import AuthenticationError, DecodeError, KeyMissingError, SecurityError
from pydlms.obis import ObisCode
from pydlms.security.ciphering import unwrap
from pydlms.security.context import SecurityContext

ec = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ec")

# Test-only P-256 scalars. Never used anywhere else.
GURUX_SIGNING = 0x1F2E3D4C5B6A79880102030405060708090A0B0C0D0E0F101112131415161718
RECIPIENT_KA = 0x2A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F70819
RECIPIENT_SIGNING = 0x3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F8091A2
GURUX_KA = 0x4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3

EK = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
AK = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")

GENERAL_CIPHERING = bytes.fromhex(
    "dd00084758436c69656e74084752580000000001000001020101818036d3f1cf278726f53a19b1896601"
    "d85b80a1846b119b1d22ddbf105019a8f43886c1c8f109e723375286a9e7990b5dfa3e9b93999a3a964c"
    "1f74b3e879284863bff1cae13452b65a02a26d33b73690e1e0a1a903c6a55cca6ceaaa0f32f5ad18fd0b"
    "8f243a3916aca169f3ea9cb1220123b90c7734773f325d3efceace7cb85b1e310000004d4e74beab3243"
    "51f49494b1dbd0071a4df5f64e9405d2b9e63e"
)
GENERAL_SIGNING = bytes.fromhex(
    "df00084758436c69656e74084752580000000001000020c81e310000004da18b61a0d45a8acd7541c200"
    "dd5f99f2e8ef45cdf4f4368e5e40afe51030a3aea59eadbbdcce5e9ad28f6c9f41da8e3958af0db8166e"
    "035f2b1778f25edf1b8230cf4a527699252b63069dfdbd74c03a8a92a775a4114956e6a3"
)
# Static unified model (key-id 2), transaction-id 0102030405060708: no
# ephemeral key and no signature; both parties' static key-agreement keys.
STATIC_UNIFIED = bytes.fromhex(
    "dd080102030405060708084758436c69656e74084752580000000001000001020102001e310000004d"
    "ece09a28ffc78af82b5506242b1e44a113fed0edc5645c9f7c"
)
FRAMES = {
    "general-ciphering": GENERAL_CIPHERING,
    "general-signing": GENERAL_SIGNING,
    "static-unified": STATIC_UNIFIED,
}
SIGNED = ["general-ciphering", "general-signing"]
# unwrap reports the innermost ciphered tag: 0xDD itself, or the glo-get-request
# (0xC8) that Gurux wrapped in its 0xDF.
INNER_TAG = {"general-ciphering": 0xDD, "general-signing": 0xC8, "static-unified": 0xDD}
# GET 0.0.42.0.0.255 attribute 2, invoke-id-and-priority 0xC1, as Gurux built it.
PLAINTEXT = bytes.fromhex("c001c1000100002a0000ff0200")


def _key(scalar: int):
    return ec.derive_private_key(scalar, ec.SECP256R1())


def _ctx(**overrides) -> SecurityContext:
    kwargs = {
        "client_system_title": bytes.fromhex("4752580000000001"),
        "server_system_title": b"GXClient",
        "suite": 1,
        "key_agreement_key": _key(RECIPIENT_KA),
        "peer_signing_key": _key(GURUX_SIGNING).public_key(),
        "peer_key_agreement_key": _key(GURUX_KA).public_key(),
    }
    kwargs.update(overrides)
    return SecurityContext(EK, AK, **kwargs)


@pytest.mark.parametrize("mode", FRAMES)
def test_gurux_frame_decrypts_and_verifies(mode):
    result = unwrap(_ctx(), FRAMES[mode])
    assert result.tag == INNER_TAG[mode]
    assert result.authenticated
    assert result.plaintext == PLAINTEXT
    request = decode_apdu(result.plaintext)
    assert isinstance(request, GetRequestNormal)
    assert request.attribute.instance_id == ObisCode.parse("0.0.42.0.0.255")


@pytest.mark.parametrize("mode", SIGNED)
def test_gurux_frame_rejected_with_wrong_signing_key(mode):
    with pytest.raises(AuthenticationError):
        unwrap(_ctx(peer_signing_key=_key(RECIPIENT_SIGNING).public_key()), FRAMES[mode])


@pytest.mark.parametrize("mode", ["general-ciphering", "static-unified"])
def test_gurux_frame_rejected_with_wrong_own_agreement_key(mode):
    with pytest.raises(AuthenticationError):
        unwrap(_ctx(key_agreement_key=_key(RECIPIENT_SIGNING)), FRAMES[mode])


def test_gurux_static_unified_rejected_with_wrong_peer_agreement_key():
    wrong = _key(RECIPIENT_SIGNING).public_key()
    with pytest.raises(AuthenticationError):
        unwrap(_ctx(peer_key_agreement_key=wrong), STATIC_UNIFIED)


def test_gurux_static_unified_needs_peer_agreement_key():
    with pytest.raises(KeyMissingError):
        unwrap(_ctx(peer_key_agreement_key=None), STATIC_UNIFIED)


@pytest.mark.parametrize("mode", SIGNED)
def test_gurux_frame_needs_peer_signing_key(mode):
    with pytest.raises(KeyMissingError):
        unwrap(_ctx(peer_signing_key=None), FRAMES[mode])


@pytest.mark.parametrize(
    "mode,position", [(mode, pos) for mode, data in FRAMES.items() for pos in range(len(data))]
)
def test_gurux_frame_every_byte_flip_rejected(mode, position):
    tampered = bytearray(FRAMES[mode])
    tampered[position] ^= 0x01
    with pytest.raises((SecurityError, DecodeError)):
        unwrap(_ctx(), bytes(tampered))
