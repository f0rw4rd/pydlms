"""Suite 2 (P-384, SHA-384, AES-GCM-256) inbound general-ciphering and
general-signing APDUs built by the Gurux.DLMS.Net client library.

Same harness and conventions as ``test_gurux_general_frames.py`` (suite 1);
the harness selects suite 2 from the P-384 signing key and uses the 32-octet
EK and AK below. Upstream Gurux cannot build suite-2 0xDD at all: it
truncates the agreed key to 16 octets and hardcodes the one-pass DH
key-ciphered-data length to 0x80; ``tests/integration/gurux_client/Dockerfile``
patches both (fixes 4 and 5) without touching the rest of the encoding.
"""

from __future__ import annotations

import pytest

from pydlms.exceptions import AuthenticationError, DecodeError, SecurityError
from pydlms.security.ciphering import unwrap
from pydlms.security.context import SecurityContext

ec = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ec")

# Test-only P-384 scalars. Never used anywhere else.
GURUX_SIGNING = int(
    "11223344556677889900AABBCCDDEEFF00112233445566778899AABBCCDDEEFF0011223344556677889900AABB", 16
)
RECIPIENT_KA = int(
    "2233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDD", 16
)
RECIPIENT_SIGNING = int(
    "33445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEE", 16
)
GURUX_KA = int(
    "7A5566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF01020304",
    16,
)

EK = bytes.fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
AK = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF")

FRAMES = {
    "general-ciphering": bytes.fromhex(
        "dd00084758436c69656e7408475258000000000100000102010181c043140430270b47b5ca5327ed3961"
        "00553aca0fdb1fa84f78ded3a2d77fa99dceedb30ee0b2085b4c27cbae85bec1fe8df782e66d63e6df9b"
        "9b2690b6d57bf65276600d9c42a47ba148d11f03f7156ecc6098fcf6f64d1d1c99b8b4dc03b1d095e57b"
        "20e340ba9cfb41e62d9751bb010d36e02450826da41c8063906cbc1b167e9987fe40ac39244b06d2ac3a"
        "0997722144ed9630a58fa2755bf9a8628fadf6e077a6d139b3559c1a0669322d47d6b9580e620469a525"
        "0020ed8c2c14ece195491e320000004d1bb7c151c33e4b5f05ff22bcf99edab7705fac167d10dc1782"
    ),
    "general-signing": bytes.fromhex(
        "df00084758436c69656e74084752580000000001000020c81e320000004d60dcee21f0033cc1b4289e14"
        "39ba59b8dec5f947288be747fc603a26bd4fe976ed0fa33fc03f34c57e85b4746df944cd917dd16d50c1"
        "f8e13bec30aa3b7c1d5c282cfb90b4f8fe364aaf0d7021dbc61b26dee7b54dcab2361cc8f653f50c383a"
        "5631107201c0aaaf51118475df6c24d21ef8d92bbe94965cbb2d"
    ),
    "static-unified": bytes.fromhex(
        "dd080102030405060708084758436c69656e74084752580000000001000001020102001e320000004d"
        "f23e58a59d7e09c6ecb4fff60a244f9d31f19137db14cf18a3"
    ),
}
INNER_TAG = {"general-ciphering": 0xDD, "general-signing": 0xC8, "static-unified": 0xDD}
PLAINTEXT = bytes.fromhex("c001c1000100002a0000ff0200")


def _key(scalar: int):
    return ec.derive_private_key(scalar, ec.SECP384R1())


def _ctx(**overrides) -> SecurityContext:
    kwargs = {
        "client_system_title": bytes.fromhex("4752580000000001"),
        "server_system_title": b"GXClient",
        "suite": 2,
        "key_agreement_key": _key(RECIPIENT_KA),
        "peer_signing_key": _key(GURUX_SIGNING).public_key(),
        "peer_key_agreement_key": _key(GURUX_KA).public_key(),
    }
    kwargs.update(overrides)
    return SecurityContext(EK, AK, **kwargs)


def test_one_pass_dh_carries_p384_point_and_signature():
    # 0x81 0xC0: 192 octets = 96-octet ephemeral point + 96-octet signature.
    assert FRAMES["general-ciphering"][26:28] == b"\x81\xc0"


@pytest.mark.parametrize("mode", FRAMES)
def test_gurux_suite2_frame_decrypts_and_verifies(mode):
    result = unwrap(_ctx(), FRAMES[mode])
    assert result.tag == INNER_TAG[mode]
    assert result.authenticated
    assert result.security_control.suite == 2
    assert result.plaintext == PLAINTEXT


@pytest.mark.parametrize("mode", ["general-ciphering", "general-signing"])
def test_gurux_suite2_frame_rejected_with_wrong_signing_key(mode):
    with pytest.raises(AuthenticationError):
        unwrap(_ctx(peer_signing_key=_key(RECIPIENT_SIGNING).public_key()), FRAMES[mode])


def test_gurux_suite2_static_unified_rejected_with_wrong_peer_agreement_key():
    wrong = _key(RECIPIENT_SIGNING).public_key()
    with pytest.raises(AuthenticationError):
        unwrap(_ctx(peer_key_agreement_key=wrong), FRAMES["static-unified"])


@pytest.mark.parametrize(
    "mode,position", [(mode, pos) for mode, data in FRAMES.items() for pos in range(len(data))]
)
def test_gurux_suite2_frame_every_byte_flip_rejected(mode, position):
    tampered = bytearray(FRAMES[mode])
    tampered[position] ^= 0x01
    with pytest.raises((SecurityError, DecodeError)):
        unwrap(_ctx(), bytes(tampered))
