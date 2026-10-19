"""general-ciphering (0xDD) and general-signing (0xDF)."""

from __future__ import annotations

import pytest

from pydlms.exceptions import AuthenticationError, DecodeError, KeyMissingError
from pydlms.security import ec
from pydlms.security.ciphering import unwrap
from pydlms.security.context import SecurityContext
from pydlms.security.general import (
    ONE_PASS_DH,
    STATIC_UNIFIED_MODEL,
    KeyInfo,
    unwrap_general_ciphering,
    verify_general_signing,
    wrap_general_ciphering,
    wrap_general_signing,
)
from pydlms.security.suites import SecurityControl, SecuritySuite
from tests.crypto.vectors import GB_PLAINTEXT

CLIENT, SERVER = b"CLIENT01", b"SERVER01"


def pair(suite=SecuritySuite.ECDH_ECDSA_AES_GCM_128_SHA256, **kw):
    """A client and a server context holding each other's public keys.

    ``kw`` goes to both contexts (e.g. ``general_aad``, ``signing_form``).
    """
    n = 32 if suite == SecuritySuite.ECDH_ECDSA_AES_GCM_256_SHA384 else 16
    ek, ak, kek = bytes(range(n)), bytes(range(16, 32)), bytes(range(40, 40 + n))
    keys = {
        role: (ec.generate_private_key(suite), ec.generate_private_key(suite))
        for role in ("client", "server")
    }
    client = SecurityContext(
        ek,
        ak,
        client_system_title=CLIENT,
        suite=suite,
        master_key=kek,
        broadcast_key=bytes(reversed(range(n))),
        signing_key=keys["client"][0],
        key_agreement_key=keys["client"][1],
        peer_signing_key=keys["server"][0].public_key(),
        peer_key_agreement_key=keys["server"][1].public_key(),
        **kw,
    )
    server = SecurityContext(
        ek,
        ak,
        client_system_title=SERVER,
        suite=suite,
        master_key=kek,
        broadcast_key=bytes(reversed(range(n))),
        signing_key=keys["server"][0],
        key_agreement_key=keys["server"][1],
        peer_signing_key=keys["client"][0].public_key(),
        peer_key_agreement_key=keys["client"][1].public_key(),
        **kw,
    )
    return client, server


KINDS = [
    KeyInfo("none"),
    KeyInfo("identified", 0),
    KeyInfo("identified", 1),
    KeyInfo("wrapped"),
    KeyInfo("agreed", scheme=ONE_PASS_DH),
    KeyInfo("agreed", scheme=STATIC_UNIFIED_MODEL),
]


@pytest.mark.parametrize(
    "suite",
    [SecuritySuite.ECDH_ECDSA_AES_GCM_128_SHA256, SecuritySuite.ECDH_ECDSA_AES_GCM_256_SHA384],
    ids=["suite1", "suite2"],
)
@pytest.mark.parametrize("info", KINDS, ids=[f"{k.kind}-{k.key_id}-{k.scheme}" for k in KINDS])
def test_round_trip_between_independent_contexts(suite, info):
    client, server = pair(suite)
    apdu = wrap_general_ciphering(client, GB_PLAINTEXT, SERVER, info, transaction_id=b"\x00" * 8)
    result = unwrap(server, apdu)
    assert result.plaintext == GB_PLAINTEXT
    assert result.system_title == CLIENT and result.authenticated


def test_one_pass_dh_wire_layout_matches_reference():
    client, _ = pair()
    apdu = wrap_general_ciphering(client, GB_PLAINTEXT, SERVER, KeyInfo("agreed"))
    # DD | 00 | 08 orig | 08 recip | 00 | 00 | 01 02 01 01 | 81 80 X||Y||r||s | content
    head = bytes.fromhex("DD00") + b"\x08" + CLIENT + b"\x08" + SERVER + bytes.fromhex("0000")
    assert apdu.startswith(head + bytes.fromhex("0102010181 80".replace(" ", "")))
    content_len_at = len(head) + 6 + 128
    assert apdu[content_len_at + 1] == 0x31  # SC: auth+enc, suite 1


def test_one_pass_dh_forged_ephemeral_signature_rejected():
    client, server = pair()
    apdu = bytearray(wrap_general_ciphering(client, GB_PLAINTEXT, SERVER, KeyInfo("agreed")))
    signature_at = 1 + 1 + 9 + 9 + 1 + 1 + 4 + 2 + 64
    apdu[signature_at] ^= 0x01
    with pytest.raises(AuthenticationError):
        unwrap(server, bytes(apdu))


def test_one_pass_dh_requires_peer_signing_key_unless_relaxed():
    client, server = pair()
    apdu = wrap_general_ciphering(client, GB_PLAINTEXT, SERVER, KeyInfo("agreed"))
    server.peer_signing_key = None
    with pytest.raises(KeyMissingError, match="peer_signing_key"):
        unwrap(server, apdu)
    server.allow_unverified_auth = True
    assert unwrap(server, apdu).plaintext == GB_PLAINTEXT


@pytest.mark.parametrize("info", KINDS, ids=[f"{k.kind}-{k.key_id}-{k.scheme}" for k in KINDS])
def test_every_ciphertext_and_tag_flip_rejected(info):
    client, server = pair()
    apdu = wrap_general_ciphering(client, GB_PLAINTEXT, SERVER, info)
    tail = len(GB_PLAINTEXT) + 12
    for position in range(len(apdu) - tail, len(apdu)):
        tampered = bytearray(apdu)
        tampered[position] ^= 0x01
        # A failed tag never advances the stored counter, so one server suffices.
        with pytest.raises(AuthenticationError):
            unwrap(server, bytes(tampered))
    assert unwrap(server, apdu).plaintext == GB_PLAINTEXT


def test_wrong_master_key_rejected():
    client, server = pair()
    apdu = wrap_general_ciphering(client, GB_PLAINTEXT, SERVER, KeyInfo("wrapped"))
    server.master_key = bytes(16)
    with pytest.raises(AuthenticationError):
        unwrap(server, apdu)


def test_missing_key_material():
    client, _ = pair()
    client.peer_key_agreement_key = None
    with pytest.raises(KeyMissingError, match="peer_key_agreement_key"):
        wrap_general_ciphering(client, GB_PLAINTEXT, SERVER, KeyInfo("agreed"))
    with pytest.raises(ValueError):
        wrap_general_ciphering(client, GB_PLAINTEXT, b"short", KeyInfo("identified"))
    with pytest.raises(ValueError):
        wrap_general_ciphering(client, GB_PLAINTEXT, SERVER, KeyInfo("bogus"))


@pytest.mark.parametrize(
    "raw",
    [
        "DD00",
        "DD0007" + "00" * 7 + "08" + "00" * 8 + "0000" + "00" + "00",  # 7-octet originator
        "DD0008" + "00" * 8 + "08" + "00" * 8 + "0000" + "02",  # presence flag 2
        "DD0008" + "00" * 8 + "08" + "00" * 8 + "0000" + "0109",  # unknown choice
        "DD0008" + "00" * 8 + "08" + "00" * 8 + "0000" + "010002",  # key-id 2
        "DD0008" + "00" * 8 + "08" + "00" * 8 + "0000" + "0102020101" + "00",  # 2-octet params
        "DD0008" + "00" * 8 + "08" + "00" * 8 + "0000" + "01020107" + "00",  # unknown scheme
        "DD0008" + "00" * 8 + "08" + "00" * 8 + "0000" + "01020102" + "0101",  # SUM with data
    ],
)
def test_malformed_general_ciphering(raw):
    _, server = pair()
    with pytest.raises(DecodeError):
        unwrap_general_ciphering(server, bytes.fromhex(raw))


def test_general_signing_round_trip_plain_and_ciphered():
    client, server = pair()
    signed = wrap_general_signing(client, GB_PLAINTEXT, SERVER, transaction_id=b"\x01" * 8)
    originator, content = verify_general_signing(server, signed)
    assert (originator, content) == (CLIENT, GB_PLAINTEXT)
    assert unwrap(server, signed).plaintext == GB_PLAINTEXT
    # Signing around a ciphered APDU: unwrap verifies, then deciphers.
    inner = wrap_general_ciphering(client, GB_PLAINTEXT, SERVER, KeyInfo("identified"))
    assert unwrap(server, wrap_general_signing(client, inner, SERVER)).plaintext == GB_PLAINTEXT


def test_general_signing_tamper_and_missing_key():
    client, server = pair()
    signed = wrap_general_signing(client, GB_PLAINTEXT, SERVER)
    for position in range(1, len(signed) - 66):  # header and content, not the signature
        tampered = bytearray(signed)
        tampered[position] ^= 0x01
        with pytest.raises((AuthenticationError, DecodeError)):
            verify_general_signing(server, bytes(tampered))
    server.peer_signing_key = None
    with pytest.raises(KeyMissingError):
        verify_general_signing(server, signed)


def test_sc_broadcast_bit_follows_identified_key():
    client, server = pair()
    apdu = wrap_general_ciphering(client, GB_PLAINTEXT, SERVER, KeyInfo("identified", 1))
    assert unwrap(server, apdu).security_control.broadcast_key
    assert SecurityControl.from_byte(0x71).broadcast_key


def test_general_signing_without_signature_rejected():
    """Regression: the Gurux server can emit DF ... content with no signature."""
    client, server = pair()
    signed = wrap_general_signing(client, GB_PLAINTEXT, SERVER)
    unsigned = signed[: -(1 + 64)]  # drop "40" + r||s
    with pytest.raises(DecodeError, match="no signature"):
        verify_general_signing(server, unsigned)


# --- general-signing freshness -----------------------------------------------------------

P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def test_signed_plain_apdu_cannot_be_replayed():
    """A signed plain APDU carries no invocation counter: an exact replay of
    a verified one is refused within the context."""
    from pydlms.exceptions import ReplayError

    client, server = pair()
    signed = wrap_general_signing(client, GB_PLAINTEXT, SERVER)
    assert unwrap(server, signed).plaintext == GB_PLAINTEXT
    with pytest.raises(ReplayError, match="general-signing"):
        unwrap(server, signed)
    # The same content signed again (fresh ECDSA nonce) is a new APDU.
    assert unwrap(server, wrap_general_signing(client, GB_PLAINTEXT, SERVER)).authenticated


def test_signature_malleation_is_still_a_replay():
    """(r, n - s) verifies too; the replay check keys on the message and r."""
    from pydlms.exceptions import ReplayError

    client, server = pair()
    signed = wrap_general_signing(client, GB_PLAINTEXT, SERVER)
    unwrap(server, signed)
    r, s = signed[-64:-32], int.from_bytes(signed[-32:], "big")
    malleated = signed[:-64] + r + (P256_ORDER - s).to_bytes(32, "big")
    header_end = len(signed) - 65 - len(GB_PLAINTEXT) - 1
    message = signed[1:header_end] + GB_PLAINTEXT
    ec.ecdsa_verify(client.signing_key.public_key(), message, malleated[-64:])  # still valid
    with pytest.raises(ReplayError):
        unwrap(server, malleated)


def test_signed_replay_memory_is_bounded():
    """Documented limit: only the last ``signed_replay_window`` APDUs."""
    client, server = pair()
    server.signed_replay_window = 2
    first = wrap_general_signing(client, GB_PLAINTEXT, SERVER)
    unwrap(server, first)
    unwrap(server, wrap_general_signing(client, GB_PLAINTEXT, SERVER))
    unwrap(server, wrap_general_signing(client, GB_PLAINTEXT, SERVER))
    assert unwrap(server, first).plaintext == GB_PLAINTEXT  # evicted: accepted again
