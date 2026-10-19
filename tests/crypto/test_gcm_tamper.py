"""Tamper tests: flipping any byte of an authenticated APDU
must raise AuthenticationError and must not return plaintext.

Parametrized over every byte position of the Green Book example in both
authenticated modes, and over every byte of a real L+G E450 auth+enc push,
each through the SoftwareProvider and the HandleProvider (``crypto``
fixture, tests/crypto/conftest.py).
"""

from __future__ import annotations

import pytest

from pydlms.exceptions import AuthenticationError, DecodeError, SecurityError
from pydlms.security import gcm
from pydlms.security.ciphering import unwrap, wrap_general_glo
from pydlms.security.context import SecurityContext
from pydlms.security.suites import SecurityControl
from tests.crypto.real_frames import e450_ciphered_apdu
from tests.crypto.vectors import GB_AK, GB_EK, GB_IC, GB_PLAINTEXT, GB_SYSTEM_TITLE

AUTH_ENC = SecurityControl.from_byte(0x30)
AUTH_ONLY = SecurityControl.from_byte(0x10)

PROTECTED = {
    "auth+enc": gcm.encrypt(AUTH_ENC, GB_EK, GB_AK, GB_SYSTEM_TITLE, GB_IC, GB_PLAINTEXT),
    "auth-only": gcm.encrypt(AUTH_ONLY, GB_EK, GB_AK, GB_SYSTEM_TITLE, GB_IC, GB_PLAINTEXT),
}
CASES = [
    (mode, pos, bit)
    for mode, data in PROTECTED.items()
    for pos in range(len(data))
    for bit in (0x01, 0x80)
]


@pytest.mark.parametrize("mode,position,bit", CASES)
def test_flipped_byte_raises(mode, position, bit, crypto):
    sc = AUTH_ENC if mode == "auth+enc" else AUTH_ONLY
    tampered = bytearray(PROTECTED[mode])
    tampered[position] ^= bit
    ek, ak = crypto.ref(GB_EK), crypto.ref(GB_AK)
    with pytest.raises(AuthenticationError):
        gcm.decrypt(sc, ek, ak, GB_SYSTEM_TITLE, GB_IC, bytes(tampered), provider=crypto.provider)


@pytest.mark.parametrize("mode", ["auth+enc", "auth-only"])
def test_wrong_iv_inputs_raise(mode, crypto):
    sc = AUTH_ENC if mode == "auth+enc" else AUTH_ONLY
    data = PROTECTED[mode]
    ek, ak, p = crypto.ref(GB_EK), crypto.ref(GB_AK), crypto.provider
    with pytest.raises(AuthenticationError):
        gcm.decrypt(sc, ek, ak, GB_SYSTEM_TITLE, GB_IC + 1, data, provider=p)
    with pytest.raises(AuthenticationError):
        gcm.decrypt(sc, ek, ak, bytes(8), GB_IC, data, provider=p)
    # A different SC changes the AAD.
    other = SecurityControl.from_byte(sc.to_byte() | 0x01)
    with pytest.raises(AuthenticationError):
        gcm.decrypt(other, ek, ak, GB_SYSTEM_TITLE, GB_IC, data, provider=p)
    # So does another authentication key (it is in the AAD).
    with pytest.raises(AuthenticationError):
        gcm.decrypt(sc, ek, crypto.ref(bytes(16)), GB_SYSTEM_TITLE, GB_IC, data, provider=p)


def test_truncated_tag_raises(crypto):
    ek, ak = crypto.ref(GB_EK), crypto.ref(GB_AK)
    with pytest.raises(AuthenticationError):
        gcm.decrypt(
            AUTH_ENC, ek, ak, GB_SYSTEM_TITLE, GB_IC, b"\x00" * 11, provider=crypto.provider
        )


E450 = e450_ciphered_apdu()


def _e450_ctx(crypto=None):
    if crypto is None:
        return SecurityContext(E450.encryption_key, E450.authentication_key)
    return SecurityContext(
        crypto.ref(E450.encryption_key),
        crypto.ref(E450.authentication_key),
        provider=crypto.provider,
    )


def test_real_e450_push_authenticates(crypto):
    result = unwrap(_e450_ctx(crypto), E450.apdu)
    assert result.authenticated
    assert result.plaintext[0] == 0x0F


@pytest.mark.parametrize("position", range(len(E450.apdu)))
def test_real_e450_any_byte_flip_rejected(position, crypto):
    tampered = bytearray(E450.apdu)
    tampered[position] ^= 0x01
    # Tag octet flips make it a non-ciphered APDU (SecurityError), length
    # flips a DecodeError, everything else must fail authentication.
    with pytest.raises((SecurityError, DecodeError)):
        unwrap(_e450_ctx(crypto), bytes(tampered))


def test_unwrap_never_advances_counter_on_forgery(crypto):
    ctx = _e450_ctx(crypto)
    tampered = bytearray(E450.apdu)
    tampered[-1] ^= 0x01
    with pytest.raises(AuthenticationError):
        unwrap(ctx, bytes(tampered))
    assert ctx.last_inbound_counter(E450.system_title) is None
    unwrap(ctx, E450.apdu)  # the genuine APDU still goes through


def test_general_glo_round_trip_and_tamper(crypto):
    p = crypto.provider
    sender = SecurityContext(
        crypto.ref(GB_EK),
        crypto.ref(GB_AK),
        client_system_title=GB_SYSTEM_TITLE,
        invocation_counter=5,
        provider=p,
    )
    apdu = wrap_general_glo(sender, GB_PLAINTEXT)
    assert apdu[0] == 0xDB and apdu[2:10] == GB_SYSTEM_TITLE
    receiver = SecurityContext(crypto.ref(GB_EK), crypto.ref(GB_AK), provider=p)
    assert unwrap(receiver, apdu).plaintext == GB_PLAINTEXT
    bad = bytearray(apdu)
    bad[-3] ^= 0x10
    with pytest.raises(AuthenticationError):
        unwrap(SecurityContext(crypto.ref(GB_EK), crypto.ref(GB_AK), provider=p), bytes(bad))
