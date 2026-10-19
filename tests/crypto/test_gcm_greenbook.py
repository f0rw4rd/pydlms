"""Green Book suite-0 known-answer tests for the three GCM operations.

Source: IEC 62056-5-3 worked example (EK 000102..0F, AK D0..DF, system title
4D4D4D0000BC614E, IC 01234567, plaintext GET-Request C0 01 00 00 08 ...).
Pins two facts: the AAD per level and that
encryption-only keystream starts at counter block 2. Also pins the 12-octet tag.

The ``crypto`` fixture runs each vector through the default
SoftwareProvider and through a HandleProvider (keys behind integer handles,
tests/crypto/handle_provider.py): both must give the same bytes.
"""

from __future__ import annotations

from pydlms.security import gcm
from pydlms.security.suites import SecurityControl
from tests.crypto.vectors import (
    GB_AK,
    GB_CIPHERTEXT,
    GB_EK,
    GB_IC,
    GB_PLAINTEXT,
    GB_SYSTEM_TITLE,
    GB_TAG_AUTH_ENC,
    GB_TAG_AUTH_ONLY,
)

AUTH_ENC = SecurityControl.from_byte(0x30)
AUTH_ONLY = SecurityControl.from_byte(0x10)
ENC_ONLY = SecurityControl.from_byte(0x20)


def test_iv_is_system_title_then_counter():
    assert gcm.make_iv(GB_SYSTEM_TITLE, GB_IC) == bytes.fromhex("4D4D4D0000BC614E01234567")


def test_authenticated_encryption_kat(crypto):
    ek, ak, p = crypto.ref(GB_EK), crypto.ref(GB_AK), crypto.provider
    out = gcm.encrypt(AUTH_ENC, ek, ak, GB_SYSTEM_TITLE, GB_IC, GB_PLAINTEXT, provider=p)
    assert out == GB_CIPHERTEXT + GB_TAG_AUTH_ENC
    back = gcm.decrypt(AUTH_ENC, ek, ak, GB_SYSTEM_TITLE, GB_IC, out, provider=p)
    assert back == GB_PLAINTEXT


def test_authentication_only_kat(crypto):
    ek, ak, p = crypto.ref(GB_EK), crypto.ref(GB_AK), crypto.provider
    out = gcm.encrypt(AUTH_ONLY, ek, ak, GB_SYSTEM_TITLE, GB_IC, GB_PLAINTEXT, provider=p)
    assert out == GB_PLAINTEXT + GB_TAG_AUTH_ONLY
    back = gcm.decrypt(AUTH_ONLY, ek, ak, GB_SYSTEM_TITLE, GB_IC, out, provider=p)
    assert back == GB_PLAINTEXT


def test_encryption_only_kat_starts_at_counter_two(crypto):
    ek, p = crypto.ref(GB_EK), crypto.provider
    out = gcm.encrypt(ENC_ONLY, ek, None, GB_SYSTEM_TITLE, GB_IC, GB_PLAINTEXT, provider=p)
    # Same ciphertext as GCM: the keystream begins at counter block 2.
    assert out == GB_CIPHERTEXT
    back = gcm.decrypt(ENC_ONLY, ek, None, GB_SYSTEM_TITLE, GB_IC, out, provider=p)
    assert back == GB_PLAINTEXT


def test_tag_is_twelve_octets():
    _, tag = gcm.gcm_encrypt(GB_EK, bytes(12), b"x", b"")
    assert len(tag) == 12


def test_ciphered_apdu_bytes(crypto):
    """The full glo-get-request of the example: C8 1E 30 01234567 C || T."""
    from pydlms.security.ciphering import unwrap, wrap
    from pydlms.security.context import SecurityContext

    ctx = SecurityContext(
        crypto.ref(GB_EK),
        crypto.ref(GB_AK),
        client_system_title=GB_SYSTEM_TITLE,
        invocation_counter=GB_IC,
        provider=crypto.provider,
    )
    apdu = wrap(ctx, GB_PLAINTEXT)
    assert apdu == bytes.fromhex("C81E3001234567") + GB_CIPHERTEXT + GB_TAG_AUTH_ENC
    # The receiving side (server title = our title here) recovers it.
    peer = SecurityContext(
        crypto.ref(GB_EK),
        crypto.ref(GB_AK),
        server_system_title=GB_SYSTEM_TITLE,
        provider=crypto.provider,
    )
    result = unwrap(peer, apdu)
    assert result.plaintext == GB_PLAINTEXT
    assert result.invocation_counter == GB_IC
    assert result.authenticated
