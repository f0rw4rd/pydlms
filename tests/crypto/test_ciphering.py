"""Ciphered-APDU envelope parsing: every malformed form must be rejected."""

from __future__ import annotations

import pytest

from pydlms.exceptions import (
    AuthenticationError,
    DecodeError,
    KeyMissingError,
    SecurityError,
)
from pydlms.security.ciphering import is_ciphered_apdu, unwrap, wrap, wrap_general_glo
from pydlms.security.context import SecurityContext
from pydlms.security.suites import SecurityControl, SecurityPolicy
from tests.crypto.vectors import GB_AK, GB_EK, GB_PLAINTEXT

TITLE = b"SENDER01"


def sender(**kw):
    return SecurityContext(GB_EK, GB_AK, client_system_title=TITLE, **kw)


def receiver(**kw):
    return SecurityContext(GB_EK, GB_AK, server_system_title=TITLE, **kw)


def test_dedicated_key_round_trip_and_missing_key():
    tx = sender()
    tx.set_dedicated_key(bytes(range(16)))
    apdu = wrap(tx, GB_PLAINTEXT, dedicated=True)
    assert apdu[0] == 0xD0  # ded-get-request
    rx = receiver()
    with pytest.raises(KeyMissingError, match="dedicated"):
        unwrap(rx, apdu)
    rx.set_dedicated_key(bytes(range(16)))
    assert unwrap(rx, apdu).plaintext == GB_PLAINTEXT


def test_dedicated_key_length_checked():
    with pytest.raises(ValueError):
        sender().set_dedicated_key(bytes(15))


def test_broadcast_key_selected_by_sc_bit():
    tx = sender(broadcast_key=bytes(range(16, 32)))
    apdu = wrap(tx, GB_PLAINTEXT, sc=SecurityControl(0, True, True, broadcast_key=True))
    with pytest.raises(KeyMissingError, match="broadcast"):
        unwrap(receiver(), apdu)
    assert unwrap(receiver(broadcast_key=bytes(range(16, 32))), apdu).plaintext == GB_PLAINTEXT


def test_key_specific_needs_server_title():
    apdu = wrap(sender(), GB_PLAINTEXT)
    with pytest.raises(KeyMissingError, match="system title"):
        unwrap(SecurityContext(GB_EK, GB_AK), apdu)


def test_wrap_rejects_unwrappable_and_empty():
    with pytest.raises(ValueError):
        wrap(sender(), b"\x0f\x00\x00\x00\x01\x00\x00")  # data-notification has no glo- form
    with pytest.raises(ValueError):
        wrap(sender(), b"")


@pytest.mark.parametrize(
    "apdu,error",
    [
        (b"", DecodeError),
        (b"\xc0\x01", SecurityError),  # not ciphered at all
        (bytes.fromhex("C805 30000000"), DecodeError),  # declared 5, only 4 present
        (bytes.fromhex("C803300000"), DecodeError),  # too short for SC and IC
        (bytes.fromhex("DB07" + "00" * 7 + "05") + bytes(5), DecodeError),  # 7-octet title
        (bytes.fromhex("DB08") + TITLE + bytes.fromhex("0520000000 01 FF"), DecodeError),
        (bytes.fromhex("DB08") + TITLE + bytes.fromhex("10 30 00000001") + bytes(11), DecodeError),
        (
            bytes.fromhex("DB08") + TITLE + bytes.fromhex("05 B0 00000001"),
            DecodeError,
        ),  # compressed
        (bytes.fromhex("DB08") + TITLE + bytes.fromhex("05 2F 00000001"), DecodeError),  # suite 15
    ],
)
def test_malformed_envelopes(apdu, error):
    ctx = receiver()
    with pytest.raises(error):
        unwrap(ctx, apdu)


def test_trailing_octets_after_key_specific_rejected():
    apdu = wrap(sender(), GB_PLAINTEXT) + b"\x00"
    with pytest.raises(DecodeError, match="trailing"):
        unwrap(receiver(), apdu)


def _general_ciphering(content: bytes, key_info: bytes = b"\x01\x00\x00") -> bytes:
    def os_(b: bytes) -> bytes:
        return bytes([len(b)]) + b

    return (
        b"\xdd"
        + os_(b"\x01\x02\x03\x04")  # transaction-id
        + os_(TITLE)  # originator
        + os_(b"RECIPIEN")  # recipient
        + os_(b"")  # date-time
        + os_(b"")  # other-information
        + key_info
        + os_(content)
    )


def test_general_ciphering_identified_key_enc_only():
    """Encryption-only content does not depend on the disputed AAD."""
    inner = wrap_general_glo(sender(), GB_PLAINTEXT, sc=SecurityControl.from_byte(0x20))
    content = inner[11:]  # strip DB 08 title len
    enc_only = SecurityContext(GB_EK, GB_AK, policy=SecurityPolicy.ENCRYPTED)
    result = unwrap(enc_only, _general_ciphering(content))
    assert result.plaintext == GB_PLAINTEXT
    assert result.system_title == TITLE


def test_general_ciphering_key_info_without_key_and_truncation():
    inner = wrap_general_glo(sender(), GB_PLAINTEXT, sc=SecurityControl.from_byte(0x20))
    content = inner[11:]
    # Wrapped key-info is supported; without a master key it cannot be opened.
    with pytest.raises(KeyMissingError, match="master_key"):
        unwrap(receiver(), _general_ciphering(content, b"\x01\x01\x00\x18" + bytes(24)))
    with pytest.raises(DecodeError):
        unwrap(receiver(), _general_ciphering(content)[:20])
    no_key_info = _general_ciphering(content, b"\x00")
    enc_only = SecurityContext(GB_EK, GB_AK, policy=SecurityPolicy.ENCRYPTED)
    assert unwrap(enc_only, no_key_info).plaintext == GB_PLAINTEXT


def test_auth_only_apdu_round_trip():
    apdu = wrap(sender(), GB_PLAINTEXT, sc=SecurityControl.from_byte(0x10))
    assert GB_PLAINTEXT in apdu  # plaintext travels in clear
    tampered = apdu.replace(GB_PLAINTEXT, GB_PLAINTEXT[:-1] + b"\x01")
    with pytest.raises(AuthenticationError):
        unwrap(receiver(policy=SecurityPolicy.AUTHENTICATED), tampered)
    assert unwrap(receiver(policy=SecurityPolicy.AUTHENTICATED), apdu).plaintext == GB_PLAINTEXT


def test_unverified_auth_is_flagged():
    apdu = wrap(sender(), GB_PLAINTEXT)
    ctx = SecurityContext(GB_EK, server_system_title=TITLE, allow_unverified_auth=True)
    result = unwrap(ctx, apdu)
    assert result.plaintext == GB_PLAINTEXT and not result.authenticated


def test_is_ciphered_apdu():
    assert is_ciphered_apdu(b"\xdb") and is_ciphered_apdu(b"\xcc") and is_ciphered_apdu(b"\xdd")
    assert not is_ciphered_apdu(b"") and not is_ciphered_apdu(b"\xc4")


def test_context_validation():
    with pytest.raises(ValueError):
        SecurityContext(bytes(15))
    with pytest.raises(ValueError):
        SecurityContext(bytes(16), bytes(5))
    with pytest.raises(ValueError):
        SecurityContext(bytes(16), client_system_title=b"short")
    with pytest.raises(ValueError):
        SecurityContext(bytes(16), server_system_title=b"short")
    with pytest.raises(ValueError):
        SecurityContext(bytes(16), suite=2)  # suite 2 needs 32-octet keys
    assert SecurityContext(bytes(32), suite=2).suite == 2
    with pytest.raises(KeyMissingError):
        SecurityContext().require_encryption_key()
    with pytest.raises(KeyMissingError):
        SecurityContext().require_authentication_key()
