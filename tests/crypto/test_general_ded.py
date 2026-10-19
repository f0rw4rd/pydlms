"""general-ded-ciphering (0xDC): the dedicated-key twin of 0xDB.

``tag | len(8) | system-title(8) | len | SC | IC(4) | C [| T]`` with the
session's dedicated key as EK (IEC 62056-5-3 9.2.7.2). The tests pin that
the dedicated key, not the global one, is selected on both sides, and that
every byte of an authenticated 0xDC APDU is covered.
"""

from __future__ import annotations

import pytest

from pydlms.exceptions import AuthenticationError, DecodeError, KeyMissingError, SecurityError
from pydlms.security.ciphering import unwrap, wrap_general_glo
from pydlms.security.context import SecurityContext
from pydlms.security.suites import SecurityControl, SecurityPolicy
from tests.crypto.vectors import GB_AK, GB_EK, GB_PLAINTEXT, GB_SYSTEM_TITLE

DEDICATED = bytes(range(0x40, 0x50))
AUTH_ENC = SecurityControl.from_byte(0x30)


def _sender(**kw) -> SecurityContext:
    ctx = SecurityContext(GB_EK, GB_AK, client_system_title=GB_SYSTEM_TITLE, **kw)
    ctx.set_dedicated_key(DEDICATED)
    return ctx


def _receiver(dedicated: bytes | None = DEDICATED, **kw) -> SecurityContext:
    ctx = SecurityContext(GB_EK, GB_AK, **kw)
    ctx.set_dedicated_key(dedicated)
    return ctx


APDU = wrap_general_glo(_sender(invocation_counter=7), GB_PLAINTEXT, sc=AUTH_ENC, dedicated=True)
# tag(1) | 08 | title(8) | len(1) | SC(1) | IC(4) | C | T(12)
TITLE_SLICE = slice(2, 10)
SECURED_FROM = 11


@pytest.mark.parametrize("sc_byte", [0x10, 0x20, 0x30])
def test_round_trip_every_security_level(sc_byte):
    sc = SecurityControl.from_byte(sc_byte)
    apdu = wrap_general_glo(_sender(), GB_PLAINTEXT, sc=sc, dedicated=True)
    assert apdu[0] == 0xDC
    assert apdu[1] == 8 and apdu[TITLE_SLICE] == GB_SYSTEM_TITLE
    result = unwrap(_receiver(policy=SecurityPolicy(sc_byte)), apdu)
    assert result.tag == 0xDC
    assert result.plaintext == GB_PLAINTEXT
    assert result.system_title == GB_SYSTEM_TITLE
    assert result.invocation_counter == 0
    assert result.authenticated == sc.authenticated


def test_layout_and_counter():
    assert APDU[SECURED_FROM - 1] == len(APDU) - SECURED_FROM
    assert APDU[SECURED_FROM] == 0x30
    assert APDU[SECURED_FROM + 1 : SECURED_FROM + 5] == (7).to_bytes(4, "big")
    assert len(APDU) == SECURED_FROM + 5 + len(GB_PLAINTEXT) + 12


def test_dedicated_key_not_global_key_is_used():
    # Ciphered under the dedicated key: the same SC/IC/title under the global
    # key would give a different ciphertext.
    glo = wrap_general_glo(_sender(invocation_counter=7), GB_PLAINTEXT, sc=AUTH_ENC)
    assert glo[0] == 0xDB
    assert glo[SECURED_FROM:] != APDU[SECURED_FROM:]
    # A receiver holding the dedicated key only as its global key fails.
    with pytest.raises(KeyMissingError, match="dedicated"):
        unwrap(SecurityContext(DEDICATED, GB_AK), APDU)


def test_wrong_dedicated_key_rejected():
    with pytest.raises(AuthenticationError):
        unwrap(_receiver(bytes(16)), APDU)


def test_wrong_authentication_key_rejected():
    rx = SecurityContext(GB_EK, bytes(16))
    rx.set_dedicated_key(DEDICATED)
    with pytest.raises(AuthenticationError):
        unwrap(rx, APDU)


def test_missing_dedicated_key_on_receive():
    with pytest.raises(KeyMissingError, match="dedicated"):
        unwrap(_receiver(None), APDU)


def test_missing_dedicated_key_on_send():
    tx = SecurityContext(GB_EK, GB_AK, client_system_title=GB_SYSTEM_TITLE)
    with pytest.raises(KeyMissingError, match="dedicated"):
        wrap_general_glo(tx, GB_PLAINTEXT, dedicated=True)


def test_replay_rejected_after_first_accept():
    rx = _receiver()
    unwrap(rx, APDU)
    with pytest.raises(SecurityError):
        unwrap(rx, APDU)


@pytest.mark.parametrize("position", range(len(APDU)))
@pytest.mark.parametrize("bit", [0x01, 0x80])
def test_any_flipped_byte_rejected(position, bit):
    tampered = bytearray(APDU)
    tampered[position] ^= bit
    rx = _receiver()
    if position in range(TITLE_SLICE.start, TITLE_SLICE.stop) or position > SECURED_FROM:
        # System title (IV), IC (IV), ciphertext and tag: authentication.
        with pytest.raises(AuthenticationError):
            unwrap(rx, bytes(tampered))
    else:
        # Tag, length octets and the SC byte change the parse or the key/AAD;
        # whichever check trips, no plaintext may come back.
        with pytest.raises((SecurityError, DecodeError)):
            unwrap(rx, bytes(tampered))
    assert rx.last_inbound_counter(GB_SYSTEM_TITLE) is None


@pytest.mark.parametrize("dedicated", [False, True])
def test_empty_apdu_rejected_without_consuming_a_counter(dedicated):
    tx = _sender(invocation_counter=3)
    with pytest.raises(ValueError, match="empty"):
        wrap_general_glo(tx, b"", dedicated=dedicated)
    assert tx.invocation_counter == 3
