"""Inbound APDUs must meet the context's security policy and suite.

Regression for a downgrade: the SC byte of a received APDU used to decide
how much protection was checked, so an attacker could keep the ``glo-``
envelope, set SC to 0x00 (no protection) or 0x20 (no tag) and have the
payload accepted under an AUTHENTICATED_ENCRYPTED policy. The policy is the
association's Security Setup ``security_policy`` (IEC 62056-6-2, class 64,
attribute 2): what both sides must apply, not a hint the peer may lower.
"""

from __future__ import annotations

import pytest

from pydlms.exceptions import AuthenticationError
from pydlms.security import gcm
from pydlms.security.ciphering import unwrap
from pydlms.security.context import SecurityContext
from pydlms.security.suites import SecurityControl, SecurityPolicy

EK, AK = bytes(range(16)), bytes(range(16, 32))
SERVER = b"MMM\x00\x00\x00\x00\x01"
CLIENT = b"CLI\x00\x00\x00\x00\x01"
PLAIN = bytes.fromhex("c401c1000600000001")  # get-response normal, uint32 1


def ctx(policy=SecurityPolicy.AUTHENTICATED_ENCRYPTED, **kw) -> SecurityContext:
    return SecurityContext(EK, AK, CLIENT, SERVER, policy=policy, **kw)


def envelope(sc: int, ic: int, plain: bytes = PLAIN, tag: int = 0xCC) -> bytes:
    control = SecurityControl.from_byte(sc)
    if control.authenticated or control.encrypted:
        body = gcm.encrypt(control, EK, AK if control.authenticated else None, SERVER, ic, plain)
    else:
        body = plain
    content = bytes([sc]) + ic.to_bytes(4, "big") + body
    return bytes([tag, len(content)]) + content


@pytest.mark.parametrize("sc", [0x00, 0x10, 0x20])
def test_weaker_than_policy_is_refused(sc):
    rx = ctx()
    with pytest.raises(AuthenticationError, match="policy|protects nothing"):
        unwrap(rx, envelope(sc, 5))
    assert rx.last_inbound_counter(SERVER) is None


def test_plaintext_inside_envelope_is_refused_under_any_policy():
    with pytest.raises(AuthenticationError, match="protects nothing"):
        unwrap(ctx(SecurityPolicy.NONE), envelope(0x00, 5))


@pytest.mark.parametrize(
    ("policy", "sc"),
    [
        (SecurityPolicy.AUTHENTICATED_ENCRYPTED, 0x30),
        (SecurityPolicy.ENCRYPTED, 0x20),
        (SecurityPolicy.ENCRYPTED, 0x30),
        (SecurityPolicy.AUTHENTICATED, 0x10),
        (SecurityPolicy.AUTHENTICATED, 0x30),
    ],
)
def test_policy_or_stronger_is_accepted(policy, sc):
    assert unwrap(ctx(policy), envelope(sc, 5)).plaintext == PLAIN


def test_security_suite_must_match_the_context():
    rx = SecurityContext(EK, AK, CLIENT, SERVER, suite=1)
    with pytest.raises(AuthenticationError, match="suite"):
        unwrap(rx, envelope(0x30, 8))
    assert rx.last_inbound_counter(SERVER) is None
    assert unwrap(rx, envelope(0x31, 8)).plaintext == PLAIN


def test_general_glo_is_held_to_the_policy_too():
    sc = 0x20
    ct = gcm.ctr_transform(EK, gcm.make_iv(SERVER, 6), PLAIN)
    content = bytes([sc]) + (6).to_bytes(4, "big") + ct
    apdu = bytes([0xDB, 8]) + SERVER + bytes([len(content)]) + content
    with pytest.raises(AuthenticationError, match="policy"):
        unwrap(ctx(), apdu)


def test_analysis_tools_can_still_show_a_downgraded_apdu():
    result = unwrap(ctx(), envelope(0x00, 5), strict=False)
    assert result.plaintext == PLAIN
    assert not result.authenticated
