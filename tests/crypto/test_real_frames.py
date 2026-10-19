"""Real-meter decryption, at the security-layer level.

Each capture is from esphome-libs/dlms_parser (Apache-2.0) with the keys
published alongside it. The full decode to OBIS values is asserted in
``tests/meters/test_meter_dumps.py``; here we pin the security layer: SC
level, invocation counter, authentication outcome and the plaintext APDU type.
"""

from __future__ import annotations

import pytest

from pydlms.exceptions import AuthenticationError, KeyMissingError
from pydlms.security.ciphering import unwrap
from pydlms.security.context import SecurityContext
from pydlms.security.suites import SecurityPolicy
from tests.crypto.real_frames import capture

CASES = [
    # name, SC, IC, system title, authenticated
    ("hdlc_landis_gyr_e450", 0x30, 0x00177BCA, "4C475A677370B177", True),
    ("hdlc_lgz_e450_2", 0x30, None, None, True),
    ("hdlc_kamstrup_omnipower", 0x30, None, None, True),
    ("mbus_netz_noe_p1", 0x20, 35, "4B464D6750000009", False),
    ("mbus_kaifa_ma309m", 0x21, 1, "4B464D0000000001", False),
]


@pytest.mark.parametrize("name,sc,ic,title,authenticated", CASES)
def test_real_capture_deciphers(name, sc, ic, title, authenticated):
    cap = capture(name)
    ctx = SecurityContext(
        cap.encryption_key,
        cap.authentication_key,
        suite=sc & 0x0F,
        policy=SecurityPolicy(sc & 0x30),
        allow_unverified_auth=not authenticated,
    )
    result = unwrap(ctx, cap.apdu)
    assert result.security_control.to_byte() == sc
    if ic is not None:
        assert result.invocation_counter == ic
    if title is not None:
        assert result.system_title == bytes.fromhex(title)
    assert result.authenticated == authenticated
    # Every one of these pushes is a DataNotification; its long-invoke-id is
    # followed by a date-time octet string or 00.
    assert result.plaintext[0] == 0x0F


def test_auth_capture_without_ak_is_refused_by_default():
    cap = capture("hdlc_kamstrup_omnipower")
    with pytest.raises(KeyMissingError):
        unwrap(SecurityContext(cap.encryption_key), cap.apdu)


def test_auth_capture_with_wrong_ak_raises():
    cap = capture("hdlc_kamstrup_omnipower")
    with pytest.raises(AuthenticationError):
        unwrap(SecurityContext(cap.encryption_key, bytes(16)), cap.apdu)


def test_wrong_encryption_key_raises_for_authenticated_capture():
    cap = capture("hdlc_landis_gyr_e450")
    with pytest.raises(AuthenticationError):
        unwrap(SecurityContext(bytes(16), cap.authentication_key), cap.apdu)


def test_replayed_capture_rejected_then_allowed_for_analysis():
    from pydlms.exceptions import ReplayError

    cap = capture("hdlc_landis_gyr_e450")
    ctx = SecurityContext(cap.encryption_key, cap.authentication_key)
    unwrap(ctx, cap.apdu)
    with pytest.raises(ReplayError):
        unwrap(ctx, cap.apdu)
    relaxed = SecurityContext(cap.encryption_key, cap.authentication_key, replay_protection=False)
    unwrap(relaxed, cap.apdu)
    unwrap(relaxed, cap.apdu)


def test_encryption_only_capture_does_not_advance_the_counter():
    """An enc-only counter is not authenticated, so it is never stored (a
    forged one would make genuine APDUs look stale); replays of enc-only
    APDUs are only caught against an authenticated counter."""
    cap = capture("mbus_netz_noe_p1")
    ctx = SecurityContext(cap.encryption_key, policy=SecurityPolicy.ENCRYPTED)
    unwrap(ctx, cap.apdu)
    assert ctx.last_inbound_counter(bytes.fromhex("4B464D6750000009")) is None
