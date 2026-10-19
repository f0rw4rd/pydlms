"""Invocation-counter policy."""

from __future__ import annotations

import pytest

from pydlms.exceptions import ReplayError
from pydlms.security.ciphering import unwrap, wrap
from pydlms.security.context import SecurityContext
from tests.crypto.vectors import GB_AK, GB_EK, GB_PLAINTEXT

TITLE = b"ABCDEFGH"


def test_outbound_strictly_increasing_and_never_repeated():
    ctx = SecurityContext(GB_EK, GB_AK, invocation_counter=10)
    seen = [ctx.next_invocation_counter() for _ in range(100)]
    assert seen == list(range(10, 110))
    assert ctx.invocation_counter == 110


def test_wrapped_apdus_use_distinct_ivs():
    ctx = SecurityContext(GB_EK, GB_AK)
    apdus = [wrap(ctx, GB_PLAINTEXT) for _ in range(5)]
    counters = [a[3:7] for a in apdus]
    assert len(set(counters)) == 5
    assert len(set(apdus)) == 5


def test_counter_cannot_move_backwards():
    ctx = SecurityContext(GB_EK, GB_AK, invocation_counter=100)
    ctx.set_invocation_counter(200)
    with pytest.raises(ReplayError):
        ctx.set_invocation_counter(150)
    assert ctx.next_invocation_counter() == 200


def test_counter_exhaustion_refuses_reuse():
    ctx = SecurityContext(GB_EK, GB_AK, invocation_counter=0xFFFFFFFE)
    assert ctx.next_invocation_counter() == 0xFFFFFFFE
    assert ctx.next_invocation_counter() == 0xFFFFFFFF
    with pytest.raises(ReplayError):
        ctx.next_invocation_counter()
    with pytest.raises(ReplayError):
        wrap(ctx, GB_PLAINTEXT)


def test_inbound_stale_rejected_by_default():
    ctx = SecurityContext(GB_EK, GB_AK)
    ctx.check_inbound_counter(TITLE, 5)
    ctx.check_inbound_counter(TITLE, 6)
    with pytest.raises(ReplayError):
        ctx.check_inbound_counter(TITLE, 6)
    with pytest.raises(ReplayError):
        ctx.check_inbound_counter(TITLE, 2)
    # Another peer has its own counter.
    ctx.check_inbound_counter(b"OTHERSYS", 1)


def test_inbound_relaxed_only_when_explicitly_disabled(caplog):
    ctx = SecurityContext(GB_EK, GB_AK, replay_protection=False)
    assert "DISABLED" in caplog.text
    ctx.check_inbound_counter(TITLE, 5)
    ctx.check_inbound_counter(TITLE, 5)
    assert "stale IC" in caplog.text


def test_replayed_apdu_rejected_end_to_end():
    sender = SecurityContext(GB_EK, GB_AK, client_system_title=TITLE)
    receiver = SecurityContext(GB_EK, GB_AK, server_system_title=TITLE)
    first = wrap(sender, GB_PLAINTEXT)
    second = wrap(sender, GB_PLAINTEXT)
    unwrap(receiver, first)
    unwrap(receiver, second)
    with pytest.raises(ReplayError):
        unwrap(receiver, first)


# --- only authenticated APDUs may advance the stored inbound counter --------------------


def _enc_only(ic: int, payload: bytes) -> bytes:
    """A glo-get-response claiming SC 0x20 and ``ic``: anyone can forge one,
    the keystream only turns ``payload`` into garbage."""
    content = bytes([0x20]) + ic.to_bytes(4, "big") + payload
    return bytes([0xCC, len(content)]) + content


def test_unauthenticated_apdu_cannot_poison_the_counter():
    """Counter poisoning: a forged enc-only APDU with IC 0xFFFFFFFF used to be
    stored, so every genuine reply after it was rejected as stale."""
    from pydlms.security.suites import SecurityControl, SecurityPolicy

    rx = SecurityContext(GB_EK, GB_AK, server_system_title=TITLE, policy=SecurityPolicy.ENCRYPTED)
    unwrap(rx, _enc_only(0xFFFFFFFF, bytes(9)))  # garbage plaintext, no tag
    assert rx.last_inbound_counter(TITLE) is None
    tx = SecurityContext(GB_EK, GB_AK, client_system_title=TITLE, invocation_counter=7)
    genuine = wrap(tx, GB_PLAINTEXT, sc=SecurityControl.from_byte(0x30))
    assert unwrap(rx, genuine).plaintext == GB_PLAINTEXT
    assert rx.last_inbound_counter(TITLE) == 7


def test_unauthenticated_apdu_is_still_checked():
    from pydlms.security.suites import SecurityPolicy

    rx = SecurityContext(GB_EK, GB_AK, server_system_title=TITLE, policy=SecurityPolicy.ENCRYPTED)
    tx = SecurityContext(GB_EK, GB_AK, client_system_title=TITLE, invocation_counter=10)
    unwrap(rx, wrap(tx, GB_PLAINTEXT))
    with pytest.raises(ReplayError):
        unwrap(rx, _enc_only(10, bytes(9)))
    with pytest.raises(ReplayError):
        unwrap(rx, _enc_only(3, bytes(9)))
    unwrap(rx, _enc_only(11, bytes(9)))
    assert rx.last_inbound_counter(TITLE) == 10


def test_unverified_tag_does_not_advance_the_counter():
    tx = SecurityContext(GB_EK, GB_AK, client_system_title=TITLE, invocation_counter=50)
    rx = SecurityContext(GB_EK, server_system_title=TITLE, allow_unverified_auth=True)
    assert not unwrap(rx, wrap(tx, GB_PLAINTEXT)).authenticated
    assert rx.last_inbound_counter(TITLE) is None


def test_check_without_commit_leaves_the_store():
    ctx = SecurityContext(GB_EK, GB_AK)
    ctx.check_inbound_counter(TITLE, 9, commit=False)
    assert ctx.last_inbound_counter(TITLE) is None
    ctx.check_inbound_counter(TITLE, 9)
    with pytest.raises(ReplayError):
        ctx.check_inbound_counter(TITLE, 9, commit=False)


# --- one inbound counter per key -----------------------------------------------------------


def _pair_with_dedicated(dedicated: bytes):
    tx = SecurityContext(GB_EK, GB_AK, client_system_title=TITLE, invocation_counter=1000)
    tx.set_dedicated_key(dedicated)
    rx = SecurityContext(GB_EK, GB_AK, server_system_title=TITLE)
    rx.set_dedicated_key(dedicated)
    return tx, rx


def test_global_and_dedicated_counters_are_independent():
    """The IV only has to be unique per key, so a meter may run its
    dedicated-key counter from 1 after a high global one."""
    dedicated = bytes(range(100, 116))
    tx, rx = _pair_with_dedicated(dedicated)
    unwrap(rx, wrap(tx, GB_PLAINTEXT))  # global key, IC 1000
    low = SecurityContext(GB_EK, GB_AK, client_system_title=TITLE, invocation_counter=1)
    low.set_dedicated_key(dedicated)
    ded = wrap(low, GB_PLAINTEXT, dedicated=True)  # dedicated key, IC 1
    assert unwrap(rx, ded).plaintext == GB_PLAINTEXT
    assert rx.last_inbound_counter(TITLE) == 1000
    assert rx.last_inbound_counter(TITLE, key="dedicated") == 1
    with pytest.raises(ReplayError):
        unwrap(rx, ded)  # replay of the dedicated APDU


def test_new_dedicated_key_starts_a_new_counter():
    dedicated = bytes(range(100, 116))
    tx, rx = _pair_with_dedicated(dedicated)
    unwrap(rx, wrap(tx, GB_PLAINTEXT, dedicated=True))  # IC 1000
    fresh = bytes(range(200, 216))
    rx.set_dedicated_key(fresh)
    assert rx.last_inbound_counter(TITLE, key="dedicated") is None
    low = SecurityContext(GB_EK, GB_AK, client_system_title=TITLE, invocation_counter=1)
    low.set_dedicated_key(fresh)
    unwrap(rx, wrap(low, GB_PLAINTEXT, dedicated=True))
    assert rx.last_inbound_counter(TITLE) is None  # the global counter is untouched
