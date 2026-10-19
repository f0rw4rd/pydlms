"""Property tests: round trip for every level and random
single-bit-flip detection in the authenticated modes."""

from __future__ import annotations

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from pydlms.exceptions import AuthenticationError  # noqa: E402
from pydlms.security import gcm  # noqa: E402
from pydlms.security.suites import SecurityControl  # noqa: E402

keys = st.binary(min_size=16, max_size=16)
titles = st.binary(min_size=8, max_size=8)
counters = st.integers(min_value=0, max_value=0xFFFFFFFF)
levels = st.sampled_from([0x10, 0x20, 0x30, 0x11, 0x21, 0x31, 0x50, 0x70])


@settings(max_examples=200, deadline=None)
@given(ek=keys, ak=keys, title=titles, ic=counters, sc=levels, plaintext=st.binary(max_size=300))
def test_round_trip(ek, ak, title, ic, sc, plaintext):
    control = SecurityControl.from_byte(sc)
    protected = gcm.encrypt(control, ek, ak, title, ic, plaintext)
    assert gcm.decrypt(control, ek, ak, title, ic, protected) == plaintext


@settings(max_examples=200, deadline=None)
@given(
    ek=keys,
    ak=keys,
    title=titles,
    ic=counters,
    sc=st.sampled_from([0x10, 0x30]),
    plaintext=st.binary(min_size=1, max_size=200),
    data=st.data(),
)
def test_single_bit_flip_always_detected(ek, ak, title, ic, sc, plaintext, data):
    control = SecurityControl.from_byte(sc)
    protected = bytearray(gcm.encrypt(control, ek, ak, title, ic, plaintext))
    bit = data.draw(st.integers(min_value=0, max_value=len(protected) * 8 - 1))
    protected[bit // 8] ^= 1 << (bit % 8)
    with pytest.raises(AuthenticationError):
        gcm.decrypt(control, ek, ak, title, ic, bytes(protected))
