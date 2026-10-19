"""Security-control bit 7 (compression) and the opt-in decompressor hook.

IEC 62056-5-3 9.2.7 reserves SC bit 7 for V.44 compression of the APDU
before it is protected. No DLMS test vector exists and the V.44 parameters
are not negotiated anywhere in the association, so bit 7 is refused unless ``SecurityContext.decompressor`` is
set, and even then only for suites 1/2 in a general-glo, general-ded or
general-ciphering envelope, only when the tag verified, and the hook runs
strictly after that verification.

The "compression" in these tests is a stand-in (zlib): the hook is a black
box to pydlms, so any reversible transform exercises the gating.
"""

from __future__ import annotations

import zlib

import pytest

from pydlms.apdu.tags import Tag
from pydlms.exceptions import AuthenticationError, DecodeError
from pydlms.security import gcm
from pydlms.security.ciphering import (
    MAX_DECOMPRESSED_DEFAULT,
    unwrap,
    wrap,
    wrap_general_glo,
)
from pydlms.security.context import SecurityContext
from pydlms.security.general import wrap_general_ciphering
from pydlms.security.suites import SecurityControl, SecurityPolicy
from tests.crypto.vectors import GB_AK, GB_EK, GB_PLAINTEXT

TITLE = b"SENDER01"
RECIPIENT = b"RECIPIEN"
#: auth+enc, suite 1, compressed.
SC_COMPRESSED = SecurityControl(1, authenticated=True, encrypted=True, compressed=True)


class Hook:
    """Recording decompressor (zlib stand-in for V.44)."""

    def __init__(self, transform=zlib.decompress):
        self.calls: list[bytes] = []
        self.transform = transform

    def __call__(self, data: bytes) -> bytes:
        self.calls.append(data)
        return self.transform(data)


def receiver(suite: int = 1, hook=None, **kw) -> SecurityContext:
    return SecurityContext(
        GB_EK, GB_AK, server_system_title=TITLE, suite=suite, decompressor=hook, **kw
    )


def _content(sc: SecurityControl, payload: bytes, ic: int = 1) -> bytes:
    body = gcm.encrypt(sc, GB_EK, GB_AK, TITLE, ic, payload)
    return bytes([sc.to_byte()]) + ic.to_bytes(4, "big") + body


def _os(data: bytes) -> bytes:
    assert len(data) < 0x80
    return bytes([len(data)]) + data


def general_glo(sc: SecurityControl, payload: bytes, ic: int = 1, ded: bool = False) -> bytes:
    """A general-glo/-ded APDU whose protected data is ``payload`` as is."""
    tag = Tag.GENERAL_DED_CIPHERING if ded else Tag.GENERAL_GLO_CIPHERING
    content = _content(sc, payload, ic)
    return bytes([tag, 8]) + TITLE + _os(content)


def general_ciphering(sc: SecurityControl, payload: bytes, ic: int = 1) -> bytes:
    """A general-ciphering APDU (identified unicast key, SC || AK AAD)."""
    return (
        bytes([Tag.GENERAL_CIPHERING])
        + _os(b"\x01\x02\x03\x04")
        + _os(TITLE)
        + _os(RECIPIENT)
        + _os(b"")
        + _os(b"")
        + b"\x01\x00\x00"
        + _os(_content(sc, payload, ic))
    )


def key_specific(sc: SecurityControl, payload: bytes, ic: int = 1) -> bytes:
    content = _content(sc, payload, ic)
    return bytes([Tag.GLO_GET_RESPONSE]) + _os(content)


COMPRESSED = zlib.compress(GB_PLAINTEXT)


# --- refused by default ------------------------------------------------------------


@pytest.mark.parametrize("build", [general_glo, general_ciphering, key_specific])
def test_bit7_without_hook_raises(build):
    with pytest.raises(DecodeError, match="compressed"):
        unwrap(receiver(), build(SC_COMPRESSED, COMPRESSED))


def test_bit7_without_hook_raises_even_non_strict():
    with pytest.raises(DecodeError, match="compressed"):
        unwrap(receiver(), general_glo(SC_COMPRESSED, COMPRESSED), strict=False)


def test_from_byte_default_still_refuses():
    with pytest.raises(DecodeError):
        SecurityControl.from_byte(0xB1)
    assert SecurityControl.from_byte(0xB1, allow_compressed=True).compressed


def test_context_default_has_no_decompressor():
    assert SecurityContext(GB_EK, GB_AK).decompressor is None


def test_decompressor_must_be_callable():
    with pytest.raises(TypeError):
        SecurityContext(GB_EK, GB_AK, decompressor=b"zlib")


# --- accepted with a hook ------------------------------------------------------------


@pytest.mark.parametrize("suite", [1, 2])
@pytest.mark.parametrize("ded", [False, True])
def test_general_glo_and_ded_decompressed(suite, ded):
    hook = Hook()
    ek = GB_EK if suite == 1 else GB_EK * 2
    ctx = SecurityContext(ek, GB_AK, server_system_title=TITLE, suite=suite, decompressor=hook)
    if ded:
        ctx.set_dedicated_key(ek)
    sc = SecurityControl(suite, True, True, compressed=True)
    body = gcm.encrypt(sc, ek, GB_AK, TITLE, 7, COMPRESSED)
    content = bytes([sc.to_byte()]) + (7).to_bytes(4, "big") + body
    tag = Tag.GENERAL_DED_CIPHERING if ded else Tag.GENERAL_GLO_CIPHERING
    apdu = bytes([tag, 8]) + TITLE + _os(content)
    result = unwrap(ctx, apdu)
    assert result.plaintext == GB_PLAINTEXT
    assert result.security_control.compressed
    assert result.authenticated
    assert hook.calls == [COMPRESSED]


def test_general_ciphering_decompressed():
    hook = Hook()
    result = unwrap(receiver(hook=hook), general_ciphering(SC_COMPRESSED, COMPRESSED))
    assert result.plaintext == GB_PLAINTEXT
    assert hook.calls == [COMPRESSED]


def test_uncompressed_apdu_never_calls_hook():
    hook = Hook()
    sc = SecurityControl(1, True, True)
    result = unwrap(receiver(hook=hook), general_glo(sc, GB_PLAINTEXT))
    assert result.plaintext == GB_PLAINTEXT
    assert hook.calls == []


def test_auth_only_compressed():
    hook = Hook()
    sc = SecurityControl(1, authenticated=True, compressed=True)
    ctx = receiver(hook=hook, policy=SecurityPolicy.AUTHENTICATED)
    assert unwrap(ctx, general_glo(sc, COMPRESSED)).plaintext == GB_PLAINTEXT


# --- gating ----------------------------------------------------------------------------


def test_suite0_with_bit7_raises():
    hook = Hook()
    sc = SecurityControl(0, True, True, compressed=True)
    with pytest.raises(DecodeError, match="suite"):
        unwrap(receiver(suite=0, hook=hook), general_glo(sc, COMPRESSED))
    with pytest.raises(DecodeError, match="suite"):
        unwrap(receiver(suite=0, hook=hook), general_glo(sc, COMPRESSED), strict=False)
    assert hook.calls == []


def test_service_specific_envelope_with_bit7_raises():
    hook = Hook()
    with pytest.raises(DecodeError, match="general"):
        unwrap(receiver(hook=hook), key_specific(SC_COMPRESSED, COMPRESSED))
    assert hook.calls == []


def test_encryption_only_compressed_raises():
    """No tag, nothing verified: the hook must never see unauthenticated data."""
    hook = Hook()
    sc = SecurityControl(1, encrypted=True, compressed=True)
    ctx = receiver(hook=hook, policy=SecurityPolicy.ENCRYPTED)
    with pytest.raises(DecodeError, match="authenticated"):
        unwrap(ctx, general_glo(sc, COMPRESSED))
    assert hook.calls == []


def test_unverified_tag_compressed_raises():
    hook = Hook()
    ctx = SecurityContext(
        GB_EK,
        None,
        server_system_title=TITLE,
        suite=1,
        decompressor=hook,
        allow_unverified_auth=True,
    )
    with pytest.raises(DecodeError, match="verif"):
        unwrap(ctx, general_glo(SC_COMPRESSED, COMPRESSED))
    assert hook.calls == []


def _tamper_cases():
    apdu = general_glo(SC_COMPRESSED, COMPRESSED)
    # Every octet from the SC on (title tampering changes the IV, so it fails
    # the tag too): flip one bit at a time.
    start = 2 + 8 + 1
    return apdu, range(start, len(apdu))


_APDU, _POSITIONS = _tamper_cases()


@pytest.mark.parametrize("position", list(range(2, 10)) + list(_POSITIONS))
def test_every_byte_tampered_fails_before_hook(position):
    hook = Hook()
    tampered = bytearray(_APDU)
    tampered[position] ^= 0x01
    with pytest.raises((AuthenticationError, DecodeError)):
        unwrap(receiver(hook=hook), bytes(tampered))
    assert hook.calls == []


def test_tamper_baseline_untampered_passes():
    hook = Hook()
    assert unwrap(receiver(hook=hook), _APDU).plaintext == GB_PLAINTEXT
    assert len(hook.calls) == 1


# --- output limits and hook failures ---------------------------------------------------


def test_oversized_output_refused():
    hook = Hook(lambda data: b"\xc4" * (MAX_DECOMPRESSED_DEFAULT + 1))
    with pytest.raises(DecodeError, match="exceeds"):
        unwrap(receiver(hook=hook), general_glo(SC_COMPRESSED, COMPRESSED))
    assert len(hook.calls) == 1


def test_explicit_limit():
    hook = Hook()
    apdu = general_glo(SC_COMPRESSED, COMPRESSED)
    with pytest.raises(DecodeError, match="exceeds"):
        unwrap(receiver(hook=hook), apdu, max_decompressed=len(GB_PLAINTEXT) - 1)
    exact = unwrap(receiver(hook=hook), apdu, max_decompressed=len(GB_PLAINTEXT))
    assert exact.plaintext == GB_PLAINTEXT


def test_hook_exception_becomes_decode_error():
    def broken(data: bytes) -> bytes:
        raise RuntimeError("bad stream")

    with pytest.raises(DecodeError, match="decompressor") as info:
        unwrap(receiver(hook=broken), general_glo(SC_COMPRESSED, COMPRESSED))
    assert isinstance(info.value.__cause__, RuntimeError)


@pytest.mark.parametrize("output", [None, "text", b""])
def test_hook_bad_output_refused(output):
    with pytest.raises(DecodeError, match="decompressor"):
        unwrap(receiver(hook=lambda data: output), general_glo(SC_COMPRESSED, COMPRESSED))


def test_counter_committed_only_for_verified_apdu():
    """A refused compressed APDU before the tag check must not move the counter."""
    hook = Hook()
    ctx = receiver(hook=hook)
    tampered = bytearray(general_glo(SC_COMPRESSED, COMPRESSED, ic=50))
    tampered[-1] ^= 1
    with pytest.raises(AuthenticationError):
        unwrap(ctx, bytes(tampered))
    # A genuine APDU with a lower counter is still accepted.
    assert unwrap(ctx, general_glo(SC_COMPRESSED, COMPRESSED, ic=2)).plaintext == GB_PLAINTEXT


# --- outbound ---------------------------------------------------------------------------


def _sender(suite: int = 1) -> SecurityContext:
    return SecurityContext(
        GB_EK, GB_AK, client_system_title=TITLE, suite=suite, decompressor=Hook()
    )


def test_outbound_never_sets_bit7():
    ctx = _sender()
    for apdu in (
        wrap(ctx, GB_PLAINTEXT),
        wrap_general_glo(ctx, GB_PLAINTEXT),
    ):
        sc_pos = 2 if apdu[0] != Tag.GENERAL_GLO_CIPHERING else 11
        assert not apdu[sc_pos] & 0x80
    gc = wrap_general_ciphering(ctx, GB_PLAINTEXT, RECIPIENT)
    # header: tag, 5 octet strings, key-info 01 00 00, content length, SC
    assert gc[-len(GB_PLAINTEXT) - 12 - 5] & 0x80 == 0


@pytest.mark.parametrize("dedicated", [False, True])
def test_outbound_compressed_sc_refused(dedicated):
    ctx = _sender()
    ctx.set_dedicated_key(GB_EK)
    with pytest.raises(ValueError, match="compress"):
        wrap(ctx, GB_PLAINTEXT, sc=SC_COMPRESSED, dedicated=dedicated)
    with pytest.raises(ValueError, match="compress"):
        wrap_general_glo(ctx, GB_PLAINTEXT, sc=SC_COMPRESSED, dedicated=dedicated)


def test_outbound_general_ciphering_compressed_sc_refused():
    with pytest.raises(ValueError, match="compress"):
        wrap_general_ciphering(_sender(), GB_PLAINTEXT, RECIPIENT, sc=SC_COMPRESSED)


# --- association ------------------------------------------------------------------------


def _associate_compressed(max_receive_pdu_size: int = 0xFFFF):
    from pydlms.apdu.acse import AARE, ApplicationContext
    from pydlms.association import Association, AssociationSettings
    from tests.test_association import INITIATE_RESPONSE, ScriptedLink
    from tests.test_association_security import CLIENT, GET_REQUEST, GET_RESPONSE, SERVER

    srv = SecurityContext(
        GB_EK, GB_AK, client_system_title=SERVER, server_system_title=CLIENT, suite=1
    )
    sc = SC_COMPRESSED
    body = gcm.encrypt(sc, GB_EK, GB_AK, SERVER, 9, zlib.compress(GET_RESPONSE))
    content = bytes([sc.to_byte()]) + (9).to_bytes(4, "big") + body
    reply = bytes([Tag.GENERAL_GLO_CIPHERING, 8]) + SERVER + _os(content)
    aare = AARE(
        ApplicationContext.LN_CIPHERED,
        0,
        responding_ap_title=SERVER,
        user_information=wrap(srv, INITIATE_RESPONSE),
    ).to_bytes()
    hook = Hook()
    settings = AssociationSettings(
        security=SecurityContext(GB_EK, GB_AK, CLIENT, suite=1, decompressor=hook),
        max_receive_pdu_size=max_receive_pdu_size,
    )
    assoc = Association(ScriptedLink([aare, lambda _: reply]), settings)
    assoc.associate()
    return assoc, hook, GET_REQUEST, GET_RESPONSE


def test_association_decompresses_reply():
    assoc, hook, request, response = _associate_compressed()
    assert assoc.request(request) == response
    assert len(hook.calls) == 1


def test_association_caps_decompressed_reply_at_max_receive_pdu():
    from tests.test_association_security import GET_RESPONSE

    assoc, hook, request, _ = _associate_compressed(len(GET_RESPONSE) - 1)
    with pytest.raises(DecodeError, match="exceeds"):
        assoc.request(request)
