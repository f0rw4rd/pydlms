"""The two open general-ciphering / general-signing divergences as an opt-in.

``SecurityContext(general_aad=..., signing_form=...)``. No known-answer test
exists for either non-default form:

* general-ciphering AAD: the only standard example (IEC 62056-5-3:2023
  annex I.2 / Table 31) reproduces its tag with neither ``SC || AK`` nor
  ``SC || AK || header`` (pinned below; cB-Sigma finding F-171).
* general-signing signed data: no standard example exists at all.

So the tests here are self-consistency, an independent recomputation of
each composition with ``cryptography`` directly, fail-closed in both
directions, tampering, and frames produced by the cB-Sigma (go-dlms)
oracle (``go_dlms_frames.py``), the one implementation using the
alternative forms.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from pydlms.exceptions import AuthenticationError, DecodeError, ReplayError
from pydlms.security import ec, gcm
from pydlms.security.ciphering import unwrap
from pydlms.security.context import SecurityContext
from pydlms.security.general import (
    GeneralAad,
    KeyInfo,
    SigningForm,
    signing_replay_token,
    verify_general_signing,
    wrap_general_ciphering,
    wrap_general_signing,
)
from pydlms.security.suites import SecurityControl, SecurityPolicy, SecuritySuite
from tests.crypto.test_general import CLIENT, KINDS, SERVER, pair
from tests.crypto.vectors import (
    GB_AK,
    GB_PLAINTEXT,
    I2_EK_GC_C,
    I2_REQUEST_CONTENT,
    I2_REQUEST_HEADER,
    I2_REQUEST_ORIGINATOR,
)

WITH_HEADER = {"general_aad": GeneralAad.WITH_HEADER}
PREFIXED = {"signing_form": SigningForm.LENGTH_PREFIXED_CONTENT}
TX, DATE_TIME, OTHER = b"\x11" * 8, bytes(range(1, 13)), b"\x22\x33"


def _header(originator: bytes, recipient: bytes) -> bytes:
    """The five header fields as sent (each A-XDR length-prefixed)."""
    return b"".join(bytes([len(f)]) + f for f in (TX, originator, recipient, DATE_TIME, OTHER))


IDENTIFIED = KeyInfo("identified", 0)


def _wrap(ctx, info=IDENTIFIED, sc=None):
    return wrap_general_ciphering(
        ctx,
        GB_PLAINTEXT,
        SERVER,
        info,
        transaction_id=TX,
        date_time=DATE_TIME,
        other_information=OTHER,
        sc=sc,
    )


# --- the context options ------------------------------------------------------------------


def test_defaults_are_the_gurux_forms_and_silent(caplog):
    with caplog.at_level(logging.WARNING, logger="pydlms"):
        ctx = SecurityContext(bytes(16), bytes(16))
    assert ctx.general_aad is GeneralAad.SC_AK
    assert ctx.signing_form is SigningForm.CONTENT
    assert not caplog.records


@pytest.mark.parametrize(
    ("kw", "word"), [(WITH_HEADER, "AAD"), (PREFIXED, "signed data")], ids=["aad", "signing"]
)
def test_non_default_form_warns_once_at_construction(caplog, kw, word):
    with caplog.at_level(logging.WARNING, logger="pydlms"):
        ctx = SecurityContext(bytes(16), bytes(16), **kw)
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert word in warnings[0].getMessage()
    assert "no standard example" in warnings[0].getMessage()
    assert "general_aad" in repr(ctx) or "signing_form" in repr(ctx)


def test_both_non_default_forms_warn_once_each(caplog):
    with caplog.at_level(logging.WARNING, logger="pydlms"):
        SecurityContext(bytes(16), bytes(16), **WITH_HEADER, **PREFIXED)
    assert len([r for r in caplog.records if r.levelno == logging.WARNING]) == 2


def test_forms_accept_their_values_and_refuse_others():
    ctx = SecurityContext(general_aad="with-header", signing_form="length-prefixed-content")
    assert ctx.general_aad is GeneralAad.WITH_HEADER
    assert ctx.signing_form is SigningForm.LENGTH_PREFIXED_CONTENT
    with pytest.raises(ValueError):
        SecurityContext(general_aad="both")
    with pytest.raises(ValueError):
        SecurityContext(signing_form=None)


# --- gcm extra_aad ------------------------------------------------------------------------


@pytest.mark.parametrize("authenticated_only", [False, True], ids=["auth-enc", "auth-only"])
def test_extra_aad_order_against_cryptography(authenticated_only):
    """auth+enc: SC || AK || extra; auth-only: SC || AK || extra || P."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    sc = SecurityControl(0, authenticated=True, encrypted=not authenticated_only)
    ek, title, ic, extra = bytes(range(16)), b"ABCDEFGH", 7, b"\x01\x02\x03"
    body = gcm.encrypt(sc, ek, GB_AK, title, ic, GB_PLAINTEXT, extra_aad=extra)
    nonce, sc_byte = title + ic.to_bytes(4, "big"), bytes([sc.to_byte()])
    if authenticated_only:
        tag = AESGCM(ek).encrypt(nonce, b"", sc_byte + GB_AK + extra + GB_PLAINTEXT)
        assert body == GB_PLAINTEXT + tag[:12]
    else:
        out = AESGCM(ek).encrypt(nonce, GB_PLAINTEXT, sc_byte + GB_AK + extra)
        n = len(GB_PLAINTEXT)
        assert body == out[:n] + out[n : n + 12]
    assert gcm.decrypt(sc, ek, GB_AK, title, ic, body, extra_aad=extra) == GB_PLAINTEXT
    with pytest.raises(AuthenticationError):
        gcm.decrypt(sc, ek, GB_AK, title, ic, body)
    assert gcm.encrypt(sc, ek, GB_AK, title, ic, GB_PLAINTEXT, extra_aad=b"") == gcm.encrypt(
        sc, ek, GB_AK, title, ic, GB_PLAINTEXT
    )


# --- annex I.2: not reproducible under either AAD ------------------------------------------


@pytest.mark.parametrize("extra", [b"", I2_REQUEST_HEADER], ids=["sc-ak", "with-header"])
def test_annex_i2_request_tag_is_not_reproducible(extra):
    """IEC 62056-5-3:2023 annex I.2: the tag verifies under neither AAD.

    Pinned so that a corrected edition (or a correct reading of Table 28 /
    Table 31) that makes one of them reproduce fails this test and becomes
    the known answer that settles the divergence. Key and IV are right: the
    ciphertext decrypts to an ACCESS request.
    """
    sc = SecurityControl.from_byte(I2_REQUEST_CONTENT[0])
    ic = int.from_bytes(I2_REQUEST_CONTENT[1:5], "big")
    payload = I2_REQUEST_CONTENT[5:]
    plain = gcm.ctr_transform(I2_EK_GC_C, gcm.make_iv(I2_REQUEST_ORIGINATOR, ic), payload[:-12])
    assert plain[0] == 0xD9  # access-request
    with pytest.raises(AuthenticationError):
        gcm.decrypt(sc, I2_EK_GC_C, GB_AK, I2_REQUEST_ORIGINATOR, ic, payload, extra_aad=extra)


# --- general-ciphering WITH_HEADER --------------------------------------------------------


@pytest.mark.parametrize(
    "suite",
    [SecuritySuite.ECDH_ECDSA_AES_GCM_128_SHA256, SecuritySuite.ECDH_ECDSA_AES_GCM_256_SHA384],
    ids=["suite1", "suite2"],
)
@pytest.mark.parametrize("info", KINDS, ids=[f"{k.kind}-{k.key_id}-{k.scheme}" for k in KINDS])
def test_with_header_round_trip(suite, info):
    """Self-consistency only (no known answer exists, see the module docstring)."""
    client, server = pair(suite, **WITH_HEADER)
    result = unwrap(server, _wrap(client, info))
    assert result.plaintext == GB_PLAINTEXT and result.authenticated


def test_with_header_aad_recomputed_with_cryptography():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    client, _ = pair(**WITH_HEADER)
    apdu = _wrap(client)
    content = apdu[-(5 + len(GB_PLAINTEXT) + 12) :]
    sc, ic = content[0], int.from_bytes(content[1:5], "big")
    aad = bytes([sc]) + client.authentication_key + _header(CLIENT, SERVER)
    out = AESGCM(client.encryption_key).encrypt(CLIENT + ic.to_bytes(4, "big"), GB_PLAINTEXT, aad)
    n = len(GB_PLAINTEXT)
    assert content[5:] == out[:n] + out[n : n + 12]


def test_with_header_auth_only_round_trip():
    client, server = pair(**WITH_HEADER, policy=SecurityPolicy.AUTHENTICATED)
    sc = SecurityControl(int(client.suite), authenticated=True, encrypted=False)
    assert unwrap(server, _wrap(client, sc=sc)).plaintext == GB_PLAINTEXT


def _header_span(apdu: bytes) -> range:
    """Positions 1 .. end of other-information (the AAD header) in ``apdu``."""
    pos = 1
    for _ in range(5):
        pos += 1 + apdu[pos]
    return range(1, pos)


def test_with_header_every_header_byte_tampered_fails_closed():
    """Every header octet (values and lengths) is covered under WITH_HEADER.

    ``strict=False`` turns the title checks off, so the AAD alone has to
    catch a changed recipient, transaction-id, date-time or other-information.
    """
    client, server = pair(**WITH_HEADER)
    apdu = _wrap(client)
    for position in _header_span(apdu):
        tampered = bytearray(apdu)
        tampered[position] ^= 0x01
        with pytest.raises((AuthenticationError, DecodeError)):
            unwrap(server, bytes(tampered), strict=False)
    assert server.last_inbound_counter(CLIENT) is None  # nothing forged was stored
    assert unwrap(server, apdu).plaintext == GB_PLAINTEXT


def test_default_aad_leaves_header_values_unauthenticated():
    """The flip side, pinned: under SC_AK a changed transaction-id passes.

    This is why the header form exists; it is not a reason to switch the
    default while no standard example supports it.
    """
    client, server = pair()
    apdu = bytearray(_wrap(client))
    apdu[2] ^= 0x01  # first transaction-id octet
    assert unwrap(server, bytes(apdu), strict=False).plaintext == GB_PLAINTEXT


@pytest.mark.parametrize("sender_kw", [{}, WITH_HEADER], ids=["sc-ak-sent", "with-header-sent"])
def test_aad_mismatch_fails_closed_both_ways(sender_kw):
    """One form per context, never a fallback trial of the other."""
    client, server = pair(**sender_kw)
    server.general_aad = GeneralAad.SC_AK if sender_kw else GeneralAad.WITH_HEADER
    for info in KINDS:
        with pytest.raises(AuthenticationError):
            unwrap(server, _wrap(client, info))
    assert not server._last_inbound  # no counter stored for any key


# --- general-signing LENGTH_PREFIXED_CONTENT ----------------------------------------------


def test_length_prefixed_round_trip_plain_and_ciphered():
    """Self-consistency only (no standard example exists for either form)."""
    client, server = pair(**PREFIXED)
    signed = wrap_general_signing(client, GB_PLAINTEXT, SERVER, transaction_id=TX)
    assert verify_general_signing(server, signed) == (CLIENT, GB_PLAINTEXT)
    assert unwrap(server, signed).plaintext == GB_PLAINTEXT
    inner = wrap_general_ciphering(client, GB_PLAINTEXT, SERVER, KeyInfo("identified"))
    assert unwrap(server, wrap_general_signing(client, inner, SERVER)).plaintext == GB_PLAINTEXT


@pytest.mark.parametrize(
    ("form", "prefixed"),
    [(SigningForm.CONTENT, False), (SigningForm.LENGTH_PREFIXED_CONTENT, True)],
    ids=["content", "length-prefixed"],
)
def test_signed_data_recomputed(form, prefixed):
    client, server = pair(signing_form=form)
    signed = wrap_general_signing(client, GB_PLAINTEXT, SERVER, transaction_id=TX)
    header = b"\x08" + TX + b"\x08" + CLIENT + b"\x08" + SERVER + b"\x00\x00"
    assert signed[1 : 1 + len(header)] == header
    content = bytes([len(GB_PLAINTEXT)]) + GB_PLAINTEXT if prefixed else GB_PLAINTEXT
    signature = signed[-64:]
    ec.ecdsa_verify(client.signing_key.public_key(), header + content, signature)
    other = GB_PLAINTEXT if prefixed else bytes([len(GB_PLAINTEXT)]) + GB_PLAINTEXT
    with pytest.raises(AuthenticationError):
        ec.ecdsa_verify(client.signing_key.public_key(), header + other, signature)


@pytest.mark.parametrize("sender_kw", [{}, PREFIXED], ids=["content-sent", "prefixed-sent"])
def test_signing_form_mismatch_fails_closed_both_ways(sender_kw):
    client, server = pair(**sender_kw)
    server.signing_form = SigningForm.CONTENT if sender_kw else SigningForm.LENGTH_PREFIXED_CONTENT
    signed = wrap_general_signing(client, GB_PLAINTEXT, SERVER)
    with pytest.raises(AuthenticationError):
        verify_general_signing(server, signed)
    with pytest.raises(AuthenticationError):
        unwrap(server, signed)


def test_length_prefixed_every_byte_tampered_fails_closed():
    client, server = pair(**PREFIXED)
    signed = wrap_general_signing(client, GB_PLAINTEXT, SERVER, transaction_id=TX)
    for position in range(1, len(signed)):
        tampered = bytearray(signed)
        tampered[position] ^= 0x01
        with pytest.raises((AuthenticationError, DecodeError)):
            verify_general_signing(server, bytes(tampered))


def test_replay_token_hashes_the_verified_form():
    client, server = pair(**PREFIXED)
    signed = wrap_general_signing(client, GB_PLAINTEXT, SERVER)
    content = signing_replay_token(signed)
    prefixed = signing_replay_token(signed, SigningForm.LENGTH_PREFIXED_CONTENT)
    assert content != prefixed
    unwrap(server, signed)
    with pytest.raises(ReplayError):
        unwrap(server, signed)
    with pytest.raises(ReplayError):
        server.check_signed_replay(prefixed)  # stored under the form it verified


# --- frames from the cB-Sigma oracle -------------------------------------------------------


def _oracle_ctx(suite: int, **kw) -> SecurityContext:
    from tests.crypto import go_dlms_frames as go

    extra = {"peer_signing_key": go.server_signing_public_key()} if suite else {}
    return SecurityContext(
        go.EK,
        go.AK,
        client_system_title=go.CLIENT_TITLE,
        server_system_title=go.SERVER_TITLE,
        suite=suite,
        **extra,
        **kw,
    )


def test_oracle_pins_its_commit():
    from tests.crypto import go_dlms_frames as go

    dockerfile = (Path(__file__).parents[1] / "interop" / "go-dlms" / "Dockerfile").read_text()
    assert f"DLMS_COMMIT={go.ORACLE_COMMIT}" in dockerfile


@pytest.mark.parametrize("name", ["GC_PASS3", "GC_GET"])
def test_oracle_general_ciphering_opens_only_with_header_aad(name):
    from tests.crypto import go_dlms_frames as go

    apdu = getattr(go, name)
    default = _oracle_ctx(0)
    with pytest.raises(AuthenticationError):
        unwrap(default, apdu)
    assert not default._last_inbound
    result = unwrap(_oracle_ctx(0, **WITH_HEADER), apdu)
    assert result.authenticated and result.system_title == go.SERVER_TITLE
    if name == "GC_GET":
        assert result.plaintext[0] == 0xC4 and result.plaintext.endswith(go.VALUE)
    else:
        assert result.plaintext[0] == 0xC7  # action-response to HLS pass 3


def test_oracle_general_ciphering_every_header_byte_tampered_fails_closed():
    from tests.crypto import go_dlms_frames as go

    ctx = _oracle_ctx(0, **WITH_HEADER)
    for position in _header_span(go.GC_GET):
        tampered = bytearray(go.GC_GET)
        tampered[position] ^= 0x01
        with pytest.raises((AuthenticationError, DecodeError)):
            unwrap(ctx, bytes(tampered), strict=False)
    assert not ctx._last_inbound


@pytest.mark.parametrize("name", ["SIGN_PASS3", "SIGN_GET"])
def test_oracle_general_signing_verifies_only_length_prefixed(name):
    from tests.crypto import go_dlms_frames as go

    apdu = getattr(go, name)
    default = _oracle_ctx(1)
    with pytest.raises(AuthenticationError):
        verify_general_signing(default, apdu)
    with pytest.raises(AuthenticationError):
        unwrap(default, apdu)
    assert not default._last_inbound
    ctx = _oracle_ctx(1, **PREFIXED)
    originator, content = verify_general_signing(ctx, apdu)
    assert originator == go.SERVER_TITLE and content[0] in (0xCC, 0xCF)
    result = unwrap(ctx, apdu)  # signature, then the glo content
    assert result.authenticated
    if name == "SIGN_GET":
        assert result.plaintext[0] == 0xC4 and result.plaintext.endswith(go.VALUE)
