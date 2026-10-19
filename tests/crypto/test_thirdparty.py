"""Third-party protection layers (IEC 62056-5-3:2023 4.1.7, 5.7.3, Table 26, annex J).

Known answer: none exists. Annex J has no byte example transcribed here
(neither in pydlms nor in cB-Sigma dlms 26360a1, whose third-party tests
build their frames). It is replaced by

* an independent reconstruction: the TP's general-ciphering layer from
  :func:`nest` opened with ``cryptography`` directly (ECDH, the KDF over
  the OtherInfo pinned by the annex I vectors, AES-GCM with IV = TP title
  || 0 and AAD SC || AK) and its general-signing layer verified with
  ``cryptography``'s ECDSA;
* cB-Sigma's own J.3 vector (``thirdparty_internal_test.go``,
  ``protectNone(1, C4 01 41 00 12 5A 0A)``) for the unprotected form;
* answers recorded from the cB-Sigma meter
  (``go_dlms_thirdparty_frames.py``) and the
  live interop in ``tests/interop/test_go_dlms.py``.

Every byte of each response layer is tampered, wrong keys, swapped and
doubled layers, missing and foreign layers, and the J.3 opt-in are tested.
"""

from __future__ import annotations

import hashlib
import logging

import pytest

from pydlms.apdu.tags import Tag
from pydlms.exceptions import (
    AuthenticationError,
    DecodeError,
    DlmsError,
    KeyMissingError,
    SecurityError,
)
from pydlms.security.context import SecurityContext
from pydlms.security.general import (
    ONE_PASS_DH,
    STATIC_UNIFIED_MODEL,
    GeneralAad,
    KeyInfo,
    SigningForm,
    _read_os,
    wrap_general_ciphering,
    wrap_general_signing,
)
from pydlms.security.suites import SecurityPolicy
from pydlms.security.thirdparty import (
    ThirdParty,
    nest,
    unnest,
    unwrap_unprotected_general_ciphering,
    wrap_unprotected_general_ciphering,
)
from tests.crypto.thirdparty_meter import TpMeter, TpTransaction

METER = b"METER001"
CLIENT = b"CLIENT01"
TP = b"TPH\x00\x00\x00\x00\x07"  # cB-Sigma thirdparty_internal_test.go tpST
AK16 = bytes.fromhex("d0d1d2d3d4d5d6d7d8d9dadbdcdddedf")
AK32 = AK16 + bytes.fromhex("e0e1e2e3e4e5e6e7e8e9eaebecedeeef")
EK16 = bytes(range(16))
EK32 = bytes(range(32))
#: A GET response (cB-Sigma's J.3 test payload): long-unsigned 0x5A0A.
RESPONSE = bytes.fromhex("C401410012 5A0A".replace(" ", ""))
REQUEST = bytes.fromhex("C001C100030100010800FF0200")
AE = SecurityPolicy.AUTHENTICATED_ENCRYPTED

_ORDER = {
    1: 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    2: int(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AE"
        "CEC196ACCC52973",
        16,
    ),
}


def key(label: str, suite: int):
    """Fixed test keys: d = H(label) mod (n - 1) + 1 (as the go-dlms adapter)."""
    from cryptography.hazmat.primitives.asymmetric import ec

    digest = (hashlib.sha384 if suite == 2 else hashlib.sha256)(label.encode()).digest()
    curve = ec.SECP384R1() if suite == 2 else ec.SECP256R1()
    return ec.derive_private_key(int.from_bytes(digest, "big") % (_ORDER[suite] - 1) + 1, curve)


def ak(suite: int) -> bytes:
    return AK32 if suite == 2 else AK16


def client_ctx(suite: int, **kw) -> SecurityContext:
    """The client's context: its own keys and the meter's public keys."""
    return SecurityContext(
        EK32 if suite == 2 else EK16,
        ak(suite),
        client_system_title=CLIENT,
        server_system_title=METER,
        suite=suite,
        signing_key=key("client-sign", suite),
        key_agreement_key=key("client-ka", suite),
        peer_signing_key=key("meter-sign", suite).public_key(),
        peer_key_agreement_key=key("meter-ka", suite).public_key(),
        **kw,
    )


def third_party(suite: int, **kw) -> ThirdParty:
    args = {
        "system_title": TP,
        "signing_key": key("tp-sign", suite),
        "key_agreement_key": key("tp-ka", suite),
        "authentication_key": ak(suite),
    }
    args.update(kw)
    return ThirdParty(**args)


def meter(suite: int, **kw) -> TpMeter:
    args = {
        "suite": suite,
        "meter_title": METER,
        "tp_title": TP,
        "meter_sign": key("meter-sign", suite),
        "meter_ka": key("meter-ka", suite),
        "tp_sign_pub": key("tp-sign", suite).public_key(),
        "tp_ka_pub": key("tp-ka", suite).public_key(),
        "ak": ak(suite),
    }
    args.update(kw)
    return TpMeter(**args)


def exchange(tp: ThirdParty, m: TpMeter, ctx: SecurityContext) -> tuple[bytes, bytes]:
    """(request with the TP's layers, the meter's answer for the TP)."""
    request = nest(tp, ctx, REQUEST)
    inner, tx = m.open(request)
    assert inner == REQUEST
    return request, m.answer(tx, RESPONSE)


#: name -> ThirdParty overrides (sign, policy, scheme).
MODES = {
    "sign": {"sign": True},
    "cipher-ae-one-pass": {"sign": False, "policy": AE},
    "cipher-ae-static": {"sign": False, "policy": AE, "key_agreement": STATIC_UNIFIED_MODEL},
    "cipher-auth-static": {
        "sign": False,
        "policy": SecurityPolicy.AUTHENTICATED,
        "key_agreement": STATIC_UNIFIED_MODEL,
    },
    "cipher-enc-one-pass": {"sign": False, "policy": SecurityPolicy.ENCRYPTED},
    "sign+cipher-ae-one-pass": {"policy": AE},
    "sign+cipher-ae-static": {"policy": AE, "key_agreement": STATIC_UNIFIED_MODEL},
}


# --- configuration --------------------------------------------------------------------


@pytest.mark.parametrize(
    "kw,error,match",
    [
        ({"system_title": b"short"}, ValueError, "8 octets"),
        ({"sign": False}, ValueError, "no protection"),
        ({"signing_key": None}, KeyMissingError, "signing_key"),
        (
            {"sign": False, "policy": AE, "signing_key": None},
            KeyMissingError,
            "ephemeral",
        ),
        (
            {"sign": False, "policy": AE, "key_agreement": 2, "key_agreement_key": None},
            KeyMissingError,
            "key_agreement_key",
        ),
        ({"policy": AE, "authentication_key": None}, KeyMissingError, "authentication_key"),
        ({"policy": AE, "key_agreement": 0}, ValueError, "global or master"),
        ({"authentication_key": b"\x00" * 5}, ValueError, "16 or 32"),
        ({"ciphered_responses": True, "key_agreement_key": None}, KeyMissingError, "ciphered"),
        ({"accept_unprotected_responses": True}, ValueError, "signed_responses=False"),
        (
            {"accept_unprotected_responses": True, "signed_responses": False, "policy": AE},
            ValueError,
            "ciphered_responses=False",
        ),
    ],
)
def test_configuration_is_checked(kw, error, match):
    with pytest.raises(error, match=match):
        third_party(1, **kw)


def test_defaults_require_the_layers_the_third_party_applies():
    tp = third_party(1)
    assert (tp.sign, tp.policy, tp.signed_responses, tp.ciphered_responses) == (
        True,
        SecurityPolicy.NONE,
        True,
        False,
    )
    tp = third_party(1, sign=False, policy=AE)
    assert (tp.signed_responses, tp.ciphered_responses) == (False, True)
    assert tp.accept_unprotected_responses is False
    assert (tp.general_aad, tp.signing_form) == (GeneralAad.SC_AK, SigningForm.CONTENT)


def test_suite_0_is_refused():
    ctx = SecurityContext(EK16, AK16, client_system_title=CLIENT, server_system_title=METER)
    with pytest.raises(SecurityError, match="suite 1 or 2"):
        nest(third_party(1), ctx, REQUEST)
    with pytest.raises(SecurityError, match="suite 1 or 2"):
        unnest(third_party(1), ctx, RESPONSE)


def test_meter_title_is_needed():
    ctx = client_ctx(1)
    ctx.server_system_title = None
    with pytest.raises(KeyMissingError, match="system title"):
        nest(third_party(1), ctx, REQUEST)
    assert nest(third_party(1), ctx, REQUEST, meter_title=METER)[0] == Tag.GENERAL_SIGNING


# --- round trips ----------------------------------------------------------------------


@pytest.mark.parametrize("suite", [1, 2])
@pytest.mark.parametrize("mode", list(MODES))
@pytest.mark.parametrize("sign_answers", [True, False], ids=["signed-answer", "unsigned-answer"])
def test_round_trip(suite, mode, sign_answers):
    kw = dict(MODES[mode])
    signs = kw.get("sign", True)
    unprotected = signs and not sign_answers and "policy" not in kw
    if signs and not sign_answers:
        kw["signed_responses"] = False
        kw["accept_unprotected_responses"] = unprotected
    tp = third_party(suite, **kw)
    request, answer = exchange(tp, meter(suite, sign_answers=sign_answers), client_ctx(suite))
    assert request[0] == (Tag.GENERAL_CIPHERING if "policy" in kw else Tag.GENERAL_SIGNING)
    assert answer[0] == request[0] or unprotected or not sign_answers
    assert unnest(tp, client_ctx(suite), answer) == RESPONSE


@pytest.mark.parametrize("mode", ["sign+cipher-ae-one-pass", "sign+cipher-ae-static"])
def test_round_trip_through_a_handle_provider(crypto, mode):
    """The TP's keys behind provider handles."""
    tp = third_party(
        1,
        **MODES[mode],
        signing_key=crypto.ref(key("tp-sign", 1)),
        key_agreement_key=crypto.ref(key("tp-ka", 1)),
        authentication_key=crypto.ref(AK16),
        provider=crypto.provider,
    )
    _, answer = exchange(tp, meter(1), client_ctx(1))
    assert unnest(tp, client_ctx(1), answer) == RESPONSE


@pytest.mark.parametrize("mode", list(MODES))
def test_cb_sigma_forms_round_trip(mode):
    forms = {"general_aad": GeneralAad.WITH_HEADER, "signing_form": "length-prefixed-content"}
    tp = third_party(1, **MODES[mode], **forms)
    m = meter(
        1, general_aad=GeneralAad.WITH_HEADER, signing_form=SigningForm.LENGTH_PREFIXED_CONTENT
    )
    _, answer = exchange(tp, m, client_ctx(1))
    assert unnest(tp, client_ctx(1), answer) == RESPONSE
    # The default forms refuse the cB-Sigma ones (each form is one of a
    # signature or an authenticated layer; enc-only has neither, no AAD).
    default = third_party(1, **MODES[mode])
    if MODES[mode].get("policy") == SecurityPolicy.ENCRYPTED:
        assert unnest(default, client_ctx(1), answer) == RESPONSE
        return
    with pytest.raises(AuthenticationError):
        unnest(default, client_ctx(1), answer)


# --- the request's layers -------------------------------------------------------------


def _fields(apdu: bytes) -> tuple[list[bytes], int]:
    pos, out = 1, []
    for _ in range(5):
        value, pos = _read_os(apdu, pos, "field")
        out.append(value)
    return out, pos


@pytest.mark.parametrize("scheme", [ONE_PASS_DH, STATIC_UNIFIED_MODEL])
def test_request_layers_are_pinned(scheme):
    tp = third_party(1, policy=AE, key_agreement=scheme)
    request = nest(tp, client_ctx(1), REQUEST)
    (tid, originator, recipient, date_time, other), pos = _fields(request)
    assert request[0] == Tag.GENERAL_CIPHERING
    assert (len(tid), originator, recipient, date_time, other) == (8, TP, METER, b"", b"")
    assert request[pos : pos + 4] == bytes([1, 2, 1, scheme])  # agreed-key only
    data, pos = _read_os(request, pos + 4, "key data")
    # One-pass: ephemeral X || Y || r || s (P-256); static: no data.
    assert len(data) == (128 if scheme == ONE_PASS_DH else 0)
    content, end = _read_os(request, pos, "content")
    assert end == len(request)
    assert content[0] == 0x31  # suite 1, A and E
    assert content[1:5] == b"\x00\x00\x00\x00"  # IC 0 under the new agreed key
    inner, tx = meter(1).open(request)
    assert inner == REQUEST
    assert tx.signed and tx.policy == 0x30


def test_every_request_has_a_new_key():
    """IC is always 0, so no (key, IV) pair may repeat: a fresh ephemeral key
    (one-pass) or transaction-id (static) per APDU."""
    for scheme in (ONE_PASS_DH, STATIC_UNIFIED_MODEL):
        tp = third_party(1, sign=False, policy=AE, key_agreement=scheme)
        a, b = (nest(tp, client_ctx(1), REQUEST) for _ in range(2))
        (tid_a, *_), pos = _fields(a)
        (tid_b, *_), _ = _fields(b)
        assert tid_a != tid_b
        assert a[pos:] != b[pos:]  # key data or ciphertext differ


def test_request_reconstructed_with_cryptography():
    """The KAT replacement: open nest()'s layers with cryptography directly."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec as cec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    from pydlms.security.ec import algorithm_id

    tp = third_party(1, policy=AE, key_agreement=STATIC_UNIFIED_MODEL)
    request = nest(tp, client_ctx(1), REQUEST)
    (tid, *_), pos = _fields(request)
    assert request[pos : pos + 5] == bytes([1, 2, 1, 2, 0])  # static, no key data
    content, _ = _read_os(request, pos + 5, "content")
    z = key("meter-ka", 1).exchange(cec.ECDH(), key("tp-ka", 1).public_key())
    info = algorithm_id(1) + TP + bytes([len(tid)]) + tid + METER
    k = hashlib.sha256(b"\x00\x00\x00\x01" + z + info).digest()[:16]
    sc, ic, body = content[:1], content[1:5], content[5:]
    assert ic == b"\x00\x00\x00\x00"
    # DLMS truncates the GCM tag to 12 octets.
    decryptor = Cipher(
        algorithms.AES(k), modes.GCM(TP + ic, body[-12:], min_tag_length=12)
    ).decryptor()
    decryptor.authenticate_additional_data(sc + AK16)
    signed = decryptor.update(body[:-12]) + decryptor.finalize()
    assert signed[0] == Tag.GENERAL_SIGNING
    fields, spos = _fields(signed)
    inner, spos2 = _read_os(signed, spos, "content")
    signature, _ = _read_os(signed, spos2, "signature")
    assert inner == REQUEST and fields[1:3] == [TP, METER]
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    key("tp-sign", 1).public_key().verify(
        encode_dss_signature(r, s), signed[1:spos] + inner, cec.ECDSA(hashes.SHA256())
    )


# --- tampering ------------------------------------------------------------------------


def _answer(mode: str, suite: int = 1, **forms) -> tuple[ThirdParty, bytes]:
    tp = third_party(suite, **MODES[mode], **forms)
    m_forms = {}
    if forms:
        m_forms = {
            "general_aad": GeneralAad.WITH_HEADER,
            "signing_form": SigningForm.LENGTH_PREFIXED_CONTENT,
        }
    _, answer = exchange(tp, meter(suite, **m_forms), client_ctx(suite))
    return tp, answer


def _unauthenticated_tid(answer: bytes) -> set[int]:
    """Octets of a one-pass general-ciphering transaction-id: under the default
    SC || AK AAD neither the KDF nor the tag covers them."""
    if answer[0] != Tag.GENERAL_CIPHERING:
        return set()
    (tid, *_), pos = _fields(answer)
    if answer[pos : pos + 4] != b"\x01\x02\x01\x01":
        return set()
    return set(range(2, 2 + len(tid)))


TAMPER_MODES = ["sign", "cipher-ae-one-pass", "cipher-auth-static", "sign+cipher-ae-one-pass"]


@pytest.mark.parametrize("mode", TAMPER_MODES)
@pytest.mark.parametrize("forms", ["default", "cb-sigma"])
def test_every_answer_byte_tampered_fails(mode, forms):
    kw = (
        {}
        if forms == "default"
        else {"general_aad": "with-header", "signing_form": "length-prefixed-content"}
    )
    tp, answer = _answer(mode, **kw)
    loose = _unauthenticated_tid(answer) if forms == "default" else set()
    for i in range(len(answer)):
        bad = bytearray(answer)
        bad[i] ^= 0x01
        if i in loose:
            # Pinned: the default AAD leaves the one-pass transaction-id open.
            assert unnest(tp, client_ctx(1), bytes(bad)) == RESPONSE
            continue
        with pytest.raises(DlmsError):
            unnest(tp, client_ctx(1), bytes(bad))


def test_tampered_answer_inside_the_clients_layer_fails():
    """A J.3 answer is unauthenticated on its own; the client's layer around
    it is what protects it: every octet of the whole frame flipped fails."""
    from pydlms.security.ciphering import unwrap, wrap_general_glo

    tp = third_party(1, signed_responses=False, accept_unprotected_responses=True)
    _, answer = exchange(tp, meter(1, sign_answers=False), client_ctx(1))
    assert answer[0] == Tag.GENERAL_CIPHERING
    srv = SecurityContext(
        EK16, AK16, client_system_title=METER, server_system_title=CLIENT, suite=1
    )
    frame = wrap_general_glo(srv, answer)
    assert unnest(tp, client_ctx(1), unwrap(client_ctx(1), frame).plaintext) == RESPONSE
    for i in range(len(frame)):
        bad = bytearray(frame)
        bad[i] ^= 0x01
        with pytest.raises(DlmsError):
            unnest(tp, client_ctx(1), unwrap(client_ctx(1), bytes(bad)).plaintext)


# --- wrong keys -------------------------------------------------------------------------


def test_wrong_keys_fail():
    tp = third_party(1, policy=AE)
    request = nest(tp, client_ctx(1), REQUEST)
    # The meter signed with another key.
    _, tx = meter(1).open(request)
    forged = meter(1, meter_sign=key("other", 1)).answer(tx, RESPONSE)
    with pytest.raises(AuthenticationError):
        unnest(tp, client_ctx(1), forged)
    # Ciphered for another third party key agreement key (static: no signature).
    static = third_party(1, policy=AE, key_agreement=STATIC_UNIFIED_MODEL)
    _, tx = meter(1).open(nest(static, client_ctx(1), REQUEST))
    other = meter(1, tp_ka_pub=key("other-ka", 1).public_key()).answer(tx, RESPONSE)
    with pytest.raises(AuthenticationError):
        unnest(static, client_ctx(1), other)
    # Another authentication key.
    other_ak = meter(1, ak=bytes(16)).answer(tx, RESPONSE)
    with pytest.raises(AuthenticationError):
        unnest(static, client_ctx(1), other_ak)
    # The TP opens with a key agreement key that is not its own.
    good = meter(1).answer(tx, RESPONSE)
    wrong = third_party(
        1, policy=AE, key_agreement=STATIC_UNIFIED_MODEL, key_agreement_key=key("x", 1)
    )
    with pytest.raises(AuthenticationError):
        unnest(wrong, client_ctx(1), good)
    assert unnest(static, client_ctx(1), good) == RESPONSE


def test_meter_request_signed_by_another_key_is_refused_by_the_meter():
    tp = third_party(1, signing_key=key("intruder", 1))
    with pytest.raises(AuthenticationError):
        meter(1).open(nest(tp, client_ctx(1), REQUEST))


def test_one_pass_answer_needs_the_meters_signing_key():
    tp = third_party(1, sign=False, policy=AE)
    _, answer = exchange(tp, meter(1), client_ctx(1))
    ctx = client_ctx(1)
    ctx.peer_signing_key = None
    with pytest.raises(KeyMissingError, match="peer_signing_key"):
        unnest(tp, ctx, answer)


# --- layer structure --------------------------------------------------------------------


def _meter_ctx(policy=0, **kw) -> SecurityContext:
    return meter(1).ctx(policy)


def test_layer_order_swapped_is_refused():
    """Signing outside ciphering (the meter must cipher last)."""
    tp = third_party(1, policy=AE)
    ciphered = wrap_general_ciphering(
        _meter_ctx(0x30), RESPONSE, TP, KeyInfo("agreed"), transaction_id=b"t", sc=None
    )
    swapped = wrap_general_signing(_meter_ctx(), ciphered, TP)
    with pytest.raises(AuthenticationError, match="order"):
        unnest(tp, client_ctx(1), swapped)


def test_doubled_and_extra_layers_are_refused():
    tp = third_party(1, policy=AE)
    signed = wrap_general_signing(_meter_ctx(), RESPONSE, TP)
    twice = wrap_general_signing(_meter_ctx(), signed, TP)
    with pytest.raises(AuthenticationError, match="signed twice"):
        unnest(third_party(1), client_ctx(1), twice)
    c1 = wrap_general_ciphering(_meter_ctx(0x30), signed, TP, KeyInfo("agreed"))
    c2 = wrap_general_ciphering(_meter_ctx(0x30), c1, TP, KeyInfo("agreed"))
    with pytest.raises(AuthenticationError, match="order"):
        unnest(tp, client_ctx(1), c2)
    three = wrap_general_signing(_meter_ctx(), twice, TP)
    with pytest.raises(AuthenticationError):
        unnest(tp, client_ctx(1), three)


def test_layer_inside_an_unprotected_layer_is_refused():
    tp = third_party(1, signed_responses=False, accept_unprotected_responses=True)
    signed = wrap_general_signing(_meter_ctx(), RESPONSE, TP)
    j3 = wrap_unprotected_general_ciphering(1, signed, METER, TP)
    with pytest.raises(AuthenticationError, match="more layers"):
        unnest(tp, client_ctx(1), j3)


@pytest.mark.parametrize(
    "kw,answer_kind,match",
    [
        ({}, "cipher", "did not sign"),
        ({"policy": AE, "signed_responses": False}, "sign", "did not cipher"),
        ({}, "plain", "no layer"),
        ({}, "foreign", "no layer"),
        ({}, "glo", "no layer"),
    ],
)
def test_missing_layer_is_refused(kw, answer_kind, match):
    tp = third_party(1, **kw)
    answers = {
        "cipher": lambda: wrap_general_ciphering(_meter_ctx(0x30), RESPONSE, TP, KeyInfo("agreed")),
        "sign": lambda: wrap_general_signing(_meter_ctx(), RESPONSE, TP),
        "plain": lambda: RESPONSE,
        # A layer for someone else (the client) is not one for the third party.
        "foreign": lambda: wrap_general_signing(_meter_ctx(), RESPONSE, CLIENT),
        "glo": lambda: bytes([Tag.GENERAL_GLO_CIPHERING, 8]) + METER + b"\x05\x31\x00\x00\x00\x01",
    }
    with pytest.raises(AuthenticationError, match=match):
        unnest(tp, client_ctx(1), answers[answer_kind]())


def test_layer_from_another_originator_is_refused():
    tp = third_party(1)
    other = meter(1, meter_title=b"OTHERMTR").ctx()
    with pytest.raises(AuthenticationError, match="not the meter"):
        unnest(tp, client_ctx(1), wrap_general_signing(other, RESPONSE, TP))


@pytest.mark.parametrize("info", [KeyInfo("identified", 0), KeyInfo("none")])
def test_tp_layer_with_a_global_key_is_refused(info):
    tp = third_party(1, sign=False, policy=AE)
    srv = meter(1).ctx(0x30)
    srv.encryption_key = EK16
    with pytest.raises(AuthenticationError, match="agree its key"):
        unnest(tp, client_ctx(1), wrap_general_ciphering(srv, RESPONSE, TP, info))


def test_weaker_ciphered_answer_is_refused():
    tp = third_party(1, sign=False, policy=AE, key_agreement=STATIC_UNIFIED_MODEL)
    _, tx = meter(1).open(nest(tp, client_ctx(1), REQUEST))
    weaker = meter(1).answer(TpTransaction(False, 0x10, 2, tx.transaction_id), RESPONSE)
    with pytest.raises(AuthenticationError, match="encrypted"):
        unnest(tp, client_ctx(1), weaker)


def test_compressed_or_key_set_tp_layer_is_refused():
    tp = third_party(1, sign=False, policy=AE)
    _, answer = exchange(tp, meter(1), client_ctx(1))
    (_, *_), pos = _fields(answer)
    _, pos = _read_os(answer, pos + 4, "key data")
    sc_at = pos + 1
    for bit in (0x40, 0x80):
        bad = bytearray(answer)
        bad[sc_at] |= bit
        with pytest.raises(DlmsError):
            unnest(tp, client_ctx(1), bytes(bad))


# --- annex J.3 ---------------------------------------------------------------------------


def test_unprotected_form_matches_cb_sigma_vector():
    """cB-Sigma thirdparty_internal_test.go: protectNone(1, res) == 01 || res."""
    apdu = wrap_unprotected_general_ciphering(1, RESPONSE, METER, TP, b"\x02")
    assert apdu == (
        bytes([Tag.GENERAL_CIPHERING, 1, 2, 8])
        + METER
        + b"\x08"
        + TP
        + b"\x00\x00\x00"
        + bytes([1 + len(RESPONSE), 0x01])
        + RESPONSE
    )
    assert unwrap_unprotected_general_ciphering(apdu, 1) == (METER, TP, RESPONSE)


@pytest.mark.parametrize(
    "sc,error",
    [
        (0x02, AuthenticationError),  # another suite
        (0x81, DecodeError),  # compressed
        (0x41, AuthenticationError),  # key-set bit
        (0x11, AuthenticationError),  # authenticated: not the unprotected form
        (0x21, AuthenticationError),
    ],
)
def test_unprotected_form_refusals(sc, error):
    apdu = wrap_unprotected_general_ciphering(1, RESPONSE, METER, TP)
    bad = apdu[: -len(RESPONSE) - 1] + bytes([sc]) + RESPONSE
    with pytest.raises(error):
        unwrap_unprotected_general_ciphering(bad, 1)


def test_unprotected_form_empty_and_key_info_refused():
    empty = bytes([Tag.GENERAL_CIPHERING, 0, 8]) + METER + b"\x08" + TP + b"\x00\x00\x00\x01\x01"
    with pytest.raises(DecodeError, match="no APDU"):
        unwrap_unprotected_general_ciphering(empty, 1)
    with_info = bytes([Tag.GENERAL_CIPHERING, 0, 8]) + METER + b"\x08" + TP + b"\x00\x00"
    with_info += b"\x01\x00\x00" + bytes([1 + len(RESPONSE), 1]) + RESPONSE
    with pytest.raises(AuthenticationError, match="no key-info"):
        unwrap_unprotected_general_ciphering(with_info, 1)
    with pytest.raises(ValueError):
        wrap_unprotected_general_ciphering(0, RESPONSE, METER, TP)


def test_unprotected_answer_needs_the_opt_in():
    j3 = wrap_unprotected_general_ciphering(1, RESPONSE, METER, TP)
    for tp in (third_party(1), third_party(1, signed_responses=False)):
        with pytest.raises(AuthenticationError, match="J.3"):
            unnest(tp, client_ctx(1), j3)
    tp = third_party(1, signed_responses=False, accept_unprotected_responses=True)
    assert unnest(tp, client_ctx(1), j3) == RESPONSE


def test_unprotected_form_is_never_accepted_as_the_clients_own_layer():
    from pydlms.security.ciphering import unwrap

    ours = wrap_unprotected_general_ciphering(1, RESPONSE, METER, CLIENT)
    with pytest.raises(DlmsError):
        unwrap(client_ctx(1), ours)


# --- secrets ---------------------------------------------------------------------------


def test_no_key_in_repr_or_logs(caplog):
    from pydlms.debug import TRACE

    tp = third_party(1, policy=AE)
    text = repr(tp)
    assert "***" in text and AK16.hex() not in text
    caplog.set_level(TRACE, logger="pydlms")
    _, answer = exchange(tp, meter(1), client_ctx(1))
    unnest(tp, client_ctx(1), answer)
    logged = caplog.text.replace(" ", "").lower()
    assert AK16.hex() not in logged
    d = key("tp-sign", 1).private_numbers().private_value.to_bytes(32, "big").hex()
    assert d not in logged
    assert logging.getLogger("pydlms").isEnabledFor(TRACE)


# --- answers recorded from the cB-Sigma meter -----------------------------------------------


def _go_frames():
    from tests.crypto import go_dlms_thirdparty_frames as f

    return f


#: name -> (suite, ThirdParty overrides).
GO_FRAMES = {
    "S1_SIGNED": (1, {}),
    "S1_SIGNED_CIPHERED_ONE_PASS": (1, {"policy": AE}),
    "S1_CIPHERED_STATIC": (1, {"sign": False, "policy": AE, "key_agreement": 2}),
    "S1_UNPROTECTED": (1, {"signed_responses": False, "accept_unprotected_responses": True}),
    "S2_SIGNED_CIPHERED_ONE_PASS": (2, {"policy": AE}),
}


def _go_tp(suite: int, **kw) -> tuple[ThirdParty, SecurityContext]:
    f = _go_frames()
    args = {
        "signing_key": key(f"tp-sign-{suite}", suite),
        "key_agreement_key": key(f"tp-ka-{suite}", suite),
        "authentication_key": ak(suite),
        "general_aad": GeneralAad.WITH_HEADER,
        "signing_form": SigningForm.LENGTH_PREFIXED_CONTENT,
    }
    args.update(kw)
    tp = ThirdParty(f.TP_TITLE, **args)
    ctx = SecurityContext(
        EK32 if suite == 2 else EK16,
        ak(suite),
        client_system_title=b"PYDLMS01",
        server_system_title=f.METER_TITLE,
        suite=suite,
        peer_signing_key=key(f"server-sign-{suite}", suite).public_key(),
        peer_key_agreement_key=key(f"server-ka-{suite}", suite).public_key(),
    )
    return tp, ctx


@pytest.mark.parametrize("name", list(GO_FRAMES))
def test_cb_sigma_answers_open(name):
    f = _go_frames()
    suite, kw = GO_FRAMES[name]
    tp, ctx = _go_tp(suite, **kw)
    assert unnest(tp, ctx, getattr(f, name)) == f.GET_RESPONSE
    if name != "S1_UNPROTECTED":
        # The pydlms default forms do not open them.
        default = third_party(suite, **kw)
        default.system_title = f.TP_TITLE
        with pytest.raises(DlmsError):
            unnest(default, ctx, getattr(f, name))


def test_cb_sigma_layers_use_ic_0_and_agreed_keys():
    """cB-Sigma's reading pinned: IC 0 under every new agreed key."""
    f = _go_frames()
    for name in ("S1_SIGNED_CIPHERED_ONE_PASS", "S1_CIPHERED_STATIC"):
        apdu = getattr(f, name)
        _, pos = _fields(apdu)
        assert apdu[pos : pos + 3] == b"\x01\x02\x01"
        _, pos = _read_os(apdu, pos + 4, "key data")
        content, _ = _read_os(apdu, pos, "content")
        assert content[:5] == b"\x31\x00\x00\x00\x00"
    assert unwrap_unprotected_general_ciphering(f.S1_UNPROTECTED, 1) == (
        f.METER_TITLE,
        f.TP_TITLE,
        f.GET_RESPONSE,
    )


@pytest.mark.parametrize("name", [n for n in GO_FRAMES if n != "S1_UNPROTECTED"])
def test_cb_sigma_answers_every_byte_tampered_fail(name):
    f = _go_frames()
    suite, kw = GO_FRAMES[name]
    tp, ctx = _go_tp(suite, **kw)
    frame = getattr(f, name)
    for i in range(len(frame)):
        bad = bytearray(frame)
        bad[i] ^= 0x01
        with pytest.raises(DlmsError):
            unnest(tp, ctx, bytes(bad))


def test_cb_sigma_answer_with_the_wrong_third_party_key_fails():
    f = _go_frames()
    tp, ctx = _go_tp(1, policy=AE, key_agreement_key=key("tp-ka-other", 1))
    with pytest.raises(AuthenticationError):
        unnest(tp, ctx, f.S1_SIGNED_CIPHERED_ONE_PASS)
    tp, ctx = _go_tp(1)
    ctx.peer_signing_key = key("server-sign-other", 1).public_key()
    with pytest.raises(AuthenticationError):
        unnest(tp, ctx, f.S1_SIGNED)
