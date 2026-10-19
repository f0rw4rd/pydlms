"""Third-party protection layers (IEC 62056-5-3:2023 4.1.7, 5.7.3, Table 26, annex J).

A third party (TP), for example a head-end that owns its own keys, protects
a request for the meter; the client then protects the result with its own
layer, so the meter removes the client's layer first and the TP's after
it::

    request   the client's general-glo / general-ded / general-ciphering
                general-ciphering by the TP (optional), recipient the meter
                  general-signing by the TP (optional), recipient the meter
                    the xDLMS request
    response  the client's layer, as above
                general-ciphering by the meter for the TP (optional)
                  general-signing by the meter for the TP (optional)
                    the xDLMS response
              or, instead of both meter layers, general-ciphering with
              neither authentication nor encryption (annex J.3)

The TP signs before it ciphers (5.7.3), so a response is opened outside in:
general-ciphering first, then general-signing. A signing layer outside a
ciphering one, two layers of one kind, more than two layers, or anything
inside an unprotected J.3 layer is refused.

This module is a pure transform: :func:`nest` adds the TP's layers to a
plaintext request, :func:`unnest` removes and verifies the meter's layers
for the TP from a response the client's own layer already opened.
:attr:`pydlms.association.AssociationSettings.third_party` applies both
to every service APDU of an association.

Keys
----

The TP's general-signing uses its ECDSA ``signing_key``; the meter checks
it with the TP's certificate. Its general-ciphering always uses a key
agreed for the one APDU (key-info ``agreed-key``): one-pass Diffie-Hellman
C(1e, 1s) (the TP's ephemeral key signed with ``signing_key``) or the
static unified model C(0e, 2s) (``key_agreement_key`` and a fresh random
transaction-id, the KDF input that makes the key new). Identified and
wrapped keys are refused both ways: the global keys and the master key are
the client's, not disclosed to a third party (5.5.2 note, 5.5.4, as read
by cB-Sigma dlms; the clause text is not available here). The
authentication key of an authenticated TP layer is the global one the TP
was given outside the exchange (Table 26); it is
``ThirdParty.authentication_key``. The meter's keys (``peer_signing_key``,
``peer_key_agreement_key``) come from the client's
:class:`~pydlms.security.context.SecurityContext`: the meter is the same
peer for both.

Invocation counter
------------------

Every agreed key is new, so the TP's layer is sent with invocation counter
0, as cB-Sigma dlms does (its reading of Table 29 and the annex I
examples; **unverified** against the clause text). The IV is the TP's
system title || 0 under a key used for one APDU only, so no (key, IV) pair
repeats: each one-pass key has a fresh ephemeral key, each static key a
fresh 8-octet transaction-id. Inbound, the counter of a meter layer for
the TP is not checked against a store: its key is the meter's fresh one.
Replay protection of the whole response comes from the client's own
layer, which is why the association requires a ciphering envelope
(general-glo / general-ded / general-ciphering) around the TP's layers.
Signed content from the meter additionally passes the context's
:meth:`~pydlms.security.context.SecurityContext.check_signed_replay`.

Annex J.3 (no protection)
-------------------------

When the meter's policy asks for no protection of its answer to the TP, it
sends general-ciphering whose ciphered-content is ``SC || APDU``: the SC
has A and E clear (only the suite in the low nibble) and there is no
invocation counter and no tag. :func:`wrap_unprotected_general_ciphering`
builds and :func:`unwrap_unprotected_general_ciphering` parses that form.
:func:`unnest` accepts it only with ``accept_unprotected_responses=True``
and only when neither ``signed_responses`` nor ``ciphered_responses`` is
required, since it loosens the policy. The general unwrap path
(:func:`pydlms.security.ciphering.unwrap`) keeps refusing an SC that
protects nothing.

Forms
-----

The general-ciphering AAD and general-signing signed data have two
readings in the field; ``ThirdParty.general_aad`` and
``signing_form`` pick one for the TP's layers, both ways, independent of
the client's own context (cB-Sigma dlms uses ``WITH_HEADER`` and
``LENGTH_PREFIXED_CONTENT``). Compression (SC bit 7) is never sent and is
refused inbound in a TP layer.

No known answer exists: annex J of IEC 62056-5-3:2023 has no transcribed
byte example here. The layers are built from the pinned general-ciphering
and general-signing primitives (:mod:`pydlms.security.general`) and are
checked against the cB-Sigma dlms meter and its recorded answers
(``tests/crypto/test_thirdparty.py``, ``tests/interop/test_go_dlms.py``).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from pydlms.apdu.tags import Tag
from pydlms.debug import get_logger, register_secret
from pydlms.exceptions import (
    AuthenticationError,
    DecodeError,
    KeyMissingError,
    ReplayError,
    SecurityError,
)
from pydlms.security.general import (
    ONE_PASS_DH,
    STATIC_UNIFIED_MODEL,
    GeneralAad,
    KeyInfo,
    SigningForm,
    _header,
    _os,
    _read_os,
    signing_replay_token,
    unwrap_general_ciphering,
    verify_general_signing,
    wrap_general_ciphering,
    wrap_general_signing,
)
from pydlms.security.provider import is_raw_key
from pydlms.security.suites import SecurityControl, SecurityPolicy, SecuritySuite

__all__ = [
    "ThirdParty",
    "nest",
    "unnest",
    "wrap_unprotected_general_ciphering",
    "unwrap_unprotected_general_ciphering",
]

log = get_logger("security")

#: Octets a TP layer adds at most (for request sizing): general-signing
#: with a P-384 signature and an 8-octet transaction-id, general-ciphering
#: with a one-pass P-384 ephemeral key and its signature.
SIGNING_OVERHEAD = 1 + 9 + 9 + 9 + 1 + 1 + 3 + 2 + 96
CIPHERING_OVERHEAD = 1 + 9 + 9 + 9 + 1 + 1 + 4 + 3 + 192 + 3 + 1 + 4 + 12


@dataclass(repr=False)
class ThirdParty:
    """A third party on whose behalf requests are protected.

    ``system_title``: the TP's 8-octet system title (the originator of its
    layers, the recipient of the meter's). ``sign``: apply its
    general-signing layer (needs ``signing_key``). ``policy``: its
    general-ciphering layer (:class:`SecurityPolicy`; ``NONE``, the
    default, adds none) under a key agreed by ``key_agreement``
    (``ONE_PASS_DH``, needs ``signing_key``; ``STATIC_UNIFIED_MODEL``,
    needs ``key_agreement_key``). An authenticated layer needs
    ``authentication_key``.

    Responses: ``signed_responses`` (default: when the TP signs) requires
    the meter's general-signing layer for the TP, ``ciphered_responses``
    (default: when the TP ciphers) its general-ciphering layer with at
    least ``policy``; opening a ciphered layer needs ``key_agreement_key``
    and the meter's signing key in the client's context (one-pass) or its
    key agreement key (static). ``accept_unprotected_responses`` (off)
    accepts the annex J.3 layer with no protection; it needs both
    requirements off.

    Key fields may be references of ``provider`` (default: the client
    context's provider). No key appears in ``repr``.
    """

    system_title: bytes
    signing_key: object | None = None
    sign: bool = True
    policy: SecurityPolicy = SecurityPolicy.NONE
    key_agreement: int = ONE_PASS_DH
    key_agreement_key: object | None = None
    authentication_key: object | None = None
    signed_responses: bool | None = None
    ciphered_responses: bool | None = None
    accept_unprotected_responses: bool = False
    general_aad: GeneralAad = GeneralAad.SC_AK
    signing_form: SigningForm = SigningForm.CONTENT
    provider: object | None = None

    def __post_init__(self) -> None:
        title = self.system_title
        if not isinstance(title, (bytes, bytearray)) or len(title) != 8:
            raise ValueError("third party system title must be 8 octets")
        self.system_title = bytes(title)
        self.policy = SecurityPolicy(self.policy)
        self.general_aad = GeneralAad(self.general_aad)
        self.signing_form = SigningForm(self.signing_form)
        if self.key_agreement not in (ONE_PASS_DH, STATIC_UNIFIED_MODEL):
            raise ValueError(
                f"third party key agreement {self.key_agreement} is not one-pass DH (1) or "
                "the static unified model (2): a third party holds no global or master key"
            )
        if self.signed_responses is None:
            self.signed_responses = self.sign
        if self.ciphered_responses is None:
            self.ciphered_responses = self.policy != SecurityPolicy.NONE
        if is_raw_key(self.authentication_key) and len(self.authentication_key) not in (16, 32):
            raise ValueError("third party authentication_key must be 16 or 32 octets")
        register_secret(self.authentication_key)
        ciphers = self.policy != SecurityPolicy.NONE
        if not self.sign and not ciphers:
            raise ValueError("third party applies no protection: set sign or policy")
        if self.sign and self.signing_key is None:
            raise KeyMissingError("third party signing needs signing_key")
        if self.policy & SecurityPolicy.AUTHENTICATED and self.authentication_key is None:
            raise KeyMissingError("an authenticated third party layer needs authentication_key")
        if ciphers and self.key_agreement == ONE_PASS_DH and self.signing_key is None:
            raise KeyMissingError(
                "third party one-pass DH needs signing_key (it signs the ephemeral key)"
            )
        if ciphers and self.key_agreement == STATIC_UNIFIED_MODEL:
            if self.key_agreement_key is None:
                raise KeyMissingError("third party static unified model needs key_agreement_key")
        if self.ciphered_responses and self.key_agreement_key is None:
            raise KeyMissingError(
                "ciphered responses for the third party need its key_agreement_key"
            )
        if self.accept_unprotected_responses and (self.signed_responses or self.ciphered_responses):
            raise ValueError(
                "accept_unprotected_responses needs signed_responses=False and "
                "ciphered_responses=False: a required layer is never unprotected"
            )
        if self.accept_unprotected_responses:
            log.warning(
                "third party %s accepts UNPROTECTED responses (annex J.3)", self.system_title.hex()
            )

    def __repr__(self) -> str:
        held = [
            n
            for n in ("signing_key", "key_agreement_key", "authentication_key")
            if getattr(self, n) is not None
        ]
        return (
            f"ThirdParty(system_title={self.system_title.hex()}, sign={self.sign}, "
            f"policy={self.policy.name}, key_agreement={self.key_agreement}, "
            f"signed_responses={self.signed_responses}, "
            f"ciphered_responses={self.ciphered_responses}, "
            f"accept_unprotected_responses={self.accept_unprotected_responses}, "
            f"keys=[{', '.join(f'{n}=***' for n in held)}])"
        )

    __str__ = __repr__


class _View:
    """The TP's side of one layer, as :mod:`pydlms.security.general` reads a context.

    Its own title is the TP's, the peer is the meter; the meter's keys come
    from the client's context. It has no global or master key, hands out
    invocation counter 0 once, and keeps no inbound counter (every key it
    meets is agreed for one APDU).
    """

    master_key = None
    dedicated_key = None
    broadcast_key = None
    encryption_key = None
    allow_unverified_auth = False
    decompressor = None
    own_title_known = True
    replay_protection = True

    def __init__(self, tp: ThirdParty, ctx, meter_title: bytes, policy: SecurityPolicy) -> None:
        self.suite = SecuritySuite(int(ctx.suite))
        self.policy = SecurityPolicy(policy)
        self.client_system_title = tp.system_title
        self.server_system_title = meter_title
        self.signing_key = tp.signing_key
        self.key_agreement_key = tp.key_agreement_key
        self.authentication_key = tp.authentication_key
        self.peer_signing_key = getattr(ctx, "peer_signing_key", None)
        self.peer_key_agreement_key = getattr(ctx, "peer_key_agreement_key", None)
        self.general_aad = tp.general_aad
        self.signing_form = tp.signing_form
        self.provider = tp.provider if tp.provider is not None else getattr(ctx, "provider", None)
        self._ic_used = False

    def __repr__(self) -> str:
        return f"_View(third party {self.client_system_title.hex()})"

    def require_encryption_key(self, broadcast: bool = False, dedicated: bool = False):
        raise KeyMissingError(
            "a third party holds no global, broadcast or dedicated key: its layers use an "
            "agreed key"
        )

    def require_authentication_key(self):
        if self.authentication_key is None:
            raise KeyMissingError("the third party has no authentication_key")
        return self.authentication_key

    def next_invocation_counter(self) -> int:
        if self._ic_used:
            raise ReplayError("a third party layer view ciphers one APDU only")
        self._ic_used = True
        return 0

    def check_inbound_counter(self, system_title, ic, commit=True, key="agreed") -> None:
        log.debug(
            "third party layer from %s: IC %d under a key agreed for this APDU",
            bytes(system_title).hex(),
            ic,
        )


def _suite(ctx) -> int:
    suite = int(getattr(ctx, "suite", 0))
    if suite not in (1, 2):
        raise SecurityError(
            "third party layers need security suite 1 or 2 (their keys are ECDSA and ECDH)"
        )
    return suite


def _meter_title(ctx, meter_title: bytes | None) -> bytes:
    title = meter_title if meter_title is not None else getattr(ctx, "server_system_title", None)
    if title is None:
        raise KeyMissingError("third party layers need the meter's system title")
    if len(title) != 8:
        raise ValueError("meter system title must be 8 octets")
    return bytes(title)


def nest(tp: ThirdParty, ctx, apdu: bytes, meter_title: bytes | None = None) -> bytes:
    """Apply the TP's layers to the plaintext request ``apdu``.

    general-signing (when ``tp.sign``), then general-ciphering under an
    agreed key (when ``tp.policy``), both addressed to ``meter_title``
    (default: the context's server system title). ``ctx`` is the client's
    security context: it supplies the suite and the meter's keys. The
    result is what the client's own layer then protects.
    """
    if not apdu:
        raise ValueError("empty APDU")
    suite = _suite(ctx)
    meter = _meter_title(ctx, meter_title)
    out = bytes(apdu)
    if tp.sign:
        out = wrap_general_signing(
            _View(tp, ctx, meter, tp.policy), out, meter, transaction_id=os.urandom(8)
        )
    if tp.policy != SecurityPolicy.NONE:
        view = _View(tp, ctx, meter, tp.policy)
        if view.peer_key_agreement_key is None and tp.key_agreement == STATIC_UNIFIED_MODEL:
            raise KeyMissingError(
                "third party static unified model needs the meter's key agreement key "
                "(SecurityContext.peer_key_agreement_key)"
            )
        out = wrap_general_ciphering(
            view,
            out,
            meter,
            KeyInfo("agreed", scheme=tp.key_agreement),
            # Fresh per APDU: the static unified model's KDF input, and a
            # transaction to answer in either scheme.
            transaction_id=os.urandom(8),
            sc=SecurityControl.for_policy(tp.policy, suite),
        )
    log.debug(
        "third party %s layers: %s%s",
        tp.system_title.hex(),
        "signed" if tp.sign else "",
        f"{'+' if tp.sign else ''}ciphered {tp.policy.name}" if tp.policy else "",
    )
    return out


@dataclass(frozen=True)
class _GeneralCiphering:
    transaction_id: bytes
    originator: bytes
    recipient: bytes
    key_info: int | None  # key-info CHOICE, None when absent
    content: bytes


def _parse_general_ciphering(apdu: bytes) -> _GeneralCiphering:
    """Split a general-ciphering APDU (bounds-checked, nothing deciphered)."""
    if not apdu or apdu[0] != Tag.GENERAL_CIPHERING:
        raise DecodeError("not a general-ciphering APDU")
    pos = 1
    transaction_id, pos = _read_os(apdu, pos, "transaction-id")
    originator, pos = _read_os(apdu, pos, "originator-system-title")
    recipient, pos = _read_os(apdu, pos, "recipient-system-title")
    _, pos = _read_os(apdu, pos, "date-time")
    _, pos = _read_os(apdu, pos, "other-information")
    if pos >= len(apdu):
        raise DecodeError("general-ciphering truncated before key-info")
    present = apdu[pos]
    pos += 1
    choice = None
    if present == 1:
        if pos >= len(apdu):
            raise DecodeError("general-ciphering truncated in key-info")
        choice = apdu[pos]
        pos += 1
        if choice == 0:
            pos += 1
        elif choice == 1:
            pos += 1
            _, pos = _read_os(apdu, pos, "wrapped key")
        elif choice == 2:
            _, pos = _read_os(apdu, pos, "key-parameters")
            _, pos = _read_os(apdu, pos, "key-ciphered-data")
        else:
            raise DecodeError(f"unknown key-info choice {choice}")
    elif present != 0:
        raise DecodeError(f"key-info presence flag {present} is not 0 or 1")
    content, end = _read_os(apdu, pos, "ciphered content")
    if end != len(apdu):
        raise DecodeError(f"{len(apdu) - end} trailing octets after general-ciphering")
    return _GeneralCiphering(transaction_id, originator, recipient, choice, content)


def _route(apdu: bytes) -> tuple[int, bytes, bytes] | None:
    """``(tag, originator, recipient)`` of a general-signing/-ciphering APDU, else None."""
    if not apdu or apdu[0] not in (Tag.GENERAL_SIGNING, Tag.GENERAL_CIPHERING):
        return None
    pos = 1
    _, pos = _read_os(apdu, pos, "transaction-id")
    originator, pos = _read_os(apdu, pos, "originator-system-title")
    recipient, pos = _read_os(apdu, pos, "recipient-system-title")
    return apdu[0], originator, recipient


def wrap_unprotected_general_ciphering(
    suite: int,
    apdu: bytes,
    originator: bytes,
    recipient: bytes,
    transaction_id: bytes = b"",
    date_time: bytes = b"",
    other_information: bytes = b"",
) -> bytes:
    """general-ciphering with no protection (annex J.3): content ``SC || APDU``.

    The SC carries only ``suite`` (A, E, key-set and compression bits
    clear); there is no key-info, invocation counter or tag. What a meter
    sends a third party when its policy asks for no protection.
    """
    if int(suite) not in (1, 2):
        raise ValueError("the unprotected general-ciphering layer is for suites 1 and 2")
    if len(originator) != 8 or len(recipient) != 8:
        raise ValueError("system titles must be 8 octets")
    if not apdu:
        raise ValueError("empty APDU")
    header = _header(transaction_id, originator, recipient, date_time, other_information)
    content = bytes([int(suite)]) + bytes(apdu)
    return bytes([Tag.GENERAL_CIPHERING]) + header + b"\x00" + _os(content)


def unwrap_unprotected_general_ciphering(apdu: bytes, suite: int) -> tuple[bytes, bytes, bytes]:
    """Parse the annex J.3 form; returns ``(originator, recipient, apdu)``.

    Refuses key-info, an SC with A, E, key-set or compression set, another
    suite and empty content. It authenticates nothing: whether to accept
    the result is the caller's policy (:func:`unnest` needs an opt-in).
    """
    g = _parse_general_ciphering(apdu)
    if g.key_info is not None:
        raise AuthenticationError("an unprotected general-ciphering layer carries no key-info")
    if len(g.content) < 2:
        raise DecodeError("the unprotected general-ciphering content holds no APDU")
    sc = g.content[0]
    if sc & 0x80:
        raise DecodeError("compression in an unprotected third party layer is not supported")
    if sc & 0x30:
        raise AuthenticationError(
            f"SC 0x{sc:02X} is authenticated or encrypted, not the unprotected form"
        )
    if sc & 0x40:
        raise AuthenticationError("the key-set bit is set in an unprotected general-ciphering")
    if sc & 0x0F != int(suite):
        raise AuthenticationError(f"the layer uses security suite {sc & 0x0F}, not {int(suite)}")
    if len(g.originator) != 8 or len(g.recipient) != 8:
        raise DecodeError("general-ciphering system titles must be 8 octets")
    return g.originator, g.recipient, g.content[1:]


def unnest(tp: ThirdParty, ctx, apdu: bytes, meter_title: bytes | None = None) -> bytes:
    """Remove and verify the meter's layers for the TP from a response.

    ``apdu`` is what the client's own layer held. Every layer must come
    from ``meter_title`` (default: the context's server system title) to
    the TP; general-ciphering (agreed key, at least ``tp.policy`` when
    ciphered responses are required) outside general-signing (the meter's
    key, ``ctx.peer_signing_key``). Raises :class:`AuthenticationError`
    when a layer is missing, out of order, doubled, from someone else,
    does not verify, or is the unprotected J.3 form without the opt-in.
    """
    suite = _suite(ctx)
    meter = _meter_title(ctx, meter_title)
    route = _route(apdu)
    if route is None or route[2] != tp.system_title:
        raise AuthenticationError("the response carries no layer for the third party")
    signed = ciphered = unprotected = False
    layers = 0
    while (route := _route(apdu)) is not None and route[2] == tp.system_title:
        tag, originator, _ = route
        if unprotected or layers == 2:
            raise AuthenticationError(
                "the response has more layers for the third party than it can carry"
            )
        layers += 1
        if originator != meter:
            raise AuthenticationError(
                f"a layer for the third party comes from {originator.hex()}, "
                f"not the meter {meter.hex()}"
            )
        if tag == Tag.GENERAL_SIGNING:
            if signed:
                raise AuthenticationError("the response is signed twice for the third party")
            view = _View(tp, ctx, meter, SecurityPolicy.NONE)
            if view.peer_signing_key is None:
                raise KeyMissingError(
                    "the meter's signature for the third party needs "
                    "SecurityContext.peer_signing_key"
                )
            _, content = verify_general_signing(view, apdu)
            check = getattr(ctx, "check_signed_replay", None)
            if check is not None:
                check(signing_replay_token(apdu, tp.signing_form))
            apdu, signed = content, True
            continue
        # general-ciphering
        if signed or ciphered:
            raise AuthenticationError(
                "the third party's layers are not in the order signing inside ciphering"
            )
        g = _parse_general_ciphering(apdu)
        if g.content and not g.content[0] & 0x30:
            if not tp.accept_unprotected_responses:
                raise AuthenticationError(
                    "the meter answered the third party without protection (annex J.3); "
                    "accept_unprotected_responses is off"
                )
            _, _, apdu = unwrap_unprotected_general_ciphering(apdu, suite)
            log.warning("accepting an UNPROTECTED layer for third party %s", tp.system_title.hex())
            unprotected = True
            continue
        if g.key_info != 2:
            raise AuthenticationError(
                "the meter's layer for the third party does not agree its key "
                "(a third party holds no global or master key)"
            )
        if g.content and g.content[0] & 0x40:
            raise AuthenticationError("the key-set bit is set in a general-ciphering APDU")
        policy = tp.policy if tp.ciphered_responses else SecurityPolicy.NONE
        result = unwrap_general_ciphering(_View(tp, ctx, meter, policy), apdu)
        apdu, ciphered = result.plaintext, True
    if tp.signed_responses and not signed:
        raise AuthenticationError(
            "the meter did not sign its response for the third party, which is required"
        )
    if tp.ciphered_responses and not ciphered:
        raise AuthenticationError(
            "the meter did not cipher its response for the third party, which is required"
        )
    if not apdu:
        raise DecodeError("the third party's layers hold no APDU")
    return apdu
