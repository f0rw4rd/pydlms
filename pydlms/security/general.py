"""general-ciphering (0xDD) and general-signing (0xDF) envelopes.

general-ciphering::

    DD | transaction-id | originator-system-title | recipient-system-title
       | date-time | other-information          (each an A-XDR octet string)
       | key-info OPTIONAL | ciphered-content (len | SC | IC | C [| T])

key-info CHOICE (present flag ``01``, absent ``00``):

* ``00 key-id``: identified key (0 global unicast, 1 global broadcast)
* ``01 kek-id len wrapped``: key wrapped (RFC 3394) under the master key
* ``02 len(1) scheme len data``: agreed key; scheme 1 = one-pass
  Diffie-Hellman C(1e,1s), data = ephemeral X||Y || ECDSA signature over
  ``X || Y``; scheme 2 = static unified model C(0e,2s), no data.

The ephemeral-key signature covers the bare point ``X || Y``: the
IEC 62056-5-3:2023 annex I.2 example verifies only that way
(``tests/crypto/test_one_pass_dh_signature.py``). Gurux.DLMS.Net signs
``01 || X || Y`` instead (the scheme id over the point's ``04`` prefix);
inbound both are accepted so Gurux peers keep working (the same peer key
must have made the signature either way). The Gurux server does not verify
this signature on general-ciphering, so the standard form interoperates.

The content key is the identified/unwrapped key, or for agreed keys the
SP 800-56A KDF of the ECDH secret with PartyUInfo = originator title and
PartyVInfo = recipient title (static unified model: PartyVInfo = the
length-prefixed transaction id, SuppPubInfo = recipient title). GCM IV =
originator title || IC; AAD = SC || AK as for every other envelope
(:attr:`GeneralAad.SC_AK`, the default).

general-signing::

    DF | transaction-id | originator | recipient | date-time | other-information
       | content (len | APDU) | signature (len | r||s)

The signature covers everything after the tag up to the content length, then
the content bytes without their length (:attr:`SigningForm.CONTENT`, the
default).

Open divergences: cB-Sigma dlms authenticates the five
header fields too (``SC || AK || header``, its reading of IEC 62056-5-3:2023
Table 28) and signs the content with its length. No standard example
verifies either reading (the annex I.2 tag reproduces under neither AAD),
so the alternative forms are an explicit per-context opt-in,
``SecurityContext(general_aad=GeneralAad.WITH_HEADER,
signing_form=SigningForm.LENGTH_PREFIXED_CONTENT)``. A context uses exactly
one form, outbound and inbound; the other is never tried as a fallback,
which would let whoever builds the frame pick the weaker check.

Evidence: layout, key-info bytes, KDF parties and the signed ephemeral data
agree with two independent implementations (Gurux .NET and Java, consulted as
behavioural references) and are exercised end to end against the Gurux .NET
server (``tests/integration/test_gurux.py``). Gurux .NET keeps only 16 KDF
octets even for suite 2 (AES-256); pydlms derives 32 as the suite requires.
"""

from __future__ import annotations

import enum
import os
from dataclasses import dataclass

from pydlms.apdu.tags import Tag, tag_name
from pydlms.axdr import decode_length, encode_length
from pydlms.debug import get_logger
from pydlms.exceptions import AuthenticationError, DecodeError, KeyMissingError
from pydlms.security import gcm
from pydlms.security.provider import provider_of
from pydlms.security.suites import SecurityControl, key_length

__all__ = [
    "GeneralAad",
    "SigningForm",
    "KeyInfo",
    "wrap_general_ciphering",
    "unwrap_general_ciphering",
    "verify_ephemeral_signature",
    "wrap_general_signing",
    "verify_general_signing",
    "signing_replay_token",
    "ONE_PASS_DH",
    "STATIC_UNIFIED_MODEL",
]

log = get_logger("security")

ONE_PASS_DH = 1
STATIC_UNIFIED_MODEL = 2


class GeneralAad(enum.Enum):
    """What general-ciphering authenticates besides the ciphered content.

    ``SC_AK`` (default): ``SC || AK``, as every other envelope; Gurux and
    pydlms. ``WITH_HEADER``: ``SC || AK || header`` where ``header`` is the
    five length-prefixed fields transaction-id, originator, recipient,
    date-time and other-information as sent (auth-only:
    ``SC || AK || header || P``); cB-Sigma dlms. The Green Book text sides
    with header fields in the AAD (DLMS UA 1000-2 Ed. 9 Excerpt 9.2.7.2.4.8
    Figure 32: "the length and the value of each field is included in the
    AAD") without giving the layout, and neither form reproduces the IEC
    62056-5-3:2023 annex I.2 tag, so neither has a known answer.
    """

    SC_AK = "sc-ak"
    WITH_HEADER = "with-header"


class SigningForm(enum.Enum):
    """What a general-signing signature covers after the five header fields.

    ``CONTENT`` (default): the content octets without their length; Gurux
    and pydlms. ``LENGTH_PREFIXED_CONTENT``: the content as its A-XDR octet
    string (length, then octets); cB-Sigma dlms. No standard example exists.
    """

    CONTENT = "content"
    LENGTH_PREFIXED_CONTENT = "length-prefixed-content"


def _general_aad(ctx) -> GeneralAad:
    return getattr(ctx, "general_aad", GeneralAad.SC_AK)


def _signing_form(ctx) -> SigningForm:
    return getattr(ctx, "signing_form", SigningForm.CONTENT)


def _header(
    transaction_id: bytes, originator: bytes, recipient: bytes, date_time: bytes, other: bytes
) -> bytes:
    """The five general-ciphering/-signing header fields, as sent."""
    return b"".join(_os(f) for f in (transaction_id, originator, recipient, date_time, other))


@dataclass(frozen=True)
class KeyInfo:
    """Which content key a general-ciphering APDU uses.

    ``kind``: ``"none"`` (no key-info: global unicast key), ``"identified"``
    (``key_id`` 0 unicast / 1 broadcast), ``"wrapped"`` (fresh random key
    wrapped under the master key) or ``"agreed"`` (``scheme`` one-pass DH or
    static unified model).
    """

    kind: str = "none"
    key_id: int = 0
    scheme: int = ONE_PASS_DH


#: Default key-info: the global unicast key, identified.
IDENTIFIED_UNICAST = KeyInfo("identified", 0)


def _os(data: bytes) -> bytes:
    return encode_length(len(data)) + data


def _read_os(data: bytes, pos: int, what: str) -> tuple[bytes, int]:
    length, pos = decode_length(data, pos)
    end = pos + length
    if end > len(data):
        raise DecodeError(f"{what}: declared {length} octets, {len(data) - pos} available")
    return data[pos:end], end


def _point(public_key) -> bytes:
    from pydlms.security.ec import public_key_bytes

    return public_key_bytes(public_key)


def _agreed_key(
    ctx,
    scheme: int,
    private_key,
    peer_public_key,
    originator: bytes,
    recipient: bytes,
    transaction_id: bytes,
    ephemeral: bool = False,
):
    """The content key: ECDH of ``private_key`` with ``peer_public_key``, then the KDF.

    pydlms builds the OtherInfo. A configured key (``ephemeral=False``) is a
    provider key reference: the provider's ``ecdh_kdf`` is used when it has
    one (``Z`` never leaves it), else its ``ecdh`` and the KDF here. An
    ephemeral key pydlms generated itself is computed in software.
    """
    from pydlms.security import ec

    suite = int(ctx.suite)
    if scheme == ONE_PASS_DH:
        info = ec.other_info(suite, originator, recipient)
    else:
        info = ec.other_info(suite, originator, _os(transaction_id), recipient)
    if ephemeral:
        return ec.kdf_other_info(suite, ec.ecdh_shared_secret(private_key, peer_public_key), info)
    crypto = provider_of(ctx)
    if crypto.supports("ecdh_kdf"):
        return crypto.ecdh_kdf(private_key, peer_public_key, suite, info)
    return ec.kdf_other_info(suite, crypto.ecdh(private_key, peer_public_key), info)


def _require(ctx, name: str):
    value = getattr(ctx, name, None)
    if value is None:
        raise KeyMissingError(f"general-ciphering needs SecurityContext.{name}")
    return value


def verify_ephemeral_signature(public_key, point: bytes, signature: bytes) -> None:
    """Verify a one-pass DH ephemeral-key signature by ``public_key``.

    Accepts a signature over ``X || Y`` (IEC 62056-5-3:2023 annex I.2) or
    over ``01 || X || Y`` (Gurux.DLMS.Net); raises
    :class:`AuthenticationError` otherwise.
    """
    from pydlms.security.ec import ecdsa_verify

    try:
        ecdsa_verify(public_key, point, signature)
    except AuthenticationError:
        ecdsa_verify(public_key, bytes([ONE_PASS_DH]) + point, signature)


# --- general-ciphering ------------------------------------------------------------------


def wrap_general_ciphering(
    ctx,
    plaintext_apdu: bytes,
    recipient_title: bytes,
    key_info: KeyInfo = IDENTIFIED_UNICAST,
    transaction_id: bytes = b"",
    sc: SecurityControl | None = None,
    date_time: bytes = b"",
    other_information: bytes = b"",
) -> bytes:
    """Protect ``plaintext_apdu`` in a general-ciphering envelope."""
    if len(recipient_title) != 8:
        raise ValueError("recipient system title must be 8 octets")
    from pydlms.security.ciphering import _trace, refuse_outbound_compression

    originator = ctx.client_system_title
    sc = sc or SecurityControl.for_policy(ctx.policy, int(ctx.suite))
    refuse_outbound_compression(sc)
    if key_info.kind == "none":
        key, info = ctx.require_encryption_key(), b"\x00"
    elif key_info.kind == "identified":
        key = ctx.require_encryption_key(broadcast=key_info.key_id == 1)
        info = bytes([1, 0, key_info.key_id])
        sc = SecurityControl(
            sc.suite, sc.authenticated, sc.encrypted, broadcast_key=key_info.key_id == 1
        )
    elif key_info.kind == "wrapped":
        key = os.urandom(key_length(int(ctx.suite)))
        wrapped = provider_of(ctx).aes_wrap(_require(ctx, "master_key"), key)
        info = bytes([1, 1, 0]) + _os(wrapped)
    elif key_info.kind == "agreed":
        from pydlms.security.ec import generate_private_key

        peer = _require(ctx, "peer_key_agreement_key")
        if key_info.scheme == ONE_PASS_DH:
            ephemeral = generate_private_key(int(ctx.suite))
            key = _agreed_key(
                ctx, ONE_PASS_DH, ephemeral, peer, originator, recipient_title, transaction_id, True
            )
            point = _point(ephemeral)
            signature = provider_of(ctx).ecdsa_sign(
                _require(ctx, "signing_key"), point, int(ctx.suite)
            )
            data = point + signature
        elif key_info.scheme == STATIC_UNIFIED_MODEL:
            key = _agreed_key(
                ctx,
                STATIC_UNIFIED_MODEL,
                _require(ctx, "key_agreement_key"),
                peer,
                originator,
                recipient_title,
                transaction_id,
            )
            data = b""
        else:
            raise ValueError(f"unknown key agreement scheme {key_info.scheme}")
        info = bytes([1, 2, 1, key_info.scheme]) + _os(data)
    else:
        raise ValueError(f"unknown key-info kind {key_info.kind!r}")
    header = _header(transaction_id, originator, recipient_title, date_time, other_information)
    extra = header if _general_aad(ctx) is GeneralAad.WITH_HEADER else b""
    ak = ctx.require_authentication_key() if sc.authenticated else None
    ic = ctx.next_invocation_counter()
    body = gcm.encrypt(
        sc, key, ak, originator, ic, plaintext_apdu, extra_aad=extra, provider=provider_of(ctx)
    )
    content = bytes([sc.to_byte()]) + ic.to_bytes(4, "big") + body
    apdu = bytes([Tag.GENERAL_CIPHERING]) + header + info + _os(content)
    log.debug(
        "cipher %s -> GENERAL_CIPHERING (%s) %s IC=%d",
        tag_name(plaintext_apdu[0]),
        key_info.kind,
        sc.describe(),
        ic,
    )
    _trace("encrypt", Tag.GENERAL_CIPHERING, sc, ic, originator, plaintext_apdu, apdu)
    return apdu


def _check_titles(ctx, originator: bytes, recipient: bytes) -> None:
    """Refuse general-ciphering for someone else or from an unexpected peer.

    Checked only against what the context knows: our own title when it was
    configured (an empty recipient names no one), the peer title once set
    (AARE responding-AP-title, certificate, or given).
    """
    own = ctx.client_system_title if getattr(ctx, "own_title_known", True) else None
    if own is not None and recipient and recipient != own:
        raise AuthenticationError(
            f"general-ciphering recipient {recipient.hex()} is not us ({own.hex()})"
        )
    peer = ctx.server_system_title
    if peer is not None and originator != peer:
        raise AuthenticationError(
            f"general-ciphering originator {originator.hex()} is not the peer {peer.hex()}"
        )


def unwrap_general_ciphering(
    ctx, apdu: bytes, strict: bool = True, max_decompressed: int | None = None
):
    """Parse a general-ciphering APDU, establish its key, decipher it.

    ``strict`` and ``max_decompressed`` as for
    :func:`pydlms.security.ciphering.unwrap`.
    """
    from pydlms.security.ciphering import MAX_DECOMPRESSED_DEFAULT, _unprotect

    if max_decompressed is None:
        max_decompressed = MAX_DECOMPRESSED_DEFAULT

    pos = 1
    transaction_id, pos = _read_os(apdu, pos, "transaction-id")
    originator, pos = _read_os(apdu, pos, "originator-system-title")
    recipient, pos = _read_os(apdu, pos, "recipient-system-title")
    _date_time, pos = _read_os(apdu, pos, "date-time")
    _other, pos = _read_os(apdu, pos, "other-information")
    header = apdu[1:pos]
    if len(originator) != 8:
        raise DecodeError("general-ciphering originator system title must be 8 octets")
    if pos >= len(apdu):
        raise DecodeError("general-ciphering truncated before key-info")
    key = None
    key_kind = None  # no key-info: the global key the SC names
    broadcast = False
    present = apdu[pos]
    pos += 1
    if present not in (0, 1):
        raise DecodeError(f"key-info presence flag {present} is not 0 or 1")
    if present:
        if pos >= len(apdu):
            raise DecodeError("general-ciphering truncated in key-info")
        choice = apdu[pos]
        pos += 1
        if choice == 0:  # identified-key
            if pos >= len(apdu):
                raise DecodeError("identified-key without key-id")
            key_id = apdu[pos]
            pos += 1
            if key_id not in (0, 1):
                raise DecodeError(f"identified key-id {key_id} is not 0 or 1")
            broadcast = key_id == 1
            key = ctx.require_encryption_key(broadcast=broadcast)
            key_kind = "broadcast" if broadcast else "unicast"
        elif choice == 1:  # wrapped-key
            pos += 1  # kek-id (0: master key)
            wrapped, pos = _read_os(apdu, pos, "wrapped key")
            key = provider_of(ctx).aes_unwrap(_require(ctx, "master_key"), wrapped)
            key_kind = "wrapped"
        elif choice == 2:  # agreed-key
            params, pos = _read_os(apdu, pos, "key-parameters")
            data, pos = _read_os(apdu, pos, "key-ciphered-data")
            if len(params) != 1:
                raise DecodeError("agreed-key parameters must be one octet")
            scheme = params[0]
            from pydlms.security.ec import load_public_key

            if scheme == ONE_PASS_DH:
                if len(data) % 4 or not data:
                    raise DecodeError("one-pass DH key data must be X || Y || r || s")
                half = len(data) // 2
                point, signature = data[:half], data[half:]
                peer_signing = getattr(ctx, "peer_signing_key", None)
                if peer_signing is not None:
                    verify_ephemeral_signature(peer_signing, point, signature)
                elif not ctx.allow_unverified_auth:
                    raise KeyMissingError(
                        "one-pass DH: the ephemeral key signature cannot be verified without "
                        "SecurityContext.peer_signing_key"
                    )
                peer = load_public_key(int(ctx.suite), point)
            elif scheme == STATIC_UNIFIED_MODEL:
                if data:
                    raise DecodeError("static unified model carries no key data")
                peer = _require(ctx, "peer_key_agreement_key")
            else:
                raise DecodeError(f"unknown key agreement scheme {scheme}")
            key = _agreed_key(
                ctx,
                scheme,
                _require(ctx, "key_agreement_key"),
                peer,
                originator,
                recipient,
                transaction_id,
            )
            key_kind = "agreed"
        else:
            raise DecodeError(f"unknown key-info choice {choice}")
    content, end = _read_os(apdu, pos, "ciphered content")
    if end != len(apdu):
        raise DecodeError(f"{len(apdu) - end} trailing octets after general-ciphering")
    if strict:
        _check_titles(ctx, originator, recipient)
    return _unprotect(
        ctx,
        Tag.GENERAL_CIPHERING,
        content,
        originator,
        False,
        apdu,
        key_override=key,
        strict=strict,
        key_kind=key_kind,
        extra_aad=header if _general_aad(ctx) is GeneralAad.WITH_HEADER else b"",
        max_decompressed=max_decompressed,
    )


# --- general-signing -----------------------------------------------------------------------


def wrap_general_signing(
    ctx,
    content_apdu: bytes,
    recipient_title: bytes,
    transaction_id: bytes = b"",
    date_time: bytes = b"",
    other_information: bytes = b"",
) -> bytes:
    """Sign ``content_apdu`` (plain or already ciphered) as general-signing."""
    header = _header(
        transaction_id, ctx.client_system_title, recipient_title, date_time, other_information
    )
    signature = provider_of(ctx).ecdsa_sign(
        _require(ctx, "signing_key"),
        _signed_data(header, content_apdu, _signing_form(ctx)),
        getattr(ctx, "suite", None),
    )
    log.debug(
        "signed %s as GENERAL_SIGNING (%d-octet signature)",
        tag_name(content_apdu[0]),
        len(signature),
    )
    return bytes([Tag.GENERAL_SIGNING]) + header + _os(content_apdu) + _os(signature)


def _signed_data(header: bytes, content: bytes, form: SigningForm) -> bytes:
    if form is SigningForm.LENGTH_PREFIXED_CONTENT:
        return header + _os(content)
    return header + content


def _parse_general_signing(
    apdu: bytes, form: SigningForm = SigningForm.CONTENT
) -> tuple[bytes, bytes, bytes, bytes]:
    """``(originator, signed data, content, signature)`` of a general-signing APDU.

    The signed data is the one ``form`` defines.
    """
    if not apdu or apdu[0] != Tag.GENERAL_SIGNING:
        raise DecodeError("not a general-signing APDU")
    pos = 1
    _transaction_id, pos = _read_os(apdu, pos, "transaction-id")
    originator, pos = _read_os(apdu, pos, "originator-system-title")
    _recipient, pos = _read_os(apdu, pos, "recipient-system-title")
    _date_time, pos = _read_os(apdu, pos, "date-time")
    _other, pos = _read_os(apdu, pos, "other-information")
    header_end = pos
    content, pos = _read_os(apdu, pos, "content")
    if pos >= len(apdu):
        # Seen from the Gurux server when its signing mode is unset: an
        # unsigned "general-signing" must never be accepted as signed.
        raise DecodeError("general-signing APDU carries no signature")
    signature, pos = _read_os(apdu, pos, "signature")
    if pos != len(apdu):
        raise DecodeError(f"{len(apdu) - pos} trailing octets after general-signing")
    return originator, _signed_data(apdu[1:header_end], content, form), content, signature


def signing_replay_token(apdu: bytes, form: SigningForm = SigningForm.CONTENT) -> bytes:
    """Identity of a signed message for the replay check.

    SHA-256 of the signed data (as ``form``, the one that verified, defines
    it) and the signature's ``r``: ``(r, n - s)`` is a second valid
    signature of the same message, so ``s`` is left out; a re-signed message
    gets a fresh ``r`` from a fresh nonce.
    """
    import hashlib

    _, signed, _, signature = _parse_general_signing(apdu, SigningForm(form))
    return hashlib.sha256(signed + signature[: len(signature) // 2]).digest()


def verify_general_signing(ctx, apdu: bytes) -> tuple[bytes, bytes]:
    """Verify a general-signing APDU; returns ``(originator, content_apdu)``.

    Only the context's :class:`SigningForm` is checked, never the other one.
    """
    from pydlms.security.ec import ecdsa_verify

    originator, signed, content, signature = _parse_general_signing(apdu, _signing_form(ctx))
    peer = getattr(ctx, "peer_signing_key", None)
    if peer is None:
        raise KeyMissingError("general-signing needs SecurityContext.peer_signing_key")
    try:
        ecdsa_verify(peer, signed, signature)
    except AuthenticationError:
        log.debug("general-signing from %s: signature did NOT verify", originator.hex())
        raise
    log.debug(
        "general-signing from %s verified, content %s",
        originator.hex(),
        tag_name(content[0]) if content else "-",
    )
    return originator, content
