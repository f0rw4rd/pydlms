"""Ciphered APDU wrapping (IEC 62056-5-3, 9.2.7.2 and the xDLMS ASN.1).

Three envelopes:

* **key-specific** ``glo-*`` / ``ded-*``::

      tag | len | SC | IC(4) | C [| T]

  The tag names the plaintext APDU type; the system title is the sender's
  (client title outbound, server title from the AARE inbound).

* **general-glo-ciphering** ``0xDB`` / **general-ded-ciphering** ``0xDC``::

      tag | len(8) | system-title(8) | len | SC | IC(4) | C [| T]

  Carries its own system title: the form pushes use.

* **general-ciphering** ``0xDD`` (suites 1/2, also usable with suite 0)::

      tag | transaction-id | originator-st | recipient-st | date-time
          | other-information | key-info OPTIONAL | ciphered-content

  every field an A-XDR octet-string. Only ``identified-key`` key-info is
  supported here; wrapped/agreed keys raise :class:`NotImplementedError`.
  **Open:** DLMS UA 1000-2 Ed. 9 Excerpt 9.2.7.2.4.8 (Figure 32, and the
  note under Figure 29) says the length and value of each header field are
  included in the AAD, which the default ``SC || AK`` does not do. The
  excerpt does not give the exact AAD layout, no known-answer vector
  reproduces (annex I.2 verifies under neither form), and the
  project gates crypto changes on one, so the default stays (Gurux interop)
  and
  the header form is the opt-in ``GeneralAad.WITH_HEADER``. A wrong guess
  can only make authentication fail (fail closed), never yield forged
  plaintext. Outbound 0xDD is not offered.

:func:`unwrap` dispatches on the tag, enforces the inbound invocation-counter
policy through the :class:`SecurityContext`, and never returns plaintext from
an authenticated APDU whose tag failed.

By default (``strict=True``) the received security control must also meet
the context: the suite id must equal ``ctx.suite``, an APDU must be
authenticated when ``ctx.policy`` authenticates and encrypted when it
encrypts, and SC ``0x00`` inside a ciphered envelope is always refused. The
SC byte is chosen by the sender, so trusting it would let an active attacker
strip protection while keeping the envelope. Analysis tools that must show
whatever a capture holds (``pydlms decode``, the XML translators) pass
``strict=False``; the counter is checked either way.

**Compression (SC bit 7).** The standard compresses the APDU (ITU-T V.44)
*before* it is protected, so the protected data is the compressed APDU.
No DLMS test vector exists, and the V.44 parameters (dictionary size,
string length) are not negotiated anywhere in the association, so
decoding is opt-in: bit 7 is refused unless
:attr:`SecurityContext.decompressor` is set (for example to
:func:`pydlms.security.v44.v44_decompressor`). With a hook, a
compressed APDU is accepted only

* for suites 1 and 2 (the suites the standard allows compression for),
* in a general-glo, general-ded or general-ciphering envelope (never a
  service-specific ``glo-``/``ded-`` one, whose tag would have to name the
  compressed APDU),
* when it is authenticated and its tag verified: the hook runs strictly
  after verification and after the counter check, never on unauthenticated
  data (encryption-only or ``allow_unverified_auth`` is refused),

and the hook's output must be non-empty ``bytes`` of at most
``max_decompressed`` octets (:data:`MAX_DECOMPRESSED_DEFAULT`, the
association passes its receive limit). Anything the hook raises becomes a
:class:`DecodeError`. A hook that can expand without bound should stop at
that limit itself; the check here runs on its result. Outbound APDUs never
set bit 7: an SC asking for it raises :class:`ValueError`.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydlms.apdu.tags import DED_TAG, GLO_TAG, PLAIN_FOR_CIPHERED, Tag, tag_name
from pydlms.axdr import decode_length, encode_length
from pydlms.debug import TRACE, get_logger, hexdump, payloads_sensitive
from pydlms.exceptions import (
    AuthenticationError,
    DecodeError,
    KeyMissingError,
    ReplayError,
    SecurityError,
)
from pydlms.security import gcm
from pydlms.security.context import SecurityContext
from pydlms.security.provider import provider_of
from pydlms.security.suites import TAG_LENGTH, SecurityControl, SecurityPolicy

__all__ = [
    "CipheredApdu",
    "MAX_DECOMPRESSED_DEFAULT",
    "wrap",
    "wrap_general_glo",
    "unwrap",
    "is_ciphered_apdu",
]

log = get_logger("security")

#: Largest decompressed APDU :func:`unwrap` accepts when the caller names no
#: limit: the largest max-receive-pdu-size an InitiateRequest can carry.
MAX_DECOMPRESSED_DEFAULT = 0xFFFF

#: Envelopes that may carry a compressed APDU (SC bit 7) with a decompressor.
_COMPRESSIBLE = frozenset(
    (Tag.GENERAL_GLO_CIPHERING, Tag.GENERAL_DED_CIPHERING, Tag.GENERAL_CIPHERING)
)
_COMPRESSION_SUITES = (1, 2)


@dataclass
class CipheredApdu:
    """Result of :func:`unwrap`."""

    tag: int
    security_control: SecurityControl
    invocation_counter: int
    system_title: bytes
    plaintext: bytes
    authenticated: bool


def _trace(
    direction: str,
    envelope: int,
    sc: SecurityControl,
    ic: int,
    title: bytes,
    plaintext: bytes,
    ciphered: bytes,
    verdict: str = "",
) -> None:
    """TRACE: the full plaintext and ciphered APDU of one ciphering operation.

    Keys are never part of the record; plaintext is, because seeing what was
    encrypted is the point when debugging a meter.
    """
    if not log.isEnabledFor(TRACE):
        return
    if payloads_sensitive():
        log.log(
            TRACE,
            "%s %s %s IC=%d title=%s%s (%d octets; content withheld: HLS pass 3/4)",
            direction,
            tag_name(envelope),
            sc.describe(),
            ic,
            title.hex(),
            f" [{verdict}]" if verdict else "",
            len(plaintext),
        )
        return
    log.log(
        TRACE,
        "%s %s %s IC=%d title=%s%s\n  plaintext (%d octets):\n%s\n  ciphered (%d octets):\n%s",
        direction,
        tag_name(envelope),
        sc.describe(),
        ic,
        title.hex(),
        f" [{verdict}]" if verdict else "",
        len(plaintext),
        hexdump(plaintext, prefix="    "),
        len(ciphered),
        hexdump(ciphered, prefix="    "),
    )


def _octet_string(data: bytes, offset: int, what: str) -> tuple[bytes, int]:
    length, pos = decode_length(data, offset)
    end = pos + length
    if end > len(data):
        raise DecodeError(f"{what}: declared {length} octets, {len(data) - pos} available")
    return data[pos:end], end


def refuse_outbound_compression(sc: SecurityControl) -> None:
    """pydlms never compresses: an outbound SC with bit 7 is a caller error."""
    if sc.compressed:
        raise ValueError(f"{sc.describe()}: outbound compression (SC bit 7) is not supported")


def _protect(
    ctx: SecurityContext,
    sc: SecurityControl,
    system_title: bytes,
    ic: int,
    plaintext: bytes,
    dedicated: bool,
) -> bytes:
    ek = ctx.require_encryption_key(broadcast=sc.broadcast_key, dedicated=dedicated)
    ak = ctx.require_authentication_key() if sc.authenticated else None
    body = gcm.encrypt(sc, ek, ak, system_title, ic, plaintext, provider=provider_of(ctx))
    return bytes([sc.to_byte()]) + ic.to_bytes(4, "big") + body


def wrap(
    ctx: SecurityContext,
    plaintext_apdu: bytes,
    sc: SecurityControl | None = None,
    dedicated: bool = False,
) -> bytes:
    """Cipher an outbound APDU into its key-specific ``glo-``/``ded-`` form."""
    if not plaintext_apdu:
        raise ValueError("cannot cipher an empty APDU")
    table = DED_TAG if dedicated else GLO_TAG
    try:
        tag = table[plaintext_apdu[0]]
    except KeyError:
        raise ValueError(
            f"APDU {tag_name(plaintext_apdu[0])} has no key-specific ciphered form"
        ) from None
    sc = sc or SecurityControl.for_policy(ctx.policy, int(ctx.suite))
    refuse_outbound_compression(sc)
    ic = ctx.next_invocation_counter()
    content = _protect(ctx, sc, ctx.client_system_title, ic, plaintext_apdu, dedicated)
    log.debug(
        "cipher %s -> %s %s IC=%d", tag_name(plaintext_apdu[0]), tag_name(tag), sc.describe(), ic
    )
    apdu = bytes([tag]) + encode_length(len(content)) + content
    _trace("encrypt", tag, sc, ic, ctx.client_system_title, plaintext_apdu, apdu)
    return apdu


def wrap_general_glo(
    ctx: SecurityContext,
    plaintext_apdu: bytes,
    sc: SecurityControl | None = None,
    dedicated: bool = False,
) -> bytes:
    """Cipher an outbound APDU as general-glo-/general-ded-ciphering."""
    if not plaintext_apdu:
        raise ValueError("cannot cipher an empty APDU")
    sc = sc or SecurityControl.for_policy(ctx.policy, int(ctx.suite))
    refuse_outbound_compression(sc)
    ic = ctx.next_invocation_counter()
    content = _protect(ctx, sc, ctx.client_system_title, ic, plaintext_apdu, dedicated)
    tag = Tag.GENERAL_DED_CIPHERING if dedicated else Tag.GENERAL_GLO_CIPHERING
    apdu = bytes([tag, 8]) + ctx.client_system_title + encode_length(len(content)) + content
    log.debug(
        "cipher %s -> %s %s IC=%d", tag_name(plaintext_apdu[0]), tag_name(tag), sc.describe(), ic
    )
    _trace("encrypt", tag, sc, ic, ctx.client_system_title, plaintext_apdu, apdu)
    return apdu


def is_ciphered_apdu(apdu: bytes) -> bool:
    return bool(apdu) and (
        apdu[0] in PLAIN_FOR_CIPHERED
        or apdu[0]
        in (
            Tag.GENERAL_GLO_CIPHERING,
            Tag.GENERAL_DED_CIPHERING,
            Tag.GENERAL_CIPHERING,
            Tag.GENERAL_SIGNING,
        )
    )


def check_policy(ctx: SecurityContext, sc: SecurityControl, tag: int) -> None:
    """Refuse an inbound SC that is weaker than ``ctx`` or of another suite.

    Raises :class:`AuthenticationError` before anything is deciphered.
    """
    what = f"{tag_name(tag)} {sc.describe()}"
    if not (sc.authenticated or sc.encrypted):
        raise AuthenticationError(f"{what} protects nothing inside a ciphered envelope")
    if sc.suite != int(ctx.suite):
        raise AuthenticationError(f"{what}: the security context uses suite {int(ctx.suite)}")
    if ctx.policy & SecurityPolicy.AUTHENTICATED and not sc.authenticated:
        raise AuthenticationError(f"{what} is not authenticated, the policy requires it")
    if ctx.policy & SecurityPolicy.ENCRYPTED and not sc.encrypted:
        raise AuthenticationError(f"{what} is not encrypted, the policy requires it")


def _check_compression(sc: SecurityControl, tag: int) -> None:
    """Refuse a compressed APDU outside the conditions in the module docstring."""
    what = f"{tag_name(tag)} {sc.describe()} compressed"
    if tag not in _COMPRESSIBLE:
        raise DecodeError(f"{what}: compression is only accepted in general ciphering envelopes")
    if sc.suite not in _COMPRESSION_SUITES:
        raise DecodeError(f"{what}: compression is only accepted for security suites 1 and 2")
    if not sc.authenticated:
        raise DecodeError(f"{what}: compression is only accepted on authenticated APDUs")


def _decompress(ctx: SecurityContext, tag: int, data: bytes, limit: int) -> bytes:
    """Run the context's decompressor on verified protected data."""
    hook = ctx.decompressor
    assert hook is not None
    try:
        out = hook(data)
    except Exception as exc:  # the hook is user code; any failure is a decode failure
        raise DecodeError(f"{tag_name(tag)}: decompressor failed: {exc}") from exc
    if not isinstance(out, (bytes, bytearray)) or not out:
        raise DecodeError(
            f"{tag_name(tag)}: decompressor returned {type(out).__name__} "
            f"of {len(out) if isinstance(out, (bytes, bytearray, str)) else 0} items, "
            "expected non-empty bytes"
        )
    if len(out) > limit:
        raise DecodeError(
            f"{tag_name(tag)}: decompressed APDU of {len(out)} octets exceeds the "
            f"limit of {limit} octets"
        )
    log.debug("decompressed %s: %d -> %d octets", tag_name(tag), len(data), len(out))
    return bytes(out)


def _unprotect(
    ctx: SecurityContext,
    tag: int,
    content: bytes,
    system_title: bytes,
    dedicated: bool,
    raw: bytes = b"",
    key_override: object | None = None,
    strict: bool = True,
    key_kind: str | None = None,
    extra_aad: bytes = b"",
    max_decompressed: int = MAX_DECOMPRESSED_DEFAULT,
) -> CipheredApdu:
    if len(content) < 5:
        raise DecodeError(f"ciphered content of {len(content)} octets lacks SC and IC")
    hook = getattr(ctx, "decompressor", None)
    sc = SecurityControl.from_byte(content[0], allow_compressed=hook is not None)
    if sc.compressed:
        _check_compression(sc, tag)
    if strict:
        check_policy(ctx, sc, tag)
    ic = int.from_bytes(content[1:5], "big")
    payload = content[5:]
    if sc.authenticated and len(payload) < TAG_LENGTH:
        raise DecodeError("ciphered payload shorter than the authentication tag")
    log.debug(
        "decipher %s from %s %s IC=%d (%d octets)",
        tag_name(tag),
        system_title.hex(),
        sc.describe(),
        ic,
        len(payload),
    )
    if key_override is not None:
        ek = key_override
    else:
        ek = (
            ctx.require_encryption_key(broadcast=sc.broadcast_key, dedicated=dedicated)
            if sc.encrypted or sc.authenticated
            else None
        )
    verify = True
    ak = None
    if sc.authenticated:
        if ctx.authentication_key is None:
            if not ctx.allow_unverified_auth:
                raise KeyMissingError(
                    "APDU is authenticated but no authentication key is configured; "
                    "set allow_unverified_auth=True to decode it without verification"
                )
            log.warning("decoding authenticated APDU WITHOUT verifying its tag (no AK)")
            verify = False
        else:
            ak = ctx.authentication_key
    if sc.compressed and not verify:
        raise DecodeError(
            f"{tag_name(tag)} compressed: the tag cannot be verified without an "
            "authentication key, so the APDU is not decompressed"
        )
    assert ek is not None or not (sc.encrypted or sc.authenticated)
    # Authenticate before the replay check, and store the counter only when
    # the tag verified: an unauthenticated counter can be forged at will.
    try:
        plaintext = (
            gcm.decrypt(
                sc,
                ek if ek is not None else b"",
                ak,
                system_title,
                ic,
                payload,
                verify=verify,
                extra_aad=extra_aad,
                provider=provider_of(ctx),
            )
            if (sc.encrypted or sc.authenticated)
            else payload
        )
    except AuthenticationError:
        log.debug(
            "decipher %s from %s IC=%d: authentication tag did NOT verify",
            tag_name(tag),
            system_title.hex(),
            ic,
        )
        raise
    try:
        if key_kind is None:
            key_kind = (
                "dedicated" if dedicated else ("broadcast" if sc.broadcast_key else "unicast")
            )
        ctx.check_inbound_counter(
            system_title, ic, commit=sc.authenticated and verify, key=key_kind
        )
    except ReplayError:
        log.debug(
            "decipher %s from %s: invocation counter %d rejected as stale",
            tag_name(tag),
            system_title.hex(),
            ic,
        )
        raise
    verdict = (
        "tag verified"
        if sc.authenticated and verify
        else ("tag NOT verified (no AK)" if sc.authenticated else "no tag in this mode")
    )
    _trace("decrypt", tag, sc, ic, system_title, plaintext, raw or content, verdict)
    if sc.compressed:
        # Tag verified and counter accepted above: only now is the protected
        # (compressed) APDU handed to the hook.
        plaintext = _decompress(ctx, tag, plaintext, max_decompressed)
    return CipheredApdu(tag, sc, ic, system_title, plaintext, sc.authenticated and verify)


def unwrap(
    ctx: SecurityContext,
    apdu: bytes,
    *,
    strict: bool = True,
    max_decompressed: int = MAX_DECOMPRESSED_DEFAULT,
) -> CipheredApdu:
    """Decipher any ciphered APDU envelope. See the module docstring.

    ``strict=False`` skips the policy and suite checks (and, for
    general-ciphering, the system title checks) so analysis tools can show a
    captured APDU as it is; never use it on a live association. The
    compression conditions apply either way. ``max_decompressed`` caps the
    output of :attr:`SecurityContext.decompressor`.
    """
    if not apdu:
        raise DecodeError("empty APDU")
    tag = apdu[0]
    if tag in PLAIN_FOR_CIPHERED:
        _, dedicated = PLAIN_FOR_CIPHERED[tag]
        content, end = _octet_string(apdu, 1, tag_name(tag))
        if end != len(apdu):
            raise DecodeError(f"{len(apdu) - end} trailing octets after {tag_name(tag)}")
        if ctx.server_system_title is None:
            raise KeyMissingError("server system title unknown (no AARE yet)")
        return _unprotect(
            ctx,
            tag,
            content,
            ctx.server_system_title,
            dedicated,
            apdu,
            strict=strict,
            max_decompressed=max_decompressed,
        )
    if tag in (Tag.GENERAL_GLO_CIPHERING, Tag.GENERAL_DED_CIPHERING):
        system_title, pos = _octet_string(apdu, 1, "system title")
        if len(system_title) != 8:
            raise DecodeError(f"system title is {len(system_title)} octets, expected 8")
        content, end = _octet_string(apdu, pos, "ciphered content")
        if end != len(apdu):
            raise DecodeError(f"{len(apdu) - end} trailing octets after general ciphering")
        return _unprotect(
            ctx,
            tag,
            content,
            system_title,
            tag == Tag.GENERAL_DED_CIPHERING,
            apdu,
            strict=strict,
            max_decompressed=max_decompressed,
        )
    if tag == Tag.GENERAL_CIPHERING:
        from pydlms.security.general import unwrap_general_ciphering

        return unwrap_general_ciphering(ctx, apdu, strict=strict, max_decompressed=max_decompressed)
    if tag == Tag.GENERAL_SIGNING:
        from pydlms.security.general import signing_replay_token, verify_general_signing

        originator, content = verify_general_signing(ctx, apdu)
        if is_ciphered_apdu(content):
            return unwrap(ctx, content, strict=strict, max_decompressed=max_decompressed)
        # Signed plain content carries no invocation counter: refuse at least
        # an exact replay of an APDU this context already verified.
        ctx.check_signed_replay(signing_replay_token(apdu, ctx.signing_form))
        sc = SecurityControl()
        return CipheredApdu(tag, sc, 0, originator, content, authenticated=True)
    raise SecurityError(f"{tag_name(tag)} is not a ciphered APDU")
