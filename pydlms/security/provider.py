"""Pluggable crypto provider: keys behind handles (HSM, TPM, KMS, smart card).

pydlms never needs to hold key bytes itself. Every key field of
:class:`~pydlms.security.context.SecurityContext` (and
``AssociationSettings.signing_key`` / ``secret`` for HLS mechanisms 2 and
7) takes an opaque **key reference**; the context's ``provider`` turns
references into primitive results. :class:`SoftwareProvider`, the default,
takes raw ``bytes`` (and ``cryptography`` EC private key objects) and makes
exactly the ``cryptography`` calls pydlms made before providers existed.

The split is deliberate. pydlms keeps everything that is DLMS policy:

* IV assembly (system title || invocation counter), SC byte, AAD layout,
  the CTR start block ``IV || 00000002`` and the KDF OtherInfo;
* tag-length pinning (12 octets), the constant-time GMAC comparison of
  authentication-only APDUs, invocation-counter and replay checks, the
  security policy and suite checks.

A provider only sees primitives (AES-GCM, AES-CTR, GMAC, one AES block,
ECDSA, ECDH, the SP 800-56A KDF, RFC 3394 key wrap) and cannot weaken any
of the above. Every provider, :class:`SoftwareProvider` included, is
called through :class:`GuardedProvider`, which type- and length-checks each
output (a tag must be exactly 12 octets, plaintext must be ``bytes`` of the
ciphertext's length, a signature ``r || s`` of the suite's size) and raises
:class:`~pydlms.exceptions.CryptoProviderError` otherwise. It never catches
an exception a provider raises.

**AAD carries the authentication key.** DLMS authenticates
``SC || AK || ...``, so the AK is part of the GCM additional data. The
``aad`` argument is therefore a tuple of segments: ``bytes`` and
:class:`AadKey` markers holding a key reference. The provider concatenates
them, resolving each :class:`AadKey` to its key value inside the provider
(:func:`flatten_aad`); pydlms never sees AK bytes when AK is a handle.

**Session keys arrive as bytes.** Keys pydlms itself creates (the dedicated
key it sends in the AARQ, a general-ciphering content key it unwraps or
agrees with an ephemeral key pair) are passed to the provider as raw
``bytes``. A provider must accept ``bytes`` as a key reference as well as
its own handles (delegating them to :class:`SoftwareProvider` is fine).

**Operations.** ``gcm_seal``, ``gcm_open``, ``ctr`` and ``gmac`` are
required. The others are needed only by the keys that use them and may be
left out: ``aes_ecb_block`` (HLS mechanism 2 secret), ``ecdsa_sign`` and
``public_key`` (signing keys), ``ecdh`` and/or ``ecdh_kdf`` (key-agreement
keys; ``ecdh_kdf`` is preferred when present so ``Z`` never leaves the
provider), ``aes_wrap`` / ``aes_unwrap`` (master key / KEK) and
``key_fingerprint`` (a handle encryption key with a
:class:`~pydlms.counters.CounterStore`). A missing operation raises
:class:`~pydlms.exceptions.CryptoProviderError` when first needed.

**Writing a PKCS#11 adapter** (not shipped in core; ``python-pkcs11`` or
``PyKCS11``): key references are object handles (or labels resolved once).
``gcm_seal`` / ``gcm_open`` map to ``CKM_AES_GCM`` with ``ulTagBits=96``
(``gcm_open`` must raise :class:`~pydlms.exceptions.AuthenticationError` on
``CKR_ENCRYPTED_DATA_INVALID`` / ``CKR_SIGNATURE_INVALID``, never return a
flag); ``gmac`` is ``CKM_AES_GCM`` encrypting an empty plaintext; ``ctr`` is
``CKM_AES_CTR`` with the 16-octet counter block and ``ulCounterBits=32``;
``aes_ecb_block`` is ``CKM_AES_ECB``; ``ecdsa_sign`` is ``CKM_ECDSA`` over a
host-side SHA-256/384 digest (PKCS#11 already returns raw ``r || s``);
``ecdh_kdf`` is ``CKM_ECDH1_DERIVE`` with ``CKD_NULL`` followed by a
``CKM_SP800_108``-style or vendor concatenation KDF, or ``ecdh`` with
``CKD_NULL`` into an extractable generic secret; ``aes_wrap`` /
``aes_unwrap`` are ``CKM_AES_KEY_WRAP`` (RFC 3394, no padding). PKCS#11 has
no GCM mechanism that reads a key into the AAD, so an :class:`AadKey` has
to be resolved by reading the AK's ``CKA_VALUE`` (store it as a
non-sensitive generic secret) inside the adapter, or the token needs a
vendor DLMS mechanism.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any, Protocol, runtime_checkable

from pydlms.exceptions import AuthenticationError, CryptoProviderError
from pydlms.security.suites import TAG_LENGTH, SecuritySuite, key_length

__all__ = [
    "AadKey",
    "CryptoProvider",
    "GuardedProvider",
    "SoftwareProvider",
    "flatten_aad",
    "is_raw_key",
    "provider_of",
    "resolve",
]

#: An opaque key reference: ``bytes`` / a ``cryptography`` EC key for
#: :class:`SoftwareProvider`, any handle object for other providers.
KeyRef = Any


class AadKey:
    """AAD segment standing for the value of the key behind ``key_ref``.

    Its ``repr`` never shows the reference (handles are secrets too).
    """

    __slots__ = ("key_ref",)

    def __init__(self, key_ref: KeyRef) -> None:
        self.key_ref = key_ref

    def __repr__(self) -> str:
        return "AadKey(***)"


#: GCM/GMAC additional data: ``bytes`` segments and :class:`AadKey` markers,
#: concatenated in order.
Aad = Sequence["bytes | AadKey"]


def is_raw_key(key: object) -> bool:
    """Whether ``key`` is raw key bytes (as opposed to a provider handle)."""
    return isinstance(key, (bytes, bytearray))


def flatten_aad(aad: Aad, resolve_key: Callable[[KeyRef], bytes]) -> bytes:
    """Concatenate ``aad``, mapping each :class:`AadKey` through ``resolve_key``."""
    out = bytearray()
    for segment in aad:
        if isinstance(segment, AadKey):
            value = resolve_key(segment.key_ref)
            if not is_raw_key(value):
                raise CryptoProviderError("an AAD key did not resolve to bytes")
            out += value
        elif isinstance(segment, (bytes, bytearray)):
            out += segment
        else:
            raise CryptoProviderError(f"AAD segment of type {type(segment).__name__}")
    return bytes(out)


@runtime_checkable
class CryptoProvider(Protocol):
    """The primitive operations pydlms asks of a key store.

    Only the four symmetric operations are required; see the module
    docstring for the optional ones and for what a provider must never do
    (return a flag instead of raising).
    """

    def gcm_seal(
        self, key_ref: KeyRef, iv: bytes, plaintext: bytes, aad: Aad
    ) -> tuple[bytes, bytes]:
        """AES-GCM encrypt; returns ``(ciphertext, tag)``, tag exactly 12 octets."""
        ...

    def gcm_open(
        self, key_ref: KeyRef, iv: bytes, ciphertext: bytes, aad: Aad, tag: bytes
    ) -> bytes:
        """AES-GCM decrypt with a 12-octet tag; raise ``AuthenticationError`` on mismatch."""
        ...

    def ctr(self, key_ref: KeyRef, counter_block: bytes, data: bytes) -> bytes:
        """AES-CTR from the 16-octet ``counter_block`` (32-bit big-endian counter)."""
        ...

    def gmac(self, key_ref: KeyRef, iv: bytes, aad: Aad) -> bytes:
        """The 12-octet GCM tag over ``aad`` with an empty plaintext."""
        ...


class SoftwareProvider:
    """Raw keys in process memory, computed with ``cryptography``.

    Key references are ``bytes`` (symmetric keys) and ``cryptography`` EC
    private key objects (signing / key-agreement keys). This is the default
    provider and reproduces the pre-provider code paths call for call.
    """

    def __repr__(self) -> str:
        return "SoftwareProvider()"

    @staticmethod
    def _raw(key_ref: KeyRef) -> bytes:
        if not is_raw_key(key_ref):
            raise CryptoProviderError(
                f"SoftwareProvider takes raw key bytes, got {type(key_ref).__name__}; "
                "configure the provider that issued this handle"
            )
        return bytes(key_ref)

    def _aad(self, aad: Aad) -> bytes:
        return flatten_aad(aad, self._raw)

    def gcm_seal(
        self, key_ref: KeyRef, iv: bytes, plaintext: bytes, aad: Aad
    ) -> tuple[bytes, bytes]:
        from pydlms.security import gcm

        return gcm.gcm_encrypt(self._raw(key_ref), iv, plaintext, self._aad(aad))

    def gcm_open(
        self, key_ref: KeyRef, iv: bytes, ciphertext: bytes, aad: Aad, tag: bytes
    ) -> bytes:
        from pydlms.security import gcm

        return gcm.gcm_decrypt(self._raw(key_ref), iv, ciphertext, self._aad(aad), tag)

    def ctr(self, key_ref: KeyRef, counter_block: bytes, data: bytes) -> bytes:
        from pydlms.security import gcm

        return gcm.aes_ctr(self._raw(key_ref), counter_block, data)

    def gmac(self, key_ref: KeyRef, iv: bytes, aad: Aad) -> bytes:
        from pydlms.security import gcm

        return gcm.gmac(self._raw(key_ref), iv, self._aad(aad))

    def aes_ecb_block(self, key_ref: KeyRef, block: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        # One block for HLS mechanism 2 (a vendor convention that specifies
        # ECB); not bulk data.
        encryptor = Cipher(algorithms.AES(self._raw(key_ref)), modes.ECB()).encryptor()  # nosec B305
        return encryptor.update(block) + encryptor.finalize()

    def ecdsa_sign(self, key_ref: KeyRef, message: bytes, suite: int | None = None) -> bytes:
        from pydlms.security import ec

        return ec.ecdsa_sign(key_ref, message)

    def public_key(self, key_ref: KeyRef) -> Any:
        return key_ref.public_key()

    def ecdh(self, key_ref: KeyRef, peer_public_key: Any) -> bytes:
        from pydlms.security import ec

        return ec.ecdh_shared_secret(key_ref, peer_public_key)

    def ecdh_kdf(
        self, key_ref: KeyRef, peer_public_key: Any, suite: int, other_info: bytes
    ) -> bytes:
        from pydlms.security import ec

        return ec.kdf_other_info(suite, self.ecdh(key_ref, peer_public_key), other_info)

    def aes_wrap(self, kek_ref: KeyRef, key: bytes) -> bytes:
        from cryptography.hazmat.primitives.keywrap import aes_key_wrap

        return aes_key_wrap(self._raw(kek_ref), self._raw(key))

    def aes_unwrap(self, kek_ref: KeyRef, wrapped: bytes) -> bytes:
        from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap

        try:
            return aes_key_unwrap(self._raw(kek_ref), wrapped)
        except InvalidUnwrap:
            raise AuthenticationError("AES key unwrap integrity check failed") from None


def _bytes_out(value: object, what: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise CryptoProviderError(f"provider {what} returned {type(value).__name__}, not bytes")
    return bytes(value)


def _signature_size(suite: int | None) -> tuple[int, ...]:
    if suite == SecuritySuite.ECDH_ECDSA_AES_GCM_128_SHA256:
        return (64,)
    if suite == SecuritySuite.ECDH_ECDSA_AES_GCM_256_SHA384:
        return (96,)
    return (64, 96)


class GuardedProvider:
    """Checks every output of a provider before pydlms uses it.

    Wraps any provider (including :class:`SoftwareProvider`). Exceptions
    the wrapped provider raises propagate unchanged; a malformed output
    raises :class:`~pydlms.exceptions.CryptoProviderError`. A provider that
    returns well-formed plaintext for a forged tag cannot be detected here:
    ``gcm_open`` must raise, which is the provider's contract.
    """

    __slots__ = ("_inner",)

    _REQUIRED = ("gcm_seal", "gcm_open", "ctr", "gmac")

    def __init__(self, inner: object) -> None:
        if isinstance(inner, GuardedProvider):
            inner = inner._inner
        missing = [n for n in self._REQUIRED if not callable(getattr(inner, n, None))]
        if missing:
            raise CryptoProviderError(
                f"{type(inner).__name__} is not a crypto provider (lacks {', '.join(missing)})"
            )
        self._inner = inner

    @property
    def inner(self) -> object:
        """The wrapped provider."""
        return self._inner

    def __repr__(self) -> str:
        return f"GuardedProvider({type(self._inner).__name__})"

    def supports(self, operation: str) -> bool:
        return callable(getattr(self._inner, operation, None))

    def _op(self, name: str) -> Callable[..., Any]:
        fn = getattr(self._inner, name, None)
        if not callable(fn):
            raise CryptoProviderError(f"{type(self._inner).__name__} does not implement {name}")
        return fn

    # -- symmetric -------------------------------------------------------------
    def gcm_seal(
        self, key_ref: KeyRef, iv: bytes, plaintext: bytes, aad: Aad
    ) -> tuple[bytes, bytes]:
        out = self._op("gcm_seal")(key_ref, iv, plaintext, tuple(aad))
        if not isinstance(out, tuple) or len(out) != 2:
            raise CryptoProviderError("provider gcm_seal must return (ciphertext, tag)")
        ciphertext = _bytes_out(out[0], "gcm_seal ciphertext")
        tag = _bytes_out(out[1], "gcm_seal tag")
        if len(ciphertext) != len(plaintext):
            raise CryptoProviderError(
                f"provider gcm_seal returned {len(ciphertext)} ciphertext octets "
                f"for {len(plaintext)} plaintext octets"
            )
        if len(tag) != TAG_LENGTH:
            raise CryptoProviderError(
                f"provider gcm_seal returned a {len(tag)}-octet tag, not {TAG_LENGTH}"
            )
        return ciphertext, tag

    def gcm_open(
        self, key_ref: KeyRef, iv: bytes, ciphertext: bytes, aad: Aad, tag: bytes
    ) -> bytes:
        if len(tag) != TAG_LENGTH:
            raise AuthenticationError(
                f"authentication tag must be {TAG_LENGTH} octets, got {len(tag)}"
            )
        out = self._op("gcm_open")(key_ref, iv, ciphertext, tuple(aad), tag)
        plaintext = _bytes_out(out, "gcm_open")
        if len(plaintext) != len(ciphertext):
            raise CryptoProviderError(
                f"provider gcm_open returned {len(plaintext)} octets "
                f"for {len(ciphertext)} ciphertext octets"
            )
        return plaintext

    def ctr(self, key_ref: KeyRef, counter_block: bytes, data: bytes) -> bytes:
        out = _bytes_out(self._op("ctr")(key_ref, counter_block, data), "ctr")
        if len(out) != len(data):
            raise CryptoProviderError(
                f"provider ctr returned {len(out)} octets for {len(data)} input octets"
            )
        return out

    def gmac(self, key_ref: KeyRef, iv: bytes, aad: Aad) -> bytes:
        tag = _bytes_out(self._op("gmac")(key_ref, iv, tuple(aad)), "gmac")
        if len(tag) != TAG_LENGTH:
            raise CryptoProviderError(
                f"provider gmac returned a {len(tag)}-octet tag, not {TAG_LENGTH}"
            )
        return tag

    def aes_ecb_block(self, key_ref: KeyRef, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError(f"an AES block is 16 octets, got {len(block)}")
        out = _bytes_out(self._op("aes_ecb_block")(key_ref, block), "aes_ecb_block")
        if len(out) != 16:
            raise CryptoProviderError(f"provider aes_ecb_block returned {len(out)} octets")
        return out

    # -- key wrap ----------------------------------------------------------------
    def aes_wrap(self, kek_ref: KeyRef, key: bytes) -> bytes:
        out = _bytes_out(self._op("aes_wrap")(kek_ref, key), "aes_wrap")
        if is_raw_key(key):
            if len(out) != len(key) + 8:
                raise CryptoProviderError(
                    f"provider aes_wrap returned {len(out)} octets for a {len(key)}-octet key"
                )
        elif len(out) < 24 or len(out) % 8:
            raise CryptoProviderError(f"provider aes_wrap returned {len(out)} octets")
        return out

    def aes_unwrap(self, kek_ref: KeyRef, wrapped: bytes) -> KeyRef:
        out = self._op("aes_unwrap")(kek_ref, wrapped)
        if out is None or isinstance(out, bool):
            raise CryptoProviderError("provider aes_unwrap returned no key")
        if is_raw_key(out) and len(out) != len(wrapped) - 8:
            raise CryptoProviderError(
                f"provider aes_unwrap returned {len(out)} octets for {len(wrapped)} wrapped octets"
            )
        return bytes(out) if is_raw_key(out) else out

    # -- elliptic curve ----------------------------------------------------------
    def ecdsa_sign(self, key_ref: KeyRef, message: bytes, suite: int | None = None) -> bytes:
        signature = _bytes_out(self._op("ecdsa_sign")(key_ref, message, suite), "ecdsa_sign")
        if len(signature) not in _signature_size(suite):
            raise CryptoProviderError(
                f"provider ecdsa_sign returned {len(signature)} octets, "
                f"not a raw r || s of suite {suite}"
            )
        return signature

    def public_key(self, key_ref: KeyRef) -> Any:
        public = self._op("public_key")(key_ref)
        if not callable(getattr(public, "public_numbers", None)):
            raise CryptoProviderError("provider public_key did not return an EC public key")
        return public

    def ecdh(self, key_ref: KeyRef, peer_public_key: Any) -> bytes:
        z = _bytes_out(self._op("ecdh")(key_ref, peer_public_key), "ecdh")
        size = (peer_public_key.curve.key_size + 7) // 8
        if len(z) != size:
            raise CryptoProviderError(f"provider ecdh returned {len(z)} octets, not {size}")
        return z

    def ecdh_kdf(
        self, key_ref: KeyRef, peer_public_key: Any, suite: int, other_info: bytes
    ) -> KeyRef:
        out = self._op("ecdh_kdf")(key_ref, peer_public_key, suite, other_info)
        if out is None or isinstance(out, bool):
            raise CryptoProviderError("provider ecdh_kdf returned no key")
        if is_raw_key(out):
            if len(out) != key_length(suite):
                raise CryptoProviderError(
                    f"provider ecdh_kdf returned {len(out)} octets for suite {suite}"
                )
            return bytes(out)
        return out

    def key_fingerprint(self, key_ref: KeyRef) -> bytes:
        out = _bytes_out(self._op("key_fingerprint")(key_ref), "key_fingerprint")
        if len(out) < 8:
            raise CryptoProviderError("provider key_fingerprint must be at least 8 octets")
        return out


_DEFAULT: GuardedProvider | None = None


def resolve(provider: object | None) -> GuardedProvider:
    """``provider`` behind a :class:`GuardedProvider`; ``None`` is the software default."""
    global _DEFAULT
    if isinstance(provider, GuardedProvider):
        return provider
    if provider is None:
        if _DEFAULT is None:
            _DEFAULT = GuardedProvider(SoftwareProvider())
        return _DEFAULT
    return GuardedProvider(provider)


def provider_of(ctx: object) -> GuardedProvider:
    """The guarded provider of a security context (duck-typed; default software)."""
    return resolve(getattr(ctx, "provider", None))
