"""The three DLMS AES-GCM operations (IEC 62056-5-3, 9.2.7.2.4).

All primitives come from ``cryptography`` (hazmat); this module only builds
the DLMS-specific IV, AAD and counter block around them. Each function is pure
and takes every input explicitly.

* IV (12 octets) = system-title (8) || invocation-counter (4, big-endian).
* Tag length is 12 octets (:data:`~pydlms.security.suites.TAG_LENGTH`).
* **auth+enc**: AAD = SC || AK; output C || T.
* **auth-only**: AAD = SC || AK || P; plaintext stays in clear, output T.
* ``extra_aad`` (empty unless a caller opts in) goes after AK:
  ``SC || AK || extra`` and ``SC || AK || extra || P``. Only general-ciphering
  under :attr:`~pydlms.security.general.GeneralAad.WITH_HEADER` uses it
  (two readings exist in the field); no standard example verifies that form.
* **enc-only**: no tag; GCM used as a stream cipher, i.e. AES-CTR starting at
  counter block ``IV || 00000002`` (GCM reserves block 1 for the tag).

These facts are pinned by the Green Book suite-0 worked example in
``tests/crypto/test_gcm_greenbook.py``.

:func:`encrypt` / :func:`decrypt` assemble IV, AAD and counter block here
and hand only the primitive to a crypto provider
(:mod:`pydlms.security.provider`; default :class:`SoftwareProvider`, which
calls the raw functions below). Keys may be provider handles; the AK enters
the AAD as an :class:`~pydlms.security.provider.AadKey`.
"""

from __future__ import annotations

import hmac
from typing import Any

from pydlms.exceptions import AuthenticationError
from pydlms.security.suites import TAG_LENGTH, SecurityControl

#: A provider key reference (see :mod:`pydlms.security.provider`).
KeyRef = Any

__all__ = [
    "make_iv",
    "encrypt",
    "decrypt",
    "gmac",
    "ctr_transform",
    "aes_ctr",
    "gcm_encrypt",
    "gcm_decrypt",
]


def _crypto():
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:  # pragma: no cover - depends on extras
        raise ImportError(
            "ciphering needs cryptography: pip install 'pydlms-client[crypto]'"
        ) from exc
    return Cipher, algorithms, modes


def _check_key(key: bytes, name: str) -> None:
    if len(key) not in (16, 32):
        raise ValueError(f"{name} must be 16 or 32 octets, got {len(key)}")


def make_iv(system_title: bytes, invocation_counter: int) -> bytes:
    if len(system_title) != 8:
        raise ValueError(f"system title must be 8 octets, got {len(system_title)}")
    if not 0 <= invocation_counter <= 0xFFFFFFFF:
        raise ValueError(f"invocation counter {invocation_counter} out of uint32 range")
    return system_title + invocation_counter.to_bytes(4, "big")


def gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Raw AES-GCM; returns ``(ciphertext, 12-octet tag)``."""
    _check_key(key, "encryption key")
    Cipher, algorithms, modes = _crypto()
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    encryptor.authenticate_additional_data(aad)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, encryptor.tag[:TAG_LENGTH]


def gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, aad: bytes, tag: bytes) -> bytes:
    """Raw AES-GCM decrypt with a truncated tag; raises on mismatch.

    ``cryptography`` accepts truncated tags (min 4 octets) only when
    ``min_tag_length`` is given; we pin it to exactly 12.
    """
    _check_key(key, "encryption key")
    if len(tag) != TAG_LENGTH:
        raise AuthenticationError(f"authentication tag must be {TAG_LENGTH} octets, got {len(tag)}")
    Cipher, algorithms, modes = _crypto()
    from cryptography.exceptions import InvalidTag

    decryptor = Cipher(
        algorithms.AES(key), modes.GCM(iv, tag, min_tag_length=TAG_LENGTH)
    ).decryptor()
    decryptor.authenticate_additional_data(aad)
    plaintext = decryptor.update(ciphertext)
    try:
        decryptor.finalize()
    except InvalidTag:
        raise AuthenticationError("GCM authentication tag mismatch") from None
    return plaintext


#: GCM reserves counter block 1 for the tag; the keystream starts at 2.
_CTR_START = b"\x00\x00\x00\x02"


def aes_ctr(key: bytes, counter_block: bytes, data: bytes) -> bytes:
    """Raw AES-CTR from the 16-octet ``counter_block``."""
    _check_key(key, "encryption key")
    Cipher, algorithms, modes = _crypto()
    cipher = Cipher(algorithms.AES(key), modes.CTR(counter_block))
    return cipher.encryptor().update(data)


def ctr_transform(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Encryption-only transform: AES-CTR from counter block ``IV || 00000002``."""
    return aes_ctr(key, iv + _CTR_START, data)


def gmac(key: bytes, iv: bytes, aad: bytes) -> bytes:
    """GMAC: the 12-octet GCM tag over ``aad`` with an empty plaintext."""
    _, tag = gcm_encrypt(key, iv, b"", aad)
    return tag


def encrypt(
    sc: SecurityControl,
    ek: KeyRef,
    ak: KeyRef | None,
    system_title: bytes,
    invocation_counter: int,
    plaintext: bytes,
    extra_aad: bytes = b"",
    *,
    provider: object | None = None,
) -> bytes:
    """Protect ``plaintext``; returns the bytes that follow ``SC || IC``.

    auth+enc -> ``C || T``; auth-only -> ``P || T``; enc-only -> ``C``.
    ``extra_aad`` is authenticated after AK (see the module docstring).
    ``ek`` / ``ak`` are key references of ``provider`` (raw bytes for the
    default software provider).
    """
    from pydlms.security.provider import AadKey, resolve

    crypto = resolve(provider)
    iv = make_iv(system_title, invocation_counter)
    sc_byte = bytes([sc.to_byte()])
    if sc.authenticated:
        if ak is None:
            raise ValueError("authenticated mode needs an authentication key")
        if sc.encrypted:
            ciphertext, tag = crypto.gcm_seal(ek, iv, plaintext, (sc_byte, AadKey(ak), extra_aad))
            return ciphertext + tag
        return plaintext + crypto.gmac(ek, iv, (sc_byte, AadKey(ak), extra_aad, plaintext))
    if sc.encrypted:
        return crypto.ctr(ek, iv + _CTR_START, plaintext)
    return plaintext


def decrypt(
    sc: SecurityControl,
    ek: KeyRef,
    ak: KeyRef | None,
    system_title: bytes,
    invocation_counter: int,
    payload: bytes,
    verify: bool = True,
    extra_aad: bytes = b"",
    *,
    provider: object | None = None,
) -> bytes:
    """Inverse of :func:`encrypt`. Raises :class:`AuthenticationError` on a bad tag.

    ``verify=False`` exists only for decoding auth+enc pushes when the
    authentication key is unknown; the caller must opt in explicitly and the
    result is unauthenticated. ``extra_aad`` must be what the sender
    authenticated after AK, else the tag does not verify.
    """
    from pydlms.security.provider import AadKey, resolve

    crypto = resolve(provider)
    iv = make_iv(system_title, invocation_counter)
    sc_byte = bytes([sc.to_byte()])
    if sc.authenticated:
        if len(payload) < TAG_LENGTH:
            raise AuthenticationError("ciphered payload shorter than the authentication tag")
        body, tag = payload[:-TAG_LENGTH], payload[-TAG_LENGTH:]
        if not verify:
            return crypto.ctr(ek, iv + _CTR_START, body) if sc.encrypted else body
        if ak is None:
            raise ValueError("authenticated mode needs an authentication key")
        if sc.encrypted:
            return crypto.gcm_open(ek, iv, body, (sc_byte, AadKey(ak), extra_aad), tag)
        # The comparison stays here, not in the provider: a provider only
        # computes the tag and cannot accept a forged one.
        expected = crypto.gmac(ek, iv, (sc_byte, AadKey(ak), extra_aad, body))
        if not hmac.compare_digest(expected, tag):
            raise AuthenticationError("GMAC authentication tag mismatch")
        return body
    if sc.encrypted:
        return crypto.ctr(ek, iv + _CTR_START, payload)
    return payload
