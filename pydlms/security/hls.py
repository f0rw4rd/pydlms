"""Authentication mechanisms for the association (IEC 62056-5-3, 9.2.2 / 9.2.7.4).

The AARQ carries ``CtoS`` (client challenge) for HLS, or the password for LLS.
For HLS the AARE carries ``StoC``; the client then invokes
``reply_to_HLS_authentication`` (Association LN method 1) with ``f(StoC)`` and
must verify the ``f(CtoS)`` the server returns.

========  ============  =====================================================
mech      name          f(challenge)
========  ============  =====================================================
0         lowest        no authentication
1         LLS           password in the AARQ, no challenge
2         HLS (manuf.)  vendor specific; default AES-128-ECB(secret, challenge)
3         HLS MD5       MD5(challenge || secret)            (weak; legacy)
4         HLS SHA-1     SHA1(challenge || secret)           (weak; legacy)
5         HLS GMAC      SC || IC || GMAC(EK, ST||IC, SC||AK||challenge)
6         HLS SHA-256   SHA256(secret || ST_own || ST_peer || chal_rx || chal_tx)
7         HLS ECDSA     ECDSA(ST_own || ST_peer || chal_rx || chal_tx)
========  ============  =====================================================

For GMAC the client's f(StoC) uses its own system title and invocation
counter; the server's f(CtoS) is checked with the server system title and the
IC carried in the response. Pinned by the Green Book HLS-GMAC example in
``tests/crypto/test_hls.py``.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from enum import IntEnum
from typing import Any

from pydlms.exceptions import AuthenticationError, DecodeError
from pydlms.security import gcm
from pydlms.security.suites import TAG_LENGTH

__all__ = [
    "default_challenge_length",
    "Mechanism",
    "generate_challenge",
    "hls_manufacturer_aes",
    "hls_md5",
    "hls_sha1",
    "hls_sha256",
    "hls_gmac",
    "verify_hls_gmac",
    "hls_ecdsa_sign",
    "hls_ecdsa_verify",
    "mechanism_oid",
]


class Mechanism(IntEnum):
    NONE = 0
    LLS = 1
    HLS = 2
    HLS_MD5 = 3
    HLS_SHA1 = 4
    HLS_GMAC = 5
    HLS_SHA256 = 6
    HLS_ECDSA = 7

    @property
    def is_hls(self) -> bool:
        return self >= Mechanism.HLS


def mechanism_oid(mechanism: Mechanism) -> bytes:
    """Encoded OID body 2.16.756.5.8.2.N of a mechanism-name."""
    return bytes([0x60, 0x85, 0x74, 0x05, 0x08, 0x02, int(mechanism)])


def default_challenge_length(mechanism: int) -> int:
    """Challenge length pydlms sends for ``mechanism``.

    8..64 octets for mechanisms 3..6 and 32..64 for mechanism 7 (ECDSA),
    IEC 62056-5-3:2023 Table 32 as cited by cB-Sigma dlms (checkStoC); 16 is
    what most meters accept for the others.
    """
    return 32 if mechanism == Mechanism.HLS_ECDSA else 16


def generate_challenge(length: int = 16, mechanism: int | None = None) -> bytes:
    """A random HLS challenge (8..64 octets, 32..64 for ECDSA)."""
    low = 32 if mechanism == Mechanism.HLS_ECDSA else 8
    if not low <= length <= 64:
        raise ValueError(f"HLS challenge must be {low}..64 octets for this mechanism")
    return os.urandom(length)


def hls_manufacturer_aes(challenge: bytes, secret: Any, *, provider: object | None = None) -> bytes:
    """Mechanism 2 (manufacturer specific), common AES-128 convention.

    The standard leaves mechanism 2 to the manufacturer. The convention many
    meters and the Gurux tools use: AES-128 in ECB mode keyed by the secret
    (zero-padded/truncated to 16 octets) over the challenge zero-padded to a
    multiple of 16 octets. Meters with another function need
    ``AssociationSettings.hls2_function``. Behavioural reference only (Gurux,
    GPL-2, not copied); no standard test vector exists.

    ``secret`` may be a provider handle of a 16-octet AES key; each block
    then goes through ``provider.aes_ecb_block``.
    """
    from pydlms.security.provider import is_raw_key, resolve

    key = secret[:16].ljust(16, b"\x00") if is_raw_key(secret) else secret
    padded = challenge + b"\x00" * (-len(challenge) % 16)
    # ECB is what this vendor convention specifies; each block is one
    # challenge block, not bulk data, and the mechanism is labelled weak.
    crypto = resolve(provider)
    return b"".join(
        crypto.aes_ecb_block(key, padded[i : i + 16]) for i in range(0, len(padded), 16)
    )


def hls_md5(challenge: bytes, secret: bytes) -> bytes:
    return hashlib.md5(challenge + secret, usedforsecurity=False).digest()  # noqa: S324


def hls_sha1(challenge: bytes, secret: bytes) -> bytes:
    return hashlib.sha1(challenge + secret, usedforsecurity=False).digest()  # noqa: S324


def hls_sha256(
    secret: bytes, own_title: bytes, peer_title: bytes, received: bytes, sent: bytes
) -> bytes:
    """Mechanism 6: the computing party puts its own title and the challenge
    it received first (client: ``secret||STc||STs||StoC||CtoS``)."""
    return hashlib.sha256(secret + own_title + peer_title + received + sent).digest()


def hls_gmac(
    ek: Any,
    ak: Any,
    system_title: bytes,
    invocation_counter: int,
    challenge: bytes,
    suite: int = 0,
    *,
    provider: object | None = None,
) -> bytes:
    """Mechanism 5: ``SC || IC || GMAC`` (17 octets) over ``challenge``.

    ``ek`` / ``ak`` are key references of ``provider`` (default software).
    """
    from pydlms.security.provider import AadKey, resolve

    sc = bytes([0x10 | suite])
    iv = gcm.make_iv(system_title, invocation_counter)
    tag = resolve(provider).gmac(ek, iv, (sc, AadKey(ak), challenge))
    return sc + invocation_counter.to_bytes(4, "big") + tag


def verify_hls_gmac(
    ek: Any,
    ak: Any,
    peer_system_title: bytes,
    challenge: bytes,
    response: bytes,
    suite: int | None = None,
    *,
    provider: object | None = None,
) -> int:
    """Verify a peer's GMAC ``f(challenge)``; returns the IC it carried.

    ``suite``: the security suite of the association; a response whose SC
    names another suite is refused.
    """
    if len(response) != 1 + 4 + TAG_LENGTH:
        raise DecodeError(f"HLS-GMAC response must be 17 octets, got {len(response)}")
    sc = response[0]
    if sc & 0xF0 != 0x10:
        raise AuthenticationError(f"HLS-GMAC response SC 0x{sc:02X} is not authentication-only")
    if suite is not None and sc & 0x0F != suite:
        raise AuthenticationError(f"HLS-GMAC response SC 0x{sc:02X} is not of suite {suite}")
    ic = int.from_bytes(response[1:5], "big")
    expected = hls_gmac(ek, ak, peer_system_title, ic, challenge, sc & 0x0F, provider=provider)
    if not hmac.compare_digest(expected, response):
        raise AuthenticationError("HLS-GMAC response from the meter did not verify")
    return ic


def hls_ecdsa_sign(
    private_key,
    own_title: bytes,
    peer_title: bytes,
    received: bytes,
    sent: bytes,
    *,
    provider: object | None = None,
    suite: int | None = None,
) -> bytes:
    """Mechanism 7: raw ``r || s`` signature over ``own||peer||received||sent``.

    ``private_key`` is a key reference of ``provider`` (default software:
    a ``cryptography`` EC private key).
    """
    from pydlms.security.provider import resolve

    return resolve(provider).ecdsa_sign(
        private_key, own_title + peer_title + received + sent, suite
    )


def hls_ecdsa_verify(
    public_key,
    peer_title: bytes,
    own_title: bytes,
    peer_received: bytes,
    peer_sent: bytes,
    signature: bytes,
) -> None:
    """Verify the peer's mechanism-7 signature (its title and received challenge first)."""
    from pydlms.security.ec import ecdsa_verify

    ecdsa_verify(public_key, peer_title + own_title + peer_received + peer_sent, signature)


def hash_response(mechanism: Mechanism, challenge: bytes, secret: bytes) -> bytes:
    """f(challenge) for the hash mechanisms 3 and 4."""
    if mechanism == Mechanism.HLS_MD5:
        return hls_md5(challenge, secret)
    if mechanism == Mechanism.HLS_SHA1:
        return hls_sha1(challenge, secret)
    raise ValueError(f"{mechanism.name} is not a challenge||secret hash mechanism")
