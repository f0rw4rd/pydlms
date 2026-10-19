"""Elliptic-curve operations for security suites 1 (P-256) and 2 (P-384).

* ECDSA with the raw ``r || s`` signature encoding DLMS uses (64 octets for
  P-256, 96 for P-384), over SHA-256 / SHA-384.
* ECDH shared secret ``Z`` and the NIST SP 800-56A single-step concatenation
  KDF used to derive the AES key from it::

      K = Hash(counter=00000001 || Z || AlgorithmID || PartyUInfo || PartyVInfo)

  truncated to the key length; AlgorithmID is the 7-octet OID body
  ``60 85 74 05 08 03 00`` (aes-gcm-128) or ``...03 01`` (aes-gcm-256).

The KDF OtherInfo composition was first taken from behavioural reference
implementations; it is now pinned by the IEC 62056-5-3:2023 annex I.1
key_agreement example (``tests/crypto/test_key_agreement.py``: Z and the
agreed global unicast key reproduce), besides the SP 800-56A definition
(independent hashlib computation) and ECDH agreement symmetry.

Public keys travel as the uncompressed point without the ``04`` prefix
(``X || Y``), which is what DLMS key-agreement data and certificates use.
"""

from __future__ import annotations

import hashlib

from pydlms.exceptions import AuthenticationError
from pydlms.security.suites import SecuritySuite

__all__ = [
    "curve_for_suite",
    "generate_private_key",
    "public_key_bytes",
    "load_public_key",
    "ecdsa_sign",
    "ecdsa_verify",
    "ecdh_shared_secret",
    "kdf",
    "kdf_other_info",
    "other_info",
    "algorithm_id",
]

_ALG_ID = {
    SecuritySuite.ECDH_ECDSA_AES_GCM_128_SHA256: bytes.fromhex("60857405080300"),
    SecuritySuite.ECDH_ECDSA_AES_GCM_256_SHA384: bytes.fromhex("60857405080301"),
}


def _ec():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    return ec, hashes, utils


def curve_for_suite(suite: int):
    ec, _, _ = _ec()
    if suite == SecuritySuite.ECDH_ECDSA_AES_GCM_128_SHA256:
        return ec.SECP256R1()
    if suite == SecuritySuite.ECDH_ECDSA_AES_GCM_256_SHA384:
        return ec.SECP384R1()
    raise ValueError(f"security suite {suite} has no elliptic curve")


def _hash_for(key):
    _, hashes, _ = _ec()
    return hashes.SHA256() if key.curve.key_size == 256 else hashes.SHA384()


def _coord_size(key) -> int:
    return (key.curve.key_size + 7) // 8


def generate_private_key(suite: int):
    ec, _, _ = _ec()
    return ec.generate_private_key(curve_for_suite(suite))


def public_key_bytes(key) -> bytes:
    """``X || Y`` of a public (or the public half of a private) key."""
    public = key.public_key() if hasattr(key, "private_numbers") else key
    numbers = public.public_numbers()
    size = _coord_size(public)
    return numbers.x.to_bytes(size, "big") + numbers.y.to_bytes(size, "big")


def load_public_key(suite: int, xy: bytes):
    ec, _, _ = _ec()
    curve = curve_for_suite(suite)
    size = (curve.key_size + 7) // 8
    if len(xy) != 2 * size:
        raise ValueError(f"public key must be {2 * size} octets (X||Y), got {len(xy)}")
    return ec.EllipticCurvePublicKey.from_encoded_point(curve, b"\x04" + xy)


def ecdsa_sign(private_key, message: bytes) -> bytes:
    ec, _, utils = _ec()
    der = private_key.sign(message, ec.ECDSA(_hash_for(private_key)))
    r, s = utils.decode_dss_signature(der)
    size = _coord_size(private_key)
    return r.to_bytes(size, "big") + s.to_bytes(size, "big")


def ecdsa_verify(public_key, message: bytes, signature: bytes) -> None:
    """Raise :class:`AuthenticationError` unless ``signature`` (r||s) verifies."""
    from cryptography.exceptions import InvalidSignature

    ec, _, utils = _ec()
    size = _coord_size(public_key)
    if len(signature) != 2 * size:
        raise AuthenticationError(f"ECDSA signature must be {2 * size} octets")
    r = int.from_bytes(signature[:size], "big")
    s = int.from_bytes(signature[size:], "big")
    der = utils.encode_dss_signature(r, s)
    try:
        public_key.verify(der, message, ec.ECDSA(_hash_for(public_key)))
    except InvalidSignature:
        raise AuthenticationError("ECDSA signature did not verify") from None


def ecdh_shared_secret(private_key, peer_public_key) -> bytes:
    ec, _, _ = _ec()
    return private_key.exchange(ec.ECDH(), peer_public_key)


#: Security Setup ``key_id`` values whose agreed key is an AES-GCM key and so
#: takes the suite's AES-GCM AlgorithmID: 0 global unicast encryption, 1
#: global broadcast encryption, 2 authentication. IEC 62056-5-3:2023 Table 8
#: via cB-Sigma 26360a1 (suite 2 authentication key 60857405080301).
_GCM_KEY_IDS = (0, 1, 2)


def algorithm_id(suite: int, key_id: int | None = None) -> bytes:
    """KDF AlgorithmID for ``suite`` (and, for ``key_agreement``, ``key_id``).

    Without ``key_id`` (general-ciphering content keys) and for key ids 0,
    1 and 2 it is the suite's AES-GCM OID body. The master key (key id 3)
    is refused: its AlgorithmID (an AES key-wrap OID) is only known from
    one implementation's reading, so pydlms does not derive a KEK.
    """
    if key_id is not None and key_id not in _GCM_KEY_IDS:
        raise ValueError(f"key_id {key_id} has no key-agreement AlgorithmID in pydlms")
    try:
        return _ALG_ID[SecuritySuite(suite)]
    except (KeyError, ValueError):
        raise ValueError(f"security suite {suite} has no key-agreement AlgorithmID") from None


def _kdf_hash(suite: int):
    suite = SecuritySuite(suite)
    if suite == SecuritySuite.ECDH_ECDSA_AES_GCM_128_SHA256:
        return hashlib.sha256, 16
    if suite == SecuritySuite.ECDH_ECDSA_AES_GCM_256_SHA384:
        return hashlib.sha384, 32
    raise ValueError("suite 0 has no key agreement")


def other_info(
    suite: int,
    party_u_info: bytes,
    party_v_info: bytes,
    supp_pub_info: bytes = b"",
    *,
    algorithm: bytes | None = None,
) -> bytes:
    """The KDF OtherInfo: ``AlgorithmID || PartyUInfo || PartyVInfo [|| SuppPubInfo]``."""
    _kdf_hash(suite)
    if algorithm is None:
        algorithm = algorithm_id(suite)
    return algorithm + party_u_info + party_v_info + supp_pub_info


def kdf_other_info(suite: int, z: bytes, info: bytes) -> bytes:
    """SP 800-56A single-step KDF over ``Z`` with a prepared OtherInfo."""
    digest, key_len = _kdf_hash(suite)
    return digest(b"\x00\x00\x00\x01" + z + info).digest()[:key_len]


def kdf(
    suite: int,
    z: bytes,
    party_u_info: bytes,
    party_v_info: bytes,
    supp_pub_info: bytes = b"",
    *,
    algorithm: bytes | None = None,
) -> bytes:
    """SP 800-56A concatenation KDF with the DLMS OtherInfo (see module doc).

    ``algorithm`` overrides the AlgorithmID (see :func:`algorithm_id`).
    """
    info = other_info(suite, party_u_info, party_v_info, supp_pub_info, algorithm=algorithm)
    return kdf_other_info(suite, z, info)
