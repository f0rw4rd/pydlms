"""Security Setup ``key_agreement`` (IC 64 method 3) for suites 1 and 2.

The method agrees global keys with the Ephemeral Unified Model C(2e, 0s)
scheme (IEC 62056-5-3:2023 annex I.1): each side sends, per key id, a
fresh ephemeral public key signed with its static ECDSA signing key::

    key_data = X || Y || ECDSA-sign(key_id || X || Y)       (r || s)

Both derive ``Z = ECDH(own ephemeral, peer ephemeral)`` and the key with
the SP 800-56A concatenation KDF of :func:`pydlms.security.ec.kdf`::

    K = Hash(00000001 || Z || AlgorithmID || client title || server title)

The method parameter and the return data have the same shape::

    array of structure { key_id enum, key_data octet-string }

This module is a pure transform: it builds and checks those values and
never touches a link. Key ids 0 (global unicast), 1 (global broadcast) and
2 (authentication) are supported; the master key (3) is refused, see
:func:`pydlms.security.ec.algorithm_id`.

Sources: the signature over ``key_id || X || Y``, the KDF inputs and the
encoding are pinned by the annex I.1 / Table I.1 example as transcribed in
cB-Sigma dlms (Apache-2.0) ``cosem/iec6205653_vectors_test.go`` at 26360a1;
``tests/crypto/test_key_agreement.py`` reproduces Z, the agreed key and the
request bytes from it.

Ephemeral private keys, Z and the derived keys are never logged; derived
keys are registered with the debug redaction filter.

The static signing key may be a crypto provider handle
(:mod:`pydlms.security.provider`): only ``ecdsa_sign`` (and, for the curve
check, ``public_key`` when the provider has it) reach the provider. The
ephemeral key pairs are pydlms's own and stay in software.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from pydlms.cosem.data import DlmsData
from pydlms.cosem.enums import DataType
from pydlms.debug import register_secret
from pydlms.exceptions import AuthenticationError, DecodeError, SecurityError
from pydlms.security import ec
from pydlms.security.keywrap import KeyId
from pydlms.security.provider import SoftwareProvider, resolve
from pydlms.security.suites import SecuritySuite

__all__ = [
    "AGREEABLE_KEY_IDS",
    "make_offer",
    "open_offer",
    "derive_key",
    "key_agreement_data",
    "parse_key_agreement_data",
    "agree",
    "offers_for",
]

#: Key ids ``key_agreement`` may agree in pydlms (no master key, see module doc).
AGREEABLE_KEY_IDS = (
    KeyId.GLOBAL_UNICAST_ENCRYPTION,
    KeyId.GLOBAL_BROADCAST_ENCRYPTION,
    KeyId.AUTHENTICATION,
)


def _key_id(key_id: int) -> KeyId:
    try:
        resolved = KeyId(key_id)
    except ValueError:
        raise ValueError(f"unknown key_id {key_id}") from None
    if resolved not in AGREEABLE_KEY_IDS:
        raise ValueError(
            f"key_agreement for {resolved.name} is not supported "
            "(no checkable AlgorithmID source for the master key)"
        )
    return resolved


def _suite(suite: int) -> SecuritySuite:
    resolved = SecuritySuite(suite)
    if resolved == SecuritySuite.AES_GCM_128:
        raise SecurityError("key_agreement needs security suite 1 or 2")
    return resolved


def _coordinate_size(suite: SecuritySuite) -> int:
    return 32 if suite == SecuritySuite.ECDH_ECDSA_AES_GCM_128_SHA256 else 48


def _check_curve(key: Any, suite: SecuritySuite, who: str) -> None:
    expected = ec.curve_for_suite(suite).name
    curve = getattr(getattr(key, "curve", None), "name", None)
    if curve != expected:
        raise SecurityError(f"{who} is on {curve}, suite {int(suite)} needs {expected}")


def _generate_ephemeral(suite: SecuritySuite) -> Any:
    """A fresh ephemeral key pair (a seam for the known-answer test)."""
    return ec.generate_private_key(suite)


def make_offer(
    signing_key: Any, suite: int, key_id: int, *, provider: object | None = None
) -> tuple[Any, bytes]:
    """A fresh ephemeral key pair and its signed public key for ``key_id``.

    Returns ``(ephemeral_private_key, X || Y || r || s)``; the signature
    covers ``key_id || X || Y``. Keep the private key only until the
    answer is opened, then drop it.
    """
    resolved = _suite(suite)
    key_id = _key_id(key_id)
    crypto = resolve(provider)
    if hasattr(signing_key, "curve") or isinstance(crypto.inner, SoftwareProvider):
        _check_curve(signing_key, resolved, "signing_key")
    elif crypto.supports("public_key"):
        _check_curve(crypto.public_key(signing_key), resolved, "signing_key")
    # else: a handle whose provider cannot show its public key; the guard's
    # signature-size check for the suite still refuses a wrong curve.
    ephemeral = _generate_ephemeral(resolved)
    point = ec.public_key_bytes(ephemeral)
    signature = crypto.ecdsa_sign(signing_key, bytes([key_id]) + point, resolved)
    return ephemeral, point + signature


def open_offer(peer_signing_key: Any, suite: int, key_id: int, data: bytes) -> Any:
    """Check the peer's signed ephemeral key for ``key_id`` and return it.

    ``data`` must be exactly ``X || Y || r || s`` (128 octets for suite 1,
    192 for suite 2), the signature must verify under ``peer_signing_key``
    over ``key_id || X || Y`` and the point must lie on the suite's curve.
    Any failure raises :class:`AuthenticationError`; nothing derived from
    ``data`` is returned then.
    """
    resolved = _suite(suite)
    key_id = _key_id(key_id)
    if peer_signing_key is None:
        raise SecurityError("key_agreement needs the peer's signing key")
    _check_curve(peer_signing_key, resolved, "peer_signing_key")
    size = _coordinate_size(resolved)
    data = bytes(data)
    if len(data) != 4 * size:
        raise AuthenticationError(
            f"key_agreement data for {key_id.name} is {len(data)} octets, "
            f"suite {int(resolved)} needs {4 * size} (X || Y || r || s)"
        )
    point, signature = data[: 2 * size], data[2 * size :]
    ec.ecdsa_verify(peer_signing_key, bytes([key_id]) + point, signature)
    try:
        return ec.load_public_key(resolved, point)
    except ValueError:
        raise AuthenticationError(
            f"key_agreement ephemeral key for {key_id.name} is not a point on the curve"
        ) from None


def derive_key(
    suite: int, key_id: int, z: bytes, client_title: bytes, server_title: bytes
) -> bytes:
    """The agreed key: the suite's KDF over ``Z`` with the key id's
    AlgorithmID, PartyUInfo the client and PartyVInfo the server system title.
    """
    resolved = _suite(suite)
    key_id = _key_id(key_id)
    if len(client_title) != 8 or len(server_title) != 8:
        raise ValueError("system titles must be 8 octets")
    return ec.kdf(
        resolved,
        z,
        bytes(client_title),
        bytes(server_title),
        algorithm=ec.algorithm_id(resolved, key_id),
    )


def key_agreement_data(offers: Mapping[int, bytes]) -> DlmsData:
    """The method parameter for ``offers`` (key id -> key data), in order."""
    return DlmsData.array(
        [
            DlmsData.structure([DlmsData.enum(int(key_id)), DlmsData.octet_string(data)])
            for key_id, data in offers.items()
        ]
    )


def parse_key_agreement_data(data: DlmsData | None) -> dict[KeyId, bytes]:
    """Read ``array of structure { key_id enum, key_data octet-string }``.

    Raises :class:`DecodeError` for any other shape, an unknown key id or a
    key id listed twice.
    """
    if data is None or data.tag != DataType.ARRAY:
        raise DecodeError("key_agreement data is not an array")
    out: dict[KeyId, bytes] = {}
    for item in data.value:
        if item.tag != DataType.STRUCTURE or len(item.value) != 2:
            raise DecodeError("key_agreement entry is not a structure of two elements")
        key_id, key_data = item.value
        if key_id.tag != DataType.ENUM or key_data.tag != DataType.OCTET_STRING:
            raise DecodeError("key_agreement entry is not {key_id enum, key_data octet-string}")
        try:
            resolved = KeyId(key_id.value)
        except ValueError:
            raise DecodeError(f"key_agreement names unknown key_id {key_id.value}") from None
        if resolved in out:
            raise DecodeError(f"key_agreement names {resolved.name} twice")
        out[resolved] = bytes(key_data.value)
    return out


def agree(
    suite: int,
    ephemeral_keys: Mapping[int, Any],
    peer_signing_key: Any,
    answer: DlmsData | None,
    client_title: bytes,
    server_title: bytes,
) -> dict[KeyId, bytes]:
    """Open the meter's ``answer`` to our offers and derive the keys.

    The answer must name exactly the key ids offered (``ephemeral_keys``),
    each signed by ``peer_signing_key``; otherwise :class:`SecurityError`
    (a missing or unsolicited key id) or :class:`AuthenticationError` (a
    bad offer) is raised and no key is returned. Derived keys are
    registered for log redaction.
    """
    resolved = _suite(suite)
    entries = parse_key_agreement_data(answer)
    offered = {_key_id(k) for k in ephemeral_keys}
    unsolicited = sorted(k.name for k in set(entries) - offered)
    if unsolicited:
        raise SecurityError(f"key_agreement answer names keys not offered: {unsolicited}")
    missing = sorted(k.name for k in offered - set(entries))
    if missing:
        raise SecurityError(f"key_agreement answer lacks offered keys: {missing}")
    peers = {
        key_id: open_offer(peer_signing_key, resolved, key_id, data)
        for key_id, data in entries.items()
    }
    keys: dict[KeyId, bytes] = {}
    for key_id in ephemeral_keys:
        key_id = KeyId(key_id)
        z = ec.ecdh_shared_secret(ephemeral_keys[key_id], peers[key_id])
        key = derive_key(resolved, key_id, z, client_title, server_title)
        register_secret(key)
        keys[key_id] = key
    return keys


def offers_for(
    signing_key: Any, suite: int, key_ids: Iterable[int], *, provider: object | None = None
) -> tuple[dict[KeyId, Any], dict[KeyId, bytes]]:
    """Ephemeral keys and signed offers for each of ``key_ids`` (no repeats)."""
    ids = [_key_id(k) for k in key_ids]
    if not ids:
        raise ValueError("no key ids to agree")
    if len(set(ids)) != len(ids):
        raise ValueError("a key id is listed twice")
    ephemeral: dict[KeyId, Any] = {}
    offers: dict[KeyId, bytes] = {}
    for key_id in ids:
        ephemeral[key_id], offers[key_id] = make_offer(
            signing_key, suite, key_id, provider=provider
        )
    return ephemeral, offers
