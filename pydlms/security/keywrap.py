"""AES key wrap (RFC 3394) for the Security Setup ``key_transfer`` method.

``key_transfer`` (IC 64 method 2) takes an array of
``structure { key_id enum, key_wrapped octet-string }`` where each key is
wrapped under the master key (KEK). Wrapping goes through the crypto
provider (:mod:`pydlms.security.provider`); the default software provider
uses ``cryptography``'s ``aes_key_wrap``; nothing is hand-rolled. The KEK
may be a provider handle.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Any

from pydlms.cosem.data import DlmsData
from pydlms.security.provider import resolve

__all__ = ["KeyId", "wrap_key", "unwrap_key", "key_transfer_data"]


class KeyId(IntEnum):
    """Security Setup ``key_id`` (global key type)."""

    GLOBAL_UNICAST_ENCRYPTION = 0
    GLOBAL_BROADCAST_ENCRYPTION = 1
    AUTHENTICATION = 2
    MASTER = 3


def wrap_key(kek: Any, key: bytes, *, provider: object | None = None) -> bytes:
    return resolve(provider).aes_wrap(kek, key)


def unwrap_key(kek: Any, wrapped: bytes, *, provider: object | None = None) -> Any:
    """Unwrap under ``kek``; raises :class:`AuthenticationError` on a bad integrity check.

    Returns the key bytes, or a provider handle when the provider unwraps
    into its own store.
    """
    return resolve(provider).aes_unwrap(kek, wrapped)


def key_transfer_data(
    kek: Any, keys: dict[KeyId, bytes], *, provider: object | None = None
) -> DlmsData:
    """Build the ``key_transfer`` method parameter for ``keys``."""
    return DlmsData.array(
        [
            DlmsData.structure(
                [
                    DlmsData.enum(int(key_id)),
                    DlmsData.octet_string(wrap_key(kek, key, provider=provider)),
                ]
            )
            for key_id, key in keys.items()
        ]
    )
