"""A test crypto provider whose keys live behind integer handles.

Stands in for an HSM: pydlms only ever holds the integers. Raw ``bytes``
key references (session keys pydlms creates itself) are accepted as the
provider contract requires. Every call is recorded as ``(operation,
key reference)`` so tests can see what reached the provider.

The arithmetic is the raw ``cryptography`` primitives in
:mod:`pydlms.security.gcm` / :mod:`pydlms.security.ec`, so results must
equal :class:`~pydlms.security.provider.SoftwareProvider` byte for byte.
"""

from __future__ import annotations

import hashlib
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.keywrap import (
    InvalidUnwrap,
    aes_key_unwrap,
    aes_key_wrap,
)

from pydlms.exceptions import AuthenticationError
from pydlms.security import ec, gcm
from pydlms.security.provider import flatten_aad


class HandleProvider:
    """Keys behind integer handles, recording calls."""

    def __init__(self, *, with_ecdh_kdf: bool = True, unwrap_to_handle: bool = False) -> None:
        self._keys: dict[int, Any] = {}
        self._next = 0x1000
        self.calls: list[tuple[str, object]] = []
        self.unwrap_to_handle = unwrap_to_handle
        if not with_ecdh_kdf:
            # Instance attribute shadows the method: the provider "lacks" it.
            self.ecdh_kdf = None

    def __repr__(self) -> str:
        return f"HandleProvider({len(self._keys)} keys)"

    def add(self, key: Any) -> int:
        handle = self._next
        self._next += 1
        self._keys[handle] = key
        return handle

    def _key(self, ref: Any) -> Any:
        if isinstance(ref, (bytes, bytearray)):
            return bytes(ref)  # a session key pydlms created
        if isinstance(ref, int) and not isinstance(ref, bool) and ref in self._keys:
            return self._keys[ref]
        raise KeyError("unknown key handle")

    def _record(self, op: str, ref: Any) -> None:
        self.calls.append((op, ref if isinstance(ref, int) else "bytes"))

    def gcm_seal(self, key_ref, iv, plaintext, aad):
        self._record("gcm_seal", key_ref)
        return gcm.gcm_encrypt(self._key(key_ref), iv, plaintext, flatten_aad(aad, self._key))

    def gcm_open(self, key_ref, iv, ciphertext, aad, tag):
        self._record("gcm_open", key_ref)
        return gcm.gcm_decrypt(self._key(key_ref), iv, ciphertext, flatten_aad(aad, self._key), tag)

    def ctr(self, key_ref, counter_block, data):
        self._record("ctr", key_ref)
        return gcm.aes_ctr(self._key(key_ref), counter_block, data)

    def gmac(self, key_ref, iv, aad):
        self._record("gmac", key_ref)
        return gcm.gmac(self._key(key_ref), iv, flatten_aad(aad, self._key))

    def aes_ecb_block(self, key_ref, block):
        self._record("aes_ecb_block", key_ref)
        encryptor = Cipher(algorithms.AES(self._key(key_ref)), modes.ECB()).encryptor()  # nosec B305
        return encryptor.update(block) + encryptor.finalize()

    def ecdsa_sign(self, key_ref, message, suite=None):
        self._record("ecdsa_sign", key_ref)
        return ec.ecdsa_sign(self._key(key_ref), message)

    def public_key(self, key_ref):
        self._record("public_key", key_ref)
        return self._key(key_ref).public_key()

    def ecdh(self, key_ref, peer_public_key):
        self._record("ecdh", key_ref)
        return ec.ecdh_shared_secret(self._key(key_ref), peer_public_key)

    def ecdh_kdf(self, key_ref, peer_public_key, suite, other_info):
        self._record("ecdh_kdf", key_ref)
        z = ec.ecdh_shared_secret(self._key(key_ref), peer_public_key)
        return self.add(ec.kdf_other_info(suite, z, other_info))

    def aes_wrap(self, kek_ref, key):
        self._record("aes_wrap", kek_ref)
        return aes_key_wrap(self._key(kek_ref), self._key(key))

    def aes_unwrap(self, kek_ref, wrapped):
        self._record("aes_unwrap", kek_ref)
        try:
            key = aes_key_unwrap(self._key(kek_ref), wrapped)
        except InvalidUnwrap:
            raise AuthenticationError("AES key unwrap integrity check failed") from None
        return self.add(key) if self.unwrap_to_handle else key

    def key_fingerprint(self, key_ref):
        self._record("key_fingerprint", key_ref)
        return hashlib.sha256(b"handle-provider" + str(key_ref).encode()).digest()

    def ops(self) -> set[str]:
        return {op for op, _ in self.calls}
