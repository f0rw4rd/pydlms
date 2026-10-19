"""Security suites and the security-control (SC) byte (IEC 62056-5-3, 9.2.7).

SC byte layout::

    bit 7    compression (refused unless SecurityContext.decompressor is set)
    bit 6    key set: 0 = unicast (GUEK), 1 = broadcast (GBEK)
    bit 5    encryption
    bit 4    authentication
    bits 3-0 security suite id

Observed in the field: ``0x20`` enc-only suite 0, ``0x21`` enc-only suite 1,
``0x30`` auth+enc suite 0, ``0x10`` auth-only.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, IntFlag

from pydlms.exceptions import DecodeError

__all__ = [
    "SecuritySuite",
    "SecurityPolicy",
    "SecurityControl",
    "TAG_LENGTH",
    "key_length",
    "SecurityPolicyV0",
    "SecurityPolicyBits",
    "security_policy_value",
    "security_policy_weakens",
]

#: DLMS truncates the GCM authentication tag to 12 octets (96 bits); see the
#: Green Book suite-0 worked example (tag ``7D825C3BE4A77C3FCC056B6B``).
TAG_LENGTH = 12


class SecuritySuite(IntEnum):
    AES_GCM_128 = 0
    ECDH_ECDSA_AES_GCM_128_SHA256 = 1
    ECDH_ECDSA_AES_GCM_256_SHA384 = 2


def key_length(suite: int) -> int:
    """Symmetric key length in octets for ``suite``."""
    return 32 if suite == SecuritySuite.ECDH_ECDSA_AES_GCM_256_SHA384 else 16


class SecurityPolicy(IntEnum):
    """What a ciphered APDU must provide (subset used to build SC)."""

    NONE = 0x00
    AUTHENTICATED = 0x10
    ENCRYPTED = 0x20
    AUTHENTICATED_ENCRYPTED = 0x30


class SecurityPolicyV0(IntEnum):
    """Security Setup version 0 ``security_policy`` (attribute 2, an enum).

    Sources: Gurux .NET ``SecurityPolicy`` 0..3 and its version 0 check
    (behaviour only, 6f263019). DLMS UA 1000-2 Ed. 9 Excerpt 9.2.7.2.2
    gives 0 = no protection; 3 = "Message Encryption and Message
    Authentication" per DSMR P3 4.2.2 (Netbeheer Nederland, 2014) 3.2.1,
    whose 3.2.2 table orders the levels no security, authenticated,
    encrypted, both and notes that strengthening sets a higher numeric
    value. 1 and 2 follow that order; no public text prints them as
    numbers (Blue Book 5.4.8, *unverified*).
    """

    NOTHING = 0
    ALL_AUTHENTICATED = 1
    ALL_ENCRYPTED = 2
    ALL_AUTHENTICATED_ENCRYPTED = 3


class SecurityPolicyBits(IntFlag):
    """Security Setup version 1 ``security_policy`` (a bit field in an enum).

    Per DLMS UA 1000-2 Ed. 9 Excerpt 9.2.7.2.2 Table 7: the enum is read as
    an unsigned8, bits 0 and 1 unused (shall be 0), bits 2..7 authenticated,
    encrypted and signed request, then the same for the response. cB-Sigma
    dlms ``securitysetup.go`` and Gurux .NET agree.
    """

    NONE = 0
    AUTHENTICATED_REQUEST = 0x04
    ENCRYPTED_REQUEST = 0x08
    DIGITALLY_SIGNED_REQUEST = 0x10
    AUTHENTICATED_RESPONSE = 0x20
    ENCRYPTED_RESPONSE = 0x40
    DIGITALLY_SIGNED_RESPONSE = 0x80


_V0_PROTECTIONS = {0: set(), 1: {"auth"}, 2: {"enc"}, 3: {"auth", "enc"}}


def security_policy_value(policy: int, version: int) -> int:
    """Check ``policy`` for Security Setup ``version`` and return the enum value.

    Version 0 takes 0..3 (:class:`SecurityPolicyV0`), version 1 a
    combination of :class:`SecurityPolicyBits` (reserved bits 0 and 1 clear).
    The two encodings overlap (1, 2, 3 mean different things), so the
    version must be known, never guessed. Raises ``ValueError``.
    """
    policy = int(policy)
    if version == 0:
        if policy not in _V0_PROTECTIONS:
            raise ValueError(f"security policy {policy} is not a version 0 value (0..3)")
    elif version == 1:
        if not 0 <= policy <= 0xFF or policy & 0x03:
            raise ValueError(
                f"security policy 0x{policy:02X} is not a version 1 bit field "
                "(bits 2..7; bits 0 and 1 are reserved)"
            )
    else:
        raise ValueError(f"Security Setup version {version} is not supported (0 or 1)")
    return policy


def security_policy_weakens(current: int, new: int, version: int) -> bool:
    """Whether ``new`` drops any protection ``current`` requires."""
    current = security_policy_value(current, version)
    new = security_policy_value(new, version)
    if version == 0:
        return not _V0_PROTECTIONS[current] <= _V0_PROTECTIONS[new]
    return bool(current & ~new)


@dataclass(frozen=True)
class SecurityControl:
    """Parsed, validated security-control byte."""

    suite: int = 0
    authenticated: bool = False
    encrypted: bool = False
    broadcast_key: bool = False
    compressed: bool = False

    def __post_init__(self) -> None:
        if not 0 <= self.suite <= 15:
            raise ValueError(f"security suite id {self.suite} out of 0..15")

    @classmethod
    def from_byte(cls, value: int, *, allow_compressed: bool = False) -> SecurityControl:
        """Parse and validate an SC byte.

        Bit 7 (compression) raises :class:`DecodeError` unless
        ``allow_compressed``; the ciphering layer passes it only when the
        context has a decompressor and applies the remaining conditions.
        """
        sc = cls(
            suite=value & 0x0F,
            authenticated=bool(value & 0x10),
            encrypted=bool(value & 0x20),
            broadcast_key=bool(value & 0x40),
            compressed=bool(value & 0x80),
        )
        if sc.compressed and not allow_compressed:
            raise DecodeError(
                f"SC 0x{value:02X}: compressed APDUs are not supported "
                "(no SecurityContext.decompressor configured)"
            )
        if sc.suite > SecuritySuite.ECDH_ECDSA_AES_GCM_256_SHA384:
            raise DecodeError(f"SC 0x{value:02X}: unknown security suite {sc.suite}")
        return sc

    @classmethod
    def for_policy(cls, policy: SecurityPolicy, suite: int = 0, broadcast: bool = False):
        return cls(
            suite=suite,
            authenticated=bool(policy & 0x10),
            encrypted=bool(policy & 0x20),
            broadcast_key=broadcast,
        )

    def to_byte(self) -> int:
        return (
            self.suite
            | (0x10 if self.authenticated else 0)
            | (0x20 if self.encrypted else 0)
            | (0x40 if self.broadcast_key else 0)
            | (0x80 if self.compressed else 0)
        )

    def __int__(self) -> int:
        return self.to_byte()

    def describe(self) -> str:
        mode = {
            (True, True): "auth+enc",
            (False, True): "enc-only",
            (True, False): "auth-only",
            (False, False): "none",
        }[(self.authenticated, self.encrypted)]
        key = "broadcast" if self.broadcast_key else "unicast"
        return f"SC=0x{self.to_byte():02X} suite {self.suite} {mode} {key}-key"
