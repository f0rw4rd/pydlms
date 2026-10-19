"""ACSE APDUs: AARQ, AARE, RLRQ, RLRE (IEC 62056-5-3, 9.3.2; ISO 8650 BER).

These are BER-encoded (unlike the A-XDR xDLMS APDUs). Field tags used:

AARQ ``60``: ``80`` protocol-version, ``A1`` application-context-name,
``A6`` calling-AP-title, ``A7`` calling-AE-qualifier, ``8A`` sender ACSE
requirements, ``8B`` mechanism-name, ``AC`` calling-authentication-value,
``BE`` user-information (an xDLMS InitiateRequest, possibly ciphered).

AARE ``61``: ``A1`` application-context-name, ``A2`` result, ``A3``
result-source-diagnostic (``A1`` acse-service-user / ``A2``
acse-service-provider), ``A4`` responding-AP-title, ``A5``
responding-AE-qualifier, ``88`` responder ACSE requirements, ``89``
mechanism-name, ``AA`` responding-authentication-value, ``BE``
user-information.

Pinned by the Green Book v10 examples (LN no security, LLS "12345678",
accepted and rejected AARE) in ``tests/test_acse.py``.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

from pydlms.exceptions import DecodeError

__all__ = [
    "ApplicationContext",
    "AcseServiceUserDiagnostic",
    "AcseServiceProviderDiagnostic",
    "AARQ",
    "AARE",
    "RLRQ",
    "RLRE",
    "decode_acse",
    "ber_tlv",
    "parse_ber",
]

_CONTEXT_PREFIX = bytes.fromhex("60857405080101")[:-1]  # 2.16.756.5.8.1.
_MECHANISM_PREFIX = bytes.fromhex("608574050802")  # 2.16.756.5.8.2.


class ApplicationContext(enum.IntEnum):
    LN = 1
    SN = 2
    LN_CIPHERED = 3
    SN_CIPHERED = 4

    @property
    def ciphered(self) -> bool:
        return self in (ApplicationContext.LN_CIPHERED, ApplicationContext.SN_CIPHERED)

    @property
    def logical_names(self) -> bool:
        return self in (ApplicationContext.LN, ApplicationContext.LN_CIPHERED)


class AcseServiceUserDiagnostic(enum.IntEnum):
    NULL = 0
    NO_REASON_GIVEN = 1
    APPLICATION_CONTEXT_NAME_NOT_SUPPORTED = 2
    CALLING_AP_TITLE_NOT_RECOGNIZED = 3
    CALLING_AP_INVOCATION_IDENTIFIER_NOT_RECOGNIZED = 4
    CALLING_AE_QUALIFIER_NOT_RECOGNIZED = 5
    CALLING_AE_INVOCATION_IDENTIFIER_NOT_RECOGNIZED = 6
    CALLED_AP_TITLE_NOT_RECOGNIZED = 7
    CALLED_AP_INVOCATION_IDENTIFIER_NOT_RECOGNIZED = 8
    CALLED_AE_QUALIFIER_NOT_RECOGNIZED = 9
    CALLED_AE_INVOCATION_IDENTIFIER_NOT_RECOGNIZED = 10
    AUTHENTICATION_MECHANISM_NAME_NOT_RECOGNISED = 11
    AUTHENTICATION_MECHANISM_NAME_REQUIRED = 12
    AUTHENTICATION_FAILURE = 13
    AUTHENTICATION_REQUIRED = 14


class AcseServiceProviderDiagnostic(enum.IntEnum):
    NULL = 0
    NO_REASON_GIVEN = 1
    NO_COMMON_ACSE_VERSION = 2


# --- BER helpers -------------------------------------------------------------------


def _ber_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_length(len(value)) + value


def parse_ber(data: bytes) -> list[tuple[int, bytes]]:
    """Split a BER constructed body into ``(tag, value)`` pairs (single-octet tags)."""
    items = []
    pos = 0
    while pos < len(data):
        if pos + 2 > len(data):
            raise DecodeError("truncated BER TLV")
        tag = data[pos]
        if tag & 0x1F == 0x1F:
            raise DecodeError(f"multi-octet BER tag 0x{tag:02X} is not used by ACSE")
        first = data[pos + 1]
        pos += 2
        if first < 0x80:
            length = first
        else:
            n = first & 0x7F
            if n == 0 or n > 4 or pos + n > len(data):
                raise DecodeError("bad BER length")
            length = int.from_bytes(data[pos : pos + n], "big")
            pos += n
        end = pos + length
        if end > len(data):
            raise DecodeError(f"BER value of tag 0x{tag:02X} runs past the end")
        items.append((tag, data[pos:end]))
        pos = end
    return items


def _unwrap_outer(data: bytes, tag: int, name: str) -> list[tuple[int, bytes]]:
    items = parse_ber(data)
    if len(items) != 1 or items[0][0] != tag:
        raise DecodeError(f"not a single {name} (tag 0x{tag:02X})")
    return parse_ber(items[0][1])


def _oid_context(value: bytes) -> ApplicationContext:
    # value is the A1 content: 06 07 <oid>
    inner = parse_ber(value)
    if len(inner) != 1 or inner[0][0] != 0x06:
        raise DecodeError("application-context-name is not an OBJECT IDENTIFIER")
    oid = inner[0][1]
    if len(oid) != 7 or oid[:6] != _CONTEXT_PREFIX:
        raise DecodeError(f"unknown application context OID {oid.hex()}")
    try:
        return ApplicationContext(oid[6])
    except ValueError:
        raise DecodeError(f"unknown application context id {oid[6]}") from None


def _context_bytes(context: ApplicationContext) -> bytes:
    return ber_tlv(0xA1, ber_tlv(0x06, _CONTEXT_PREFIX + bytes([int(context)])))


def _mechanism_from(value: bytes) -> int:
    if len(value) != 7 or value[:6] != _MECHANISM_PREFIX:
        raise DecodeError(f"unknown mechanism-name {value.hex()}")
    return value[6]


def _octet_string_in(value: bytes, what: str) -> bytes:
    inner = parse_ber(value)
    if len(inner) != 1 or inner[0][0] != 0x04:
        raise DecodeError(f"{what} is not an OCTET STRING")
    return inner[0][1]


def _auth_value(value: bytes) -> bytes:
    inner = parse_ber(value)
    if len(inner) != 1 or inner[0][0] not in (0x80, 0x81):
        raise DecodeError("authentication-value is not charstring/bitstring")
    return inner[0][1]


def _integer_in(value: bytes) -> int:
    inner = parse_ber(value)
    if len(inner) != 1 or inner[0][0] != 0x02 or not inner[0][1]:
        raise DecodeError("expected an INTEGER")
    return int.from_bytes(inner[0][1], "big", signed=True)


# --- AARQ / AARE -----------------------------------------------------------------------


@dataclass
class AARQ:
    application_context: ApplicationContext = ApplicationContext.LN
    user_information: bytes = b""
    mechanism: int | None = None
    calling_authentication_value: bytes | None = None
    calling_ap_title: bytes | None = None
    calling_ae_qualifier: bytes | None = None

    def to_bytes(self) -> bytes:
        body = _context_bytes(self.application_context)
        if self.calling_ap_title is not None:
            body += ber_tlv(0xA6, ber_tlv(0x04, self.calling_ap_title))
        if self.calling_ae_qualifier is not None:
            body += ber_tlv(0xA7, ber_tlv(0x04, self.calling_ae_qualifier))
        if self.mechanism:
            body += ber_tlv(0x8A, b"\x07\x80")
            body += ber_tlv(0x8B, _MECHANISM_PREFIX + bytes([self.mechanism]))
            if self.calling_authentication_value is not None:
                body += ber_tlv(0xAC, ber_tlv(0x80, self.calling_authentication_value))
        if self.user_information:
            body += ber_tlv(0xBE, ber_tlv(0x04, self.user_information))
        return ber_tlv(0x60, body)

    @classmethod
    def from_bytes(cls, data: bytes) -> AARQ:
        aarq = cls()
        for tag, value in _unwrap_outer(data, 0x60, "AARQ"):
            if tag == 0xA1:
                aarq.application_context = _oid_context(value)
            elif tag == 0xA6:
                aarq.calling_ap_title = _octet_string_in(value, "calling-AP-title")
            elif tag == 0xA7:
                aarq.calling_ae_qualifier = _octet_string_in(value, "calling-AE-qualifier")
            elif tag == 0x8B:
                aarq.mechanism = _mechanism_from(value)
            elif tag == 0xAC:
                aarq.calling_authentication_value = _auth_value(value)
            elif tag == 0xBE:
                aarq.user_information = _octet_string_in(value, "user-information")
        return aarq


@dataclass
class AARE:
    application_context: ApplicationContext
    result: int
    diagnostic_source: int = 1  # 1 acse-service-user, 2 acse-service-provider
    diagnostic: int = 0
    responding_ap_title: bytes | None = None
    responding_ae_qualifier: bytes | None = None
    mechanism: int | None = None
    responding_authentication_value: bytes | None = None
    user_information: bytes = b""

    @property
    def accepted(self) -> bool:
        return self.result == 0

    def diagnostic_name(self) -> str:
        enum_cls = (
            AcseServiceUserDiagnostic
            if self.diagnostic_source == 1
            else AcseServiceProviderDiagnostic
        )
        try:
            return enum_cls(self.diagnostic).name
        except ValueError:
            return str(self.diagnostic)

    def to_bytes(self) -> bytes:
        body = _context_bytes(self.application_context)
        body += ber_tlv(0xA2, ber_tlv(0x02, bytes([self.result])))
        body += ber_tlv(
            0xA3, ber_tlv(0xA0 | self.diagnostic_source, ber_tlv(0x02, bytes([self.diagnostic])))
        )
        if self.responding_ap_title is not None:
            body += ber_tlv(0xA4, ber_tlv(0x04, self.responding_ap_title))
        if self.responding_ae_qualifier is not None:
            body += ber_tlv(0xA5, ber_tlv(0x04, self.responding_ae_qualifier))
        if self.mechanism:
            body += ber_tlv(0x88, b"\x07\x80")
            body += ber_tlv(0x89, _MECHANISM_PREFIX + bytes([self.mechanism]))
        if self.responding_authentication_value is not None:
            body += ber_tlv(0xAA, ber_tlv(0x80, self.responding_authentication_value))
        if self.user_information:
            body += ber_tlv(0xBE, ber_tlv(0x04, self.user_information))
        return ber_tlv(0x61, body)

    @classmethod
    def from_bytes(cls, data: bytes) -> AARE:
        fields: dict = {}
        context = None
        result = None
        source, diagnostic = 1, 0
        for tag, value in _unwrap_outer(data, 0x61, "AARE"):
            if tag == 0xA1:
                context = _oid_context(value)
            elif tag == 0xA2:
                result = _integer_in(value)
            elif tag == 0xA3:
                inner = parse_ber(value)
                if len(inner) != 1 or inner[0][0] not in (0xA1, 0xA2):
                    raise DecodeError("bad result-source-diagnostic")
                source = inner[0][0] & 0x0F
                diagnostic = _integer_in(inner[0][1])
            elif tag == 0xA4:
                fields["responding_ap_title"] = _octet_string_in(value, "responding-AP-title")
            elif tag == 0xA5:
                fields["responding_ae_qualifier"] = _octet_string_in(value, "AE-qualifier")
            elif tag == 0x89:
                fields["mechanism"] = _mechanism_from(value)
            elif tag == 0xAA:
                fields["responding_authentication_value"] = _auth_value(value)
            elif tag == 0xBE:
                fields["user_information"] = _octet_string_in(value, "user-information")
        if context is None or result is None:
            raise DecodeError("AARE lacks application-context-name or result")
        return cls(context, result, source, diagnostic, **fields)


# --- release --------------------------------------------------------------------------


@dataclass
class RLRQ:
    reason: int | None = 0
    user_information: bytes = b""

    def to_bytes(self) -> bytes:
        body = b"" if self.reason is None else ber_tlv(0x80, bytes([self.reason]))
        if self.user_information:
            body += ber_tlv(0xBE, ber_tlv(0x04, self.user_information))
        return ber_tlv(0x62, body)

    @classmethod
    def from_bytes(cls, data: bytes) -> RLRQ:
        rlrq = cls(reason=None)
        for tag, value in _unwrap_outer(data, 0x62, "RLRQ"):
            if tag == 0x80 and value:
                rlrq.reason = value[0]
            elif tag == 0xBE:
                rlrq.user_information = _octet_string_in(value, "user-information")
        return rlrq


@dataclass
class RLRE:
    reason: int | None = 0
    user_information: bytes = b""

    def to_bytes(self) -> bytes:
        body = b"" if self.reason is None else ber_tlv(0x80, bytes([self.reason]))
        if self.user_information:
            body += ber_tlv(0xBE, ber_tlv(0x04, self.user_information))
        return ber_tlv(0x63, body)

    @classmethod
    def from_bytes(cls, data: bytes) -> RLRE:
        rlre = cls(reason=None)
        for tag, value in _unwrap_outer(data, 0x63, "RLRE"):
            if tag == 0x80 and value:
                rlre.reason = value[0]
            elif tag == 0xBE:
                rlre.user_information = _octet_string_in(value, "user-information")
        return rlre


def decode_acse(data: bytes):
    if not data:
        raise DecodeError("empty ACSE APDU")
    decoder = {0x60: AARQ, 0x61: AARE, 0x62: RLRQ, 0x63: RLRE}.get(data[0])
    if decoder is None:
        raise DecodeError(f"0x{data[0]:02X} is not an ACSE APDU")
    return decoder.from_bytes(data)
