"""xDLMS / ACSE APDU tag constants (IEC 62056-5-3, 8.x ASN.1 module).

Plain, global-ciphered (``glo-``) and dedicated-ciphered (``ded-``) tags. The
key-specific ciphered tags are a fixed mapping from the plaintext tag, kept in
:data:`GLO_TAG` / :data:`DED_TAG`; :data:`PLAIN_FOR_CIPHERED` is the inverse.

Cross-checked against captures: ``0xDB`` general-glo-ciphering in the Kaifa
and Netz NÖ pushes, ``0xE0`` general-block-transfer in the L+G E450 push, and
``0x0F`` data-notification after decryption.
"""

from __future__ import annotations

from enum import IntEnum

__all__ = [
    "Tag",
    "GLO_TAG",
    "DED_TAG",
    "PLAIN_FOR_CIPHERED",
    "UNSOLICITED_TAGS",
    "CIPHERED_UNSOLICITED_TAGS",
    "is_ciphered",
]


class Tag(IntEnum):
    # ACSE
    AARQ = 0x60
    AARE = 0x61
    RLRQ = 0x62
    RLRE = 0x63
    # xDLMS, unciphered
    INITIATE_REQUEST = 0x01
    READ_REQUEST = 0x05
    WRITE_REQUEST = 0x06
    INITIATE_RESPONSE = 0x08
    READ_RESPONSE = 0x0C
    WRITE_RESPONSE = 0x0D
    CONFIRMED_SERVICE_ERROR = 0x0E
    DATA_NOTIFICATION = 0x0F
    UNCONFIRMED_WRITE_REQUEST = 0x16
    INFORMATION_REPORT_REQUEST = 0x18
    GET_REQUEST = 0xC0
    SET_REQUEST = 0xC1
    EVENT_NOTIFICATION_REQUEST = 0xC2
    ACTION_REQUEST = 0xC3
    GET_RESPONSE = 0xC4
    SET_RESPONSE = 0xC5
    ACTION_RESPONSE = 0xC7
    # global ciphering
    GLO_INITIATE_REQUEST = 0x21
    GLO_READ_REQUEST = 0x25
    GLO_WRITE_REQUEST = 0x26
    GLO_INITIATE_RESPONSE = 0x28
    GLO_READ_RESPONSE = 0x2C
    GLO_WRITE_RESPONSE = 0x2D
    GLO_CONFIRMED_SERVICE_ERROR = 0x2E
    GLO_UNCONFIRMED_WRITE_REQUEST = 0x36
    GLO_INFORMATION_REPORT_REQUEST = 0x38
    GLO_GET_REQUEST = 0xC8
    GLO_SET_REQUEST = 0xC9
    GLO_EVENT_NOTIFICATION_REQUEST = 0xCA
    GLO_ACTION_REQUEST = 0xCB
    GLO_GET_RESPONSE = 0xCC
    GLO_SET_RESPONSE = 0xCD
    GLO_ACTION_RESPONSE = 0xCF
    # dedicated ciphering
    DED_INITIATE_REQUEST = 0x41
    DED_READ_REQUEST = 0x45
    DED_WRITE_REQUEST = 0x46
    DED_INITIATE_RESPONSE = 0x48
    DED_READ_RESPONSE = 0x4C
    DED_WRITE_RESPONSE = 0x4D
    DED_CONFIRMED_SERVICE_ERROR = 0x4E
    DED_UNCONFIRMED_WRITE_REQUEST = 0x56
    DED_INFORMATION_REPORT_REQUEST = 0x58
    DED_GET_REQUEST = 0xD0
    DED_SET_REQUEST = 0xD1
    DED_EVENT_NOTIFICATION_REQUEST = 0xD2
    DED_ACTION_REQUEST = 0xD3
    DED_GET_RESPONSE = 0xD4
    DED_SET_RESPONSE = 0xD5
    DED_ACTION_RESPONSE = 0xD7
    # misc
    EXCEPTION_RESPONSE = 0xD8
    ACCESS_REQUEST = 0xD9
    ACCESS_RESPONSE = 0xDA
    GENERAL_GLO_CIPHERING = 0xDB
    GENERAL_DED_CIPHERING = 0xDC
    GENERAL_CIPHERING = 0xDD
    GENERAL_SIGNING = 0xDF
    GENERAL_BLOCK_TRANSFER = 0xE0


_KEY_SPECIFIC = [
    "INITIATE_REQUEST",
    "READ_REQUEST",
    "WRITE_REQUEST",
    "INITIATE_RESPONSE",
    "READ_RESPONSE",
    "WRITE_RESPONSE",
    "CONFIRMED_SERVICE_ERROR",
    "UNCONFIRMED_WRITE_REQUEST",
    "INFORMATION_REPORT_REQUEST",
    "GET_REQUEST",
    "SET_REQUEST",
    "EVENT_NOTIFICATION_REQUEST",
    "ACTION_REQUEST",
    "GET_RESPONSE",
    "SET_RESPONSE",
    "ACTION_RESPONSE",
]

#: plaintext tag -> glo- tag
GLO_TAG: dict[int, int] = {Tag[n].value: Tag["GLO_" + n].value for n in _KEY_SPECIFIC}
#: plaintext tag -> ded- tag
DED_TAG: dict[int, int] = {Tag[n].value: Tag["DED_" + n].value for n in _KEY_SPECIFIC}
#: ciphered tag -> (plaintext tag, dedicated?)
PLAIN_FOR_CIPHERED: dict[int, tuple[int, bool]] = {
    **{g: (p, False) for p, g in GLO_TAG.items()},
    **{d: (p, True) for p, d in DED_TAG.items()},
}


#: Plaintext APDUs a server sends unsolicited (IEC 62056-5-3 xDLMS APDU
#: table, server-to-client unconfirmed services): DataNotification (``0x0F``,
#: LN push), EventNotification-Request (``0xC2``, LN) and
#: InformationReport-Request (``0x18``, SN). ``0x0F`` is confirmed by the
#: Kaifa / Netz NÖ captures (see the module docstring), ``0xC2`` by the
#: Wireshark 4.6 dissection in ``tests/integration/test_tshark.py``; ``0x18``
#: per IEC 62056-53:2006 8.1 (``informationReportRequest [24] IMPLICIT``,
#: public as IS/IEC 62056-53), not seen in a capture.
UNSOLICITED_TAGS: frozenset[int] = frozenset(
    {
        Tag.DATA_NOTIFICATION,
        Tag.EVENT_NOTIFICATION_REQUEST,
        Tag.INFORMATION_REPORT_REQUEST,
    }
)
#: Their key-specific ciphered forms: glo-/ded-EventNotification-Request
#: (``0xCA``/``0xD2``) and glo-/ded-InformationReport-Request
#: (``0x38``/``0x58``). DataNotification has no key-specific form; it is
#: protected only inside the general envelopes (general-glo/-ded ``0xDB``/
#: ``0xDC``, general-ciphering ``0xDD``), which may hold a reply as well.
CIPHERED_UNSOLICITED_TAGS: frozenset[int] = frozenset(
    c for c, (p, _) in PLAIN_FOR_CIPHERED.items() if p in UNSOLICITED_TAGS
)


def is_ciphered(tag: int) -> bool:
    return tag in PLAIN_FOR_CIPHERED or tag in (
        Tag.GENERAL_GLO_CIPHERING,
        Tag.GENERAL_DED_CIPHERING,
        Tag.GENERAL_CIPHERING,
    )


def tag_name(tag: int) -> str:
    try:
        return Tag(tag).name
    except ValueError:
        return f"0x{tag:02X}"
