"""IS 15959 (India): associations, event codes and the event status word.

Sources (Bureau of Indian Standards, public copies on archive.org and
law.resource.org; editions pinned):

* Part 1, IS 15959:2011 (static energy meters) with Amendments 1 (2014),
  2 (2015), 3 (2016), 4 (2017) and 5 (2021);
* Part 2, IS 15959 (Part 2):2016 (smart meters) with Amendments 1 and 2
  (2017);
* Part 3, IS 15959 (Part 3):2017 (transformer-operated smart meters).

Second reading: cB-Sigma dlms ``is15959/`` (Apache-2.0), which agrees on
every value here except the Part 1 security setup objects (it predates
Part 1 Amendment 5). Descriptions are ours, not the standard's wording.

Associations (:data:`ASSOCIATIONS`, also registered as presets): Part 1
Table 3 and Part 2 Table 2 as amended. The standard asks for HLS with
AES-128 challenge processing but never names a mechanism id, so the HLS
presets have ``mechanism=None`` with ``default_mechanism`` HLS (2,
AES-128-ECB of the challenge with the HLS secret): the Renesas IS 15959-2
reference meter configures utility settings and firmware upgrade with
mechanism 2 and AES (RelySys/3-Phase-Smart-Meter@0cd9daf
``AssociationConfiguration.xml``, ``r_dlms_class15.c``), and gosem's L&T
and AEW utility-settings examples use mechanism 2 with a 16-octet secret
(waseeldev/gosem@53a1580, MIT). Firmware upgrade has the Renesas source
only. A caller may still pass another HLS mechanism (5 for meters that use
GMAC).

Event codes (:data:`EVENTS`): the value of the event code objects
``0.0.96.11.e.255`` and of the event logs ``0.0.99.98.e.255``, where ``e``
is the :class:`EventCategory` (Part 1 Tables 9 and 11). Codes 168 and 170,
which some implementations use, are in no part as read and are not listed.

Event status word (:data:`ESW_BITS`, :func:`decode_esw`): Part 2 6.1.5
Table 10 as amended by Amendment 1. The bit numbers are the A-XDR
bit-string index (bit 0 is the most significant bit of the first octet).
The standard does not say so explicitly; the Renesas IS 15959-2 reference
meter firmware sets bit n as octet n // 8, mask 0x80 >> n % 8, and serves
those octets (RelySys/3-Phase-Smart-Meter@0cd9daf ``r_dlms_event.c``),
and cB-Sigma reads it the same way. No capture.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from pydlms.cosem.data import DlmsData
from pydlms.cosem.enums import DataType
from pydlms.exceptions import DecodeError
from pydlms.profiles.presets import AssociationPreset, register_preset
from pydlms.security.hls import Mechanism
from pydlms.security.suites import SecurityPolicy

__all__ = [
    "ASSOCIATIONS",
    "EVENTS",
    "ESW_BITS",
    "ESW_OBIS",
    "ESWF_OBIS",
    "ESW_LENGTH",
    "EventCategory",
    "IndiaEvent",
    "EswBit",
    "event",
    "decode_esw",
]

_P1 = "IS 15959:2011 (Part 1)"
_P2 = "IS 15959 (Part 2):2016"

# -- associations -------------------------------------------------------------


def _association(name, sap, mechanism, ciphered, e, setup_e=None, policy=None, **kw):
    return register_preset(
        AssociationPreset(
            name=name,
            client_sap=sap,
            mechanism=mechanism,
            ciphered=ciphered,
            association_obis=f"0.0.40.0.{e}.255",
            security_setup_obis=None if setup_e is None else f"0.0.43.0.{setup_e}.255",
            security_policy=policy,
            security_suite=None if not ciphered else 0,
            **kw,
        )
    )


_ENC = SecurityPolicy.ENCRYPTED
_AUTH_ENC = SecurityPolicy.AUTHENTICATED_ENCRYPTED

#: ``name -> preset``. ``is15959-pc/-mr/-us``: Part 1 basic security profile
#: (no ciphering). ``is15959-sm-*``: Part 2 smart meters (always ciphered
#: except the public client, suite 0). Security setup E values per Part 1
#: Amendment 5 and Part 2 Table 2.
ASSOCIATIONS: dict[str, AssociationPreset] = {
    p.name: p
    for p in (
        _association(
            "is15959-pc",
            16,
            Mechanism.NONE,
            False,
            1,
            description="IS 15959 public client: lowest level security",
            source=f"{_P1} 5.2.5 Table 3; Amd 1 (Table 2)",
        ),
        _association(
            "is15959-mr",
            32,
            Mechanism.LLS,
            False,
            2,
            description="IS 15959 meter reader, basic security profile: LLS, no ciphering",
            source=f"{_P1} 5.2.5 Table 3, 7.5.1.2",
        ),
        _association(
            "is15959-us",
            48,
            None,
            False,
            3,
            default_mechanism=Mechanism.HLS,
            description="IS 15959 utility settings, basic security profile: HLS (AES-128)",
            source=f"{_P1} 5.2.5 Table 3, 7.5.1.3 (AES-128 challenge processing: mechanism 2)",
        ),
        _association(
            "is15959-sm-mr",
            32,
            Mechanism.LLS,
            True,
            2,
            2,
            _ENC,
            description="IS 15959-2 meter reader: LLS, encrypted, suite 0",
            source=f"{_P2} Table 2, 7.2; Amd 1",
        ),
        _association(
            "is15959-sm-us",
            48,
            None,
            True,
            3,
            3,
            _AUTH_ENC,
            default_mechanism=Mechanism.HLS,
            description="IS 15959-2 utility settings: HLS, authenticated and encrypted",
            source=f"{_P2} Table 2, 7.2; Amd 1; HLS 2: Renesas reference meter, gosem L&T/AEW",
        ),
        _association(
            "is15959-sm-push",
            64,
            None,
            True,
            4,
            4,
            _ENC,
            pre_established=True,
            description="IS 15959-2 push destination (pre-established), encrypted",
            source=f"{_P2} Table 2, 6; Amd 1, Amd 2",
        ),
        _association(
            "is15959-sm-fw",
            80,
            None,
            True,
            5,
            5,
            _AUTH_ENC,
            default_mechanism=Mechanism.HLS,
            description="IS 15959-2 firmware upgrade: HLS, authenticated and encrypted",
            source=f"{_P2} Table 2, 9; Amd 1; HLS 2: Renesas reference meter (single source)",
        ),
        _association(
            "is15959-sm-ihd",
            96,
            None,
            True,
            6,
            6,
            _ENC,
            pre_established=True,
            description="IS 15959-2 in-home display (pre-established), encrypted",
            source=f"{_P2} Table 2, 5; Amd 1, Amd 2",
        ),
    )
}

# -- event codes --------------------------------------------------------------


class EventCategory(IntEnum):
    """Event compartments; the value is the E group of the code object and
    the event log (Part 1 Tables 9 and 11)."""

    VOLTAGE = 0
    CURRENT = 1
    POWER = 2
    TRANSACTION = 3
    OTHER = 4
    NON_ROLLOVER = 5
    CONTROL = 6

    @property
    def code_obis(self) -> str:
        return f"0.0.96.11.{int(self)}.255"

    @property
    def log_obis(self) -> str:
        return f"0.0.99.98.{int(self)}.255"


@dataclass(frozen=True)
class IndiaEvent:
    code: int
    category: EventCategory
    description: str
    #: ``"occurrence"``, ``"restoration"`` or ``"single"``.
    kind: str
    source: str


def _pair(events, code, category, condition, source):
    events.append(IndiaEvent(code, category, condition, "occurrence", source))
    events.append(IndiaEvent(code + 1, category, f"{condition} cleared", "restoration", source))


def _single(events, code, category, description, source):
    events.append(IndiaEvent(code, category, description, "single", source))


def _build_events() -> dict[int, IndiaEvent]:
    out: list[IndiaEvent] = []
    v, c, p = EventCategory.VOLTAGE, EventCategory.CURRENT, EventCategory.POWER
    t, o = EventCategory.TRANSACTION, EventCategory.OTHER
    t32, t33 = f"{_P1} Table 32", f"{_P1} Table 33"
    for code, text in (
        (1, "R-phase voltage missing"),
        (3, "Y-phase voltage missing"),
        (5, "B-phase voltage missing"),
        (7, "over-voltage in any phase"),
        (9, "low voltage in any phase"),
        (11, "voltage unbalance"),
    ):
        _pair(out, code, v, text, t32)
    for code, text in (
        (51, "R-phase current reversed"),
        (53, "Y-phase current reversed"),
        (55, "B-phase current reversed"),
        (57, "R-phase CT open"),
        (59, "Y-phase CT open"),
        (61, "B-phase CT open"),
        (63, "current unbalance"),
        (65, "current bypass"),
        (67, "over-current in any phase"),
    ):
        _pair(out, code, c, text, t33)
    _pair(out, 69, c, "earth loading", f"{_P1} Amd 2 Table 49; {_P2} Table A5")
    _pair(out, 101, p, "power failure", f"{_P1} Table 34")
    for code, text, source in (
        (151, "real-time clock changed", f"{_P1} Table 35"),
        (152, "demand integration period changed", f"{_P1} Table 35"),
        (153, "profile capture period changed", f"{_P1} Table 35"),
        (154, "billing dates (single-action schedule) changed", f"{_P1} Table 35"),
        (155, "activity calendar changed", f"{_P1} Table 35"),
        (156, "RS-485 device address changed", f"{_P1} Amd 1 Table 35"),
        (157, "new firmware activated", f"{_P2} Table A7"),
        (158, "load limit (kW) set", f"{_P2} Table A7"),
        (159, "load limit function enabled", f"{_P2} Table A7"),
        (160, "load limit function disabled", f"{_P2} Table A7"),
        (161, "meter reader LLS secret changed", f"{_P2} Amd 1 Table A7"),
        (162, "utility settings HLS key changed", f"{_P2} Amd 1 Table A7"),
        (163, "firmware upgrade HLS key changed", f"{_P2} Amd 1 Table A7"),
        (164, "global key changed", f"{_P2} Amd 1 Table A7"),
        (165, "ESW filter changed", f"{_P2} Amd 1 Table A7"),
        (166, "maximum demand reset", f"{_P2} Amd 1 Table A7"),
        (167, "metering mode changed", "IS 15959 (Part 3):2017 Table 8"),
        (169, "image activation schedule changed", "IS 15959 (Part 3):2017 Table 8"),
        (177, "changed to forwarded-only metering", "IS 15959 (Part 3):2017 Table 8"),
        (178, "changed to import-export metering", "IS 15959 (Part 3):2017 Table 8"),
    ):
        _single(out, code, t, text, source)
    _pair(out, 201, o, "magnetic influence", f"{_P1} Table 36")
    _pair(out, 203, o, "neutral disturbance", f"{_P1} Table 36; Amd 1")
    _pair(out, 205, o, "very low power factor", f"{_P1} Table 36")
    _pair(out, 207, o, "single-wire operation (neutral missing)", f"{_P1} Amd 2 Table 52")
    _pair(out, 209, o, "communication module removed", f"{_P2} Amd 1 Table A8")
    for code, text in (
        (211, "changed to post-paid mode"),
        (212, "changed to pre-paid mode"),
        (213, "changed to forwarded-only metering"),
        (214, "changed to import-export metering"),
    ):
        _single(out, code, o, text, f"{_P2} Amd 1 Table A8")
    _pair(out, 215, o, "overload", f"{_P2} Amd 1 Table A8")
    _single(out, 251, EventCategory.NON_ROLLOVER, "meter cover opened", f"{_P1} Table 37")
    _single(out, 301, EventCategory.CONTROL, "load disconnected", f"{_P1} Table 38")
    _single(out, 302, EventCategory.CONTROL, "load connected", f"{_P1} Table 38")
    return {e.code: e for e in out}


#: ``code -> IndiaEvent`` for every code Parts 1 to 3 define (as amended).
EVENTS: dict[int, IndiaEvent] = _build_events()


def event(code: int) -> IndiaEvent | None:
    """The event an event code object or event log entry holds, if defined."""
    return EVENTS.get(int(code))


# -- event status word --------------------------------------------------------

#: ESW 1 (class 1, attribute 2, bit-string of 128 bits): Part 2 Table 9.
ESW_OBIS = "0.0.94.91.18.255"
#: ESW filter, same layout; 1 = event supported for push: Part 2 Amd 1.
ESWF_OBIS = "0.0.94.91.26.255"
ESW_LENGTH = 128


@dataclass(frozen=True)
class EswBit:
    bit: int
    description: str
    #: Event codes the bit stands for (occurrence, restoration); empty for
    #: bits 85 to 87, which have no event code, and for unassigned bits.
    events: tuple[int, ...]
    #: ``"3-phase"``, ``"1-phase"``, ``"common"`` or ``"unassigned"``.
    meters: str


def _esw_bits() -> dict[int, EswBit]:
    bits = [
        (0, (1, 2), "3-phase"),
        (1, (3, 4), "3-phase"),
        (2, (5, 6), "3-phase"),
        (3, (7, 8), "common"),  # moved to common by Part 2 Amd 1
        (4, (9, 10), "common"),
        (5, (11, 12), "3-phase"),
        (6, (51, 52), "3-phase"),
        (7, (53, 54), "3-phase"),
        (8, (55, 56), "3-phase"),
        (9, (63, 64), "3-phase"),
        (10, (65, 66), "3-phase"),
        (11, (67, 68), "common"),
        (12, (205, 206), "3-phase"),
        (51, (69, 70), "1-phase"),
        (81, (201, 202), "common"),
        (82, (203, 204), "common"),
        (83, (251,), "common"),
        (84, (301, 302), "common"),
    ]
    out = {
        bit: EswBit(bit, EVENTS[codes[0]].description, codes, meters) for bit, codes, meters in bits
    }
    out[84] = EswBit(84, "load switch changed (disconnected or connected)", (301, 302), "common")
    out[85] = EswBit(85, "last gasp (supply lost)", (), "common")
    out[86] = EswBit(86, "first breath (supply back)", (), "common")
    out[87] = EswBit(87, "billing counter incremented (manual or MRI reset)", (), "common")
    return out


#: ``bit -> EswBit``: Part 2 Table 10 as amended by Amendment 1.
ESW_BITS: dict[int, EswBit] = _esw_bits()


def _esw_flags(value: DlmsData | bytes | bytearray | list[bool]) -> list[bool]:
    if isinstance(value, DlmsData):
        if value.tag != DataType.BIT_STRING:
            raise DecodeError(f"ESW must be a bit-string, got {value.tag.name}")
        return list(value.value)
    if isinstance(value, (bytes, bytearray)):
        return [bool(value[i // 8] & (0x80 >> (i % 8))) for i in range(len(value) * 8)]
    return [bool(b) for b in value]


def decode_esw(value: DlmsData | bytes | bytearray | list[bool]) -> list[EswBit]:
    """The bits set in an event status word (or its filter), lowest first.

    ``value`` is the decoded bit-string, its 16 raw octets or a list of
    flags. A word that is not 128 bits long raises :class:`DecodeError`. A
    set bit the standard leaves unused is returned as ``"unassigned"``
    rather than dropped (the standard says such bits stay 0).
    """
    flags = _esw_flags(value)
    if len(flags) != ESW_LENGTH:
        raise DecodeError(f"ESW is {ESW_LENGTH} bits, got {len(flags)}")
    return [
        ESW_BITS.get(bit) or EswBit(bit, f"unassigned bit {bit}", (), "unassigned")
        for bit, flag in enumerate(flags)
        if flag
    ]
