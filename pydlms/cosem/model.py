"""Typed interface-class model: attribute and method-parameter shapes.

:mod:`pydlms.cosem.interface_classes` names attributes and methods;
this module adds their **types** (see :mod:`pydlms.cosem.types`), so complex
attributes decode into nested dataclasses and method parameters are built
and validated from Python values::

    spec = SPECS[ClassId.CLOCK]
    spec.method("shift_time").params.encode(-30)   # long, seconds
    spec.attribute("time").decode(raw)             # -> CosemDateTime

Shapes are hand-authored from the Blue Book class descriptions (IEC
62056-6-2 clause 4.x); attribute/method names are cross-checked against the
registry by ``tests/test_model.py``. Attributes whose type is a CHOICE or
vendor-dependent are ``Any`` (the raw :class:`DlmsData`).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from pydlms.cosem import types as T
from pydlms.cosem.access import AccessRights, AttributeAccess, MethodAccess
from pydlms.cosem.data import DlmsData
from pydlms.cosem.enums import Unit
from pydlms.cosem.interface_classes import ClassId, lookup
from pydlms.cosem.time import CosemDate, CosemDateTime, CosemTime
from pydlms.obis import ObisCode

__all__ = [
    "AttributeSpec",
    "MethodSpec",
    "ClassSpec",
    "SPECS",
    "spec_for",
    # structures
    "ScalerUnit",
    "CaptureObject",
    "ObjectListElement",
    "AccessRights",
    "AttributeAccess",
    "MethodAccess",
    "ScriptAction",
    "Script",
    "SpecialDay",
    "ScheduleEntry",
    "SeasonProfile",
    "WeekProfile",
    "DayProfileAction",
    "DayProfile",
    "ExecutionTime",
    "ScriptReference",
    "ImageToActivate",
    "ImageTransferInitiate",
    "ImageBlock",
    "SendDestination",
    "WindowSlot",
    "KeyData",
    "CertificateInfo",
    "ValueDefinition",
    "MonitorActions",
    "EmergencyProfile",
    "LimiterActions",
    "RegisterAssignment",
    "MaskEntry",
    "SapEntry",
    "AssociatedPartners",
    "XdlmsContextInfo",
    "PresetAdjustingTime",
    "UserEntry",
    "MbusCaptureDefinition",
    "MbusDataSend",
    "NtpKey",
]


# --- enumerations used by attributes ----------------------------------------------------


class ClockBase(enum.IntEnum):
    NOT_DEFINED = 0
    INTERNAL_CRYSTAL = 1
    MAINS_50HZ = 2
    MAINS_60HZ = 3
    GPS = 4
    RADIO_CONTROLLED = 5


class SortMethod(enum.IntEnum):
    FIFO = 1
    LIFO = 2
    LARGEST = 3
    SMALLEST = 4
    NEAREST_TO_ZERO = 5
    FAREST_FROM_ZERO = 6


class ControlState(enum.IntEnum):
    DISCONNECTED = 0
    CONNECTED = 1
    READY_FOR_RECONNECTION = 2


class AssociationStatus(enum.IntEnum):
    NON_ASSOCIATED = 0
    ASSOCIATION_PENDING = 1
    ASSOCIATED = 2


class ImageTransferStatus(enum.IntEnum):
    NOT_INITIATED = 0
    INITIATED = 1
    VERIFICATION_INITIATED = 2
    VERIFICATION_SUCCESSFUL = 3
    VERIFICATION_FAILED = 4
    ACTIVATION_INITIATED = 5
    ACTIVATION_SUCCESSFUL = 6
    ACTIVATION_FAILED = 7


class TransportService(enum.IntEnum):
    TCP = 0
    UDP = 1
    FTP = 2
    SMTP = 3
    SMS = 4
    HDLC = 5
    M_BUS = 6
    ZIGBEE = 7


class MessageType(enum.IntEnum):
    A_XDR = 0
    XML = 1


class SecuritySuiteId(enum.IntEnum):
    AES_GCM_128 = 0
    ECDH_ECDSA_AES_GCM_128_SHA256 = 1
    ECDH_ECDSA_AES_GCM_256_SHA384 = 2


class KeyType(enum.IntEnum):
    """Security setup ``generate_key_pair`` / certificate key usage."""

    DIGITAL_SIGNATURE = 0
    KEY_AGREEMENT = 1
    TLS = 2


class CommSpeed(enum.IntEnum):
    B300 = 0
    B600 = 1
    B1200 = 2
    B2400 = 3
    B4800 = 4
    B9600 = 5
    B19200 = 6
    B38400 = 7
    B57600 = 8
    B115200 = 9


# --- structures ----------------------------------------------------------------------------


@dataclass
class ScalerUnit:
    scaler: int
    unit: Unit | int


@dataclass
class CaptureObject:
    class_id: int
    logical_name: ObisCode
    attribute_index: int
    data_index: int = 0


@dataclass
class ObjectListElement:
    class_id: int
    version: int
    logical_name: ObisCode
    access_rights: DlmsData


@dataclass
class ScriptAction:
    service_id: int  # 1 write attribute, 2 execute method
    class_id: int
    logical_name: ObisCode
    index: int
    parameter: DlmsData


@dataclass
class Script:
    script_identifier: int
    actions: list[ScriptAction]


@dataclass
class SpecialDay:
    index: int
    date: CosemDate
    day_id: int


@dataclass
class ScheduleEntry:
    index: int
    enable: bool
    script_logical_name: ObisCode
    script_selector: int
    switch_time: CosemTime
    validity_window: int
    exec_weekdays: list[bool]
    exec_specdays: list[bool]
    begin_date: CosemDate
    end_date: CosemDate


@dataclass
class SeasonProfile:
    season_profile_name: bytes
    season_start: CosemDateTime
    week_name: bytes


@dataclass
class WeekProfile:
    week_profile_name: bytes
    monday: int
    tuesday: int
    wednesday: int
    thursday: int
    friday: int
    saturday: int
    sunday: int


@dataclass
class DayProfileAction:
    start_time: CosemTime
    script_logical_name: ObisCode
    script_selector: int


@dataclass
class DayProfile:
    day_id: int
    day_schedule: list[DayProfileAction]


@dataclass
class ExecutionTime:
    time: CosemTime
    date: CosemDate


@dataclass
class ScriptReference:
    script_logical_name: ObisCode
    script_selector: int


@dataclass
class ImageToActivate:
    image_to_activate_size: int
    image_to_activate_identification: bytes
    image_to_activate_signature: bytes


@dataclass
class ImageTransferInitiate:
    image_identifier: bytes
    image_size: int


@dataclass
class ImageBlock:
    image_block_number: int
    image_block_value: bytes


@dataclass
class SendDestination:
    transport_service: TransportService | int
    destination: bytes
    message: MessageType | int


@dataclass
class WindowSlot:
    start: CosemDateTime
    end: CosemDateTime


@dataclass
class KeyData:
    key_id: int
    key: bytes


@dataclass
class CertificateInfo:
    certificate_entity: int
    certificate_type: int
    serial_number: bytes
    issuer: bytes
    subject: bytes
    subject_alt_name: bytes


@dataclass
class ValueDefinition:
    class_id: int
    logical_name: ObisCode
    attribute_index: int


@dataclass
class MonitorActions:
    action_up: ScriptReference
    action_down: ScriptReference


@dataclass
class EmergencyProfile:
    emergency_profile_id: int
    emergency_activation_time: CosemDateTime
    emergency_duration: int


@dataclass
class LimiterActions:
    action_over_threshold: ScriptReference
    action_under_threshold: ScriptReference


@dataclass
class RegisterAssignment:
    class_id: int
    logical_name: ObisCode


@dataclass
class MaskEntry:
    mask_name: bytes
    index_list: list[int]


@dataclass
class SapEntry:
    sap: int
    logical_device_name: bytes


@dataclass
class AssociatedPartners:
    client_sap: int
    server_sap: int


@dataclass
class XdlmsContextInfo:
    conformance: list[bool]
    max_receive_pdu_size: int
    max_send_pdu_size: int
    dlms_version_number: int
    quality_of_service: int
    cyphering_info: bytes


@dataclass
class PresetAdjustingTime:
    preset_time: CosemDateTime
    validity_interval_start: CosemDateTime
    validity_interval_end: CosemDateTime


@dataclass
class UserEntry:
    user_id: int
    user_name: str


@dataclass
class MbusCaptureDefinition:
    data_information_block: bytes
    value_information_block: bytes


@dataclass
class MbusDataSend:
    data_information_block: bytes
    value_information_block: bytes
    data: DlmsData


@dataclass
class NtpKey:
    key_id: int
    key: bytes


# --- descriptors for the structures ------------------------------------------------------

SCALER_UNIT = T.Struct(ScalerUnit, [("scaler", T.I8), ("unit", T.Enum(Unit))])
CAPTURE_OBJECT = T.Struct(
    CaptureObject,
    [
        ("class_id", T.U16),
        ("logical_name", T.Obis()),
        ("attribute_index", T.I8),
        ("data_index", T.U16),
    ],
)
OBJECT_LIST_ELEMENT = T.Struct(
    ObjectListElement,
    [
        ("class_id", T.U16),
        ("version", T.U8),
        ("logical_name", T.Obis()),
        ("access_rights", T.Any()),
    ],
)
SCRIPT_REFERENCE = T.Struct(
    ScriptReference, [("script_logical_name", T.Obis()), ("script_selector", T.U16)]
)
SCRIPT = T.Struct(
    Script,
    [
        ("script_identifier", T.U16),
        (
            "actions",
            T.Array(
                T.Struct(
                    ScriptAction,
                    [
                        ("service_id", T.Enum()),
                        ("class_id", T.U16),
                        ("logical_name", T.Obis()),
                        ("index", T.I8),
                        ("parameter", T.Any()),
                    ],
                )
            ),
        ),
    ],
)
SPECIAL_DAY = T.Struct(SpecialDay, [("index", T.U16), ("date", T.Date()), ("day_id", T.U8)])
SCHEDULE_ENTRY = T.Struct(
    ScheduleEntry,
    [
        ("index", T.U16),
        ("enable", T.Boolean()),
        ("script_logical_name", T.Obis()),
        ("script_selector", T.U16),
        ("switch_time", T.Time()),
        ("validity_window", T.U16),
        ("exec_weekdays", T.BitString()),
        ("exec_specdays", T.BitString()),
        ("begin_date", T.Date()),
        ("end_date", T.Date()),
    ],
)
SEASON = T.Struct(
    SeasonProfile,
    [
        ("season_profile_name", T.OctetString()),
        ("season_start", T.DateTime()),
        ("week_name", T.OctetString()),
    ],
)
WEEK = T.Struct(
    WeekProfile,
    [("week_profile_name", T.OctetString())]
    + [
        (d, T.U8)
        for d in ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")
    ],
)
DAY = T.Struct(
    DayProfile,
    [
        ("day_id", T.U8),
        (
            "day_schedule",
            T.Array(
                T.Struct(
                    DayProfileAction,
                    [
                        ("start_time", T.Time()),
                        ("script_logical_name", T.Obis()),
                        ("script_selector", T.U16),
                    ],
                )
            ),
        ),
    ],
)
VALUE_DEFINITION = T.Struct(
    ValueDefinition, [("class_id", T.U16), ("logical_name", T.Obis()), ("attribute_index", T.I8)]
)
WINDOW = T.Struct(WindowSlot, [("start", T.DateTime()), ("end", T.DateTime())])
KEY_DATA = T.Struct(KeyData, [("key_id", T.Enum()), ("key", T.OctetString())])
NO_DATA = T.I8  # methods documented with "data ::= integer (0)"


# --- specs --------------------------------------------------------------------------------


@dataclass(frozen=True)
class AttributeSpec:
    index: int
    name: str
    type: T.Type


@dataclass(frozen=True)
class MethodSpec:
    index: int
    name: str
    params: T.Type | None  # None: the method takes no data (send null-data)
    returns: T.Type | None = None


@dataclass
class ClassSpec:
    class_id: int
    version: int
    name: str
    attributes: dict[str, AttributeSpec] = field(default_factory=dict)
    methods: dict[str, MethodSpec] = field(default_factory=dict)

    def attribute(self, name_or_index: str | int) -> AttributeSpec:
        if isinstance(name_or_index, int):
            for spec in self.attributes.values():
                if spec.index == name_or_index:
                    return spec
            return AttributeSpec(name_or_index, f"attribute_{name_or_index}", T.Any())
        try:
            return self.attributes[name_or_index]
        except KeyError:
            raise KeyError(f"{self.name} has no attribute {name_or_index!r}") from None

    def method(self, name_or_index: str | int) -> MethodSpec:
        if isinstance(name_or_index, int):
            for spec in self.methods.values():
                if spec.index == name_or_index:
                    return spec
            return MethodSpec(name_or_index, f"method_{name_or_index}", T.Any())
        try:
            return self.methods[name_or_index]
        except KeyError:
            raise KeyError(f"{self.name} has no method {name_or_index!r}") from None


SPECS: dict[int, ClassSpec] = {}


def _spec(
    class_id: ClassId,
    attrs: list[T.Type],
    methods: list[T.Type | None] = (),
    returns: dict[int, T.Type] | None = None,
) -> None:
    """Attach types, in registry order, to the registry's names."""
    ic = lookup(class_id)
    assert ic is not None, class_id
    if len(attrs) != len(ic.attributes) - 1:
        raise AssertionError(
            f"{ic.name}: {len(attrs)} attribute types for {len(ic.attributes) - 1} attributes"
        )
    if len(methods) != len(ic.methods):
        raise AssertionError(f"{ic.name}: {len(methods)} method types for {len(ic.methods)}")
    spec = ClassSpec(ic.class_id, ic.version, ic.name)
    spec.attributes["logical_name"] = AttributeSpec(1, "logical_name", T.Obis())
    for index, (name, kind) in enumerate(zip(ic.attributes[1:], attrs, strict=True), start=2):
        spec.attributes[name] = AttributeSpec(index, name, kind)
    for index, (name, kind) in enumerate(zip(ic.methods, methods, strict=True), start=1):
        spec.methods[name] = MethodSpec(index, name, kind, (returns or {}).get(index))
    SPECS[int(class_id)] = spec


A = T.Any()
C = ClassId

_spec(C.DATA, [A])
_spec(C.REGISTER, [A, SCALER_UNIT], [NO_DATA])
_spec(C.EXTENDED_REGISTER, [A, SCALER_UNIT, A, T.DateTime()], [NO_DATA])
_spec(
    C.DEMAND_REGISTER,
    [A, A, SCALER_UNIT, A, T.DateTime(), T.DateTime(), T.U32, T.U16],
    [NO_DATA, NO_DATA],
)
_spec(
    C.REGISTER_ACTIVATION,
    [
        T.Array(T.Struct(RegisterAssignment, [("class_id", T.U16), ("logical_name", T.Obis())])),
        T.Array(
            T.Struct(MaskEntry, [("mask_name", T.OctetString()), ("index_list", T.Array(T.U8))])
        ),
        T.OctetString(),
    ],
    [
        T.Struct(RegisterAssignment, [("class_id", T.U16), ("logical_name", T.Obis())]),
        T.Struct(MaskEntry, [("mask_name", T.OctetString()), ("index_list", T.Array(T.U8))]),
        T.OctetString(),
    ],
)
_spec(
    C.PROFILE_GENERIC,
    [T.Array(A), T.Array(CAPTURE_OBJECT), T.U32, T.Enum(SortMethod), CAPTURE_OBJECT, T.U32, T.U32],
    [NO_DATA, NO_DATA, A, A],
)
_spec(
    C.CLOCK,
    [T.DateTime(), T.I16, T.U8, T.DateTime(), T.DateTime(), T.I8, T.Boolean(), T.Enum(ClockBase)],
    [
        NO_DATA,
        NO_DATA,
        NO_DATA,
        NO_DATA,
        T.Struct(
            PresetAdjustingTime,
            [
                ("preset_time", T.DateTime()),
                ("validity_interval_start", T.DateTime()),
                ("validity_interval_end", T.DateTime()),
            ],
        ),
        T.I16,
    ],
)
_spec(C.SCRIPT_TABLE, [T.Array(SCRIPT)], [T.U16])
_spec(C.SCHEDULE, [T.Array(SCHEDULE_ENTRY)], [A, SCHEDULE_ENTRY, A])
_spec(C.SPECIAL_DAYS_TABLE, [T.Array(SPECIAL_DAY)], [SPECIAL_DAY, T.U16])
_spec(
    C.ASSOCIATION_SN,
    [T.Array(A), A, T.Obis(), A, A],
    [A, A, A, A, T.OctetString(), T.OctetString(), A, T.OctetString()],
    returns={8: T.OctetString()},
)
_spec(
    C.ASSOCIATION_LN,
    [
        T.Array(OBJECT_LIST_ELEMENT),
        T.Struct(AssociatedPartners, [("client_sap", T.I8), ("server_sap", T.U16)]),
        A,
        T.Struct(
            XdlmsContextInfo,
            [
                ("conformance", T.BitString()),
                ("max_receive_pdu_size", T.U16),
                ("max_send_pdu_size", T.U16),
                ("dlms_version_number", T.U8),
                ("quality_of_service", T.I8),
                ("cyphering_info", T.OctetString()),
            ],
        ),
        A,
        T.OctetString(),
        T.Enum(AssociationStatus),
        T.Obis(),
        A,
        A,
    ],
    [
        T.OctetString(),
        T.OctetString(),
        OBJECT_LIST_ELEMENT,
        OBJECT_LIST_ELEMENT,
        T.Struct(UserEntry, [("user_id", T.U8), ("user_name", T.Text())]),
        T.Struct(UserEntry, [("user_id", T.U8), ("user_name", T.Text())]),
    ],
    returns={1: T.OctetString()},
)
_spec(
    C.SAP_ASSIGNMENT,
    [T.Array(T.Struct(SapEntry, [("sap", T.U16), ("logical_device_name", T.OctetString())]))],
    [T.Struct(SapEntry, [("sap", T.U16), ("logical_device_name", T.OctetString())])],
)
_spec(
    C.IMAGE_TRANSFER,
    [
        T.U32,
        T.BitString(),
        T.U32,
        T.Boolean(),
        T.Enum(ImageTransferStatus),
        T.Array(
            T.Struct(
                ImageToActivate,
                [
                    ("image_to_activate_size", T.U32),
                    ("image_to_activate_identification", T.OctetString()),
                    ("image_to_activate_signature", T.OctetString()),
                ],
            )
        ),
    ],
    [
        T.Struct(
            ImageTransferInitiate, [("image_identifier", T.OctetString()), ("image_size", T.U32)]
        ),
        T.Struct(
            ImageBlock, [("image_block_number", T.U32), ("image_block_value", T.OctetString())]
        ),
        NO_DATA,
        NO_DATA,
    ],
)
_spec(
    C.IEC_LOCAL_PORT_SETUP,
    [
        T.Enum(),
        T.Enum(CommSpeed),
        T.Enum(CommSpeed),
        T.Enum(),
        T.OctetString(),
        T.OctetString(),
        T.OctetString(),
        T.OctetString(),
    ],
)
_spec(
    C.ACTIVITY_CALENDAR,
    [
        T.OctetString(),
        T.Array(SEASON),
        T.Array(WEEK),
        T.Array(DAY),
        T.OctetString(),
        T.Array(SEASON),
        T.Array(WEEK),
        T.Array(DAY),
        T.DateTime(),
    ],
    [NO_DATA],
)
_spec(
    C.REGISTER_MONITOR,
    [
        T.Array(A),
        VALUE_DEFINITION,
        T.Array(
            T.Struct(
                MonitorActions, [("action_up", SCRIPT_REFERENCE), ("action_down", SCRIPT_REFERENCE)]
            )
        ),
    ],
)
_spec(
    C.SINGLE_ACTION_SCHEDULE,
    [
        SCRIPT_REFERENCE,
        T.Enum(),
        T.Array(T.Struct(ExecutionTime, [("time", T.Time()), ("date", T.Date())])),
    ],
)
_spec(C.IEC_HDLC_SETUP, [T.Enum(CommSpeed), T.U8, T.U8, T.U16, T.U16, T.U16, T.U16, T.U16])
_spec(C.UTILITY_TABLES, [T.U16, T.U32, T.OctetString()])
_spec(C.AUTO_CONNECT, [T.Enum(), T.U8, T.U16, T.Array(WINDOW), T.Array(T.OctetString())], [NO_DATA])
_spec(
    C.PUSH_SETUP,
    [
        T.Array(CAPTURE_OBJECT),
        T.Struct(
            SendDestination,
            [
                ("transport_service", T.Enum(TransportService)),
                ("destination", T.OctetString()),
                ("message", T.Enum(MessageType)),
            ],
        ),
        T.Array(WINDOW),
        T.U16,
        T.U8,
        A,
        T.Obis(),
        T.I8,
        A,
        T.Enum(),
        A,
        T.DateTime(),
    ],
    [NO_DATA, NO_DATA],
)
_spec(C.TCP_UDP_SETUP, [T.U16, T.Obis(), T.U16, T.U8, T.U16])
_spec(
    C.IPV4_SETUP,
    [T.Obis(), T.U32, T.Array(T.U32), T.Array(A), T.U32, T.U32, T.Boolean(), T.U32, T.U32],
    [T.U32, T.U32, NO_DATA],
    returns={3: T.U16},
)
_spec(C.MAC_ADDRESS_SETUP, [T.OctetString()])
_spec(C.GPRS_MODEM_SETUP, [T.OctetString(), T.U16, A])
_spec(C.GSM_DIAGNOSTIC, [T.Text(), T.Enum(), T.Enum(), T.Enum(), A, T.Array(A), T.DateTime()])
_spec(C.REGISTER_TABLE, [T.Array(A), A, SCALER_UNIT], [NO_DATA, NO_DATA])
_spec(
    C.COMPACT_DATA,
    [T.OctetString(), T.Array(CAPTURE_OBJECT), T.U8, T.OctetString(), T.Enum()],
    [NO_DATA, NO_DATA],
)
_spec(C.STATUS_MAPPING, [A, A])
_spec(
    C.SECURITY_SETUP,
    [
        T.Enum(),
        T.Enum(SecuritySuiteId),
        T.OctetString(),
        T.OctetString(),
        T.Array(
            T.Struct(
                CertificateInfo,
                [
                    ("certificate_entity", T.Enum()),
                    ("certificate_type", T.Enum()),
                    ("serial_number", T.OctetString()),
                    ("issuer", T.OctetString()),
                    ("subject", T.OctetString()),
                    ("subject_alt_name", T.OctetString()),
                ],
            )
        ),
    ],
    [
        T.Enum(),
        T.Array(KEY_DATA),
        T.Array(KEY_DATA),
        T.Enum(KeyType),
        T.Enum(KeyType),
        T.OctetString(),
        A,
        A,
    ],
    returns={3: T.Array(KEY_DATA), 5: T.OctetString(), 7: T.OctetString()},
)
_spec(C.DISCONNECT_CONTROL, [T.Boolean(), T.Enum(ControlState), T.Enum()], [NO_DATA, NO_DATA])
_spec(
    C.LIMITER,
    [
        VALUE_DEFINITION,
        A,
        A,
        A,
        T.U32,
        T.U32,
        T.Struct(
            EmergencyProfile,
            [
                ("emergency_profile_id", T.U16),
                ("emergency_activation_time", T.DateTime()),
                ("emergency_duration", T.U32),
            ],
        ),
        T.Array(T.U16),
        T.Boolean(),
        T.Struct(
            LimiterActions,
            [
                ("action_over_threshold", SCRIPT_REFERENCE),
                ("action_under_threshold", SCRIPT_REFERENCE),
            ],
        ),
    ],
)
_spec(
    C.MBUS_CLIENT,
    [
        T.Obis(),
        T.Array(
            T.Struct(
                MbusCaptureDefinition,
                [
                    ("data_information_block", T.OctetString()),
                    ("value_information_block", T.OctetString()),
                ],
            )
        ),
        T.U32,
        T.U8,
        T.U32,
        T.U16,
        T.U8,
        T.U8,
        T.U8,
        T.U8,
        T.U8,
        T.U16,
        T.Enum(),
    ],
    [
        T.U8,
        NO_DATA,
        NO_DATA,
        NO_DATA,
        NO_DATA,
        T.Array(
            T.Struct(
                MbusDataSend,
                [
                    ("data_information_block", T.OctetString()),
                    ("value_information_block", T.OctetString()),
                    ("data", A),
                ],
            )
        ),
        T.OctetString(),
        T.OctetString(),
    ],
)
_spec(
    C.NTP_SETUP,
    [
        T.Boolean(),
        T.OctetString(),
        T.U16,
        T.Enum(),
        T.Array(T.Struct(NtpKey, [("key_id", T.U32), ("key", T.OctetString())])),
        T.OctetString(),
    ],
    [NO_DATA, T.Struct(NtpKey, [("key_id", T.U32), ("key", T.OctetString())]), T.U32],
)

# Classes whose names come from the Blue Book recollection (see the registry
# note); shapes are typed only where unambiguous, ``Any`` elsewhere.
_spec(C.MBUS_PORT_SETUP, [T.Enum(CommSpeed), T.Enum(CommSpeed), T.Enum(), T.U8])
_spec(C.MODEM_CONFIGURATION, [T.Enum(CommSpeed), T.Array(A), T.Array(T.OctetString())])
_spec(C.AUTO_ANSWER, [T.Enum(), T.Array(WINDOW), T.Enum(), T.U8, A, T.Array(A)])
_spec(C.PPP_SETUP, [T.Obis(), T.Array(A), T.Array(A), A])
_spec(C.SMTP_SETUP, [T.U16, T.OctetString(), T.OctetString(), T.OctetString(), T.OctetString()])
_spec(
    C.IPV6_SETUP,
    [
        T.Obis(),
        T.Enum(),
        T.Array(T.OctetString()),
        T.Array(T.OctetString()),
        T.Array(T.OctetString()),
        T.OctetString(),
        T.OctetString(),
        T.U8,
        A,
    ],
    [
        T.Struct(KeyData, [("key_id", T.Enum()), ("key", T.OctetString())]),
        T.Struct(KeyData, [("key_id", T.Enum()), ("key", T.OctetString())]),
    ],
)
_spec(
    C.ARBITRATOR,
    [
        T.Array(SCRIPT_REFERENCE),
        T.Array(T.BitString()),
        T.Array(T.Array(T.U16)),
        T.Array(T.BitString()),
        T.U8,
    ],
    [A, NO_DATA],
)
_spec(C.MBUS_MASTER_PORT_SETUP, [T.Enum(CommSpeed)])
_spec(
    C.MBUS_DIAGNOSTIC,
    [T.U8, T.U8, T.Enum(), T.Array(A), T.Array(A), T.Array(A), T.Array(A), A],
    [NO_DATA],
)
_spec(
    C.ACCOUNT,
    [
        A,
        T.U8,
        T.BitString(),
        T.I32,
        T.I32,
        T.I32,
        T.I32,
        T.Array(T.Obis()),
        T.Array(T.Obis()),
        T.BitString(),
        T.Obis(),
        T.DateTime(),
        T.DateTime(),
        A,
        T.I32,
        T.I32,
        T.U16,
        T.I32,
    ],
    [NO_DATA, NO_DATA, NO_DATA],
)
_spec(
    C.CREDIT,
    [T.I32, T.Enum(), T.U8, T.I32, T.I32, T.BitString(), T.Enum(), T.I32, T.I32, T.U32],
    [T.I32, T.I32, NO_DATA],
)
_spec(
    C.CHARGE,
    [
        T.I32,
        T.Enum(),
        T.U8,
        A,
        A,
        T.DateTime(),
        T.U32,
        T.BitString(),
        T.DateTime(),
        T.I32,
        T.I32,
        T.U16,
    ],
    [A, NO_DATA, NO_DATA, T.I32, T.I32],
)
_spec(
    C.TOKEN_GATEWAY,
    [T.OctetString(), T.DateTime(), T.Array(T.OctetString()), T.Enum(), A],
    [T.OctetString()],
)


# Data protection, PRIME and G3-PLC. Types come from Gurux.DLMS.Net
# GetDataType. Class 30 and the class 91 v2 / 92 v2 attribute types agree with
# DLMS UA 1000-1 Ed. 13 Excerpt 4.4.9.2 and 4.13.4/4.13.5; the PRIME classes
# and the later G3 versions are single source and unverified. A wrong scalar
# type raises DecodeError on a real meter, so attributes whose element shape
# is not sourced stay ``Any``.
_spec(
    C.DATA_PROTECTION,
    # buffer, object list (array), parameters get/set, required protection.
    # Ed. 13 Excerpt 4.4.9.2 gives parameters get/set as array (as Gurux);
    # they stay Any until their element layout is sourced.
    [T.OctetString(), T.Array(A), A, A, T.Enum()],
    [A, A, A],
)
_spec(C.PRIME_PHY_COUNTERS, [T.U16, T.U16, T.U16, T.U16], [NO_DATA])
_spec(C.PRIME_MAC_SETUP, [T.U8, T.U8, T.U8, T.U8, T.U8, T.U8, T.U8])
_spec(
    C.PRIME_MAC_FUNCTIONAL_PARAMETERS,
    # lnid and scp_length: Gurux long, Blue Book recollection long-unsigned
    [A, T.U8, T.U8, T.OctetString(), T.Enum(), A, T.U8, T.U8, T.U8, T.U8, T.U8, T.U8, T.U16],
)
_spec(C.PRIME_MAC_COUNTERS, [T.U32, T.U32, T.U32, T.U32, T.U32, T.U32], [NO_DATA])
_spec(
    C.PRIME_MAC_NETWORK_ADMINISTRATION,
    [T.Array(A), T.Array(A), T.Array(A), T.Array(A), T.Array(A)],
    [NO_DATA],
)
_spec(C.G3_MAC_COUNTERS, [T.U32] * 9, [NO_DATA])
_spec(
    C.G3_MAC_SETUP,
    [
        T.U16,  # mac_short_address
        T.U16,  # mac_rc_coord
        T.U16,  # mac_pan_id
        T.Array(A),  # mac_key_table: key material, kept raw
        T.U32,  # mac_frame_counter
        T.BitString(),  # mac_tone_mask
        T.U8,  # mac_tmr_ttl
        T.U8,  # mac_max_frame_retries
        T.U8,  # mac_neighbour_table_entry_ttl
        T.Array(A),  # mac_neighbour_table
        T.U8,  # mac_high_priority_window_size
        T.U8,  # mac_csma_fairness_limit
        T.U8,  # mac_beacon_randomization_window_length
        T.U8,  # mac_a
        T.U8,  # mac_k
        T.U8,  # mac_min_cw_attempts
        T.U8,  # mac_cenelec_legacy_mode
        T.U8,  # mac_fcc_legacy_mode
        T.U8,  # mac_max_be
        T.U8,  # mac_max_csma_backoffs
        T.U8,  # mac_min_be
        T.Boolean(),  # mac_broadcast_max_cw_enabled
        T.U8,  # mac_transmit_atten
        T.Array(A),  # mac_pos_table
        T.U8,  # mac_duplicate_detection_ttl
    ],
    [A, A],
)
_spec(
    C.G3_6LOWPAN_SETUP,
    [
        T.U8,  # max_hops
        T.U8,  # weak_lqi_value
        T.U8,  # security_level
        T.Array(A),  # prefix_table
        T.Array(A),  # routing_configuration
        T.U16,  # broadcast_log_table_entry_ttl
        T.Array(A),  # routing_table
        T.Array(A),  # context_information_table
        T.Array(A),  # blacklist_table
        T.Array(A),  # broadcast_log_table
        T.Array(A),  # group_table
        T.U16,  # max_join_wait_time
        T.U8,  # path_discovery_time
        T.U8,  # active_key_index
        T.U8,  # metric_type
        T.U16,  # coord_short_address (v1)
        T.Boolean(),  # disable_default_routing (v1)
        T.Enum(),  # device_type (v1)
        T.Boolean(),  # default_coord_route_enabled (v2)
        T.Array(A),  # destination_address (v2)
        T.U8,  # low_lqi (v3)
        T.U8,  # high_lqi (v3)
    ],
)


def spec_for(class_id: int) -> ClassSpec | None:
    """Typed spec of ``class_id`` (None when only names are known)."""
    return SPECS.get(int(class_id))
