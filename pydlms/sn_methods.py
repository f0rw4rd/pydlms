"""Short-Name method addressing (IEC 62056-6-2, SN referencing of methods).

For SN referencing a method ``m`` of an object at ``base_name`` lives at
``base_name + first_offset + 8 * (m - 1)``, where ``first_offset`` is fixed per
interface class (it skips the attribute addresses).

Evidence: every offset below agrees with an independent implementation's
table (Gurux.DLMS Java ``GXDLMS.getActionInfo``, GPL-2, consulted as a
behavioural reference only - facts, not code). The pydlms entries for
Register, Extended/Demand register, Register activation, Profile generic,
Clock, Script table, Special days, Association SN, Image transfer, Activity
calendar, Disconnect control and Security setup were written independently
first and matched; Association LN, IPv4 setup, Register table, SAP
assignment, Push setup and NTP setup come from that reference. Association SN
method 8 (0xFA58) is additionally exercised end to end. Classes without an
entry (Schedule, Data, ...) raise rather than guess.

The offset follows the attribute count, which depends on the class version
(:data:`VERSION_OFFSETS`): Security setup v0 has 5 attributes (methods from
0x28), v1 6 (0x30); M-Bus client v0 starts at 0x60, v1 at 0x70. Source: jDLMS
1.8.0 ``SnInterfaceClassList`` (behavioural reference); M-Bus client v0 0x60
with 8 methods also appears in Gurux.DLMS.Net ``GetActionInfo`` and
GuruxDLMS.c (filed there under M-Bus slave port setup, which has no methods).
Not added for want of agreeing sources: Schedule (jDLMS 0x20, GuruxDLMS.c
none), Parameter monitor and Sensor manager (jDLMS only), M-Bus diagnostic
(GuruxDLMS.c 0x30, which collides with its attribute 7).
"""

from __future__ import annotations

from pydlms.cosem.interface_classes import ClassId

__all__ = ["METHOD_OFFSETS", "VERSION_OFFSETS", "method_address", "method_offset"]

#: class_id -> offset of method 1 from the object's base name.
METHOD_OFFSETS: dict[int, int] = {
    ClassId.REGISTER: 0x28,
    ClassId.EXTENDED_REGISTER: 0x38,
    ClassId.DEMAND_REGISTER: 0x48,
    ClassId.REGISTER_ACTIVATION: 0x30,
    ClassId.PROFILE_GENERIC: 0x58,
    ClassId.CLOCK: 0x60,
    ClassId.SCRIPT_TABLE: 0x20,
    ClassId.SPECIAL_DAYS_TABLE: 0x10,
    ClassId.ASSOCIATION_SN: 0x20,
    ClassId.ASSOCIATION_LN: 0x60,
    ClassId.SAP_ASSIGNMENT: 0x20,
    ClassId.IMAGE_TRANSFER: 0x40,
    ClassId.ACTIVITY_CALENDAR: 0x50,
    ClassId.PUSH_SETUP: 0x38,
    ClassId.IPV4_SETUP: 0x60,
    ClassId.REGISTER_TABLE: 0x28,
    ClassId.SECURITY_SETUP: 0x30,
    ClassId.DISCONNECT_CONTROL: 0x20,
    ClassId.NTP_SETUP: 0x38,
    ClassId.MBUS_CLIENT: 0x70,
}

#: class_id -> {version: offset} where the offset depends on the version.
#: A version above the highest listed uses the highest; see the module doc.
VERSION_OFFSETS: dict[int, dict[int, int]] = {
    ClassId.SECURITY_SETUP: {0: 0x28, 1: 0x30},
    ClassId.MBUS_CLIENT: {0: 0x60, 1: 0x70},
}


def method_offset(class_id: int, version: int | None = None) -> int | None:
    """Offset of method 1 from the base name; None when not known.

    Without ``version`` the newest known class version is assumed.
    """
    by_version = VERSION_OFFSETS.get(int(class_id))
    if by_version is not None and version is not None:
        known = [v for v in by_version if v <= version]
        if known:
            return by_version[max(known)]
    return METHOD_OFFSETS.get(int(class_id))


def method_address(base_name: int, class_id: int, method: int, version: int | None = None) -> int:
    """Short name of ``method`` of the object at ``base_name``."""
    offset = method_offset(class_id, version)
    if offset is None:
        raise NotImplementedError(f"SN method offset for class {class_id} is not known")
    return (base_name + offset + 8 * (method - 1)) & 0xFFFF
