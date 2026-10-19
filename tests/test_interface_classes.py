"""Tests for the interface-class registry."""

from __future__ import annotations

import pytest

from pydlms.cosem.interface_classes import (
    REGISTRY,
    ClassId,
    attribute_index,
    attribute_name,
    lookup,
)


def test_register_attributes():
    assert attribute_name(ClassId.REGISTER, 1) == "logical_name"
    assert attribute_name(ClassId.REGISTER, 2) == "value"
    assert attribute_name(ClassId.REGISTER, 3) == "scaler_unit"
    assert attribute_index(ClassId.REGISTER, "scaler_unit") == 3


def test_profile_generic_and_clock():
    assert attribute_index(ClassId.PROFILE_GENERIC, "buffer") == 2
    assert attribute_index(ClassId.PROFILE_GENERIC, "capture_objects") == 3
    assert attribute_index(ClassId.CLOCK, "time") == 2


def test_association_ln_hls_method():
    ic = lookup(ClassId.ASSOCIATION_LN)
    assert ic is not None
    assert ic.method_index("reply_to_hls_authentication") == 1
    assert ic.attribute_index("object_list") == 2


def test_sap_assignment_connect_logical_device_is_method_1():
    # Gurux .NET GXDLMSSapAssignment.Invoke (index 1) and Wireshark
    # packet-cosem.c (commit fa5863c1, 1-based table with one method) agree;
    # jDLMS (and OSGP, which copies it) uses 3 - the outlier.
    ic = lookup(ClassId.SAP_ASSIGNMENT)
    assert ic is not None
    assert ic.method_index("connect_logical_device") == 1
    assert len(ic.methods) == 1


def test_security_setup_key_transfer_method():
    ic = lookup(ClassId.SECURITY_SETUP)
    assert ic.method_index("key_transfer") == 2
    assert ic.method_index("security_activate") == 1


def test_version_fallback():
    # Profile generic is registered as v1; v0 falls back to the lowest known.
    assert lookup(ClassId.PROFILE_GENERIC, 5).version == 1
    assert lookup(ClassId.PROFILE_GENERIC, 0).version == 1


def test_unknown_class_and_index():
    assert lookup(9999) is None
    assert attribute_name(9999, 1) == "logical_name"
    assert attribute_name(9999, 7) == "attribute_7"
    assert attribute_name(ClassId.DATA, 9) == "attribute_9"
    with pytest.raises(KeyError):
        attribute_index(ClassId.DATA, "nope")
    with pytest.raises(KeyError):
        attribute_index(9999, "value")


def test_every_class_starts_with_logical_name():
    for ic in REGISTRY.values():
        assert ic.attributes[0] == "logical_name"
        assert len(set(ic.attributes)) == len(ic.attributes)


@pytest.mark.parametrize(
    ("class_id", "version", "attributes", "methods"),
    [
        (ClassId.ASSOCIATION_LN, 0, 8, 4),
        (ClassId.ASSOCIATION_LN, 1, 9, 4),
        (ClassId.ASSOCIATION_LN, 2, 11, 6),
        (ClassId.ASSOCIATION_LN, 3, 11, 6),
        (ClassId.SECURITY_SETUP, 0, 5, 2),
        (ClassId.SECURITY_SETUP, 1, 6, 8),
    ],
)
def test_lookup_never_describes_a_higher_version(class_id, version, attributes, methods):
    ic = lookup(class_id, version)
    assert ic.version <= version and not ic.approximate
    assert (len(ic.attributes), len(ic.methods)) == (attributes, methods)
    assert ic.attribute_count == attributes


def test_lookup_below_the_known_versions_is_marked_approximate():
    ic = lookup(ClassId.PROFILE_GENERIC, 0)
    assert ic.approximate and ic.attribute_count is None
    assert ic.attribute_name(2) == "buffer"  # names still label the shared attributes
    assert not lookup(ClassId.PROFILE_GENERIC, 1).approximate
    assert not lookup(ClassId.PROFILE_GENERIC).approximate


# --- data protection, G3-PLC and PRIME layouts -------------------------------------------
#
# Sources: Gurux.DLMS.Net Development/Objects GXDLMS*.cs GetAttributeCount /
# GetMethodCount (version dependent for classes 91 and 92) and the Gurux C
# library gxobjects.c obj_attributeCount / obj_methodCount, which agree on
# every count below (the two are one vendor's ports, not independent). Class
# 30 is additionally confirmed by Wireshark packet-cosem.c (5 attributes and
# 3 methods, same names and order). Every other row is single source:
# unverified against the Blue Book. Counts include logical_name.
@pytest.mark.parametrize(
    ("class_id", "version", "attributes", "methods"),
    [
        (ClassId.DATA_PROTECTION, 0, 6, 3),
        (ClassId.PRIME_PHY_COUNTERS, 0, 5, 1),
        (ClassId.PRIME_MAC_SETUP, 0, 8, 0),
        (ClassId.PRIME_MAC_FUNCTIONAL_PARAMETERS, 0, 14, 0),
        (ClassId.PRIME_MAC_COUNTERS, 0, 7, 1),
        (ClassId.PRIME_MAC_NETWORK_ADMINISTRATION, 0, 6, 1),
        (ClassId.G3_MAC_COUNTERS, 1, 10, 1),
        (ClassId.G3_MAC_SETUP, 3, 26, 2),
        (ClassId.G3_6LOWPAN_SETUP, 0, 16, 0),
        (ClassId.G3_6LOWPAN_SETUP, 1, 19, 0),
        (ClassId.G3_6LOWPAN_SETUP, 2, 21, 0),
        (ClassId.G3_6LOWPAN_SETUP, 3, 23, 0),
    ],
)
def test_plc_and_protection_counts(class_id, version, attributes, methods):
    ic = lookup(class_id, version)
    assert ic.version == version and not ic.approximate
    assert (len(ic.attributes), len(ic.methods)) == (attributes, methods)
    # asking for a newer version than registered never claims that version
    assert lookup(class_id, version + 5).version <= version + 5


@pytest.mark.parametrize(
    ("class_id", "lowest"),
    [
        (ClassId.G3_MAC_COUNTERS, 1),
        (ClassId.G3_MAC_SETUP, 3),
    ],
)
def test_plc_versions_below_the_cited_one_are_approximate(class_id, lowest):
    ic = lookup(class_id, lowest - 1)
    assert ic.approximate and ic.attribute_count is None
    assert ic.version == lowest  # names label shared attributes; count unknown
    assert not lookup(class_id, lowest).approximate


def test_g3_6lowpan_versions_append_attributes():
    names = {v: lookup(ClassId.G3_6LOWPAN_SETUP, v).attributes for v in range(4)}
    for lower, higher in ((0, 1), (1, 2), (2, 3)):
        assert names[higher][: len(names[lower])] == names[lower]
    assert names[1][16:] == ("coord_short_address", "disable_default_routing", "device_type")


def test_class_86_is_prime_application_identification():
    # DLMS UA Blue Book Ed. 13 excerpt 4.12.10/4.12.11 (p. 101) and Ed. 17
    # Part 2 excerpt contents: the PRIME MAC address setup is class 43, class
    # 86 is "PRIME NB OFDM PLC Application identification". No layout is in
    # the excerpts, so none is registered.
    assert ClassId(86) is ClassId.PRIME_APPLICATION_IDENTIFICATION
    assert ClassId(86).name == "PRIME_APPLICATION_IDENTIFICATION"
    assert not hasattr(ClassId, "PRIME_MAC_ADDRESS_SETUP")
    assert ClassId.MAC_ADDRESS_SETUP == 43
    assert lookup(86) is None


def test_class_66_is_measurement_data_monitoring():
    # Blue Book Ed. 17 Part 2 excerpt contents, 4.3.11 (class_id = 66, version 0).
    assert ClassId(66) is ClassId.MEASUREMENT_DATA_MONITORING


@pytest.mark.parametrize(
    "class_id",
    [50, 51, 52, 53, 55, 56, 57, 58, 59, 66, 101, 102, 103, 104, 105],
)
def test_names_only_classes_have_no_layout(class_id):
    assert lookup(class_id) is None
    assert attribute_name(class_id, 2) == "attribute_2"
