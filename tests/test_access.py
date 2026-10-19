"""Association LN access rights (pydlms.cosem.access).

Known-good vectors: object lists frozen from two independent servers
(``tests/fixtures/object_lists/``, see the README there) plus hand-built
v0 and v3 entries whose layout is given next to each.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pydlms.cosem.access import (
    AccessMode3,
    AccessRights,
    AttributeAccess,
    AttributeAccessMode,
    MethodAccess,
    MethodAccessMode,
    MethodAccessMode3,
    decode_access_rights,
    infer_association_version,
)
from pydlms.cosem.data import DlmsData, decode_data, encode_data
from pydlms.exceptions import DecodeError

FIXTURES = Path(__file__).parent / "fixtures" / "object_lists"


def _view(name: str) -> list[DlmsData]:
    raw = bytes.fromhex((FIXTURES / name).read_text().strip())
    data, end = decode_data(raw)
    assert end == len(raw)
    return data.value


def _entry(view, obis: str) -> list[DlmsData]:
    want = bytes(int(x) for x in obis.split("."))
    return next(e.value for e in view if bytes(e.value[2].value) == want)


# --- hand-built vectors --------------------------------------------------------------
# v0: structure{ array{ {integer 1, enum 1 read_only, null-data} },
#                array{ {integer 1, boolean TRUE} } }
V0 = bytes.fromhex("0202 0101 0203 0f01 1601 00 0101 0202 0f01 0301")
# v3: attribute 2 mode 0x25 = read | authenticated_request | authenticated_response,
#     selectors {1, 2}; method 1 mode 0x09 = access | encrypted_request.
V3 = bytes.fromhex("0202 0101 0203 0f02 1625 0102 0f01 0f02 0101 0202 0f01 1609")


def test_v0_boolean_methods_known_vector():
    data, _ = decode_data(V0)
    assert infer_association_version(data) == 0
    rights = decode_access_rights(data)
    assert rights == AccessRights(
        (AttributeAccess(1, AttributeAccessMode.READ_ONLY, None),),
        (MethodAccess(1, True),),
        0,
    )
    assert rights.can_read(1) is True and rights.can_write(1) is False
    assert rights.can_execute(1) is True
    assert encode_data(rights.to_data()) == V0


def test_v3_bit_maps_known_vector():
    data, _ = decode_data(V3)
    assert infer_association_version(data) == 1  # never guesses 3
    rights = decode_access_rights(data, 3)
    attr = rights.attribute(2)
    assert attr.access_mode == (
        AccessMode3.READ | AccessMode3.AUTHENTICATED_REQUEST | AccessMode3.AUTHENTICATED_RESPONSE
    )
    assert attr.access_selectors == (1, 2)
    assert attr.readable is True and attr.writable is False
    assert rights.method(1).access_mode == (
        MethodAccessMode3.ACCESS | MethodAccessMode3.ENCRYPTED_REQUEST
    )
    assert rights.can_execute(1) is True
    assert encode_data(rights.to_data()) == V3
    # The same octets under v1 are a value v1 does not define: unknown, not denied.
    v1 = decode_access_rights(data, 1)
    assert v1.attribute(2).access_mode == 0x25 and v1.can_read(2) is None
    assert v1.method(1).access_mode == 9 and v1.can_execute(1) is None


def test_v3_write_without_read():
    rights = AccessRights((AttributeAccess(2, AccessMode3.WRITE),), (), 3)
    assert decode_access_rights(rights.to_data(), 3) == rights
    assert rights.can_read(2) is False and rights.can_write(2) is True
    assert MethodAccessMode3(0x02).executable is False  # bit 1 is unused for methods


@pytest.mark.parametrize(
    "mode,readable,writable",
    [
        (AttributeAccessMode.NO_ACCESS, False, False),
        (AttributeAccessMode.READ_ONLY, True, False),
        (AttributeAccessMode.WRITE_ONLY, False, True),
        (AttributeAccessMode.READ_AND_WRITE, True, True),
        (AttributeAccessMode.AUTHENTICATED_READ_ONLY, True, False),
        (AttributeAccessMode.AUTHENTICATED_WRITE_ONLY, False, True),
        (AttributeAccessMode.AUTHENTICATED_READ_AND_WRITE, True, True),
    ],
)
def test_v1_v2_attribute_modes(mode, readable, writable):
    assert (mode.readable, mode.writable) == (readable, writable)
    assert mode.authenticated == (mode >= 4)


def test_method_modes():
    assert [m.executable for m in MethodAccessMode] == [False, True, True]
    assert MethodAccess(1, False).executable is False


@pytest.mark.parametrize("version", [0, 1, 2, 3])
def test_round_trip(version):
    if version == 0:
        methods = (MethodAccess(1, True), MethodAccess(2, False))
    elif version < 3:
        methods = (MethodAccess(1, MethodAccessMode.AUTHENTICATED_ACCESS),)
    else:
        methods = (MethodAccess(1, MethodAccessMode3.ACCESS | MethodAccessMode3.ENCRYPTED_REQUEST),)
    mode = AccessMode3.READ | AccessMode3.WRITE if version == 3 else AttributeAccessMode(3)
    rights = AccessRights(
        (
            AttributeAccess(1, AttributeAccessMode.READ_ONLY if version < 3 else AccessMode3.READ),
            AttributeAccess(2, mode, (1, 2)),
            AttributeAccess(-1, AttributeAccessMode.NO_ACCESS if version < 3 else AccessMode3(0)),
        ),
        methods,
        version,
    )
    data = rights.to_data()
    assert decode_access_rights(data, version) == rights
    raw = encode_data(data)
    assert decode_access_rights(decode_data(raw)[0], version) == rights
    if version in (0, 1):
        assert decode_access_rights(data) == rights  # the encoding implies the version


def test_gurux_simulator_view_ln_v2():
    """Gurux.DLMS.Simulator.Net (LN v2): enum methods, a profile's selectors."""
    view = _view("gurux_sim_ln_v2.hex")
    own = _entry(view, "0.0.40.0.0.255")
    assert (own[0].value, own[1].value) == (15, 2)
    rights = decode_access_rights(own[3], own[1].value)
    assert [a.attribute_id for a in rights.attributes] == list(range(1, 12))
    assert all(a.access_mode is AttributeAccessMode.READ_ONLY for a in rights.attributes)
    assert rights.can_execute(1) is True and rights.method(6) is not None
    clock = decode_access_rights(_entry(view, "0.0.1.0.0.255")[3], 2)
    assert clock.can_read(2) is True and clock.can_write(2) is False
    assert clock.can_execute(1) is False  # public client: methods listed as no_access
    profile = decode_access_rights(_entry(view, "1.0.99.1.0.255")[3], 2)
    assert profile.attribute(2).access_selectors == (0, 1)
    assert profile.summary() == "r=1-8 w=- x=1-2"
    for entry in view:
        assert encode_data(decode_access_rights(entry.value[3], 2).to_data()) == encode_data(
            entry.value[3]
        )


def test_jdlms_view_ln_v1():
    """OpenMUC jDLMS 1.8.0 (LN v1): authenticated modes even under v1."""
    view = _view("jdlms_ln_v1.hex")
    own = _entry(view, "0.0.40.0.0.255")
    assert (own[0].value, own[1].value) == (15, 1)
    rights = decode_access_rights(own[3], 1)
    assert rights.attribute(2).access_selectors == (1, 2, 3, 4)
    assert rights.attribute(7).access_mode is AttributeAccessMode.AUTHENTICATED_READ_AND_WRITE
    security = decode_access_rights(_entry(view, "0.0.43.0.0.255")[3], 1)
    assert security.attribute(2).access_mode is AttributeAccessMode.AUTHENTICATED_READ_ONLY
    assert security.method(2).access_mode is MethodAccessMode.AUTHENTICATED_ACCESS
    assert security.can_execute(1) is None  # not listed: unknown
    register = decode_access_rights(_entry(view, "1.0.1.8.0.255")[3], 1)
    assert register.summary() == "r=1-3 w=2 x=-"
    for entry in view:
        rights = decode_access_rights(entry.value[3], 1)
        assert encode_data(rights.to_data()) == encode_data(entry.value[3])
        assert decode_access_rights(entry.value[3]) == rights  # inferred v1


def _s(*items):
    return DlmsData.structure(list(items))


def _a(*items):
    return DlmsData.array(list(items))


GOOD_ATTR = _s(DlmsData.int8(1), DlmsData.enum(1), DlmsData.null())
GOOD_METHOD = _s(DlmsData.int8(1), DlmsData.enum(1))


@pytest.mark.parametrize(
    "data,match",
    [
        (DlmsData.null(), "not a structure"),
        (_a(), "not a structure"),
        (_s(_a()), "structure of 2"),
        (_s(_a(), _a(), _a()), "structure of 2"),
        (_s(DlmsData.null(), _a()), "attribute_access is NULL"),
        (_s(_a(), DlmsData.enum(1)), "method_access is ENUM"),
        (_s(_a(DlmsData.int8(1)), _a()), "attribute_access item 1"),
        (_s(_a(_s(DlmsData.int8(1), DlmsData.enum(1))), _a()), "structure of 3"),
        (_s(_a(_s(DlmsData.enum(1), DlmsData.enum(1), DlmsData.null())), _a()), "attribute_id"),
        (_s(_a(_s(DlmsData.int8(1), DlmsData.uint8(1), DlmsData.null())), _a()), "not an enum"),
        (
            _s(_a(_s(DlmsData.int8(1), DlmsData.enum(1), DlmsData.enum(1))), _a()),
            "access_selectors is ENUM",
        ),
        (
            _s(_a(_s(DlmsData.int8(1), DlmsData.enum(1), _a(DlmsData.boolean(True)))), _a()),
            "access_selector is BOOLEAN",
        ),
        (_s(_a(GOOD_ATTR, GOOD_ATTR), _a()), "attribute 1 is listed twice"),
        (_s(_a(), _a(_s(DlmsData.int8(1)))), "method_access item 1"),
        (_s(_a(), _a(_s(DlmsData.boolean(True), DlmsData.enum(1)))), "method_id"),
        (_s(_a(), _a(_s(DlmsData.int8(1), DlmsData.uint8(1)))), "not an enum"),
        (_s(_a(), _a(GOOD_METHOD, GOOD_METHOD)), "method 1 is listed twice"),
        # Actaris SL7000 style: one bare method structure instead of an array of them.
        (_s(_a(), _s(DlmsData.int8(0), DlmsData.boolean(True))), "method_access is STRUCTURE"),
    ],
)
def test_malformed(data, match):
    with pytest.raises(DecodeError, match=match):
        decode_access_rights(data, 1)


def test_infer_on_malformed_is_v1():
    assert infer_association_version(DlmsData.null()) == 1


@pytest.mark.parametrize("cut", range(1, len(V3)))
def test_truncated_vector(cut):
    with pytest.raises(DecodeError):
        decode_data(V3[:cut])


def test_model_reexports_the_dataclasses():
    from pydlms.cosem import model

    assert model.AccessRights is AccessRights
    assert model.AttributeAccess is AttributeAccess
    assert model.MethodAccess is MethodAccess
