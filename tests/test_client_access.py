"""Access rights end to end: the simulator lists them, the client decodes
them into ``ObjectListEntry.rights``, ``can_read`` and
``CosemObject.read_all(skip_unreadable=True)`` use them, ``get`` ignores them."""

from __future__ import annotations

import logging

import pytest

from pydlms.apdu import xdlms
from pydlms.client import DlmsClient
from pydlms.cosem.access import AccessMode3, AttributeAccessMode, MethodAccessMode
from pydlms.cosem.data import DlmsData
from pydlms.cosem.enums import DataAccessResult
from pydlms.cosem.interface_classes import ClassId
from pydlms.exceptions import ServiceError
from pydlms.obis import ObisCode
from pydlms.simulator import example_meter, serve

ENERGY = "1.0.1.8.0.255"


@pytest.fixture
def sim():
    meter = example_meter()
    servers = []

    def connect(**kw) -> DlmsClient:
        server = serve(meter)
        servers.append(server)
        return DlmsClient.tcp(*server.server_address, timeout=3, **kw)

    meter.connect = connect
    yield meter
    for server in servers:
        server.shutdown()
        server.server_close()


def _gets(sim, obis: str) -> list[int]:
    """Attribute ids of the plain GET requests the meter saw for ``obis``."""
    want = ObisCode.parse(obis)
    out = []
    for apdu in sim.requests:
        if apdu[0] != 0xC0:
            continue
        request = xdlms.decode_apdu(apdu)
        if isinstance(request, xdlms.GetRequestNormal) and request.attribute.instance_id == want:
            out.append(request.attribute.attribute_id)
    return out


def test_view_carries_decoded_rights(sim):
    with sim.connect() as m:
        view = {str(e.logical_name): e for e in m.get_association_view()}
    register = view[ENERGY]
    assert register.access_rights is not None  # raw field kept
    rights = register.rights
    assert rights.version == 1
    assert rights.attribute(1).access_mode is AttributeAccessMode.READ_ONLY
    assert rights.attribute(2).access_mode is AttributeAccessMode.READ_AND_WRITE
    assert rights.method(1).access_mode is MethodAccessMode.ACCESS  # Register reset
    assert view["1.0.99.1.0.255"].rights.attribute(2).access_selectors == (1, 2)
    assert view["0.0.96.3.10.255"].rights.can_execute(1) is True


@pytest.mark.parametrize("version", [0, 1, 2, 3])
def test_version_comes_from_the_views_own_entry(sim, version):
    sim.association_version = version
    sim.set_access(ClassId.REGISTER, ENERGY, 3, AccessMode3.WRITE if version == 3 else 2)
    with sim.connect() as m:
        view = {str(e.logical_name): e for e in m.get_association_view()}
        assert view["0.0.40.0.0.255"].version == version
        rights = view[ENERGY].rights
        assert rights.version == version
        if version == 0:
            assert rights.method(1).access_mode is True
        elif version == 3:
            assert rights.attribute(3).access_mode == AccessMode3.WRITE
        assert m.can_read(ENERGY, ClassId.REGISTER, 3) is False
        assert m.can_read(ENERGY, ClassId.REGISTER, 2) is True


def test_view_without_its_own_entry_infers_the_version(sim):
    with sim.connect() as m:
        assert all(e.rights.version == 1 for e in m.get_association_view())
    sim.association_version = 0
    sim.object_list = _drop_own_entry(sim.object_list)
    with sim.connect() as m:
        assert {e.rights.version for e in m.get_association_view()} == {0, 1}  # no methods: 1


def _drop_own_entry(object_list):
    def listing():
        entries = object_list().value
        return DlmsData.array([e for e in entries if e.value[0].value != ClassId.ASSOCIATION_LN])

    return listing


def test_malformed_rights_give_none_and_a_warning(sim, caplog):
    original = sim.object_list

    def broken():
        entries = original().value
        first = entries[0].value
        entries[0] = DlmsData.structure([*first[:3], DlmsData.enum(1)])
        return DlmsData.array(entries)

    sim.object_list = broken
    with sim.connect() as m, caplog.at_level(logging.WARNING, logger="pydlms"):
        view = m.get_association_view()
        assert view[0].rights is None
        assert view[0].access_rights == DlmsData.enum(1)
        assert all(e.rights is not None for e in view[1:])
        assert m.can_read(view[0].logical_name) is None
    assert any("access_rights" in r.getMessage() for r in caplog.records)


def test_can_read_is_unknown_when_the_view_does_not_say(sim):
    sim.set_access(ClassId.REGISTER, ENERGY, 3, None)  # left out of the view
    with sim.connect() as m:
        assert m.can_read(ENERGY, ClassId.REGISTER, 3) is None
        assert m.can_read(ENERGY, ClassId.REGISTER, "scaler_unit") is None
        assert m.can_read(ENERGY, ClassId.REGISTER, "value") is True
        assert m.can_read(ENERGY) is True  # class from the view, attribute 2
        assert m.can_read("9.9.9.9.9.9") is None  # not in the view
        assert m.can_read(ENERGY, ClassId.DATA, 2) is None  # other class
        assert m.get(ENERGY, ClassId.REGISTER, 3).tag.name == "STRUCTURE"


def test_get_never_refuses_in_advance(sim):
    sim.set_access(ClassId.REGISTER, ENERGY, 2, 0)
    with sim.connect() as m:
        assert m.can_read(ENERGY, ClassId.REGISTER, 2) is False
        with pytest.raises(ServiceError) as err:
            m.get(ENERGY, ClassId.REGISTER, 2)
        assert err.value.result == DataAccessResult.READ_WRITE_DENIED
    assert 2 in _gets(sim, ENERGY)  # the request went to the meter


def test_simulator_enforces_write_and_method_modes(sim):
    sim.set_access(ClassId.DATA, "0.0.96.1.0.255", 2, 1)  # read-only
    sim.set_access(ClassId.DISCONNECT_CONTROL, "0.0.96.3.10.255", method=1, mode=0)
    with sim.connect() as m:
        view = {str(e.logical_name): e for e in m.get_association_view()}
        assert view["0.0.96.3.10.255"].rights.can_execute(1) is False
        with pytest.raises(ServiceError):
            m.set("0.0.96.1.0.255", ClassId.DATA, 2, DlmsData.visible_string("X"))
        with pytest.raises(ServiceError):
            m.action("0.0.96.3.10.255", ClassId.DISCONNECT_CONTROL, 1, DlmsData.int8(0))


def test_read_all_skips_unreadable_attributes(sim):
    sim.set_access(ClassId.REGISTER, ENERGY, 3, 0)
    with sim.connect() as m:
        values = m.object(ENERGY).read_all()
        assert set(values) == {"logical_name", "value"}
        assert 3 not in _gets(sim, ENERGY)
        everything = m.object(ENERGY).read_all(skip_unreadable=False)
        assert isinstance(everything["scaler_unit"], ServiceError)
    assert _gets(sim, ENERGY).count(3) == 1


def test_read_all_reads_attributes_the_view_does_not_list(sim):
    sim.set_access(ClassId.REGISTER, ENERGY, 3, None)
    with sim.connect() as m:
        values = m.object(ENERGY).read_all()
    assert values["scaler_unit"] is not None and not isinstance(values["scaler_unit"], Exception)


def test_short_name_views_have_no_rights(sim):
    with sim.connect(logical_names=False) as m:
        view = m.get_association_view()
        assert all(e.rights is None for e in view)
        assert m.can_read(ENERGY, ClassId.REGISTER, 2) is None
        assert m.object(ENERGY).read_all()["value"].value == 12345678
