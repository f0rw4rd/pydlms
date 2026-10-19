"""The typed COSEM model: every attribute and method of every typed class.

* Exhaustive round trip: for each attribute type and method parameter type
  of all classes in ``SPECS``, a generated value (nested structures and
  arrays included) is encoded, serialised to A-XDR bytes, parsed back and
  decoded to an equal value.
* End to end: every method of every typed class is invoked through
  ``meter.object(...)`` against the simulator, whose default handler decodes
  the parameter with the class model and records it, so the value the meter
  received is compared with the value sent.
* Structural errors name the path (``capture_objects[1].logical_name``).
"""

from __future__ import annotations

import dataclasses
import datetime as dt

import pytest

from pydlms.client import DlmsClient
from pydlms.cosem import types as T
from pydlms.cosem.data import DlmsData, decode_data, encode_data
from pydlms.cosem.interface_classes import REGISTRY, ClassId, lookup
from pydlms.cosem.model import SPECS, CaptureObject, SpecialDay, spec_for
from pydlms.cosem.time import CosemDate, CosemDateTime, CosemTime
from pydlms.exceptions import DecodeError
from pydlms.obis import ObisCode
from pydlms.simulator import example_meter, serve


def sample(kind: T.Type):
    """A deterministic, non-trivial value for a descriptor."""
    if isinstance(kind, T.Enum):
        return next(iter(kind.cls)) if kind.cls else 2
    if isinstance(kind, T.Integer):
        return {"INTEGER": -5, "LONG": -300, "DOUBLE_LONG": -70000}.get(kind.tag.name, 7)
    if isinstance(kind, T.Boolean):
        return True
    if isinstance(kind, T.Float):
        return 1.5
    if isinstance(kind, T.Obis):
        return ObisCode(1, 0, 1, 8, 0, 255)
    if isinstance(kind, T.DateTime):
        return CosemDateTime.from_datetime(
            dt.datetime(2024, 3, 4, 5, 6, 7, tzinfo=dt.timezone(dt.timedelta(hours=1)))
        )
    if isinstance(kind, T.Date):
        return CosemDate(2024, 12, 25, 3)
    if isinstance(kind, T.Time):
        return CosemTime(6, 30, 0, 0)
    if isinstance(kind, T.OctetString):
        return b"\x01\x02\x03" if kind.size is None else bytes(range(kind.size))
    if isinstance(kind, T.Text):
        return "pydlms"
    if isinstance(kind, T.BitString):
        return [True, False, True]
    if isinstance(kind, T.Array):
        return [sample(kind.item), sample(kind.item)]
    if isinstance(kind, T.Struct):
        return kind.cls(**{name: sample(member) for name, member in kind.fields})
    if isinstance(kind, T.Any):
        return DlmsData.structure([DlmsData.uint8(1), DlmsData.visible_string("any")])
    if isinstance(kind, T.Null):
        return None
    raise AssertionError(f"no sample for {kind!r}")


ALL_TYPES = [
    (f"{spec.name}.{name}", attr.type)
    for spec in SPECS.values()
    for name, attr in spec.attributes.items()
] + [
    (f"{spec.name}.{name}()", method.params)
    for spec in SPECS.values()
    for name, method in spec.methods.items()
    if method.params is not None
]


@pytest.mark.parametrize("label,kind", ALL_TYPES, ids=[label for label, _ in ALL_TYPES])
def test_every_attribute_and_parameter_round_trips(label, kind):
    value = sample(kind)
    raw = encode_data(kind.encode(value))
    parsed, end = decode_data(raw)
    assert end == len(raw)
    assert kind.decode(parsed, label) == value


def test_specs_cover_every_registered_class_and_member():
    newest = {}
    for (class_id, version), ic in REGISTRY.items():
        if version >= newest.get(class_id, (-1, None))[0]:
            newest[class_id] = (version, ic)
    for (class_id, _), ic in REGISTRY.items():
        spec = spec_for(class_id)
        assert spec is not None, ic.name
        if ic is newest[class_id][1]:
            assert list(spec.attributes) == list(ic.attributes)
            assert list(spec.methods) == list(ic.methods)
        else:  # older versions are a prefix of the newest (typed) spec
            assert list(spec.attributes)[: len(ic.attributes)] == list(ic.attributes)
            assert list(spec.methods)[: len(ic.methods)] == list(ic.methods)


def test_method_index_and_name_lookup():
    clock = SPECS[ClassId.CLOCK]
    assert clock.method("shift_time").index == 6
    assert clock.method(6).name == "shift_time"
    assert clock.attribute("time").index == 2
    assert clock.attribute(99).name == "attribute_99"
    with pytest.raises(KeyError):
        clock.method("nope")


def test_errors_name_the_path():
    bad = DlmsData.array(
        [
            T.Struct(
                CaptureObject,
                SPECS[ClassId.PROFILE_GENERIC].attribute("capture_objects").type.item.fields,
            ).encode(sample(SPECS[ClassId.PROFILE_GENERIC].attribute("capture_objects").type.item)),
            DlmsData.structure(
                [DlmsData.uint16(3), DlmsData.uint8(1), DlmsData.int8(2), DlmsData.uint16(0)]
            ),
        ]
    )
    kind = SPECS[ClassId.PROFILE_GENERIC].attribute("capture_objects").type
    with pytest.raises(DecodeError, match=r"capture_objects\[1\]\.logical_name"):
        kind.decode(bad, "capture_objects")
    with pytest.raises(DecodeError, match="has 2 members, got 1"):
        SPECS[ClassId.REGISTER].attribute("scaler_unit").type.decode(
            DlmsData.structure([DlmsData.int8(0)]), "scaler_unit"
        )


def test_integer_width_tolerance_and_unknown_enum():
    assert T.U32.decode(DlmsData.uint16(5)) == 5  # meters send narrower integers
    assert T.Enum(ClassId).decode(DlmsData.enum(250)) == 250  # vendor value kept as int
    with pytest.raises(DecodeError):
        T.U16.decode(DlmsData.octet_string(b"x"))


def test_struct_requires_dataclass():
    with pytest.raises(TypeError):
        T.Struct(dict, [])


# --- end to end against the simulator ------------------------------------------------------


METHOD_CASES = [
    (spec.class_id, name)
    for spec in SPECS.values()
    for name in spec.methods
    # the HLS reply on the current association is exercised by the HLS tests
    if not (
        spec.class_id in (ClassId.ASSOCIATION_LN, ClassId.ASSOCIATION_SN)
        and name == "reply_to_hls_authentication"
    )
]


@pytest.fixture(scope="module")
def meter():
    sim = example_meter()
    for spec in SPECS.values():
        sim.add_object(
            spec.class_id, ObisCode(0, 128, 99, spec.class_id, 0, 255), {}, version=spec.version
        )
    server = serve(sim)
    client = DlmsClient.tcp(*server.server_address, timeout=5)
    client.connect()
    yield sim, client
    client.close()
    server.shutdown()
    server.server_close()


@pytest.mark.parametrize(
    "class_id,method", METHOD_CASES, ids=[f"{lookup(c).name}.{m}" for c, m in METHOD_CASES]
)
def test_every_method_reaches_the_meter_with_the_right_value(meter, class_id, method):
    sim, client = meter
    obj = client.object(ObisCode(0, 128, 99, class_id, 0, 255))
    spec = SPECS[class_id].method(method)
    value = sample(spec.params) if spec.params is not None else None
    sim.calls.clear()
    getattr(obj, method)(value)
    assert len(sim.calls) == 1
    _, _, received_name, received = sim.calls[0]
    assert received_name == method
    expected = value
    if expected is None and isinstance(spec.params, T.Integer):
        expected = 0  # data ::= integer(0)
    assert received == expected


def test_typed_attributes_end_to_end(meter):
    sim, client = meter
    clock = client.object("0.0.1.0.0.255")
    assert isinstance(clock.time, CosemDateTime)
    assert clock.time_zone == -60
    profile = client.object("1.0.99.1.0.255")
    columns = profile.capture_objects
    assert [c.logical_name for c in columns] == [
        ObisCode(0, 0, 1, 0, 0, 255),
        ObisCode(1, 0, 1, 8, 0, 255),
    ]
    assert profile.capture_period == 900
    register = client.object("1.0.32.7.0.255")
    assert register.scaler_unit.scaler == -1 and register.scaler_unit.unit == 35
    assert repr(register).startswith("<CosemObject Register 1.0.32.7.0.255")


def test_nested_write_then_read(meter):
    sim, client = meter
    days = client.object(ObisCode(0, 128, 99, ClassId.SPECIAL_DAYS_TABLE, 0, 255))
    entries = [
        SpecialDay(1, CosemDate(2024, 12, 25, 3), 2),
        SpecialDay(2, CosemDate(None, 1, 1, None), 2),
    ]
    days.entries = entries
    assert days.entries == entries
    script = client.object(ObisCode(0, 128, 99, ClassId.SCRIPT_TABLE, 0, 255))
    value = sample(SPECS[ClassId.SCRIPT_TABLE].attribute("scripts").type)
    script.set("scripts", value)
    assert script.scripts == value


def test_methods_with_return_values(meter):
    sim, client = meter
    ipv4 = client.object(ObisCode(0, 128, 99, ClassId.IPV4_SETUP, 0, 255))
    assert ipv4.get_nbof_mc_ip_addresses() == 1
    security = client.object(ObisCode(0, 128, 99, ClassId.SECURITY_SETUP, 0, 255))
    assert security.generate_certificate_request(0) == b"\x01\x02"


def test_read_all_and_unknown_names(meter):
    sim, client = meter
    values = client.object("1.0.1.8.0.255").read_all()
    assert values["value"].value == 12345678
    with pytest.raises(AttributeError):
        client.object("1.0.1.8.0.255").does_not_exist  # noqa: B018
    from pydlms.exceptions import ServiceError

    with pytest.raises(ServiceError, match="not in the association view"):
        client.object("9.9.9.9.9.9")


def test_object_list_count(meter):
    sim, client = meter
    assert len(client.objects()) == len(sim.objects)


def test_sample_generator_covers_every_structure():
    for _, kind in ALL_TYPES:
        if isinstance(kind, T.Struct):
            assert dataclasses.is_dataclass(sample(kind))


def test_name_only_classes_fall_back_to_raw_data():
    for class_id in (ClassId.SFSK_PHY_MAC_SETUP, ClassId.ZIGBEE_NETWORK_CONTROL):
        assert spec_for(class_id) is None
        assert lookup(class_id) is None
    assert len(ClassId) >= 79


X3_CLASSES = [
    ClassId.DATA_PROTECTION,
    ClassId.PRIME_PHY_COUNTERS,
    ClassId.PRIME_MAC_SETUP,
    ClassId.PRIME_MAC_FUNCTIONAL_PARAMETERS,
    ClassId.PRIME_MAC_COUNTERS,
    ClassId.PRIME_MAC_NETWORK_ADMINISTRATION,
    ClassId.G3_MAC_COUNTERS,
    ClassId.G3_MAC_SETUP,
    ClassId.G3_6LOWPAN_SETUP,
]


@pytest.mark.parametrize("class_id", X3_CLASSES)
def test_x3_spec_matches_registry_and_round_trips(class_id):
    """Every typed attribute of the data protection / G3 / PRIME classes."""
    spec = spec_for(class_id)
    ic = lookup(class_id)
    assert spec is not None and spec.version == ic.version
    assert [a.name for a in spec.attributes.values()] == list(ic.attributes)
    assert [m.name for m in spec.methods.values()] == list(ic.methods)
    for attribute in spec.attributes.values():
        value = sample(attribute.type)
        raw = encode_data(attribute.type.encode(value))
        parsed, end = decode_data(raw)
        assert end == len(raw)
        assert attribute.type.decode(parsed, attribute.name) == value


def test_x3_unsure_attributes_stay_raw():
    """Where Gurux and the Blue Book recollection disagree, no type is claimed."""
    dp = spec_for(ClassId.DATA_PROTECTION)
    assert isinstance(dp.attribute("protection_parameters_get").type, T.Any)
    assert isinstance(dp.attribute("protection_parameters_set").type, T.Any)
    prime = spec_for(ClassId.PRIME_MAC_FUNCTIONAL_PARAMETERS)
    assert isinstance(prime.attribute("lnid").type, T.Any)
    assert isinstance(prime.attribute("scp_length").type, T.Any)


def test_x3_wrong_scalar_type_is_a_decode_error():
    counters = spec_for(ClassId.G3_MAC_COUNTERS)
    with pytest.raises(DecodeError):
        counters.attribute("tx_data_packet_count").type.decode(DlmsData.visible_string("x"))
