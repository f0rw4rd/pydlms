"""Compact data (IC 62) and the public type-description / untagged codec.

Vectors are hand-derived from the compact-array TypeDescription grammar
(IEC 62056-6-2, see tests/test_cosem_compact_array.py), from the compact
data layout Gurux.DLMS.Net writes (GXDLMSCompactData.Capture), and from the
three examples of DLMS UA 1000-1 Ed. 13 Excerpt 4.3.10.2 (Tables 6/7, 9/10
and 13/14, identical in the Ed. 12.2 excerpt). The live cross-check against Gurux's
GetValues is in tests/interop/test_gurux_net.py.
"""

from __future__ import annotations

import datetime as dt

import construct
import pytest

from pydlms.apdu import xdlms
from pydlms.client import DlmsClient
from pydlms.cosem.compact_data import (
    CompactData,
    decode_compact_buffer,
    decode_template_description,
)
from pydlms.cosem.data import (
    MAX_NESTING,
    CompactArray,
    DlmsData,
    TypeDescription,
    TypeDescriptionCodec,
    Untagged,
    decode_type_description,
    decode_untagged,
    encode_data,
    encode_type_description,
    encode_untagged,
)
from pydlms.cosem.enums import DataType as T
from pydlms.cosem.enums import Unit
from pydlms.cosem.interface_classes import ClassId
from pydlms.cosem.scaler import RegisterValue
from pydlms.cosem.time import CosemDateTime
from pydlms.exceptions import DecodeError
from pydlms.obis import ObisCode
from pydlms.simulator import example_meter, serve

U8 = TypeDescription(T.UNSIGNED)
U16 = TypeDescription(T.LONG_UNSIGNED)
U32 = TypeDescription(T.DOUBLE_LONG_UNSIGNED)
OCTETS = TypeDescription(T.OCTET_STRING)
NULL = TypeDescription(T.NULL)
STRUCT_U16_BOOL = TypeDescription(T.STRUCTURE, members=(U16, TypeDescription(T.BOOLEAN)))
ARRAY_2_U8 = TypeDescription(T.ARRAY, array_of=(2, U8))
NESTED = TypeDescription(T.STRUCTURE, members=(OCTETS, ARRAY_2_U8, STRUCT_U16_BOOL))

DESCRIPTIONS = [
    (U16, "12"),
    (STRUCT_U16_BOOL, "02 02 12 03"),
    (ARRAY_2_U8, "01 0002 11"),
    (NESTED, "02 03 09 01 0002 11 02 02 12 03"),
    (TypeDescription(T.STRUCTURE), "02 00"),
]


# --- type descriptions ----------------------------------------------------------------


@pytest.mark.parametrize("desc,hex_", DESCRIPTIONS)
def test_type_description_vectors_round_trip(desc, hex_):
    raw = bytes.fromhex(hex_)
    assert encode_type_description(desc) == raw
    assert decode_type_description(raw) == desc
    assert TypeDescriptionCodec.build(desc) == raw
    assert TypeDescriptionCodec.parse(raw) == desc


@pytest.mark.parametrize(
    "hex_",
    [
        "",  # nothing
        "02",  # structure without its count
        "02 02 12",  # one member of two
        "01 00",  # array count cut short
        "01 0002",  # array without its element type
        "fe",  # unknown tag
        "13 12",  # compact-array cannot describe compact-arrays
        "12 12",  # trailing octet
        "02 01 12 00",  # trailing octet after a structure
    ],
)
def test_malformed_type_descriptions_are_rejected(hex_):
    with pytest.raises(DecodeError):
        decode_type_description(bytes.fromhex(hex_))


def test_type_description_nesting_is_bounded():
    raw = bytes.fromhex("0201") * (MAX_NESTING + 1) + b"\x11"
    with pytest.raises(DecodeError, match="nested deeper"):
        decode_type_description(raw)


def test_type_description_construct_reports_construct_errors():
    with pytest.raises(construct.ConstructError):
        TypeDescriptionCodec.parse(bytes.fromhex("02 02 12"))


# --- untagged values ------------------------------------------------------------------


STRUCT_VALUE = DlmsData.structure([DlmsData.uint16(5), DlmsData.boolean(True)])
NESTED_VALUE = DlmsData.structure(
    [
        DlmsData.octet_string(b"ab"),
        DlmsData.array([DlmsData.uint8(1), DlmsData.uint8(2)]),
        STRUCT_VALUE,
    ]
)
UNTAGGED = [
    (U16, DlmsData.uint16(0x0304), "0304"),
    (STRUCT_U16_BOOL, STRUCT_VALUE, "0005 01"),
    (NESTED, NESTED_VALUE, "02 6162 01 02 0005 01"),
    (NULL, DlmsData.null(), ""),
    (TypeDescription(T.STRUCTURE), DlmsData.structure([]), ""),
]


@pytest.mark.parametrize("desc,value,hex_", UNTAGGED)
def test_untagged_vectors_round_trip(desc, value, hex_):
    raw = bytes.fromhex(hex_)
    assert encode_untagged(value, desc) == raw
    assert decode_untagged(raw, desc) == value
    assert Untagged(desc).build(value) == raw
    assert Untagged(desc).parse(raw) == value


@pytest.mark.parametrize(
    "desc,hex_",
    [
        (U16, "03"),  # truncated
        (U16, "030405"),  # trailing octet: the value must use every octet
        (STRUCT_U16_BOOL, "0005"),
        (NESTED, "02 61"),  # octet-string longer than what is left
        (NESTED, "02 6162 01 02 0005 01 ff"),
    ],
)
def test_malformed_untagged_values_are_rejected(desc, hex_):
    with pytest.raises(DecodeError):
        decode_untagged(bytes.fromhex(hex_), desc)
    with pytest.raises(construct.ConstructError):
        Untagged(desc).parse(bytes.fromhex(hex_))


def test_zero_width_expansion_is_bounded():
    huge = TypeDescription(
        T.ARRAY, array_of=(0xFFFF, TypeDescription(T.ARRAY, array_of=(0xFFFF, NULL)))
    )
    with pytest.raises(DecodeError, match="expands to more than"):
        decode_untagged(b"", huge)


def test_mismatched_value_is_rejected_on_encode():
    with pytest.raises(ValueError, match="description says"):
        encode_untagged(DlmsData.uint8(1), U16)


# --- decode_compact_buffer ----------------------------------------------------------------

T0 = dt.datetime(2024, 5, 1, 12, 0, tzinfo=dt.timezone(dt.timedelta(hours=2)))
STAMP = CosemDateTime.from_datetime(T0).to_bytes()
#: structure {octet-string (the clock), double-long-unsigned (a register)}
TEMPLATE = bytes.fromhex("02 02 09 06")
BUFFER = b"\x0c" + STAMP + bytes.fromhex("00bc614e")


def test_compact_buffer_vector():
    cells = decode_compact_buffer(TEMPLATE, BUFFER)
    assert cells == [DlmsData.octet_string(STAMP), DlmsData.uint32(12345678)]
    assert decode_compact_buffer(decode_type_description(TEMPLATE), BUFFER) == cells


@pytest.mark.parametrize(
    "template,buffer,match",
    [
        (TEMPLATE, BUFFER[:-1], "need"),  # truncated
        (TEMPLATE, BUFFER + BUFFER, "trailing"),  # two captures: one is expected
        (TEMPLATE, b"", "need"),
        (bytes.fromhex("06"), bytes.fromhex("00bc614e"), "structure"),  # not a structure
        (TEMPLATE + b"\x00", BUFFER, "trailing"),  # template with a trailing octet
        (bytes.fromhex("02 02 09"), BUFFER, "need"),  # truncated template
    ],
)
def test_malformed_compact_buffers_are_rejected(template, buffer, match):
    with pytest.raises(DecodeError, match=match):
        decode_compact_buffer(template, buffer)


# --- DLMS UA 1000-1 Ed. 13 Excerpt 4.3.10.2 examples --------------------------------------
#
# Each example captures the template_id (class 62, 0-0:66.0.0.255, attribute
# 4) as its first capture object, so its value is the first buffer octet.

#: Table 7 (daily billing data, template_id 0).
BB_DAILY_TEMPLATE = bytes.fromhex("02 0A 11 06 11 11 06 06 06 06 09 12")
BB_DAILY_BUFFER = bytes.fromhex(
    "00 51EE5305 29 18 0061FFD3 000D33D2 0012D687 0023CACE 06414243444546 1ED2"
)
#: Table 10 (diagnostic and alarm data, template_id 1).
BB_DIAGNOSTIC_TEMPLATE = bytes.fromhex("02 08 11 12 12 12 12 09 12 09")
BB_DIAGNOSTIC_BUFFER = bytes.fromhex(
    "01 4200 4108 4308 02FB 084142434445464748 05FC 084445464748494A4B"
)
#: Table 14 (logbook, template_id 2): the array has no count in the
#: template; the buffer gives 0x32 = 50 entries, each the values of Table 12's
#: note (Unix time 1374573317, status 0x29), 252 octets in all.
BB_LOGBOOK_TEMPLATE = bytes.fromhex("02 02 11 01 02 02 06 11")
BB_LOGBOOK_BUFFER = bytes.fromhex("02 32") + bytes.fromhex("51EE5305 29") * 50


def test_blue_book_daily_billing_example():
    cells = decode_compact_buffer(BB_DAILY_TEMPLATE, BB_DAILY_BUFFER)
    assert len(BB_DAILY_BUFFER) == 32  # "32 bytes" in Table 7
    assert [c.value for c in cells] == [
        0,
        1374573317,
        0x29,
        0x18,
        6422483,
        865234,
        1234567,
        2345678,
        b"ABCDEF",
        7890,
    ]


def test_blue_book_diagnostic_example():
    cells = decode_compact_buffer(BB_DIAGNOSTIC_TEMPLATE, BB_DIAGNOSTIC_BUFFER)
    assert len(BB_DIAGNOSTIC_BUFFER) == 29  # "29 bytes" in Table 10
    assert [c.value for c in cells] == [
        1,
        0x4200,
        0x4108,
        0x4308,
        763,
        b"ABCDEFGH",
        1532,
        b"DEFGHIJK",
    ]


def test_blue_book_logbook_example_array_count_is_in_the_buffer():
    """Ed. 13 Table 14: ``01 02 02 06 11`` is an array of structures with no
    count; the count (0x32) leads the array's values in compact_buffer."""
    desc = decode_template_description(BB_LOGBOOK_TEMPLATE)
    entry = TypeDescription(T.STRUCTURE, members=(U32, U8))
    assert desc == TypeDescription(
        T.STRUCTURE, members=(U8, TypeDescription(T.ARRAY, array_of=(None, entry)))
    )
    assert encode_type_description(desc) == BB_LOGBOOK_TEMPLATE
    cells = decode_compact_buffer(BB_LOGBOOK_TEMPLATE, BB_LOGBOOK_BUFFER)
    assert len(BB_LOGBOOK_BUFFER) == 252
    assert cells[0] == DlmsData.uint8(2)
    rows = cells[1]
    assert rows.tag == T.ARRAY and len(rows.value) == 50
    assert rows.value[0] == DlmsData.structure([DlmsData.uint32(1374573317), DlmsData.uint8(0x29)])
    assert encode_untagged(DlmsData.structure(cells), desc) == BB_LOGBOOK_BUFFER


def test_counted_template_arrays_are_still_read():
    """A template with an Unsigned16 array count (Gurux GXDLMSCompactData)
    is not in the Blue Book form and is read with the count instead."""
    template = bytes.fromhex("02 02 11 01 0002 12")
    desc = decode_template_description(template)
    assert desc.members[1] == TypeDescription(T.ARRAY, array_of=(2, U16))
    cells = decode_compact_buffer(template, bytes.fromhex("07 0001 0002"))
    assert cells == [DlmsData.uint8(7), DlmsData.array([DlmsData.uint16(1), DlmsData.uint16(2)])]


@pytest.mark.parametrize(
    "buffer",
    [
        bytes.fromhex("02 32") + bytes.fromhex("51EE5305 29") * 49,  # one entry short
        bytes.fromhex("02 32") + bytes.fromhex("51EE5305 29") * 51,  # one entry too many
        bytes.fromhex("02"),  # count missing
        bytes.fromhex("02 84 FFFFFFFF"),  # absurd count
    ],
)
def test_malformed_blue_book_array_buffers_are_rejected(buffer):
    with pytest.raises(DecodeError):
        decode_compact_buffer(BB_LOGBOOK_TEMPLATE, buffer)


def test_uncounted_description_is_refused_in_a_compact_array():
    desc = decode_template_description(BB_LOGBOOK_TEMPLATE).members[1]
    with pytest.raises(ValueError, match="needs a count"):
        encode_data(DlmsData(T.COMPACT_ARRAY, CompactArray(desc, [])))


# --- DlmsClient.read_compact_data -----------------------------------------------------------

COMPACT = "0.0.66.0.1.255"
KEY = (ClassId.COMPACT_DATA, ObisCode.parse(COMPACT))


@pytest.fixture
def meter():
    sim = example_meter()
    servers = []

    def start():
        server = serve(sim)
        servers.append(server)
        return server.server_address

    sim.start = start
    yield sim
    for server in servers:
        server.shutdown()
        server.server_close()


def connect(meter) -> DlmsClient:
    host, port = meter.start()
    return DlmsClient.tcp(host, port, timeout=3)


def requested_attributes(meter) -> list[list[int]]:
    """The attributes of every GET request, in order (with-list as one entry)."""
    out = []
    for raw in meter.requests:
        if raw[:1] != b"\xc0":  # GET-Request only
            continue
        apdu = xdlms.decode_apdu(raw)
        if isinstance(apdu, xdlms.GetRequestNormal):
            out.append([apdu.attribute.attribute_id])
        elif isinstance(apdu, xdlms.GetRequestWithList):
            out.append([d.attribute_id for d, _ in apdu.items])
    return out


def test_read_compact_data_end_to_end(meter):
    with connect(meter) as m:
        data = m.read_compact_data(COMPACT)
    assert isinstance(data, CompactData)
    assert [(c[0], str(c[1]), c[2], c[3]) for c in data.columns] == [
        (8, "0.0.1.0.0.255", 2, 0),
        (3, "1.0.1.8.0.255", 2, 0),
    ]
    assert data.template_id == 1 and data.capture_method == 0
    assert data.template_description == decode_type_description(TEMPLATE)
    assert data.values == [STAMP, 12345678]
    assert [c.to_python() for c in data.cells] == data.values
    assert requested_attributes(meter)[-2:] == [[3, 4, 5, 6], [2]]


def test_read_compact_data_typed_and_scaled(meter):
    with connect(meter) as m:
        typed = m.read_compact_data(COMPACT, typed=True)
        scaled = m.read_compact_data(COMPACT, scalers=True)
    assert typed.values[0].to_datetime() == T0 and typed.values[1] == 12345678
    assert scaled.values[1] == RegisterValue(12345678, 0, Unit.WATT_HOUR)


def test_member_count_must_match_the_capture_objects(meter):
    objects = meter.objects[KEY]
    objects[3] = DlmsData.array(objects[3].value[:1])
    with connect(meter) as m, pytest.raises(DecodeError, match="2 members for 1 capture objects"):
        m.read_compact_data(COMPACT)


def test_an_empty_buffer_means_nothing_captured(meter):
    meter.objects[KEY][2] = DlmsData.octet_string(b"")
    with connect(meter) as m:
        data = m.read_compact_data(COMPACT, typed=True)
    assert data.cells == [] and data.values == []


@pytest.mark.parametrize(
    "attribute,value,match",
    [
        (2, DlmsData.uint8(1), "compact_buffer"),
        (5, DlmsData.uint8(1), "template_description"),
        (4, DlmsData.octet_string(b"\x01"), "template_id"),
        (5, DlmsData.octet_string(bytes.fromhex("02 02 09")), "need"),
    ],
)
def test_malformed_attributes_are_rejected(meter, attribute, value, match):
    meter.objects[KEY][attribute] = value
    with connect(meter) as m, pytest.raises(DecodeError, match=match):
        m.read_compact_data(COMPACT)


def test_capture_method_is_optional(meter):
    del meter.objects[KEY][6]  # a version 0 object, or access denied
    with connect(meter) as m:
        assert m.read_compact_data(COMPACT).capture_method is None


def test_resolve_deltas_without_deltas_changes_nothing(meter):
    with connect(meter) as m:
        plain = m.read_compact_data(COMPACT)
        resolved = m.read_compact_data(COMPACT, resolve_deltas=True)
    assert resolved.values == plain.values and resolved.cells == plain.cells


def test_resolve_deltas_top_level_delta_member_raises(meter):
    """One capture is a structure, not an array: a delta member has no base
    under the provisional reading (pydlms.cosem.delta)."""
    template = TypeDescription(T.STRUCTURE, members=(OCTETS, TypeDescription(T.DELTA_UNSIGNED)))
    meter.objects[KEY][5] = DlmsData.octet_string(encode_type_description(template))
    meter.objects[KEY][2] = DlmsData.octet_string(b"\x0c" + STAMP + b"\x05")
    with connect(meter) as m:
        assert m.read_compact_data(COMPACT).values == [STAMP, 5]
        with pytest.raises(DecodeError, match="outside an array"):
            m.read_compact_data(COMPACT, resolve_deltas=True)
