"""Provisional delta-value resolution (``pydlms.cosem.delta.resolve_deltas``).

PROVISIONAL: the Green Book accumulation rule was not read and no reference
implementation resolves deltas, so these tests pin the reading documented in
the module, not a standard: inside an array each delta is the previous
element's absolute value plus the delta, retagged to that absolute value's
type; structures inside an array resolve per member position.
"""

from __future__ import annotations

import copy

import pytest

from pydlms.cosem.data import CompactArray, DlmsData, TypeDescription, decode_data, encode_data
from pydlms.cosem.delta import resolve_deltas
from pydlms.cosem.enums import DataType as T
from pydlms.exceptions import DecodeError


def d(tag: T, value: int) -> DlmsData:
    return DlmsData(tag, value)


def arr(*items: DlmsData) -> DlmsData:
    return DlmsData.array(list(items))


def st(*items: DlmsData) -> DlmsData:
    return DlmsData.structure(list(items))


def test_base_then_deltas():
    raw = arr(
        d(T.DOUBLE_LONG_UNSIGNED, 1000),
        d(T.DELTA_UNSIGNED, 5),
        d(T.DELTA_LONG_UNSIGNED, 300),
        d(T.DELTA_INTEGER, -2),
    )
    out = resolve_deltas(raw)
    assert out == arr(
        d(T.DOUBLE_LONG_UNSIGNED, 1000),
        d(T.DOUBLE_LONG_UNSIGNED, 1005),
        d(T.DOUBLE_LONG_UNSIGNED, 1305),
        d(T.DOUBLE_LONG_UNSIGNED, 1303),
    )


def test_from_wire_bytes():
    # array(3): double-long 100, delta-integer -1, delta-long 2
    raw, _ = decode_data(bytes.fromhex("0103 0500000064 1cff 1d0002"))
    assert resolve_deltas(raw).to_python() == [100, 99, 101]
    assert {item.tag for item in resolve_deltas(raw).value} == {T.DOUBLE_LONG}


def test_full_width_value_resets_base():
    raw = arr(
        d(T.LONG_UNSIGNED, 10),
        d(T.DELTA_UNSIGNED, 1),
        d(T.LONG_UNSIGNED, 500),
        d(T.DELTA_UNSIGNED, 1),
    )
    assert resolve_deltas(raw) == arr(
        d(T.LONG_UNSIGNED, 10),
        d(T.LONG_UNSIGNED, 11),
        d(T.LONG_UNSIGNED, 500),
        d(T.LONG_UNSIGNED, 501),
    )


def test_base_type_change_retags_following_deltas():
    raw = arr(d(T.UNSIGNED, 1), d(T.DELTA_UNSIGNED, 1), d(T.LONG64, -5), d(T.DELTA_INTEGER, -1))
    assert resolve_deltas(raw) == arr(
        d(T.UNSIGNED, 1), d(T.UNSIGNED, 2), d(T.LONG64, -5), d(T.LONG64, -6)
    )


def test_structure_columns_resolve_per_member():
    stamp = DlmsData(T.OCTET_STRING, bytes(12))
    raw = arr(
        st(stamp, d(T.DOUBLE_LONG_UNSIGNED, 100), d(T.LONG, -10)),
        st(stamp, d(T.DELTA_UNSIGNED, 7), d(T.DELTA_INTEGER, 3)),
        st(stamp, d(T.DELTA_UNSIGNED, 1), d(T.LONG, 50)),
        st(stamp, d(T.DOUBLE_LONG_UNSIGNED, 0), d(T.DELTA_INTEGER, -1)),
    )
    assert resolve_deltas(raw).to_python() == [
        [bytes(12), 100, -10],
        [bytes(12), 107, -7],
        [bytes(12), 108, 50],
        [bytes(12), 0, 49],
    ]


def test_nested_structure_members_resolve_per_path():
    raw = arr(
        st(st(d(T.UNSIGNED, 1), d(T.LONG, 100))),
        st(st(d(T.DELTA_UNSIGNED, 1), d(T.DELTA_LONG, -1))),
    )
    assert resolve_deltas(raw).to_python() == [[[1, 100]], [[2, 99]]]


def test_nested_arrays_resolve_independently():
    raw = st(
        arr(d(T.LONG, 1), d(T.DELTA_INTEGER, 1)),
        arr(
            arr(d(T.UNSIGNED, 10), d(T.DELTA_UNSIGNED, 5)),
            arr(d(T.UNSIGNED, 20), d(T.DELTA_UNSIGNED, 1)),
        ),
    )
    assert resolve_deltas(raw).to_python() == [[1, 2], [[10, 15], [20, 21]]]


def test_inner_array_does_not_inherit_outer_base():
    raw = arr(d(T.UNSIGNED, 1), arr(d(T.DELTA_UNSIGNED, 1)))
    with pytest.raises(DecodeError, match="no base"):
        resolve_deltas(raw)


def test_delta_first_raises():
    with pytest.raises(DecodeError, match="no base"):
        resolve_deltas(arr(d(T.DELTA_UNSIGNED, 1), d(T.UNSIGNED, 2)))


def test_delta_first_in_structure_column_raises():
    raw = arr(st(d(T.UNSIGNED, 1), d(T.DELTA_UNSIGNED, 1)))
    with pytest.raises(DecodeError, match="no base"):
        resolve_deltas(raw)


@pytest.mark.parametrize(
    "value",
    [
        d(T.DELTA_UNSIGNED, 1),
        st(d(T.UNSIGNED, 1), d(T.DELTA_UNSIGNED, 1)),
    ],
)
def test_delta_outside_array_raises(value):
    with pytest.raises(DecodeError, match="outside an array"):
        resolve_deltas(value)


@pytest.mark.parametrize(
    "base",
    [
        DlmsData.null(),
        DlmsData(T.OCTET_STRING, b"\x01"),
        DlmsData(T.FLOAT32, 1.0),
        DlmsData(T.ENUM, 1),
        DlmsData.boolean(True),
    ],
)
def test_non_integer_previous_element_is_no_base(base):
    with pytest.raises(DecodeError, match="no base"):
        resolve_deltas(arr(d(T.UNSIGNED, 1), base, d(T.DELTA_UNSIGNED, 1)))


@pytest.mark.parametrize(
    "items",
    [
        (d(T.UNSIGNED, 255), d(T.DELTA_UNSIGNED, 1)),
        (d(T.UNSIGNED, 0), d(T.DELTA_INTEGER, -1)),
        (d(T.INTEGER, -128), d(T.DELTA_INTEGER, -1)),
        (d(T.LONG_UNSIGNED, 0xFFFF), d(T.DELTA_UNSIGNED, 1)),
        (d(T.DOUBLE_LONG, 0x7FFFFFFF), d(T.DELTA_UNSIGNED, 1)),
        (d(T.UNSIGNED, 200), d(T.DELTA_DOUBLE_LONG_UNSIGNED, 100)),
        (d(T.LONG64_UNSIGNED, 2**64 - 1), d(T.DELTA_UNSIGNED, 1)),
    ],
)
def test_overflow_raises(items):
    with pytest.raises(DecodeError, match="overflows"):
        resolve_deltas(arr(*items))


def test_limits_exactly_reached():
    raw = arr(d(T.UNSIGNED, 254), d(T.DELTA_UNSIGNED, 1), d(T.DELTA_INTEGER, -128))
    assert resolve_deltas(raw).to_python() == [254, 255, 127]


def test_unsigned_delta_adds_non_negatively():
    """delta-unsigned 0xFF is +255, never a two's-complement -1."""
    raw = arr(d(T.LONG, 0), d(T.DELTA_UNSIGNED, 0xFF), d(T.DELTA_UNSIGNED, 0xFF))
    assert resolve_deltas(raw).to_python() == [0, 255, 510]
    with pytest.raises(DecodeError, match="negative"):
        resolve_deltas(arr(d(T.LONG, 0), d(T.DELTA_UNSIGNED, -1)))  # built, not decoded
    with pytest.raises(DecodeError, match="overflows"):
        resolve_deltas(arr(d(T.LONG, 0), d(T.DELTA_LONG_UNSIGNED, 0xFFFF), d(T.DELTA_UNSIGNED, 0)))


def test_raw_values_stay_available():
    raw = arr(d(T.UNSIGNED, 1), d(T.DELTA_UNSIGNED, 2))
    before = copy.deepcopy(raw)
    wire = encode_data(raw)
    out = resolve_deltas(raw)
    assert raw == before  # input untouched
    assert encode_data(raw) == wire
    assert out is not raw and out.value[1] is not raw.value[1]
    assert out.value[1] == d(T.UNSIGNED, 3)


def test_no_deltas_is_identity():
    raw = st(
        arr(d(T.UNSIGNED, 1), DlmsData(T.BIT_STRING, [True, False]), DlmsData.null()),
        DlmsData(T.VISIBLE_STRING, "x"),
        d(T.DOUBLE_LONG, -1),
    )
    out = resolve_deltas(raw)
    assert out == raw
    out.value[0].value[1].value.append(True)
    assert raw.value[0].value[1].value == [True, False]


def test_compact_array_without_deltas_unchanged():
    desc = TypeDescription(T.STRUCTURE, members=(TypeDescription(T.UNSIGNED),))
    raw = DlmsData(T.COMPACT_ARRAY, CompactArray(desc, [st(d(T.UNSIGNED, 1))]))
    assert resolve_deltas(raw) == raw


def test_compact_array_delta_column_has_no_base():
    """A compact-array description fixes every element's type, so a delta
    column never holds an absolute value to start from (reading as above)."""
    desc = TypeDescription(
        T.STRUCTURE, members=(TypeDescription(T.UNSIGNED), TypeDescription(T.DELTA_UNSIGNED))
    )
    items = [st(d(T.UNSIGNED, 1), d(T.DELTA_UNSIGNED, 1))]
    raw = DlmsData(T.COMPACT_ARRAY, CompactArray(desc, items))
    with pytest.raises(DecodeError, match="no base"):
        resolve_deltas(raw)


def test_errors_are_value_errors_too():
    with pytest.raises(ValueError):
        resolve_deltas(d(T.DELTA_LONG, 1))
