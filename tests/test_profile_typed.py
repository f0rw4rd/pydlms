"""Typed Profile generic rows: pydlms.cosem.profile and DlmsClient.read_profile.

Cell typing follows the typed model (pydlms.cosem.model, Blue Book class
descriptions); register columns get their scaler_unit (Register attr 3,
Demand register attr 4). The null-data fill for compressed buffers is
cross-checked against Gurux GXDLMSProfileGeneric (timestamp + or -
capture_period by sort order); the Blue Book clause text is unverified.
"""

from __future__ import annotations

import datetime as dt
import logging

import pytest

from pydlms.apdu.xdlms import entry_descriptor
from pydlms.client import DlmsClient, ProfileBuffer
from pydlms.cosem.data import DlmsData
from pydlms.cosem.enums import Unit
from pydlms.cosem.interface_classes import ClassId
from pydlms.cosem.profile import (
    is_timestamp_column,
    register_scaler,
    scaled_registers,
    type_cell,
    typed_rows,
)
from pydlms.cosem.scaler import RegisterValue
from pydlms.cosem.time import CosemDateTime
from pydlms.exceptions import DecodeError
from pydlms.obis import ObisCode
from pydlms.simulator import example_meter, serve

CLOCK = (8, ObisCode.parse("0.0.1.0.0.255"), 2, 0)
ENERGY = (3, ObisCode.parse("1.0.1.8.0.255"), 2, 0)
DEMAND_CUR = (5, ObisCode.parse("1.0.1.4.0.255"), 2, 0)
DEMAND_LAST = (5, ObisCode.parse("1.0.1.4.0.255"), 3, 0)
EXT_TIME = (4, ObisCode.parse("1.0.1.6.0.255"), 5, 0)
UNIX = (1, ObisCode.parse("0.0.1.1.0.255"), 2, 0)

UTC = dt.timezone.utc
T0 = dt.datetime(2024, 5, 1, 0, 0, tzinfo=UTC)


def stamp(when: dt.datetime) -> DlmsData:
    return DlmsData.octet_string(CosemDateTime.from_datetime(when).to_bytes())


# --- type_cell ----------------------------------------------------------------------------


def test_clock_cell_becomes_cosem_date_time():
    value = type_cell(CLOCK, stamp(T0))
    assert isinstance(value, CosemDateTime)
    assert value.to_datetime() == T0


def test_date_time_tagged_cell_is_typed_too():
    raw = CosemDateTime.from_datetime(T0).to_bytes()
    assert type_cell(CLOCK, DlmsData(25, raw)).to_datetime() == T0  # tag 25 date-time


def test_extended_register_capture_time_is_typed_from_the_model():
    assert type_cell(EXT_TIME, stamp(T0)).to_datetime() == T0


@pytest.mark.parametrize(
    "cell",
    [
        DlmsData.octet_string(b"\x07\xe8\x05\x01"),  # 4 octets, not 12
        DlmsData.uint32(1714521600),  # an integer where the model says date-time
        # deviation 0x7000 is outside -720..720 minutes
        DlmsData.octet_string(bytes.fromhex("07e8050103000000ff700000")),
    ],
)
def test_a_cell_that_does_not_type_stays_raw_with_a_warning(cell, caplog):
    with caplog.at_level(logging.WARNING, logger="pydlms"):
        assert type_cell(CLOCK, cell) == cell.to_python()
    assert "0.0.1.0.0.255/2" in caplog.text


def test_unix_time_columns_stay_unconverted():
    assert type_cell(UNIX, DlmsData.uint32(1714521600)) == 1714521600


def test_null_cell_is_none():
    assert type_cell(CLOCK, DlmsData.null()) is None
    assert type_cell(ENERGY, DlmsData.null(), (-1, Unit.WATT_HOUR)) is None


def test_register_value_gets_scaler_and_unit():
    value = type_cell(ENERGY, DlmsData.uint32(12345), (-1, Unit.WATT_HOUR))
    assert value == RegisterValue(12345, -1, Unit.WATT_HOUR)
    assert value.value == 1234.5 and str(value) == "1234.5 Wh"


def test_register_value_without_scaler_is_plain():
    assert type_cell(ENERGY, DlmsData.uint32(12345)) == 12345


@pytest.mark.parametrize("column", [DEMAND_CUR, DEMAND_LAST])
def test_demand_register_value_attributes_are_scaled(column):
    assert type_cell(column, DlmsData.int32(-25), (2, Unit.WATT)).value == -2500


def test_element_of_an_attribute_is_not_typed_as_the_attribute():
    column = (8, CLOCK[1], 2, 3)  # data_index 3: one element, not the date-time
    assert type_cell(column, DlmsData.uint8(5)) == 5


def test_timestamp_column():
    assert is_timestamp_column(CLOCK)
    assert not is_timestamp_column(EXT_TIME)
    assert not is_timestamp_column((8, CLOCK[1], 2, 1))


# --- scalers ------------------------------------------------------------------------------


def test_scaled_registers_lists_each_register_once():
    columns = [CLOCK, ENERGY, DEMAND_CUR, DEMAND_LAST, ENERGY, UNIX, EXT_TIME]
    assert scaled_registers(columns) == [
        (3, ENERGY[1], 3),
        (5, DEMAND_CUR[1], 4),
    ]


def test_register_scaler_decodes_and_validates():
    good = DlmsData.structure([DlmsData.int8(-2), DlmsData.enum(33)])
    assert register_scaler(good) == (-2, Unit.AMPERE)
    assert register_scaler(DlmsData.structure([DlmsData.int8(0), DlmsData.enum(250)]))[1] == 250
    for bad in (
        DlmsData.uint8(3),
        DlmsData.structure([DlmsData.int8(-2)]),
        DlmsData.structure([DlmsData.octet_string(b"x"), DlmsData.enum(33)]),
    ):
        with pytest.raises(DecodeError):
            register_scaler(bad)


# --- typed_rows and the fill options ----------------------------------------------------


def rows_of(*values):
    return [list(r) for r in values]


def compressed():
    """Three rows; rows 2 and 3 omit the timestamp, row 3 the value too."""
    null = DlmsData.null()
    return rows_of(
        [stamp(T0), DlmsData.uint32(100)],
        [null, DlmsData.uint32(107)],
        [null, null],
    )


def test_typed_rows_without_fill_leave_nulls():
    rows = typed_rows([CLOCK, ENERGY], compressed())
    assert rows[0][0].to_datetime() == T0
    assert [r[1:] for r in rows] == [[100], [107], [None]]
    assert rows[1][0] is None and rows[2][0] is None


def test_fifo_fill_adds_the_capture_period():
    rows = typed_rows(
        [CLOCK, ENERGY], compressed(), fill_timestamps=True, capture_period=900, sort_method=1
    )
    assert [r[0].to_datetime() for r in rows] == [
        T0 + dt.timedelta(minutes=15 * i) for i in (0, 1, 2)
    ]
    assert rows[2][1] is None  # values are filled only with fill_values


def test_lifo_fill_subtracts_the_capture_period():
    rows = typed_rows(
        [CLOCK, ENERGY], compressed(), fill_timestamps=True, capture_period=60, sort_method=2
    )
    assert [r[0].to_datetime() for r in rows] == [T0 - dt.timedelta(minutes=i) for i in (0, 1, 2)]


def test_fill_keeps_the_deviation_of_the_previous_stamp():
    local = dt.datetime(2024, 5, 1, 2, 0, tzinfo=dt.timezone(dt.timedelta(hours=2)))
    rows = typed_rows(
        [CLOCK], rows_of([stamp(local)], [DlmsData.null()]),
        fill_timestamps=True, capture_period=900, sort_method=1,
    )  # fmt: skip
    assert rows[1][0].deviation == -120
    assert rows[1][0].to_datetime() == local + dt.timedelta(minutes=15)


@pytest.mark.parametrize(
    "period,sort",
    [(0, 1), (None, 1), (900, 3), (900, None), (900, 4)],
    ids=["period-0", "period-unknown", "largest", "sort-unknown", "smallest"],
)
def test_fill_is_left_out_without_fifo_or_lifo_and_a_period(period, sort, caplog):
    with caplog.at_level(logging.WARNING, logger="pydlms"):
        rows = typed_rows(
            [CLOCK, ENERGY],
            compressed(),
            fill_timestamps=True,
            capture_period=period,
            sort_method=sort,
        )
    assert rows[1][0] is None and rows[2][0] is None
    assert caplog.text.count("cannot fill") == 1  # one warning per call, not per cell


def test_a_first_row_without_timestamp_is_not_filled():
    rows = typed_rows(
        [CLOCK], rows_of([DlmsData.null()], [stamp(T0)]),
        fill_timestamps=True, capture_period=900, sort_method=1,
    )  # fmt: skip
    assert rows[0][0] is None and rows[1][0].to_datetime() == T0


def test_value_fill_repeats_the_previous_value():
    scalers = {ENERGY[1]: (0, Unit.WATT_HOUR)}
    rows = typed_rows([CLOCK, ENERGY], compressed(), scalers=scalers, fill_values=True)
    assert [r[1].raw for r in rows] == [100, 107, 107]
    assert rows[2][0] is None  # a timestamp is never value-filled


def test_typed_rows_rejects_rows_that_do_not_match_the_columns():
    with pytest.raises(DecodeError, match="row 2"):
        typed_rows([CLOCK, ENERGY], rows_of([stamp(T0), DlmsData.uint8(1)], [stamp(T0)]))


# --- DlmsClient.read_profile ----------------------------------------------------------------

PROFILE = "1.0.99.1.0.255"
KEY = (ClassId.PROFILE_GENERIC, ObisCode.parse(PROFILE))


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


def with_list_reads(meter) -> list[bytes]:
    return [r for r in meter.requests if r[:2] == b"\xc0\x03"]


def add_column(meter, class_id, obis, attribute, values):
    """Append a capture object and one cell per row to the example profile."""
    objects = meter.objects[KEY]
    objects[3].value.append(
        DlmsData.structure(
            [
                DlmsData.uint16(class_id),
                DlmsData.octet_string(ObisCode.parse(obis).to_bytes()),
                DlmsData.int8(attribute),
                DlmsData.uint16(0),
            ]
        )
    )
    for row, value in zip(objects[2].value, values, strict=False):
        row.value.append(value)


def test_default_read_is_unchanged_and_keeps_the_raw_cells(meter):
    with connect(meter) as m:
        profile = m.read_profile(PROFILE)
    assert isinstance(profile.rows[0][0], bytes) and profile.rows[0][1] == 1000
    assert profile.cells[0][0].tag.name == "OCTET_STRING"
    assert [c.to_python() for c in profile.cells[5]] == profile.rows[5]
    assert ProfileBuffer(profile.columns, profile.rows).cells == []  # positional callers


def test_typed_read_returns_date_times(meter):
    with connect(meter) as m:
        profile = m.read_profile(PROFILE, typed=True)
    stamps = [row[0].to_datetime() for row in profile.rows]
    assert stamps == [T0 + dt.timedelta(minutes=15 * i) for i in range(96)]
    assert profile.rows[1][1] == 1007  # scalers not asked for: plain value
    assert not with_list_reads(meter)


def test_scalers_are_read_once_per_register_with_get_many(meter):
    add_column(meter, 3, "1.0.32.7.0.255", 2, [DlmsData.uint16(2301 + i) for i in range(96)])
    add_column(meter, 3, "1.0.32.7.0.255", 2, [DlmsData.uint16(2301 + i) for i in range(96)])
    with connect(meter) as m:
        profile = m.read_profile(PROFILE, scalers=True)
        assert len(with_list_reads(meter)) == 1
        again = m.read_profile(PROFILE, typed=True, scalers=True)
        assert len(with_list_reads(meter)) == 1  # cached on the client
    row = profile.rows[0]
    assert row[1] == RegisterValue(1000, 0, Unit.WATT_HOUR)
    assert row[2] == RegisterValue(2301, -1, Unit.VOLT) and row[2].value == 230.1
    assert again.rows == profile.rows


def test_a_scaler_that_cannot_be_read_leaves_the_value_plain(meter, caplog):
    add_column(meter, 3, "9.9.9.9.9.9", 2, [DlmsData.uint16(i) for i in range(96)])
    with caplog.at_level(logging.WARNING, logger="pydlms"), connect(meter) as m:
        profile = m.read_profile(PROFILE, scalers=True)
    assert profile.rows[3][2] == 3
    assert isinstance(profile.rows[3][1], RegisterValue)
    assert "9.9.9.9.9.9" in caplog.text


def test_scalers_from_a_mapping_are_not_read(meter):
    with connect(meter) as m:
        profile = m.read_profile(PROFILE, scalers={"1.0.1.8.0.255": (3, Unit.WATT_HOUR)})
    assert profile.rows[1][1].value == 1007000
    assert not with_list_reads(meter)


def test_typed_read_follows_the_narrowed_columns(meter):
    with connect(meter) as m:
        profile = m.read_profile(PROFILE, entry_descriptor(10, 11, 2, 2), scalers=True)
    assert profile.rows == [
        [RegisterValue(1063, 0, Unit.WATT_HOUR)],
        [RegisterValue(1070, 0, Unit.WATT_HOUR)],
    ]
    assert [len(r) for r in profile.cells] == [1, 1]


def test_fill_timestamps_reads_capture_period_and_sort_method(meter):
    rows = meter.objects[KEY][2].value
    for row in rows[1:4]:
        row.value[0] = DlmsData.null()
    rows[3].value[1] = DlmsData.null()
    with connect(meter) as m:
        plain = m.read_profile(PROFILE, typed=True)
        filled = m.read_profile(PROFILE, fill_timestamps=True, fill_values=True)
    assert plain.rows[2][0] is None
    stamps = [row[0].to_datetime() for row in filled.rows]
    assert stamps == [T0 + dt.timedelta(minutes=15 * i) for i in range(96)]
    assert [row[1] for row in filled.rows[2:5]] == [1014, 1014, 1028]


# --- resolve_deltas (provisional, pydlms.cosem.delta) -------------------------------------------


def _delta_energy(meter):
    """Rows 1.. of the energy column become delta-unsigned 7 (row 0 stays 1000)."""
    from pydlms.cosem.enums import DataType

    rows = meter.objects[(ClassId.PROFILE_GENERIC, ObisCode.parse(PROFILE))][2].value
    for row in rows[1:]:
        row.value[1] = DlmsData(DataType.DELTA_UNSIGNED, 7)


def test_resolve_deltas_off_by_default_keeps_raw_deltas(meter):
    _delta_energy(meter)
    with connect(meter) as m:
        profile = m.read_profile(PROFILE)
    assert [row[1] for row in profile.rows[:3]] == [1000, 7, 7]


@pytest.mark.parametrize("typed", [False, True])
def test_resolve_deltas_resolves_rows_and_keeps_cells(meter, typed):
    _delta_energy(meter)
    with connect(meter) as m:
        profile = m.read_profile(PROFILE, typed=typed, resolve_deltas=True)
    assert [row[1] for row in profile.rows] == [1000 + 7 * i for i in range(96)]
    assert profile.cells[1][1].tag.name == "DELTA_UNSIGNED"  # received Data untouched
    assert profile.cells[1][1].value == 7
    if typed:
        assert profile.rows[1][0].to_datetime() == T0 + dt.timedelta(minutes=15)


def test_resolve_deltas_without_base_raises(meter):
    from pydlms.cosem.enums import DataType

    rows = meter.objects[(ClassId.PROFILE_GENERIC, ObisCode.parse(PROFILE))][2].value
    rows[0].value[1] = DlmsData(DataType.DELTA_UNSIGNED, 1)
    with connect(meter) as m, pytest.raises(DecodeError, match="no base"):
        m.read_profile(PROFILE, resolve_deltas=True)
