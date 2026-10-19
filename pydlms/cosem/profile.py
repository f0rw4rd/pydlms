"""Typed Profile generic rows (IC 7 ``buffer``), also used for Compact data.

A profile buffer is an array of structures, one cell per capture object
``(class_id, logical_name, attribute_index, data_index)``. The raw cells are
plain COSEM ``Data``; this module gives them the type the capture object's
attribute has in the typed model (:mod:`pydlms.cosem.model`):

* a date-time attribute (Clock ``time``, Extended register ``capture_time``,
  Demand register ``capture_time`` / ``start_time_current``, ...) becomes a
  :class:`~pydlms.cosem.time.CosemDateTime`; any other typed attribute is
  decoded the same way (enums, structures). Untyped (``Any``) attributes stay
  plain Python, so a Unix-time column (Data object, ``double-long-unsigned``)
  stays an integer;
* the value of a Register / Extended register (attribute 2) and the
  current/last average value of a Demand register (attributes 2 and 3)
  becomes a :class:`~pydlms.cosem.scaler.RegisterValue` when its
  ``scaler_unit`` is known (Register attribute 3, Demand register
  attribute 4; Blue Book class descriptions, see ``cosem/model.py``);
* a cell whose content does not match the model stays plain Python, with a
  warning: meter data is untrusted and one bad cell must not lose the row.

``null-data`` cells become ``None``. Meters may "compress" a buffer by
sending null-data for a timestamp that follows from the previous one and the
capture period, and for a value equal to the previous entry's. The opt-in
fills reconstruct them:

* ``fill_timestamps``: a null Clock ``time`` cell (class 8, attribute 2) is
  the previous row's timestamp plus ``capture_period`` seconds for FIFO
  (``sort_method`` 1) and minus it for LIFO (2), keeping the previous
  deviation; a fill is never invented for other sort methods, a zero or
  unknown period, or a first row (those cells stay ``None`` and one warning
  per call is logged). The rule is per DSMR P3 4.2.2 (Netbeheer Nederland,
  2014) 5.5 note 5: a captured value "may be replaced by null-data if it
  can be unambiguously recovered from the previous value (for example for
  time: if it can be calculated from the previous value and
  capture_period; or for a value: if it is equal to the previous value".
  The LIFO direction (subtract) follows Gurux GXDLMSProfileGeneric only
  (*unverified*: the Green Book example, DLMS UA 1000-2 Ed. 12, 14.4, Table
  159, is not in the public excerpt).
* ``fill_values``: any other null cell repeats the previous row's value in
  that column (per the same DSMR note; Gurux does this for register
  columns only).
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Mapping, Sequence
from typing import Any

from pydlms.cosem import types as T
from pydlms.cosem.data import DlmsData
from pydlms.cosem.enums import DataType, Unit
from pydlms.cosem.interface_classes import ClassId
from pydlms.cosem.model import SCALER_UNIT, SortMethod, spec_for
from pydlms.cosem.scaler import RegisterValue
from pydlms.cosem.time import CosemDateTime
from pydlms.debug import get_logger
from pydlms.exceptions import DecodeError
from pydlms.obis import ObisCode

__all__ = [
    "Column",
    "ScalerUnitPair",
    "SCALED_ATTRIBUTES",
    "is_timestamp_column",
    "register_scaler",
    "scaled_registers",
    "type_cell",
    "typed_rows",
]

log = get_logger("profile")

#: A capture object: ``(class_id, logical_name, attribute_index, data_index)``.
Column = tuple[int, ObisCode, int, int]
#: ``(scaler, unit)`` as :func:`register_scaler` returns it.
ScalerUnitPair = tuple[int, Unit | int | None]

#: ``(class_id, value attribute) -> scaler_unit attribute`` of the classes
#: whose values carry a scaler (Blue Book: Register, Extended register,
#: Demand register).
SCALED_ATTRIBUTES: dict[tuple[int, int], int] = {
    (ClassId.REGISTER, 2): 3,
    (ClassId.EXTENDED_REGISTER, 2): 3,
    (ClassId.DEMAND_REGISTER, 2): 4,
    (ClassId.DEMAND_REGISTER, 3): 4,
}


def _scaler_attribute(column: Column) -> int | None:
    class_id, _, attribute, data_index = column
    if data_index:
        return None
    return SCALED_ATTRIBUTES.get((int(class_id), int(attribute)))


def is_timestamp_column(column: Column) -> bool:
    """Whether ``column`` is a Clock ``time`` (class 8, attribute 2) capture."""
    class_id, _, attribute, data_index = column
    return class_id == ClassId.CLOCK and attribute == 2 and not data_index


def scaled_registers(columns: Sequence[Column]) -> list[tuple[int, ObisCode, int]]:
    """``(class_id, logical_name, scaler_unit attribute)`` of every register
    whose value is captured in ``columns``, each object once, in column order."""
    out: list[tuple[int, ObisCode, int]] = []
    for column in columns:
        attribute = _scaler_attribute(column)
        if attribute is None:
            continue
        item = (int(column[0]), column[1], attribute)
        if item not in out:
            out.append(item)
    return out


def register_scaler(data: DlmsData) -> ScalerUnitPair:
    """Decode a ``scaler_unit`` attribute ``{integer scaler, enum unit}``.

    Unlike the lenient :func:`pydlms.cosem.scaler.scaler_unit` this raises
    :class:`DecodeError` on a malformed value instead of assuming scaler 0.
    """
    decoded = SCALER_UNIT.decode(data, "scaler_unit")
    return int(decoded.scaler), decoded.unit


def type_cell(column: Column, cell: DlmsData, scaler: ScalerUnitPair | None = None) -> Any:
    """The typed value of one profile cell (see the module docstring).

    ``scaler`` is the register's ``(scaler, unit)``; it is used only for a
    register value column (:data:`SCALED_ATTRIBUTES`).
    """
    if cell.tag == DataType.NULL:
        return None
    class_id, obis, attribute, data_index = column
    if scaler is not None and _scaler_attribute(column) is not None:
        return RegisterValue(cell.to_python(), *scaler)
    if not data_index:
        spec = spec_for(class_id)
        kind = spec.attribute(attribute).type if spec is not None else None
        if kind is not None and not isinstance(kind, T.Any):
            try:
                return kind.decode(cell, f"{obis}/{attribute}")
            except (DecodeError, ValueError) as exc:
                log.warning("profile cell %s/%s left untyped: %s", obis, attribute, exc)
    return cell.to_python()


def _scaler_map(scalers: Mapping[Any, ScalerUnitPair] | None) -> dict[ObisCode, ScalerUnitPair]:
    out: dict[ObisCode, ScalerUnitPair] = {}
    for key, value in (scalers or {}).items():
        obis = key if isinstance(key, ObisCode) else ObisCode.parse(str(key))
        out[obis] = value
    return out


def _step(capture_period: int | None, sort_method: int | None) -> _dt.timedelta | None:
    if not capture_period or capture_period < 0:
        return None
    if sort_method == SortMethod.FIFO:
        return _dt.timedelta(seconds=capture_period)
    if sort_method == SortMethod.LIFO:
        return -_dt.timedelta(seconds=capture_period)
    return None


def _next_stamp(previous: Any, step: _dt.timedelta | None) -> CosemDateTime | None:
    if step is None or not isinstance(previous, CosemDateTime):
        return None
    try:
        return CosemDateTime.from_datetime(previous.to_datetime() + step)
    except (ValueError, OverflowError):  # wildcard fields, or out of datetime's range
        return None


def typed_rows(
    columns: Sequence[Column],
    rows: Sequence[Sequence[DlmsData]],
    *,
    scalers: Mapping[Any, ScalerUnitPair] | None = None,
    fill_timestamps: bool = False,
    capture_period: int | None = None,
    sort_method: int | None = None,
    fill_values: bool = False,
) -> list[list[Any]]:
    """Type every cell of ``rows`` (raw ``Data`` cells, one per column).

    ``scalers`` maps a register's logical name (:class:`ObisCode` or text) to
    its ``(scaler, unit)``; registers without an entry stay unscaled.
    ``fill_timestamps`` needs the profile's ``capture_period`` (attribute 4)
    and ``sort_method`` (attribute 5). A row whose cell count differs from
    the columns raises :class:`DecodeError`.
    """
    by_obis = _scaler_map(scalers)
    step = _step(capture_period, sort_method) if fill_timestamps else None
    warned = False
    previous: list[Any] = [None] * len(columns)
    out: list[list[Any]] = []
    for number, row in enumerate(rows, 1):
        if len(row) != len(columns):
            raise DecodeError(
                f"profile row {number} has {len(row)} cells for {len(columns)} columns"
            )
        typed: list[Any] = []
        for index, (column, cell) in enumerate(zip(columns, row, strict=True)):
            value = type_cell(column, cell, by_obis.get(column[1]))
            if value is None and cell.tag == DataType.NULL:
                if is_timestamp_column(column):
                    if fill_timestamps:
                        value = _next_stamp(previous[index], step)
                        if value is None and step is None and not warned:
                            warned = True
                            log.warning(
                                "profile: cannot fill null timestamps (capture_period %s, "
                                "sort_method %s; needs FIFO or LIFO and a period > 0)",
                                capture_period,
                                sort_method,
                            )
                elif fill_values:
                    value = previous[index]
            typed.append(value)
            previous[index] = value
        out.append(typed)
    return out
