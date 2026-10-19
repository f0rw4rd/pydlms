"""Applying a COSEM ``scaler_unit`` (IEC 62056-6-2, Register class).

:class:`RegisterValue` pairs a raw value with its scaler and unit;
:func:`scaler_unit` decodes the ``{scaler, unit}`` structure.

The physical value is ``raw * 10**scaler``. A naive float multiplication
leaves binary noise (``2301 * 0.1 == 230.10000000000002``), so the result is
rounded to the precision the scaler implies.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pydlms.cosem.data import DlmsData
from pydlms.cosem.enums import DataType, Unit

__all__ = ["RegisterValue", "apply_scaler", "scaler_unit"]


def apply_scaler(raw: int | float, scaler: int) -> int | float:
    """``raw * 10**scaler``, rounded to the scaler's precision (no float noise).

    A non-negative scaler on an integer stays an integer.
    """
    if not scaler:
        return raw
    if scaler > 0 and isinstance(raw, int):
        return raw * 10**scaler
    return round(raw * 10.0**scaler, max(-scaler, 0) + 6)


@dataclass(frozen=True)
class RegisterValue:
    """A Register value with its scaler/unit applied."""

    raw: Any
    scaler: int
    unit: Unit | int | None

    @property
    def value(self) -> Any:
        if isinstance(self.raw, (int, float)) and not isinstance(self.raw, bool):
            return apply_scaler(self.raw, self.scaler)
        return self.raw

    @property
    def unit_symbol(self) -> str:
        if isinstance(self.unit, Unit):
            return self.unit.symbol
        return "" if self.unit is None else f"unit({self.unit})"

    def __str__(self) -> str:
        value = self.value
        if isinstance(value, float):
            value = round(value, 6)
        return f"{value} {self.unit_symbol}".strip()


def scaler_unit(data: DlmsData | None) -> tuple[int, Unit | int | None]:
    """Decode a ``scaler_unit`` structure ``{integer scaler, enum unit}``."""
    if data is None or data.tag != DataType.STRUCTURE or len(data.value) != 2:
        return 0, None
    scaler, unit = data.value[0].value, data.value[1].value
    try:
        unit = Unit(unit)
    except ValueError:
        pass
    return int(scaler or 0), unit
