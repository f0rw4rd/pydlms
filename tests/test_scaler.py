"""Scaler application without float noise (regression: 230.10000000000002)."""

from __future__ import annotations

import pytest

from pydlms.client import RegisterValue
from pydlms.cosem.enums import Unit
from pydlms.cosem.scaler import apply_scaler


@pytest.mark.parametrize(
    "raw,scaler,expected",
    [
        (2301, -1, 230.1),
        (523, -2, 5.23),
        (-2301, -1, -230.1),
        (5, 3, 5000),
        (12, 0, 12),
        (1.5, -1, 0.15),
        (1, -3, 0.001),
    ],
)
def test_apply_scaler(raw, scaler, expected):
    assert apply_scaler(raw, scaler) == expected
    assert repr(apply_scaler(raw, scaler)) == repr(expected)


def test_positive_scaler_keeps_int():
    assert isinstance(apply_scaler(7, 2), int)


def test_register_value_string():
    assert str(RegisterValue(2301, -1, Unit.VOLT)) == "230.1 V"
    assert str(RegisterValue(12, 0, None)) == "12"
    assert RegisterValue("text", -1, None).value == "text"
