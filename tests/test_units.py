"""Physical unit enumeration entries 66, 67 and the non-SI units 128..174.

Source for every value here: DLMS UA 1000-1 Ed. 13 Excerpt (Blue Book,
2019-05-08), 4.3.2 Table 4 "Enumerated values for physical units", pp.
51-53, publicly downloadable from DLMS UA (dlms.com/files/
Blue_Book_Edition_13-Excerpt.pdf, archived copy). 66 and 67 are also in
reitermarkus/dlms-cosem-rs ``src/unit.rs:76-77`` (MIT or Apache-2.0), which
lists 128..174 as a "non-SI units" range without names; the Gurux C
``DLMS_UNIT`` enum (GPL, facts cross-checked only, nothing copied) agrees
on every 128..174 value.
"""

from __future__ import annotations

import pytest

from pydlms.cosem.enums import Unit

# (code, member name, symbol): the table's unit column, ASCII-safe.
NON_SI = [
    (128, "INCH", "in"),
    (129, "FOOT", "ft"),
    (130, "POUND", "lb"),
    (131, "DEGREE_FAHRENHEIT", "degF"),
    (132, "DEGREE_RANKINE", "degR"),
    (133, "SQUARE_INCH", "sq in"),
    (134, "SQUARE_FOOT", "sq ft"),
    (135, "ACRE", "ac"),
    (136, "CUBIC_INCH", "cu in"),
    (137, "CUBIC_FOOT", "cu ft"),
    (138, "ACRE_FOOT", "ac ft"),
    (139, "GALLON_IMPERIAL", "gal (imp)"),
    (140, "GALLON_US", "gal (US)"),
    (141, "POUND_FORCE", "lbf"),
    (142, "POUND_FORCE_PER_SQUARE_INCH", "psi"),
    (143, "POUND_PER_CUBIC_FOOT", "lb/cu ft"),
    (144, "POUND_PER_FOOT_SECOND", "lb/(ft s)"),
    (145, "SQUARE_FOOT_PER_SECOND", "sq ft/s"),
    (146, "BRITISH_THERMAL_UNIT", "Btu"),
    (147, "THERM_EU", "thm (EC)"),
    (148, "THERM_US", "thm (US)"),
    (149, "BTU_PER_POUND", "Btu/lb"),
    (150, "BTU_PER_CUBIC_FOOT", "Btu/cu ft"),
    (151, "CUBIC_FEET", "cu ft"),
    (152, "FOOT_PER_SECOND", "ft/s"),
    (153, "CUBIC_FOOT_PER_SECOND", "cu ft/s"),
    (154, "CUBIC_FOOT_PER_MINUTE", "cu ft/min"),
    (155, "CUBIC_FOOT_PER_HOUR", "cu ft/h"),
    (156, "CUBIC_FOOT_PER_DAY", "cu ft/d"),
    (157, "ACRE_FOOT_PER_SECOND", "ac ft/s"),
    (158, "ACRE_FOOT_PER_MINUTE", "ac ft/min"),
    (159, "ACRE_FOOT_PER_HOUR", "ac ft/h"),
    (160, "ACRE_FOOT_PER_DAY", "ac ft/d"),
    (161, "IMPERIAL_GALLON", "gal (imp)"),
    (162, "IMPERIAL_GALLON_PER_SECOND", "gal (imp)/s"),
    (163, "IMPERIAL_GALLON_PER_MINUTE", "gal (imp)/min"),
    (164, "IMPERIAL_GALLON_PER_HOUR", "gal (imp)/h"),
    (165, "IMPERIAL_GALLON_PER_DAY", "gal (imp)/d"),
    (166, "US_GALLON", "gal (US)"),
    (167, "US_GALLON_PER_SECOND", "gal (US)/s"),
    (168, "US_GALLON_PER_MINUTE", "gal (US)/min"),
    (169, "US_GALLON_PER_HOUR", "gal (US)/h"),
    (170, "US_GALLON_PER_DAY", "gal (US)/d"),
    (171, "BTU_PER_SECOND", "Btu/s"),
    (172, "BTU_PER_MINUTE", "Btu/min"),
    (173, "BTU_PER_HOUR", "Btu/h"),
    (174, "BTU_PER_DAY", "Btu/d"),
]


@pytest.mark.parametrize(
    "code,name,symbol",
    [(66, "GRAM_PER_SQUARE_CENTIMETRE", "g/cm2"), (67, "ATMOSPHERE", "atm"), *NON_SI],
)
def test_units(code, name, symbol):
    unit = Unit(code)
    assert unit.name == name
    assert unit.symbol == symbol
    assert Unit[name] == code


def test_non_si_range_is_complete():
    assert [code for code, _, _ in NON_SI] == list(range(128, 175))


def test_neighbours_unchanged_and_reserved_stay_unknown():
    assert Unit(65) is Unit.SPECIFIC_ENERGY
    assert Unit(70) is Unit.DBM
    assert Unit(254) is Unit.OTHER
    # Table 4: 58, 59, 68, 69, 73..127 and 175..252 are reserved; 253
    # ("extended table of units") is not modelled.
    for reserved in (58, 59, 68, 69, 73, 127, 175, 252, 253):
        with pytest.raises(ValueError):
            Unit(reserved)


def test_non_si_unit_decodes_from_scaler_unit():
    from pydlms.cosem.data import decode_data
    from pydlms.cosem.scaler import scaler_unit

    # structure { integer(-1), enum(140) }: a register in US gallons / 10.
    data, _ = decode_data(bytes.fromhex("02020fff168c"))
    assert scaler_unit(data) == (-1, Unit.GALLON_US)
