"""COSEM enumerations (IEC 62056-6-2).

These are small, stable, factual value sets from the standard: the A-XDR data
type tags, the physical unit table, and the result/diagnostic codes used by the
xDLMS services. They are hand-authored from the standard (no table copied from
another implementation).
"""

from __future__ import annotations

from enum import IntEnum

__all__ = [
    "DataType",
    "Unit",
    "DataAccessResult",
    "ActionResult",
    "AssociationResult",
    "result_name",
]


class DataType(IntEnum):
    """Tag byte of a COSEM ``Data`` value (A-XDR CHOICE, IEC 62056-6-2 Annex A)."""

    NULL = 0
    ARRAY = 1
    STRUCTURE = 2
    BOOLEAN = 3
    BIT_STRING = 4
    DOUBLE_LONG = 5  # int32
    DOUBLE_LONG_UNSIGNED = 6  # uint32
    OCTET_STRING = 9
    VISIBLE_STRING = 10
    UTF8_STRING = 12
    BCD = 13
    INTEGER = 15  # int8
    LONG = 16  # int16
    UNSIGNED = 17  # uint8
    LONG_UNSIGNED = 18  # uint16
    COMPACT_ARRAY = 19
    LONG64 = 20  # int64
    LONG64_UNSIGNED = 21  # uint64
    ENUM = 22  # uint8
    FLOAT32 = 23
    FLOAT64 = 24
    DATE_TIME = 25  # 12 octets
    DATE = 26  # 5 octets
    TIME = 27  # 4 octets
    # Delta types: the same wire form as the base integer, but the value is a
    # difference to the previous element. Tags and base types per DLMS UA
    # 1000-1 Ed. 17 Part 2 Excerpt 4.1.5 Table 3 (delta-integer [28] Integer8
    # .. delta-double-long-unsigned [33] Unsigned32); added to the Green Book
    # in Ed. 10 (DLMS UA 1000-2 Ed. 12 Excerpt, change list, 9.5). The
    # accumulation rule is not in the public excerpts (cosem/delta.py).
    DELTA_INTEGER = 28  # int8
    DELTA_LONG = 29  # int16
    DELTA_DOUBLE_LONG = 30  # int32
    DELTA_UNSIGNED = 31  # uint8
    DELTA_LONG_UNSIGNED = 32  # uint16
    DELTA_DOUBLE_LONG_UNSIGNED = 33  # uint32
    DONT_CARE = 255  # Green Book Data CHOICE: dont-care [255] IMPLICIT NULL


class Unit(IntEnum):
    """Physical unit enumeration (IEC 62056-6-2, enumeration of physical units).

    Values follow the standard's unit table. The member name is an ASCII-safe
    identifier; :attr:`symbol` gives the printed unit.
    """

    YEAR = 1
    MONTH = 2
    WEEK = 3
    DAY = 4
    HOUR = 5
    MINUTE = 6
    SECOND = 7
    DEGREE = 8  # phase angle
    DEGREE_CELSIUS = 9
    CURRENCY = 10
    METRE = 11
    METRE_PER_SECOND = 12
    CUBIC_METRE = 13
    CUBIC_METRE_CORRECTED = 14
    CUBIC_METRE_PER_HOUR = 15
    CUBIC_METRE_PER_HOUR_CORRECTED = 16
    CUBIC_METRE_PER_DAY = 17
    CUBIC_METRE_PER_DAY_CORRECTED = 18
    LITRE = 19
    KILOGRAM = 20
    NEWTON = 21
    NEWTON_METRE = 22
    PASCAL = 23
    BAR = 24
    JOULE = 25
    JOULE_PER_HOUR = 26
    WATT = 27
    VOLT_AMPERE = 28
    VAR = 29
    WATT_HOUR = 30
    VOLT_AMPERE_HOUR = 31
    VAR_HOUR = 32
    AMPERE = 33
    COULOMB = 34
    VOLT = 35
    VOLT_PER_METRE = 36
    FARAD = 37
    OHM = 38
    OHM_METRE2_PER_METRE = 39
    WEBER = 40
    TESLA = 41
    AMPERE_PER_METRE = 42
    HENRY = 43
    HERTZ = 44
    ACTIVE_ENERGY_METER_CONSTANT = 45  # 1/(Wh)
    REACTIVE_ENERGY_METER_CONSTANT = 46  # 1/(varh)
    APPARENT_ENERGY_METER_CONSTANT = 47  # 1/(VAh)
    VOLT_SQUARED_HOURS = 48
    AMPERE_SQUARED_HOURS = 49
    KILOGRAM_PER_SECOND = 50
    SIEMENS = 51
    KELVIN = 52
    VOLT_SQUARED_HOUR_METER_CONSTANT = 53  # 1/(V2h)
    AMPERE_SQUARED_HOUR_METER_CONSTANT = 54  # 1/(A2h)
    PER_CUBIC_METRE = 55  # 1/m3
    PERCENTAGE = 56
    AMPERE_HOUR = 57
    ENERGY_PER_VOLUME = 60  # Wh/m3
    CALORIFIC_VALUE = 61  # J/m3
    MOLE_PERCENT = 62
    MASS_DENSITY = 63  # g/m3
    DYNAMIC_VISCOSITY = 64  # Pa s
    SPECIFIC_ENERGY = 65  # J/kg
    GRAM_PER_SQUARE_CENTIMETRE = 66  # g/cm2
    ATMOSPHERE = 67  # atm
    DBM = 70  # signal strength
    DB_MICROVOLT = 71
    DECIBEL = 72
    # Non-SI units 128..174: DLMS UA 1000-1 Ed. 13 Excerpt (Blue Book,
    # 2019-05-08), 4.3.2 Table 4, pp. 52-53 (public excerpt); every value
    # cross-checked against the Gurux C DLMS_UNIT enum (GPL, facts only).
    # Member names follow the table's unit names; 151, 161 and 166 are the
    # "meter constant or pulse value" volume entries next to 137, 139, 140.
    INCH = 128
    FOOT = 129
    POUND = 130
    DEGREE_FAHRENHEIT = 131
    DEGREE_RANKINE = 132
    SQUARE_INCH = 133
    SQUARE_FOOT = 134
    ACRE = 135
    CUBIC_INCH = 136
    CUBIC_FOOT = 137  # volume
    ACRE_FOOT = 138
    GALLON_IMPERIAL = 139  # volume
    GALLON_US = 140  # volume
    POUND_FORCE = 141
    POUND_FORCE_PER_SQUARE_INCH = 142
    POUND_PER_CUBIC_FOOT = 143
    POUND_PER_FOOT_SECOND = 144
    SQUARE_FOOT_PER_SECOND = 145
    BRITISH_THERMAL_UNIT = 146
    THERM_EU = 147  # Therm (EU); the table's symbol is thm(EC)
    THERM_US = 148
    BTU_PER_POUND = 149
    BTU_PER_CUBIC_FOOT = 150
    CUBIC_FEET = 151  # volume: meter constant or pulse value
    FOOT_PER_SECOND = 152
    CUBIC_FOOT_PER_SECOND = 153
    CUBIC_FOOT_PER_MINUTE = 154
    CUBIC_FOOT_PER_HOUR = 155
    CUBIC_FOOT_PER_DAY = 156
    ACRE_FOOT_PER_SECOND = 157
    ACRE_FOOT_PER_MINUTE = 158
    ACRE_FOOT_PER_HOUR = 159
    ACRE_FOOT_PER_DAY = 160
    IMPERIAL_GALLON = 161  # volume: meter constant or pulse value
    IMPERIAL_GALLON_PER_SECOND = 162
    IMPERIAL_GALLON_PER_MINUTE = 163
    IMPERIAL_GALLON_PER_HOUR = 164
    IMPERIAL_GALLON_PER_DAY = 165
    US_GALLON = 166  # volume: meter constant or pulse value
    US_GALLON_PER_SECOND = 167
    US_GALLON_PER_MINUTE = 168
    US_GALLON_PER_HOUR = 169
    US_GALLON_PER_DAY = 170
    BTU_PER_SECOND = 171
    BTU_PER_MINUTE = 172
    BTU_PER_HOUR = 173
    BTU_PER_DAY = 174
    OTHER = 254
    COUNT = 255  # unitless

    @property
    def symbol(self) -> str:
        return _UNIT_SYMBOLS.get(self, self.name.lower())


_UNIT_SYMBOLS: dict[Unit, str] = {
    Unit.YEAR: "a",
    Unit.MONTH: "mo",
    Unit.WEEK: "wk",
    Unit.DAY: "d",
    Unit.HOUR: "h",
    Unit.MINUTE: "min",
    Unit.SECOND: "s",
    Unit.DEGREE: "deg",
    Unit.DEGREE_CELSIUS: "degC",
    Unit.METRE: "m",
    Unit.METRE_PER_SECOND: "m/s",
    Unit.CUBIC_METRE: "m3",
    Unit.CUBIC_METRE_PER_HOUR: "m3/h",
    Unit.LITRE: "l",
    Unit.KILOGRAM: "kg",
    Unit.NEWTON: "N",
    Unit.NEWTON_METRE: "Nm",
    Unit.PASCAL: "Pa",
    Unit.BAR: "bar",
    Unit.JOULE: "J",
    Unit.WATT: "W",
    Unit.VOLT_AMPERE: "VA",
    Unit.VAR: "var",
    Unit.WATT_HOUR: "Wh",
    Unit.VOLT_AMPERE_HOUR: "VAh",
    Unit.VAR_HOUR: "varh",
    Unit.AMPERE: "A",
    Unit.COULOMB: "C",
    Unit.VOLT: "V",
    Unit.FARAD: "F",
    Unit.OHM: "Ohm",
    Unit.WEBER: "Wb",
    Unit.TESLA: "T",
    Unit.HENRY: "H",
    Unit.HERTZ: "Hz",
    Unit.SIEMENS: "S",
    Unit.KELVIN: "K",
    Unit.PERCENTAGE: "%",
    Unit.AMPERE_HOUR: "Ah",
    Unit.GRAM_PER_SQUARE_CENTIMETRE: "g/cm2",
    Unit.ATMOSPHERE: "atm",
    Unit.DBM: "dBm",
    Unit.DECIBEL: "dB",
    Unit.INCH: "in",
    Unit.FOOT: "ft",
    Unit.POUND: "lb",
    Unit.DEGREE_FAHRENHEIT: "degF",
    Unit.DEGREE_RANKINE: "degR",
    Unit.SQUARE_INCH: "sq in",
    Unit.SQUARE_FOOT: "sq ft",
    Unit.ACRE: "ac",
    Unit.CUBIC_INCH: "cu in",
    Unit.CUBIC_FOOT: "cu ft",
    Unit.ACRE_FOOT: "ac ft",
    Unit.GALLON_IMPERIAL: "gal (imp)",
    Unit.GALLON_US: "gal (US)",
    Unit.POUND_FORCE: "lbf",
    Unit.POUND_FORCE_PER_SQUARE_INCH: "psi",
    Unit.POUND_PER_CUBIC_FOOT: "lb/cu ft",
    Unit.POUND_PER_FOOT_SECOND: "lb/(ft s)",
    Unit.SQUARE_FOOT_PER_SECOND: "sq ft/s",
    Unit.BRITISH_THERMAL_UNIT: "Btu",
    Unit.THERM_EU: "thm (EC)",
    Unit.THERM_US: "thm (US)",
    Unit.BTU_PER_POUND: "Btu/lb",
    Unit.BTU_PER_CUBIC_FOOT: "Btu/cu ft",
    Unit.CUBIC_FEET: "cu ft",
    Unit.FOOT_PER_SECOND: "ft/s",
    Unit.CUBIC_FOOT_PER_SECOND: "cu ft/s",
    Unit.CUBIC_FOOT_PER_MINUTE: "cu ft/min",
    Unit.CUBIC_FOOT_PER_HOUR: "cu ft/h",
    Unit.CUBIC_FOOT_PER_DAY: "cu ft/d",
    Unit.ACRE_FOOT_PER_SECOND: "ac ft/s",
    Unit.ACRE_FOOT_PER_MINUTE: "ac ft/min",
    Unit.ACRE_FOOT_PER_HOUR: "ac ft/h",
    Unit.ACRE_FOOT_PER_DAY: "ac ft/d",
    Unit.IMPERIAL_GALLON: "gal (imp)",
    Unit.IMPERIAL_GALLON_PER_SECOND: "gal (imp)/s",
    Unit.IMPERIAL_GALLON_PER_MINUTE: "gal (imp)/min",
    Unit.IMPERIAL_GALLON_PER_HOUR: "gal (imp)/h",
    Unit.IMPERIAL_GALLON_PER_DAY: "gal (imp)/d",
    Unit.US_GALLON: "gal (US)",
    Unit.US_GALLON_PER_SECOND: "gal (US)/s",
    Unit.US_GALLON_PER_MINUTE: "gal (US)/min",
    Unit.US_GALLON_PER_HOUR: "gal (US)/h",
    Unit.US_GALLON_PER_DAY: "gal (US)/d",
    Unit.BTU_PER_SECOND: "Btu/s",
    Unit.BTU_PER_MINUTE: "Btu/min",
    Unit.BTU_PER_HOUR: "Btu/h",
    Unit.BTU_PER_DAY: "Btu/d",
    Unit.COUNT: "",
}


class DataAccessResult(IntEnum):
    """Result of a GET/SET on a single attribute (IEC 62056-5-3)."""

    SUCCESS = 0
    HARDWARE_FAULT = 1
    TEMPORARY_FAILURE = 2
    READ_WRITE_DENIED = 3
    OBJECT_UNDEFINED = 4
    OBJECT_CLASS_INCONSISTENT = 9
    OBJECT_UNAVAILABLE = 11
    TYPE_UNMATCHED = 12
    SCOPE_OF_ACCESS_VIOLATED = 13
    DATA_BLOCK_UNAVAILABLE = 14
    LONG_GET_ABORTED = 15
    NO_LONG_GET_IN_PROGRESS = 16
    LONG_SET_ABORTED = 17
    NO_LONG_SET_IN_PROGRESS = 18
    DATA_BLOCK_NUMBER_INVALID = 19
    OTHER_REASON = 250


class ActionResult(IntEnum):
    """Result of an ACTION on a method (IEC 62056-5-3)."""

    SUCCESS = 0
    HARDWARE_FAULT = 1
    TEMPORARY_FAILURE = 2
    READ_WRITE_DENIED = 3
    OBJECT_UNDEFINED = 4
    OBJECT_CLASS_INCONSISTENT = 9
    OBJECT_UNAVAILABLE = 11
    TYPE_UNMATCHED = 12
    SCOPE_OF_ACCESS_VIOLATED = 13
    DATA_BLOCK_UNAVAILABLE = 14
    LONG_ACTION_ABORTED = 15
    NO_LONG_ACTION_IN_PROGRESS = 16
    OTHER_REASON = 250


def result_name(value: int) -> str:
    """Name of a result code that may be undefined (kept as a bare ``int``).

    Decoders keep codes outside :class:`DataAccessResult` / :class:`ActionResult`
    (vendor-specific, or from a newer edition) as the integer the meter sent.
    """
    if isinstance(value, IntEnum):
        return value.name
    return f"undefined result {int(value)}"


class AssociationResult(IntEnum):
    """ACSE AARE top-level result (IEC 62056-5-3 / ISO 8650)."""

    ACCEPTED = 0
    REJECTED_PERMANENT = 1
    REJECTED_TRANSIENT = 2
