"""COSEM ``date``, ``time`` and ``date-time`` (IEC 62056-6-2, 4.1.6.1).

The codec in :mod:`pydlms.cosem.data` yields these as opaque octet payloads
(tags 25/26/27, or the 12-octet octet-string most meters actually send). This
module gives them meaning.

Layout of the 12-octet ``date-time``::

    year(2, big-endian) month day day-of-week hour minute second hundredths
    deviation(2, signed, minutes) clock-status(1)

Wildcards ("not specified"): year ``0xFFFF``, any single-octet field ``0xFF``,
deviation ``0x8000``. Month ``0xFD``/``0xFE`` mean DST end/begin, day ``0xFD``
/``0xFE`` mean second-last/last day of month; these are kept as raw ints.

Deviation is the offset **from local time to UTC** in minutes, so
``UTC = local + deviation`` and a CEST (UTC+2) timestamp carries ``-120``.
Some meters send the opposite sign; :meth:`CosemDateTime.to_datetime`
takes ``invert_deviation`` for those.
"""

from __future__ import annotations

import datetime as _dt
import struct
from dataclasses import dataclass
from enum import IntFlag

from pydlms.exceptions import DecodeError

__all__ = [
    "ClockStatus",
    "CosemDate",
    "CosemTime",
    "CosemDateTime",
    "NOT_SPECIFIED",
    "DEVIATION_NOT_SPECIFIED",
]

NOT_SPECIFIED = 0xFF
YEAR_NOT_SPECIFIED = 0xFFFF
DEVIATION_NOT_SPECIFIED = -0x8000  # 0x8000 as signed int16
#: Blue Book 4.1.6.1: deviation is -720..+720 minutes (or 0x8000).
DEVIATION_LIMIT = 720


class ClockStatus(IntFlag):
    """Clock status bits (Blue Book, clock_status)."""

    INVALID_VALUE = 0x01
    DOUBTFUL_VALUE = 0x02
    DIFFERENT_CLOCK_BASE = 0x04
    INVALID_CLOCK_STATUS = 0x08
    DAYLIGHT_SAVING_ACTIVE = 0x80


def _opt(value: int, wildcard: int = NOT_SPECIFIED) -> int | None:
    return None if value == wildcard else value


def _wild(value: int | None, wildcard: int = NOT_SPECIFIED) -> int:
    return wildcard if value is None else value


@dataclass(frozen=True)
class CosemDate:
    """A 5-octet COSEM date; ``None`` fields are wildcards."""

    year: int | None = None
    month: int | None = None
    day: int | None = None
    day_of_week: int | None = None

    @classmethod
    def from_bytes(cls, data: bytes) -> CosemDate:
        if len(data) != 5:
            raise DecodeError(f"COSEM date is 5 octets, got {len(data)}")
        year = struct.unpack(">H", data[0:2])[0]
        return cls(_opt(year, YEAR_NOT_SPECIFIED), _opt(data[2]), _opt(data[3]), _opt(data[4]))

    def to_bytes(self) -> bytes:
        return struct.pack(
            ">HBBB",
            _wild(self.year, YEAR_NOT_SPECIFIED),
            _wild(self.month),
            _wild(self.day),
            _wild(self.day_of_week),
        )

    @classmethod
    def from_date(cls, value: _dt.date) -> CosemDate:
        return cls(value.year, value.month, value.day, value.isoweekday())

    def to_date(self) -> _dt.date:
        if self.year is None or self.month is None or self.day is None:
            raise ValueError(f"cannot convert a wildcard date to datetime.date: {self}")
        if self.month > 12 or self.day > 31:
            raise ValueError(f"special month/day value cannot be a concrete date: {self}")
        return _dt.date(self.year, self.month, self.day)

    def __str__(self) -> str:
        y = "*" if self.year is None else f"{self.year:04d}"
        m = "*" if self.month is None else f"{self.month:02d}"
        d = "*" if self.day is None else f"{self.day:02d}"
        return f"{y}-{m}-{d}"


@dataclass(frozen=True)
class CosemTime:
    """A 4-octet COSEM time; ``None`` fields are wildcards."""

    hour: int | None = None
    minute: int | None = None
    second: int | None = None
    hundredths: int | None = None

    @classmethod
    def from_bytes(cls, data: bytes) -> CosemTime:
        if len(data) != 4:
            raise DecodeError(f"COSEM time is 4 octets, got {len(data)}")
        return cls(*(_opt(b) for b in data))

    def to_bytes(self) -> bytes:
        return bytes(_wild(v) for v in (self.hour, self.minute, self.second, self.hundredths))

    @classmethod
    def from_time(cls, value: _dt.time) -> CosemTime:
        return cls(value.hour, value.minute, value.second, value.microsecond // 10000)

    def to_time(self) -> _dt.time:
        if self.hour is None or self.minute is None:
            raise ValueError(f"cannot convert a wildcard time to datetime.time: {self}")
        return _dt.time(self.hour, self.minute, self.second or 0, (self.hundredths or 0) * 10000)

    def __str__(self) -> str:
        parts = ["*" if v is None else f"{v:02d}" for v in (self.hour, self.minute, self.second)]
        hs = "" if self.hundredths is None else f".{self.hundredths:02d}"
        return ":".join(parts) + hs


@dataclass(frozen=True)
class CosemDateTime:
    """A 12-octet COSEM date-time."""

    date: CosemDate
    time: CosemTime
    deviation: int | None = None  # minutes, local -> UTC; None = not specified
    clock_status: ClockStatus | None = None

    @classmethod
    def from_bytes(cls, data: bytes) -> CosemDateTime:
        if len(data) != 12:
            raise DecodeError(f"COSEM date-time is 12 octets, got {len(data)}")
        (deviation,) = struct.unpack(">h", data[9:11])
        if deviation != DEVIATION_NOT_SPECIFIED and abs(deviation) > DEVIATION_LIMIT:
            raise DecodeError(f"COSEM date-time deviation {deviation} is outside -720..720 minutes")
        status = data[11]
        return cls(
            CosemDate.from_bytes(data[0:5]),
            CosemTime.from_bytes(data[5:9]),
            None if deviation == DEVIATION_NOT_SPECIFIED else deviation,
            None if status == NOT_SPECIFIED else ClockStatus(status),
        )

    def to_bytes(self) -> bytes:
        deviation = DEVIATION_NOT_SPECIFIED if self.deviation is None else self.deviation
        status = NOT_SPECIFIED if self.clock_status is None else int(self.clock_status)
        return self.date.to_bytes() + self.time.to_bytes() + struct.pack(">hB", deviation, status)

    @classmethod
    def from_datetime(
        cls, value: _dt.datetime, clock_status: ClockStatus | None = None
    ) -> CosemDateTime:
        """Build from a Python datetime; an aware one carries its UTC offset."""
        deviation = None
        offset = value.utcoffset()
        if offset is not None:
            deviation = -int(offset.total_seconds() // 60)
        return cls(
            CosemDate.from_date(value.date()),
            CosemTime.from_time(value.time()),
            deviation,
            clock_status,
        )

    def to_datetime(self, invert_deviation: bool = False) -> _dt.datetime:
        """Convert to :class:`datetime.datetime`.

        Aware when the deviation is specified, naive otherwise. Raises
        :class:`ValueError` when date or time fields are wildcards.
        """
        naive = _dt.datetime.combine(self.date.to_date(), self.time.to_time())
        if self.deviation is None:
            return naive
        minutes = self.deviation if invert_deviation else -self.deviation
        return naive.replace(tzinfo=_dt.timezone(_dt.timedelta(minutes=minutes)))

    @property
    def is_fully_specified(self) -> bool:
        d, t = self.date, self.time
        return None not in (d.year, d.month, d.day, t.hour, t.minute)

    def __str__(self) -> str:
        text = f"{self.date} {self.time}"
        if self.deviation is not None:
            # Printed as the UTC offset of the local time (ISO convention).
            offset = -self.deviation
            sign = "+" if offset >= 0 else "-"
            text += f" {sign}{abs(offset) // 60:02d}:{abs(offset) % 60:02d}"
        return text
