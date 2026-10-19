"""DSMR / SMR 5 P1 telegrams (NL, BE e-MUCS, LU Smarty).

The P1 port does not speak A-XDR: it emits an ASCII telegram every second
(IEC 62056-21 mode D style), as described in the public DSMR 5.0.2 P1
Companion Standard (Netbeheer Nederland)::

    /ISK5\\2M550T-1012          header: manufacturer id + identification
                               (blank line)
    1-3:0.2.8(50)              OBIS(value)
    0-0:1.0.0(190101120000W)   timestamp YYMMDDhhmmss + W(inter)/S(ummer)
    1-0:1.8.1(001234.567*kWh)  number*unit
    0-1:24.2.1(190101120000W)(01234.567*m3)   several values on one line
    !EF2F                      CRC-16/ARC over "/" .. "!" inclusive, hex

Luxembourg Smarty meters wrap the same telegram in a general-glo-ciphering
APDU (0xDB, SC 0x30); :func:`decrypt_frame` unwraps it with a
:class:`~pydlms.security.context.SecurityContext` and parses the plaintext.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field

from pydlms.exceptions import ChecksumError, DecodeError
from pydlms.obis import ObisCode

__all__ = ["crc16_arc", "DsmrValue", "DsmrTelegram", "parse_telegram", "decrypt_frame"]

_LINE = re.compile(r"^(\d+)-(\d+):(\d+)\.(\d+)\.(\d+)((?:\([^)]*\))+)\s*$")
_GROUP = re.compile(r"\(([^)]*)\)")
_NUMBER = re.compile(r"^([-+]?\d+(?:\.\d+)?)(?:\*(.+))?$")
_TIMESTAMP = re.compile(r"^(\d{12})([WS])$")


def crc16_arc(data: bytes) -> int:
    """CRC-16/ARC (poly 0x8005 reflected, init 0): check value 0xBB3D."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


@dataclass
class DsmrValue:
    """One parenthesised value: number + unit, timestamp, or raw text."""

    raw: str
    number: float | int | None = None
    unit: str | None = None
    timestamp: dt.datetime | None = None

    @property
    def value(self):
        if self.number is not None:
            return self.number
        if self.timestamp is not None:
            return self.timestamp
        return _hex_text(self.raw)


def _hex_text(raw: str) -> str:
    """Equipment ids and messages are sent as hex-encoded ASCII."""
    if raw and len(raw) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", raw):
        try:
            text = bytes.fromhex(raw).decode("ascii")
        except UnicodeDecodeError:
            return raw
        if text.isprintable():
            return text
    return raw


def _parse_value(raw: str) -> DsmrValue:
    match = _TIMESTAMP.match(raw)
    if match:
        stamp = dt.datetime.strptime(match.group(1), "%y%m%d%H%M%S")
        # DSMR timestamps are Dutch/Belgian local time; W = CET, S = CEST.
        offset = dt.timedelta(hours=2 if match.group(2) == "S" else 1)
        return DsmrValue(raw, timestamp=stamp.replace(tzinfo=dt.timezone(offset)))
    match = _NUMBER.match(raw)
    if match:
        text, unit = match.groups()
        number: float | int = float(text) if "." in text else int(text)
        return DsmrValue(raw, number=number, unit=unit)
    return DsmrValue(raw)


@dataclass
class DsmrTelegram:
    header: str
    lines: dict[ObisCode, list[DsmrValue]] = field(default_factory=dict)
    crc_ok: bool | None = None

    def get(self, obis: str | ObisCode, default=None):
        """The (last) value on the line for ``obis``: gas lines carry
        ``(timestamp)(reading)``, so the reading is what comes back."""
        key = ObisCode.parse(obis) if isinstance(obis, str) else obis
        values = self.lines.get(key)
        return default if not values else values[-1].value

    def unit(self, obis: str | ObisCode) -> str | None:
        key = ObisCode.parse(obis) if isinstance(obis, str) else obis
        values = self.lines.get(key) or []
        return values[-1].unit if values else None

    @property
    def manufacturer(self) -> str:
        return self.header[1:4]


def parse_telegram(data: bytes | str, verify_crc: bool = True) -> DsmrTelegram:
    """Parse one telegram. Raises :class:`ChecksumError` on a CRC mismatch.

    DSMR 2.x/3.x telegrams have no CRC; they parse with ``crc_ok=None``.
    """
    raw = data.encode("ascii") if isinstance(data, str) else bytes(data)
    start = raw.find(b"/")
    end = raw.find(b"!", start)
    if start < 0 or end < 0:
        raise DecodeError("not a DSMR telegram: '/' header or '!' trailer missing")
    crc_text = raw[end + 1 : end + 5]
    crc_ok = None
    if re.fullmatch(rb"[0-9A-Fa-f]{4}", crc_text):
        computed = crc16_arc(raw[start : end + 1])
        crc_ok = computed == int(crc_text, 16)
        if verify_crc and not crc_ok:
            raise ChecksumError(f"DSMR CRC {crc_text.decode()} != computed {computed:04X}")
    body = raw[start:end].decode("ascii", errors="replace").splitlines()
    telegram = DsmrTelegram(header=body[0].strip(), crc_ok=crc_ok)
    for line in body[1:]:
        line = line.strip()
        if not line:
            continue
        match = _LINE.match(line)
        if not match:
            raise DecodeError(f"malformed DSMR line: {line!r}")
        a, b, c, d, e = (int(x) for x in match.groups()[:5])
        groups = _GROUP.findall(match.group(6))
        if c == 96 and d in (1, 13):
            # Equipment identifiers and text messages are hex-encoded ASCII,
            # which can consist of digits only: never parse them as numbers.
            values = [DsmrValue(v) for v in groups]
        else:
            values = [_parse_value(v) for v in groups]
        telegram.lines[ObisCode(a, b, c, d, e, 255)] = values
    return telegram


def decrypt_frame(apdu: bytes, security) -> DsmrTelegram:
    """Luxembourg Smarty: decipher a general-glo-ciphering frame, then parse."""
    from pydlms.security.ciphering import unwrap

    return parse_telegram(unwrap(security, apdu).plaintext)
