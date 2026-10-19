"""IEC 62056-21 message structures, independent of the serial line.

Identification message (clause 6.3.2 per the Edition 1.0 contents; the
layout is unverified against the clause text)::

    /XXXZ[\\W]Ident<CR><LF>

Data message (mode C data readout)::

    STX data-block ! CR LF ETX BCC

BCC is the XOR of every character after the first STX (or SOH) up to and
including ETX. The line handling (sign-on, wake-up, baud switch) lives in
:mod:`pydlms.transports.serial`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import reduce

import construct
from construct import (
    Byte,
    Bytes,
    Checksum,
    Const,
    GreedyBytes,
    If,
    NullTerminated,
    RawCopy,
    Struct,
    this,
)

from pydlms.exceptions import ChecksumError, FramingError, ProtocolError

__all__ = [
    "BAUD_CHARS",
    "IecIdentification",
    "parse_identification",
    "block_check_character",
    "DataMessage",
    "DataReadout",
    "ReadoutDataSet",
    "ReadoutValue",
    "parse_data_message",
    "CommandMessage",
    "build_command",
    "parse_command",
    "BREAK",
    "BREAK_CRLF",
    "BREAK_FORMS",
    "SIGN_OFF",
    "wake_up_nuls",
    "fast_wake_up_nuls",
    "WAKE_UP_PAUSE",
    "FAST_WAKE_UP_TOTAL",
    "FAST_WAKE_UP_SETTLE",
]

BAUD_CHARS = {"0": 300, "1": 600, "2": 1200, "3": 2400, "4": 4800, "5": 9600, "6": 19200}

_IDENT_RE = re.compile(rb"^/([A-Za-z]{2}[A-Za-z0-9])([0-9A-Z])(\\[0-9W])?(.*)\r\n$", re.S)


@dataclass(frozen=True)
class IecIdentification:
    """Parsed IEC 62056-21 identification message."""

    manufacturer: str
    baud_char: str
    mode_e: bool
    identification: str

    @property
    def baud(self) -> int:
        try:
            return BAUD_CHARS[self.baud_char]
        except KeyError:
            raise ProtocolError(
                f"baud character {self.baud_char!r} is not a mode C/E rate"
            ) from None


def parse_identification(line: bytes) -> IecIdentification:
    """Parse ``/XXXZ[\\W]ident<CR><LF>``."""
    match = _IDENT_RE.match(line)
    if not match:
        raise ProtocolError(f"not an IEC 62056-21 identification message: {line!r}")
    manufacturer, baud_char, escape, ident = match.groups()
    return IecIdentification(
        manufacturer.decode("ascii"),
        baud_char.decode("ascii"),
        escape == b"\\2",
        ident.decode("ascii", errors="replace"),
    )


SOH, STX, ETX, EOT, ACK, NAK = 0x01, 0x02, 0x03, 0x04, 0x06, 0x15

#: Library limits on an untrusted data readout, not values from IEC 62056-21.
MAX_READOUT_SIZE = 64 * 1024
MAX_DATA_LINE = 1024
MAX_COMMAND_SIZE = 1024


def block_check_character(data: bytes) -> int:
    """IEC 62056-21 BCC: XOR of the characters after the first STX or SOH up to
    and including ETX."""
    return reduce(lambda acc, octet: acc ^ octet, data, 0)


#: IEC 62056-21 data message ``STX data-block ETX BCC``. The block (including
#: its ``!<CR><LF>`` end) has no length field; ETX ends it and BCC covers it.
DataMessage = Struct(
    "stx" / Const(bytes([STX])),
    "body" / RawCopy(NullTerminated(GreedyBytes, term=bytes([ETX]))),
    "bcc" / Checksum(Byte, block_check_character, this.body.data),
    construct.Terminated,
)


#: IEC 62056-21 command message ``SOH C D [STX data] ETX BCC``: a command
#: message identifier (``C``, e.g. ``B`` break, ``R`` read, ``P`` password)
#: and a command type identifier (``D``, a digit), optionally a data set,
#: then ETX. The BCC covers everything after SOH up to and including ETX
#: (clause 6.3 / Annex A per cB-Sigma's iec6205621 package; the clause text
#: was not read, unverified; the BCC is the ISO/IEC 1155 longitudinal parity
#: named in clause 6.2 Figure 7). Partial blocks ending in EOT are not built.
CommandMessage = Struct(
    "soh" / Const(bytes([SOH])),
    "body"
    / RawCopy(
        Struct(
            "command" / Bytes(2),
            "data"
            / construct.Optional(
                Struct(
                    "stx" / Const(bytes([STX])),
                    "value" / NullTerminated(GreedyBytes, term=bytes([ETX])),
                )
            ),
            "etx" / If(this.data == None, Const(bytes([ETX]))),  # noqa: E711 - construct expr
        )
    ),
    "bcc" / Checksum(Byte, block_check_character, this.body.data),
    construct.Terminated,
)


def _check_command_fields(command: bytes, data: bytes | None) -> str | None:
    """Return why ``command``/``data`` cannot form a command message, or None."""
    if len(command) != 2 or not all(0x21 <= octet <= 0x7E for octet in command):
        return f"command identifier {command!r} is not two printable ASCII characters"
    if data is not None and any(octet > 0x7E or octet in (SOH, STX, ETX, EOT) for octet in data):
        return f"command data {data!r} holds a control or non-ASCII character"
    return None


def build_command(command: str, data: bytes | None = None) -> bytes:
    """Build ``SOH command [STX data] ETX BCC``; ``data=None`` omits the STX part."""
    raw_command = command.encode("ascii", errors="replace")
    problem = _check_command_fields(raw_command, data)
    if problem is not None:
        raise ValueError(problem)
    data_part = None if data is None else {"value": bytes(data)}
    return CommandMessage.build({"body": {"value": {"command": raw_command, "data": data_part}}})


def parse_command(raw: bytes) -> tuple[str, bytes | None]:
    """Parse and verify a command message; return ``(command, data)``.

    ``data`` is ``None`` when the message has no STX part. Raises
    :class:`ChecksumError` on a BCC mismatch and :class:`FramingError` on a
    missing SOH/ETX, trailing octets or a malformed field.
    """
    raw = bytes(raw)
    if len(raw) > MAX_COMMAND_SIZE:
        raise FramingError(f"command message of {len(raw)} octets exceeds {MAX_COMMAND_SIZE}")
    try:
        message = CommandMessage.parse(raw)
    except construct.ChecksumError:
        raise ChecksumError(f"command message BCC mismatch (got 0x{raw[-1]:02X})") from None
    except construct.ConstructError as exc:
        raise FramingError(f"truncated or malformed command message: {raw[:16]!r}: {exc}") from None
    body = message.body.value
    data = None if body.data is None else body.data.value
    problem = _check_command_fields(body.command, data)
    if problem is not None:
        raise FramingError(problem)
    return body.command.decode("ascii"), data


#: The break message B0 (``01 42 30 03 71``): ends the session; the meter
#: returns to its initial state. This is the command-message form with BCC,
#: sent by default.
BREAK = build_command("B0")
#: B0 as Gurux sends it (``SOH B0 ETX CR LF``, no BCC; Gurux.DLMS.Net
#: ``GXDLMSReader.cs`` DiscIEC, behaviour only). Opt-in: a meter that reads
#: whole lines and has no inter-character timeout (cB-Sigma's IEC 62056-21
#: meter) otherwise joins B0 and the following request into one line.
BREAK_CRLF = b"\x01B0\x03\r\n"
#: Accepted ``break_form`` values: ``"bcc"`` (:data:`BREAK`) and ``"crlf"``.
BREAK_FORMS = ("bcc", "crlf")
#: The sign-off message B1 (``01 42 31 03 70``) that ends a session opened
#: with the fast wake-up (Annex B.2, unverified); the meter answers ACK.
SIGN_OFF = build_command("B1")


@dataclass(frozen=True)
class ReadoutValue:
    """One ``(value*unit)`` group of a data set."""

    value: str
    unit: str | None = None


@dataclass(frozen=True)
class ReadoutDataSet:
    """``address(value*unit)(value*unit)...``; ``address`` is the OBIS/ID string."""

    address: str
    values: tuple[ReadoutValue, ...]

    @property
    def value(self) -> str:
        return self.values[0].value

    @property
    def unit(self) -> str | None:
        return self.values[0].unit


@dataclass(frozen=True)
class DataReadout:
    """Result of a mode C data readout."""

    identification: IecIdentification
    data_sets: tuple[ReadoutDataSet, ...]

    def get(self, address: str) -> ReadoutDataSet | None:
        """The first data set with ``address``, or ``None``."""
        return next((d for d in self.data_sets if d.address == address), None)


# A data set: address (empty for a continuation group), "(", value, optional
# "*unit", ")". "(", ")", "*", "/" and "!" never occur inside a field.
_DATA_SET_RE = re.compile(rb"([^()*/!]*)\(([^()*/!]*)(?:\*([^()*/!]*))?\)")


def _parse_data_line(line: bytes) -> list[ReadoutDataSet]:
    sets: list[ReadoutDataSet] = []
    pos = 0
    while pos < len(line):
        match = _DATA_SET_RE.match(line, pos)
        if match is None:
            raise FramingError(f"malformed data line at offset {pos}: {line!r}")
        address, value, unit = (
            None if g is None else g.decode("ascii").strip() for g in match.groups()
        )
        item = ReadoutValue(value or "", unit)
        if not address and sets:
            # A group without an address is another value of the preceding set.
            sets[-1] = ReadoutDataSet(sets[-1].address, (*sets[-1].values, item))
        else:
            sets.append(ReadoutDataSet(address or "", (item,)))
        pos = match.end()
    return sets


def parse_data_message(raw: bytes) -> tuple[ReadoutDataSet, ...]:
    """Parse and verify ``STX data-block ! CR LF ETX BCC`` (IEC 62056-21 6.3).

    Raises :class:`ChecksumError` on a BCC mismatch and :class:`FramingError`
    on missing STX/ETX, trailing octets, a missing end of block, overlong or
    malformed data lines and non-ASCII content.
    """
    raw = bytes(raw)
    if len(raw) > MAX_READOUT_SIZE:
        raise FramingError(f"data message of {len(raw)} octets exceeds {MAX_READOUT_SIZE}")
    try:
        message = DataMessage.parse(raw)
    except construct.ChecksumError:
        raise ChecksumError(f"data message BCC mismatch (got 0x{raw[-1]:02X})") from None
    except construct.ConstError:
        raise FramingError(f"data message does not start with STX: {raw[:16]!r}") from None
    except construct.ConstructError as exc:
        raise FramingError(f"truncated or malformed data message: {exc}") from None
    block = message.body.value  # .data also holds the ETX the BCC covers
    if not block.endswith(b"!\r\n"):
        raise FramingError("data block does not end with '!<CR><LF>'")
    block = block[:-3]
    if any(octet > 0x7E or (octet < 0x20 and octet not in b"\r\n") for octet in block):
        raise FramingError("data block contains non-printable or non-ASCII characters")
    data_sets: list[ReadoutDataSet] = []
    for line in block.split(b"\r\n") if block else []:
        if len(line) > MAX_DATA_LINE:
            raise FramingError(f"data line of {len(line)} octets exceeds {MAX_DATA_LINE}")
        if b"\r" in line or b"\n" in line:
            raise FramingError(f"data line with a bare CR or LF: {line!r}")
        data_sets.extend(_parse_data_line(line))
    return tuple(data_sets)


# --- Annex B wake-up timing ---------------------------------------------------------
# Values via cB-Sigma's iec6205621 package (Apache-2.0), which cites Annex B.1
# and B.2; the annex text was not read here (unverified). The Edition 1.0
# contents confirm Annex B (wake-up methods for battery-operated devices) with
# Figure B.2 for the fast wake-up.


def wake_up_nuls(baud: int) -> int:
    """NUL characters of the Annex B.1 wake-up message at ``baud``: 2.2 s of
    10-bit characters (the middle of 2.1 s to 2.3 s)."""
    return baud * 22 // 100


#: Annex B.1: the pause after the wake-up NULs before the request message.
WAKE_UP_PAUSE = 1.6


def fast_wake_up_nuls(baud: int) -> int:
    """NUL characters of one Annex B.2 fast wake-up string at ``baud``: about
    0.55 s (Tn 500 ms to 600 ms)."""
    return baud * 55 // 1000


#: Annex B.2: how long NUL strings are repeated without an ACK (the annex
#: recommends at least 4.5 s).
FAST_WAKE_UP_TOTAL = 5.0
#: Pause after the fast wake-up ACK before the request (Annex B.2 allows the
#: request 200 ms to 1500 ms later).
FAST_WAKE_UP_SETTLE = 0.3
