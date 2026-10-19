"""HDLC addressing (IEC 62056-46, 6.4.2).

An HDLC address field is 1, 2 or 4 octets. Each octet carries 7 address bits
in its upper bits; the least significant bit is the *extension* bit and is 1
only on the last octet of the field.

* **Client** addresses are always one octet: ``(sap << 1) | 1``. Public client
  is SAP 16 (``0x21``), management 1 (``0x03``), push client e.g. 103.
* **Server** addresses have an *upper* part (logical device, 1 = management
  logical device) and an optional *lower* part (physical device). One-octet
  form carries only the upper address; two-octet form one 7-bit octet each;
  four-octet form two 7-bit octets (14 bits) each.

Special values: upper ``0x7F`` (1-octet) / ``0x3FFF`` (4-octet) is
all-station broadcast, ``0x00`` no-station. ISO 3309:1984 5.2 / 5.3 (public
as IS 11418 (Part 1):1986) define the all-station address as the bit pattern
``11111111`` and the no-station address as ``00000000`` in the first octet;
with the low-order extension bit of 4.1 that is the one-octet ``0x7F`` and
``0x00``. The two-octet (14-bit) values are per DLMS UA 1000-2 Ed. 6
Excerpt 8.4.2.3 Table 2 (the Green Book text of the IEC 62056-46 address
rules): no-station ``0x0000``, management logical device ``0x0001``,
reserved ``0x0002..0x000F``, CALLING physical device ``0x7E`` / ``0x3FFE``,
all-station ``0x7F`` / ``0x3FFF``; the same table is in PJSC Rosseti STO
34.01-5.1-006-2019 Table 7.19. Ed. 6 Figure 21 prints the four-octet
example (upper ``0x1234``, lower ``0x3FFF``) pinned in
``tests/test_restated_spec_sources.py``.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydlms.exceptions import FramingError

__all__ = [
    "HdlcAddress",
    "encode_address",
    "decode_address",
    "read_address",
    "physical_address_from_serial",
    "SERIAL_ADDRESS_RULES",
]

#: Vendor rules for the HDLC physical (lower) server address derived from the
#: meter serial number: ``(offset, digits)`` -> ``offset + serial % 10**digits``.
SERIAL_ADDRESS_RULES: dict[str, tuple[int, int]] = {
    "landis+gyr": (1000, 4),  # confirmed by 2 (Gurux forum node/18472, .obx)
    "elgama": (1000, 4),  # confirmed by 2 (GAMA300 integration, .obx)
    "emh": (256, 4),  # single source (.obx)
    "milur": (16, 4),  # single source (esphome-dlms-cosem README)
}


def physical_address_from_serial(serial: int | str, vendor: str) -> int:
    """HDLC physical server address for meters that derive it from the serial.

    Not part of DLMS; e.g. Landis+Gyr: ``serial % 10000 + 1000`` with logical
    address 1. Raises :class:`KeyError` for vendors without a known rule
    (Hexing, for one, does not follow the L+G rule; read IEC HDLC setup
    ``device_address`` instead).
    """
    offset, digits = SERIAL_ADDRESS_RULES[vendor.lower()]
    digits_only = "".join(ch for ch in str(serial) if ch.isdigit())
    if not digits_only:
        raise ValueError(f"serial {serial!r} contains no digits")
    return offset + int(digits_only) % 10**digits


@dataclass(frozen=True)
class HdlcAddress:
    """A server (``upper``/``lower``) or client (``upper`` only) HDLC address.

    ``size`` is the encoded length (1, 2 or 4); ``lower`` is ``None`` in the
    one-octet form.
    """

    upper: int
    lower: int | None = None
    size: int = 1

    def __post_init__(self) -> None:
        if self.size not in (1, 2, 4):
            raise ValueError(f"HDLC address size must be 1, 2 or 4, got {self.size}")
        limit = 0x7F if self.size in (1, 2) else 0x3FFF
        if not 0 <= self.upper <= limit:
            raise ValueError(f"upper address {self.upper} out of range for size {self.size}")
        if self.size == 1:
            if self.lower is not None:
                raise ValueError("one-octet HDLC address has no lower part")
        elif self.lower is None or not 0 <= self.lower <= limit:
            raise ValueError(f"lower address {self.lower} out of range for size {self.size}")

    @classmethod
    def client(cls, sap: int) -> HdlcAddress:
        return cls(sap, None, 1)

    @classmethod
    def server(cls, logical: int = 1, physical: int | None = None, size: int | None = None):
        """Server address; size picked automatically when not given."""
        if physical is None:
            return cls(logical, None, size or 1)
        if size is None:
            size = 2 if logical <= 0x7F and physical <= 0x7F else 4
        return cls(logical, physical, size)

    def to_bytes(self) -> bytes:
        return encode_address(self)

    def __str__(self) -> str:
        if self.lower is None:
            return f"{self.upper}"
        return f"{self.upper}/{self.lower}"


def _split7(value: int, octets: int) -> list[int]:
    return [(value >> (7 * (octets - 1 - i))) & 0x7F for i in range(octets)]


def encode_address(address: HdlcAddress) -> bytes:
    if address.size == 1:
        parts = [address.upper]
    else:
        half = address.size // 2
        assert address.lower is not None
        parts = _split7(address.upper, half) + _split7(address.lower, half)
    out = bytearray(p << 1 for p in parts)
    out[-1] |= 1
    return bytes(out)


def decode_address(raw: bytes) -> HdlcAddress:
    """Decode a complete address field (``raw`` must be exactly the field)."""
    size = len(raw)
    if size not in (1, 2, 4):
        raise FramingError(f"HDLC address field must be 1, 2 or 4 octets, got {size}")
    for i, octet in enumerate(raw):
        last = i == size - 1
        if bool(octet & 1) != last:
            raise FramingError(f"HDLC address extension bits malformed: {raw.hex()}")
    values = [b >> 1 for b in raw]
    if size == 1:
        return HdlcAddress(values[0], None, 1)
    half = size // 2
    upper = 0
    lower = 0
    for v in values[:half]:
        upper = (upper << 7) | v
    for v in values[half:]:
        lower = (lower << 7) | v
    return HdlcAddress(upper, lower, size)


def read_address(data: bytes, offset: int) -> tuple[HdlcAddress, int]:
    """Read an address field starting at ``offset``; returns ``(addr, next)``."""
    end = offset
    while True:
        if end >= len(data):
            raise FramingError("HDLC address field runs past the end of the frame")
        if data[end] & 1:
            end += 1
            break
        end += 1
        if end - offset >= 4:
            raise FramingError("HDLC address field longer than 4 octets")
    return decode_address(data[offset:end]), end
