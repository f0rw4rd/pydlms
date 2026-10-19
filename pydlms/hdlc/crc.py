"""CRC-16/X-25, the HDLC frame check sequence (IEC 62056-46 / ISO/IEC 13239).

Parameters: poly 0x1021 (reflected 0x8408), init 0xFFFF, reflected in and out,
xorout 0xFFFF. Check value over ``b"123456789"`` is ``0x906E``. On the wire the
two octets are sent least-significant first.
"""

from __future__ import annotations

__all__ = ["crc16_x25", "fcs_bytes"]


def _make_table() -> list[int]:
    table = []
    for byte in range(256):
        crc = byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
        table.append(crc)
    return table


_TABLE = _make_table()


def crc16_x25(data: bytes) -> int:
    """CRC-16/X-25 of ``data`` as an int."""
    crc = 0xFFFF
    for byte in data:
        crc = (crc >> 8) ^ _TABLE[(crc ^ byte) & 0xFF]
    return crc ^ 0xFFFF


def fcs_bytes(data: bytes) -> bytes:
    """CRC-16/X-25 of ``data`` in wire order (LSB first)."""
    return crc16_x25(data).to_bytes(2, "little")
