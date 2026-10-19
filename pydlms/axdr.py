"""A-XDR primitives shared across DLMS/COSEM encodings.

The one piece every DLMS encoding reuses is the **variable-length length
octet(s)** (IEC 62056-5-3, A-XDR). It is *not* ASN.1 BER length, though it looks
similar:

* a single octet ``0x00..0x7F`` encodes that value directly (short form);
* an octet ``0x80 | n`` means ``n`` further octets hold the length, big-endian
  (long form). ``0x81`` -> 1 following octet, ``0x82`` -> 2, ``0x84`` -> 4.

``0x80`` on its own (n == 0) is the "indefinite" marker; DLMS does not use it for
lengths, so we reject it on parse and never emit it.

At most :data:`MAX_LENGTH_OCTETS` (4) octets follow ``0x80 | n``: a length
beyond 2**32 - 1 cannot occur in DLMS, Gurux accepts only ``0x81..0x84``,
and a larger count would only let hostile input describe absurd sizes. Every
length decoder in pydlms (this module, COSEM ``Data``, the lenient push
path) goes through :func:`read_length` so they agree on that cap.

This module exposes :data:`DlmsLength`, a ``construct`` subconstruct usable
anywhere a length field appears, plus :func:`encode_length` / :func:`decode_length`
for direct byte work.
"""

from __future__ import annotations

from collections.abc import Callable

import construct
from construct import Construct, stream_read, stream_write

from pydlms.exceptions import DecodeError

__all__ = ["DlmsLength", "encode_length", "decode_length", "read_length", "MAX_LENGTH_OCTETS"]

#: Most octets a long-form length may use (``0x84``).
MAX_LENGTH_OCTETS = 4


def encode_length(value: int) -> bytes:
    """Encode ``value`` as DLMS A-XDR length octet(s)."""
    if value < 0:
        raise ValueError(f"length must be non-negative, got {value}")
    if value < 0x80:
        return bytes([value])
    body = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if len(body) > MAX_LENGTH_OCTETS:
        raise ValueError(f"length {value} needs more than {MAX_LENGTH_OCTETS} octets to encode")
    return bytes([0x80 | len(body)]) + body


def read_length(read: Callable[[int], bytes]) -> int:
    """Decode a DLMS length from ``read(n)``, which returns exactly ``n`` octets or raises."""
    first = read(1)[0]
    if first < 0x80:
        return first
    n = first & 0x7F
    if n == 0:
        raise DecodeError("indefinite length (0x80) is not valid in DLMS")
    if n > MAX_LENGTH_OCTETS:
        raise DecodeError(
            f"length field of {n} octets exceeds the {MAX_LENGTH_OCTETS}-octet maximum"
        )
    return int.from_bytes(read(n), "big")


def decode_length(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode a DLMS length starting at ``offset``.

    Returns ``(value, next_offset)``.
    """
    if offset >= len(data):
        raise DecodeError("no bytes available to decode a length")
    pos = offset

    def read(n: int) -> bytes:
        nonlocal pos
        if pos + n > len(data):
            raise DecodeError(f"length needs {n} octets but only {len(data) - pos} remain")
        chunk = data[pos : pos + n]
        pos += n
        return chunk

    value = read_length(read)
    return value, pos


class _DlmsLength(Construct):
    """``construct`` adapter for the DLMS A-XDR variable length field."""

    def _parse(self, stream, _context, path):
        try:
            return read_length(lambda n: stream_read(stream, n, path))
        except DecodeError as exc:
            raise construct.ConstructError(str(exc), path) from exc

    def _build(self, obj, stream, _context, path):
        if not isinstance(obj, int):
            raise construct.ConstructError(f"length must be an int, got {type(obj).__name__}", path)
        try:
            data = encode_length(obj)
        except ValueError as exc:
            raise construct.ConstructError(str(exc), path) from exc
        stream_write(stream, data, len(data), path)
        return obj

    def _sizeof(self, _context, path):
        raise construct.SizeofError("DlmsLength has a variable size", path=path)


#: Singleton construct for a DLMS A-XDR length field (parse -> int, build <- int).
DlmsLength = _DlmsLength()
