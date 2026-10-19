"""OBIS codes (IEC 62056-6-1).

An OBIS code identifies a COSEM object. On the wire it is six octets
``A B C D E F``; to humans it is written ``A-B:C.D.E*F`` or, more commonly in
tooling, ``A.B.C.D.E.F``. Each group is 0..255.

Semantics of the six value groups (IEC 62056-6-1):

* **A** medium (0 abstract, 1 electricity, 6 heat, 7 gas, 8 water, ...)
* **B** channel (0 = no channel / abstract)
* **C** physical quantity (e.g. 1 active power +, 2 active power -, 32 voltage L1)
* **D** processing / tariff-independent measurement kind (e.g. 7 instantaneous,
  8 time-integral)
* **E** tariff / rate (0 total, 1..n tariff)
* **F** billing period / historical set (255 = current / not used)

This module is pure structure: it parses, formats and compares OBIS codes. The
human-readable *names* of codes live in the generated catalog (``pydlms.data``),
not here, because those names are standardized reference data with their own
redistribution constraints.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import construct
from construct import Adapter, Array, Byte

__all__ = ["ObisCode", "ObisAdapter", "Obis"]


@dataclass(frozen=True, order=True)
class ObisCode:
    """A six-group OBIS code. Immutable and hashable."""

    a: int
    b: int
    c: int
    d: int
    e: int
    f: int

    def __post_init__(self) -> None:
        for name, value in zip("abcdef", self.groups, strict=True):
            if not isinstance(value, int) or not 0 <= value <= 255:
                raise ValueError(f"OBIS group {name!r} must be 0..255, got {value!r}")

    @property
    def groups(self) -> tuple[int, int, int, int, int, int]:
        return (self.a, self.b, self.c, self.d, self.e, self.f)

    def to_bytes(self) -> bytes:
        return bytes(self.groups)

    @classmethod
    def from_bytes(cls, data: bytes) -> ObisCode:
        if len(data) != 6:
            raise ValueError(f"OBIS code is 6 octets, got {len(data)}")
        return cls(*data)

    @classmethod
    def parse(cls, text: str) -> ObisCode:
        """Parse ``A-B:C.D.E*F`` or ``A.B.C.D.E.F`` (and ``.255`` may be omitted).

        Accepts the strict reduced-code form ``A.B.C.D.E.F`` and the canonical
        IEC punctuation ``A-B:C.D.E*F``. A trailing F group defaults to 255 when
        only five groups are given. Groups are 1 to 3 ASCII digits; signs, empty
        groups or other characters raise :class:`ValueError`.
        """
        tokens = _split_obis(text)
        if len(tokens) == 5:
            tokens.append(255)
        return cls(*tokens)

    def __str__(self) -> str:
        return "{}.{}.{}.{}.{}.{}".format(*self.groups)

    def to_iec(self) -> str:
        """Canonical IEC 62056-6-1 punctuation: ``A-B:C.D.E*F``."""
        a, b, c, d, e, f = self.groups
        return f"{a}-{b}:{c}.{d}.{e}*{f}"


# A[-.]B[:.]C.D.E, then an optional [*.]F; each group 1..3 ASCII digits. The
# separators may be mixed (``1-0:1.8.0.255`` is common in tooling), but every
# group must be present and nothing else may appear.
_G = r"([0-9]{1,3})"
_OBIS_TEXT = re.compile(rf"{_G}[-.]{_G}[:.]{_G}\.{_G}\.{_G}(?:[*.]{_G})?")


def _split_obis(text: str) -> list[int]:
    match = _OBIS_TEXT.fullmatch(text.strip())
    if match is None:
        raise ValueError(
            f"OBIS code must look like A-B:C.D.E*F or A.B.C.D.E.F (F optional), got {text!r}"
        )
    return [int(g) for g in match.groups() if g is not None]


class _ObisAdapter(Adapter):
    """construct adapter: 6 raw octets <-> :class:`ObisCode`."""

    def _decode(self, obj, _context, path) -> ObisCode:
        return ObisCode.from_bytes(bytes(obj))

    def _encode(self, obj, _context, path):
        if isinstance(obj, str):
            obj = ObisCode.parse(obj)
        if not isinstance(obj, ObisCode):
            raise construct.ConstructError(
                f"expected ObisCode or str, got {type(obj).__name__}", path
            )
        return list(obj.to_bytes())


#: construct adapter for the fixed 6-octet OBIS encoding.
ObisAdapter = _ObisAdapter(Array(6, Byte))

#: Alias used by higher layers when embedding an OBIS field in a struct.
Obis = ObisAdapter
