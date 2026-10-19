"""FRMR (frame reject) information field, modulo-8 and modulo-128 numbering.

A server answers a frame it cannot accept with FRMR (IEC 62056-46 6.4.3.10,
which refers to ISO/IEC 13239 5.5.3.4.2 Figure 18a). Bits are numbered in
transmission order, bit 1 being the least significant bit of the first
octet::

    octet 1  bits 1-8    the rejected frame's control field
    octet 2  bit 9       0
             bits 10-12  V(S) of the server (bit 10 lowest)
             bit 13      C/R: 1 if the rejected frame was a response
             bits 14-16  V(R) of the server (bit 14 lowest)
    octet 3  bit 17      W: control field undefined or not implemented
             bit 18      X: information field not permitted (sent with W)
             bit 19      Y: information field longer than the server takes
             bit 20      Z: invalid N(R)
             bits 21-24  padding (0)

Octets past the third are padding and are ignored on receipt. The layout
is the HDLC FRMR field per ITU-T X.25 (10/96) 2.3.4.10 Table 2-12 and IBM
SDLC Concepts GA27-3093-4 Figure 20 (``tests/test_hdlc_spec_sources.py``).
The clause numbers above come from cB-Sigma ``hdlc/frmr.go`` (Apache-2.0);
the IEC 62056-46 and ISO/IEC 13239 texts were not read, so the clause
numbers stay *unverified*.

On a link set up with SNRME (modulo 128, opt-in, outside IEC 62056-46) the
field has five octets per ITU-T X.25 (10/96) Table 2-13 and SDLC Figure 20
(ISO/IEC 13239 Figure 18b per cB-Sigma ``hdlc/frmr.go``)::

    octets 1-2  bits 1-16   the rejected control field (an unnumbered one
                            in octet 1, octet 2 zero)
    octet 3     bit 17      0
                bits 18-24  V(S) of the server (bit 18 lowest)
    octet 4     bit 25      C/R
                bits 26-32  V(R) of the server (bit 26 lowest)
    octet 5     bits 33-36  W, X, Y, Z; bits 37-40 padding (0)

The rejected control field is kept as :class:`~pydlms.hdlc.framing.HdlcFrame`
keeps it: octet 1 in the low byte, octet 2 in the high byte. A peer that
does not take SNRME rejects it in its own modulo-8 layout.
"""

from __future__ import annotations

from dataclasses import dataclass

import construct
from construct import BitsInteger, BitStruct, Flag, Int8ub, Int16ul, Padding, Struct

from pydlms.exceptions import FramingError
from pydlms.hdlc.framing import MODULO_128, SEQ_MODULUS, check_modulus

__all__ = [
    "FRMR_INFO_LEN",
    "FRMR_INFO_LEN_128",
    "FrameReject",
    "FrmrInfoStruct",
    "FrmrInfoStruct128",
    "decode_frmr",
]

#: Octets of the modulo-8 FRMR information field (20 bits padded to 24).
FRMR_INFO_LEN = 3
#: Octets of the modulo-128 FRMR information field (36 bits padded to 40).
FRMR_INFO_LEN_128 = 5

#: The reason octet shared by both layouts: W, X, Y, Z from bit 1 up, then
#: four padding bits.
_Reasons = BitStruct(
    "reserved" / BitsInteger(4),
    "z" / Flag,
    "y" / Flag,
    "x" / Flag,
    "w" / Flag,
)

#: Modulo-8 FRMR information field. construct reads bits most significant
#: first, so each octet is listed from bit 8 down to bit 1 of that octet.
FrmrInfoStruct = Struct(
    "control" / Int8ub,
    "state"
    / BitStruct(
        "vr" / BitsInteger(3),
        "response" / Flag,
        "vs" / BitsInteger(3),
        Padding(1),
    ),
    "reasons" / _Reasons,
)

#: Modulo-128 FRMR information field, octets listed most significant bit
#: first as above. The rejected control field is octet 1 then octet 2, so
#: little-endian.
FrmrInfoStruct128 = Struct(
    "control" / Int16ul,
    "vs" / BitStruct("vs" / BitsInteger(7), Padding(1)),
    "vr" / BitStruct("vr" / BitsInteger(7), "response" / Flag),
    "reasons" / _Reasons,
)


@dataclass(frozen=True)
class FrameReject:
    """A decoded FRMR information field (modulo 8, or 128 after SNRME)."""

    #: The rejected frame's control field (modulo 128: octet 1 in the low
    #: byte, octet 2 in the high byte).
    control: int
    #: The server's send and receive state variables when it rejected.
    vs: int
    vr: int
    #: C/R bit: the rejected frame was a response (a client only sends
    #: commands, so this is normally False).
    response: bool = False
    w: bool = False
    x: bool = False
    y: bool = False
    z: bool = False
    #: Bits 21-24, zero padding in ISO/IEC 13239; kept so a vendor value
    #: shows up in the error text.
    reserved: int = 0
    #: Numbering of the link: 8 (3-octet field) or 128 (5-octet field).
    modulus: int = SEQ_MODULUS

    def __post_init__(self) -> None:
        check_modulus(self.modulus)

    @classmethod
    def from_bytes(cls, info: bytes, modulus: int = SEQ_MODULUS) -> FrameReject:
        """Decode an FRMR information field of a link numbered ``modulus``;
        shorter than 3 (modulo 8) or 5 (modulo 128) octets raises
        :class:`FramingError`, extra octets are padding."""
        if check_modulus(modulus) == MODULO_128:
            return cls._from_bytes_128(info)
        if len(info) < FRMR_INFO_LEN:
            raise FramingError(
                f"FRMR information field of {len(info)} octets, modulo 8 needs {FRMR_INFO_LEN}"
            )
        try:
            parsed = FrmrInfoStruct.parse(info[:FRMR_INFO_LEN])
        except construct.ConstructError as exc:  # pragma: no cover - length checked above
            raise FramingError(f"malformed FRMR information field: {exc}") from None
        return cls(
            control=parsed.control,
            vs=parsed.state.vs,
            vr=parsed.state.vr,
            response=parsed.state.response,
            w=parsed.reasons.w,
            x=parsed.reasons.x,
            y=parsed.reasons.y,
            z=parsed.reasons.z,
            reserved=parsed.reasons.reserved,
        )

    @classmethod
    def _from_bytes_128(cls, info: bytes) -> FrameReject:
        if len(info) < FRMR_INFO_LEN_128:
            raise FramingError(
                f"FRMR information field of {len(info)} octets, "
                f"modulo 128 needs {FRMR_INFO_LEN_128}"
            )
        try:
            parsed = FrmrInfoStruct128.parse(info[:FRMR_INFO_LEN_128])
        except construct.ConstructError as exc:  # pragma: no cover - length checked above
            raise FramingError(f"malformed FRMR information field: {exc}") from None
        return cls(
            control=parsed.control,
            vs=parsed.vs.vs,
            vr=parsed.vr.vr,
            response=parsed.vr.response,
            w=parsed.reasons.w,
            x=parsed.reasons.x,
            y=parsed.reasons.y,
            z=parsed.reasons.z,
            reserved=parsed.reasons.reserved,
            modulus=MODULO_128,
        )

    def to_bytes(self) -> bytes:
        reasons = {
            "reserved": self.reserved,
            "z": self.z,
            "y": self.y,
            "x": self.x,
            "w": self.w,
        }
        if self.modulus == MODULO_128:
            return FrmrInfoStruct128.build(
                {
                    "control": self.control,
                    "vs": {"vs": self.vs},
                    "vr": {"vr": self.vr, "response": self.response},
                    "reasons": reasons,
                }
            )
        return FrmrInfoStruct.build(
            {
                "control": self.control,
                "state": {"vr": self.vr, "response": self.response, "vs": self.vs},
                "reasons": {
                    "reserved": self.reserved,
                    "z": self.z,
                    "y": self.y,
                    "x": self.x,
                    "w": self.w,
                },
            }
        )

    @property
    def reasons(self) -> tuple[str, ...]:
        """The conditions the server reported, in bit order; empty when no
        reason bit is set (the rejection is unspecified)."""
        out = []
        if self.w and not self.x:
            out.append("control field undefined or not implemented")
        if self.x:
            out.append("information field not permitted with this frame")
        if self.y:
            out.append("information field too long")
        if self.z:
            out.append("invalid N(R)")
        if self.reserved:
            out.append(f"reserved bits 0x{self.reserved:X}")
        return tuple(out)

    def describe(self) -> str:
        reason = ", ".join(self.reasons) or "unspecified"
        kind = "response" if self.response else "command"
        control = f"0x{self.control:02X}"
        if self.modulus == MODULO_128 and self.control > 0xFF:
            octets = bytes((self.control & 0xFF, self.control >> 8))
            control = octets.hex(" ").upper()
        return f"{reason} (rejected {kind} control {control}, server V(S)={self.vs} V(R)={self.vr})"


def decode_frmr(info: bytes, modulus: int = SEQ_MODULUS) -> FrameReject:
    """Decode an FRMR information field of a link numbered ``modulus`` (see
    :class:`FrameReject`)."""
    return FrameReject.from_bytes(info, modulus)
