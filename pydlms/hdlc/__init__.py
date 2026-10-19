"""HDLC framing and connection management (IEC 62056-46 / 62056-7-5)."""

from pydlms.hdlc.address import HdlcAddress
from pydlms.hdlc.connection import (
    HdlcLink,
    HdlcParameters,
    parameter_field,
    parse_parameter_field,
)
from pydlms.hdlc.crc import crc16_x25
from pydlms.hdlc.framing import (
    MODULO_128,
    FrameReader,
    FrameType,
    HdlcFrame,
    HdlcModeTracker,
    decode_frame,
    encode_frame,
)
from pydlms.hdlc.frmr import FrameReject, decode_frmr

__all__ = [
    "MODULO_128",
    "FrameReader",
    "FrameReject",
    "FrameType",
    "HdlcAddress",
    "HdlcFrame",
    "HdlcLink",
    "HdlcModeTracker",
    "HdlcParameters",
    "crc16_x25",
    "decode_frame",
    "decode_frmr",
    "encode_frame",
    "parameter_field",
    "parse_parameter_field",
]
