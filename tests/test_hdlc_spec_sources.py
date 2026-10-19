"""HDLC encodings checked against public HDLC-family texts.

IEC 62056-46 and ISO/IEC 13239 are not public; these tests rebuild the
same frame elements from documents that are, bit by bit as the documents
print them, and compare pydlms against them. Sources:

* X.25: ITU-T Rec. X.25 (10/96), LAPB, an HDLC class of procedures.
  2.3.4.10 Tables 2-12 / 2-13 (FRMR information field), Table 2-8
  (modulo-128 control fields).
* SDLC: IBM GA27-3093-4 "SDLC Concepts" (1992), Figure 19 (command and
  response encodings, written bit 8 first) and Figure 20 (FRMR field).
* V.42: ITU-T Rec. V.42 (03/2002) 12.2 (XID information field after
  ISO/IEC 8885: user data subfield GI ``11111111`` without a group
  length, bounded by the FCS; parameters 5 to 8; values high octet first).
"""

from __future__ import annotations

import pytest

from pydlms.hdlc import FrameReject
from pydlms.hdlc.connection import HdlcParameters, parse_parameter_field
from pydlms.hdlc.framing import (
    MODULO_128,
    FrameType,
    control_i,
    control_octets,
    control_rej,
    control_rnr,
    control_rr,
)


def bits_to_octets(bits: dict[int, int], octets: int) -> bytes:
    """Octets from numbered bits, bit 1 = low-order bit of octet 1 (the
    numbering of X.25 2.3.4.10 and V.42 12.2.1)."""
    out = bytearray(octets)
    for position, value in bits.items():
        if value:
            index, bit = divmod(position - 1, 8)
            out[index] |= 1 << bit
    return bytes(out)


def field(first: int, value: int, width: int) -> dict[int, int]:
    """``value`` on bits ``first`` .. ``first + width - 1``, low-order bit
    first."""
    return {first + i: (value >> i) & 1 for i in range(width)}


def sdlc(code: str) -> int:
    """An SDLC Figure 19 encoding (``"100P 0011"``, bit 8 first) with P/F 0."""
    return int(code.replace(" ", "").replace("P", "0").replace("F", "0"), 2)


# -- control fields --------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "code"),
    [
        (FrameType.SNRM, "100P 0011"),
        (FrameType.SNRME, "110P 1111"),
        (FrameType.DISC, "010P 0011"),
        (FrameType.UA, "011F 0011"),
        (FrameType.DM, "000F 1111"),
        (FrameType.FRMR, "100F 0111"),
        (FrameType.UI, "000P 0011"),
    ],
)
def test_unnumbered_codes_match_sdlc_figure_19(kind, code):
    assert kind == sdlc(code)


@pytest.mark.parametrize(
    ("kind", "s_bits"),
    [
        (FrameType.RR, (0, 0)),
        (FrameType.RNR, (1, 0)),
        (FrameType.REJ, (0, 1)),
        (FrameType.SREJ, (1, 1)),
    ],
)
def test_supervisory_codes_match_x25_table_2_8(kind, s_bits):
    # Bits 1-4: 1 0 S S.
    assert kind == bits_to_octets({1: 1, 2: 0, 3: s_bits[0], 4: s_bits[1]}, 1)[0]


@pytest.mark.parametrize("ns", [0, 1, 64, 127])
@pytest.mark.parametrize("nr", [0, 5, 127])
@pytest.mark.parametrize("poll", [False, True])
def test_modulo128_i_frame_matches_x25_table_2_8(ns, nr, poll):
    # Bit 1 = 0, bits 2-8 N(S), bit 9 P, bits 10-16 N(R).
    expected = bits_to_octets({1: 0, **field(2, ns, 7), 9: int(poll), **field(10, nr, 7)}, 2)
    assert control_octets(control_i(ns, nr, poll, MODULO_128), MODULO_128) == expected


@pytest.mark.parametrize(
    ("build", "s_bits"),
    [(control_rr, (0, 0)), (control_rnr, (1, 0)), (control_rej, (0, 1))],
)
@pytest.mark.parametrize("nr", [0, 1, 99, 127])
@pytest.mark.parametrize("poll", [False, True])
def test_modulo128_s_frame_matches_x25_table_2_8(build, s_bits, nr, poll):
    # Bits 1-8: 1 0 S S 0 0 0 0, bit 9 P/F, bits 10-16 N(R).
    bits = {1: 1, 2: 0, 3: s_bits[0], 4: s_bits[1], 9: int(poll), **field(10, nr, 7)}
    assert control_octets(build(nr, poll, MODULO_128), MODULO_128) == bits_to_octets(bits, 2)


@pytest.mark.parametrize("kind", [FrameType.SNRME, FrameType.DISC, FrameType.UA, FrameType.UI])
def test_modulo128_unnumbered_frames_keep_one_octet(kind):
    # SDLC chapter 3: U commands and responses have a 1-byte control field
    # in modulo-8 and modulo-128 operation.
    assert control_octets(kind, MODULO_128) == bytes([kind])


# -- FRMR information field ------------------------------------------------------


@pytest.mark.parametrize("vs", range(8))
@pytest.mark.parametrize("vr", [0, 3, 7])
@pytest.mark.parametrize("response", [False, True])
@pytest.mark.parametrize("reason", ["w", "x", "y", "z"])
def test_frmr_modulo8_matches_x25_table_2_12(vs, vr, response, reason):
    # Bits 1-8 rejected control, 9 = 0, 10-12 V(S) (bit 10 low), 13 C/R,
    # 14-16 V(R) (bit 14 low), 17 W, 18 X, 19 Y, 20 Z, 21-24 = 0.
    reason_bit = {"w": 17, "x": 18, "y": 19, "z": 20}[reason]
    bits = {**field(1, 0x32, 8), 9: 0, **field(10, vs, 3), 13: int(response)}
    bits.update({**field(14, vr, 3), reason_bit: 1})
    info = bits_to_octets(bits, 3)
    reject = FrameReject.from_bytes(info)
    assert (reject.control, reject.vs, reject.vr, reject.response) == (0x32, vs, vr, response)
    assert [name for name in "wxyz" if getattr(reject, name)] == [reason]
    assert reject.reserved == 0
    assert reject.to_bytes() == info


@pytest.mark.parametrize("vs", [0, 1, 64, 127])
@pytest.mark.parametrize("vr", [0, 42, 127])
@pytest.mark.parametrize("response", [False, True])
@pytest.mark.parametrize("reason", ["w", "x", "y", "z"])
def test_frmr_modulo128_matches_x25_table_2_13(vs, vr, response, reason):
    # Bits 1-16 rejected control, 17 = 0, 18-24 V(S) (bit 18 low), 25 C/R,
    # 26-32 V(R) (bit 26 low), 33 W, 34 X, 35 Y, 36 Z, 37-40 = 0.
    rejected = control_i(5, 9, True, MODULO_128)
    reason_bit = {"w": 33, "x": 34, "y": 35, "z": 36}[reason]
    bits = {**field(1, rejected, 16), 17: 0, **field(18, vs, 7), 25: int(response)}
    bits.update({**field(26, vr, 7), reason_bit: 1})
    info = bits_to_octets(bits, 5)
    reject = FrameReject.from_bytes(info, MODULO_128)
    assert (reject.control, reject.vs, reject.vr, reject.response) == (rejected, vs, vr, response)
    assert [name for name in "wxyz" if getattr(reject, name)] == [reason]
    assert reject.to_bytes() == info


def test_frmr_modulo128_unnumbered_rejected_control_in_octet_1():
    # X.25 Table 2-13 and SDLC Figure 20: a rejected U frame's control
    # field sits in bits 1-8, bits 9-16 are 0.
    info = bits_to_octets({**field(1, FrameType.SNRME | 0x10, 8), 17: 0, 33: 1}, 5)
    reject = FrameReject.from_bytes(info, MODULO_128)
    assert info[1] == 0
    assert reject.control == FrameType.SNRME | 0x10
    assert reject.w


# -- SNRM/UA information field (ISO/IEC 8885 via V.42 12.2) -----------------------


def test_parameter_identifiers_and_value_order_match_v42_table_11a():
    # PI 5/6 maximum information field length tx/rx, PI 7/8 window tx/rx;
    # a multi-octet value carries the higher-order bits first.
    group = bytes.fromhex("0502 0400  0602 0123  0701 03  0801 05")
    params, user_data = parse_parameter_field(bytes([0x81, 0x80, len(group)]) + group)
    assert params == HdlcParameters(max_info_tx=0x400, max_info_rx=0x123, window_tx=3, window_rx=5)
    assert user_data == b""


def test_user_data_subfield_has_no_length_and_runs_to_the_end():
    # V.42 12.2.1.3: the user data subfield (GI 11111111) follows all data
    # link layer subfields, has no group length, and is bounded by the FCS.
    data = bytes([0x80, 0x05, 0xFF, 0x00, 0x81])
    _, user_data = parse_parameter_field(HdlcParameters().to_bytes(data))
    assert user_data == data
    assert HdlcParameters().to_bytes(data).endswith(b"\xff" + data)
