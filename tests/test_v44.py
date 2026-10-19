"""ITU-T V.44 packet-method decoder (``pydlms.security.v44``).

Known answers come from ITU-T V.44 (11/2000) Appendix II:
II.1 gives the input, the octets (Table II.1) and the decoder string
collection after stage 11; II.2 gives the codes and the string collection
but no octet table, so its octets are built here bit by bit from the stage
text and Tables 3 and 5 (a derived vector, not one printed in V.44).
Round trips use the test-support encoder in ``tests/v44_encoder.py``.
"""

from __future__ import annotations

import random

import pytest

from pydlms.exceptions import DecodeError
from pydlms.security.ciphering import MAX_DECOMPRESSED_DEFAULT
from pydlms.security.v44 import V44Decoder, _Packet, extension_bits, v44_decompressor
from tests.v44_encoder import compress

# --- vectors -------------------------------------------------------------------------

#: V.44 II.1 input "ABCDEXABCDEYABCDE FFH AC".
II1_INPUT = b"ABCDEXABCDEYABCDE\xffAC"
#: V.44 Table II.1, octets 1 to 15 (bit 8 first in the table).
II1_OCTETS = bytes.fromhex("828486888AB009295B29F817646800")
#: V.44 II.1 stage 11 decoder string collection: codeword -> (last position, length).
II1_STRINGS = {
    4: (1, 2),
    5: (2, 2),
    6: (3, 2),
    7: (4, 2),
    8: (5, 2),
    9: (6, 2),
    10: (10, 5),
    11: (12, 2),
    12: (17, 6),
    13: (18, 2),
    14: (19, 2),
}


def code(value: int, width: int) -> str:
    """A code's bits in transmission order: least significant first (6.6)."""
    return "".join(str(value >> i & 1) for i in range(width))


def pack(bits: str) -> bytes:
    """Pack transmission-order bits into octets, bit 1 first, zero padded."""
    bits += "0" * (-len(bits) % 8)
    return bytes(int(bits[i : i + 8][::-1], 2) for i in range(0, len(bits), 8))


FLUSH_6 = "1" + code(1, 6)  # FLUSH with prefix "1", C2 = 6

#: V.44 II.2 "CCCCCCCCCCX": ordinal C, codeword 4 (= C1, rule 4), string-extension
#: length 7, ordinal X; then FLUSH to end the packet (B.1.1).
II2_OCTETS = pack(
    "".join(
        [
            "0" + code(0x43, 7),  # ordinal "C", prefix "0" after reinitialization
            "1" + code(4, 6),  # codeword 4
            "01" + "0" + "00" + "0" + code(2, 3),  # prefix "0" "1", length 7 (Table 3)
            "0" + code(0x58, 7),  # ordinal "X", prefix "0" after an extension
            FLUSH_6,
        ]
    )
)


def decode(data: bytes, limit: int = 1 << 20, **params) -> bytes:
    return V44Decoder(**params).decompress(data, max_output=limit)


# --- known answers ---------------------------------------------------------------------


def test_appendix_ii1_octets_decode():
    assert decode(II1_OCTETS) == II1_INPUT


def test_appendix_ii1_string_collection():
    packet = _Packet(V44Decoder(), II1_OCTETS, 100)
    packet.run()
    assert packet.strings == II1_STRINGS
    assert (packet.c1, packet.c2, packet.c5) == (15, 6, 8)


def test_appendix_ii1_encoder_reproduces_table():
    assert compress(II1_INPUT) == II1_OCTETS


def test_appendix_ii2_codeword_equal_to_c1():
    assert II2_OCTETS == bytes.fromhex("860941b003")
    packet = _Packet(V44Decoder(), II2_OCTETS, 100)
    assert packet.run() == b"CCCCCCCCCCX"
    assert packet.strings == {4: (1, 2), 5: (9, 9)}
    assert compress(b"CCCCCCCCCCX") == II2_OCTETS


@pytest.mark.parametrize(
    ("n7", "width"),
    [(32, 5), (46, 5), (47, 6), (78, 6), (79, 7), (142, 7), (143, 8), (255, 8)],
)
def test_extension_width_table4(n7, width):
    assert extension_bits(n7) == width


def test_uncompressed_packet_indicator():
    """Annex B: ETM with prefix "1" in the first octet, then the original data."""
    assert pack("1" + code(0, 6)) == b"\x01"
    assert decode(b"\x01" + b"\xc4\x01\x00") == b"\xc4\x01\x00"
    with pytest.raises(DecodeError, match="exceeds"):
        decode(b"\x01" + b"\x00" * 10, limit=9)
    with pytest.raises(DecodeError, match="padding"):
        decode(b"\x81\x00")


# --- round trips ---------------------------------------------------------------------


def _samples(seed: int) -> list[bytes]:
    rng = random.Random(seed)
    out = [b"\x00", bytes(range(256)), b"\xff" * 700, II1_INPUT * 50]
    for size in (2, 17, 300, 4000):
        for alphabet in (2, 5, 256):
            out.append(bytes(rng.randrange(alphabet) for _ in range(size)))
    apdu = bytes.fromhex("C401C100010203090C07E2020C0500000000800000110006000186A0")
    out.append(apdu * 40)
    return out


@pytest.mark.parametrize("n2", [256, 1525, 4096])
@pytest.mark.parametrize("n7", [32, 46, 47, 78, 79, 142, 143, 255])
def test_round_trip(n2, n7):
    decoder = V44Decoder(n2=n2, n7=n7)
    for data in _samples(n2 * 1000 + n7):
        assert decoder.decompress(compress(data, n2, n7), max_output=len(data)) == data


def test_round_trip_steps_codeword_size_to_n1():
    """Enough distinct strings to need every codeword size up to N1 = 11 (7.11.2)."""
    data = random.Random(7).randbytes(20000)
    packet = _Packet(V44Decoder(), compress(data), len(data))
    assert packet.run() == data
    assert packet.c2 == 11 and packet.c1 == 1525


def test_empty_packet():
    assert compress(b"") == pack(FLUSH_6)
    assert decode(pack(FLUSH_6)) == b""


# --- malformed input -----------------------------------------------------------------


def test_truncated_at_every_octet():
    data = compress(II1_INPUT * 20)
    for cut in range(len(data)):
        with pytest.raises(DecodeError):
            decode(data[:cut])


def test_missing_flush():
    with pytest.raises(DecodeError, match="ends inside"):
        decode(pack("0" + code(0x41, 7)))


def test_trailing_octets_and_padding_after_flush():
    with pytest.raises(DecodeError, match="after the FLUSH"):
        decode(II1_OCTETS + b"\x00")
    bad_padding = bytearray(II1_OCTETS)
    bad_padding[-1] |= 0x80
    with pytest.raises(DecodeError, match="padding"):
        decode(bytes(bad_padding))


@pytest.mark.parametrize(
    ("bits", "message"),
    [
        ("1" + code(5, 6), "beyond the next codeword"),  # C1 = 4
        ("1" + code(4, 6), "not defined"),  # = C1 with no previous code
        ("0" + code(0x41, 7) + "1" + code(6, 6), "beyond the next codeword"),
        # = C1 after a string extension: nothing to create (6.4.1 rules 3, 4)
        ("0" + code(0x41, 7) + "1" + code(4, 6) + "011" + "1" + code(6, 6), "not defined"),
    ],
)
def test_invalid_codewords(bits, message):
    with pytest.raises(DecodeError, match=message):
        decode(pack(bits + FLUSH_6))


STEPUP_6 = "1" + code(2, 6)


@pytest.mark.parametrize(
    ("bits", "message"),
    [
        ("0" + code(0x41, 7) + "1" + code(0, 6), "ETM inside"),
        (STEPUP_6 + "1" + code(1, 7), "FLUSH straight after STEPUP"),
        (STEPUP_6 + "1" + code(3, 7), "REINIT straight after STEPUP"),
        (STEPUP_6 + "1" + code(0, 7), "ETM straight after STEPUP"),
        ("0" + code(0x41, 7) + "1" + code(3, 6), "REINIT in a packet-method"),
        (STEPUP_6 + "0" + code(0xFF, 8) + STEPUP_6 + "0" + code(0, 8), "8-bit ordinal"),
    ],
)
def test_invalid_control_codes(bits, message):
    with pytest.raises(DecodeError, match=message):
        decode(pack(bits + FLUSH_6))


def test_stepup_beyond_n1():
    """N2 = 256 gives N1 = 8: two codeword STEPUPs fit, a third does not (7.15)."""
    ab = "0" + code(0x41, 7) + "0" + code(0x42, 7)  # codeword 4 is "AB"
    two = STEPUP_6 + "1" + code(2, 7)  # C2 6 -> 7 -> 8
    assert decode(pack(ab + two + "1" + code(4, 8) + "1" + code(1, 8)), n2=256) == b"ABAB"
    three = two + "1" + code(2, 8)
    with pytest.raises(DecodeError, match="N1 = 8"):
        decode(pack(ab + three + "1" + code(4, 9) + "1" + code(1, 9)), n2=256)


def test_extension_beyond_n7():
    """Ordinal A, codeword 4 (= C1: "AA"), then an extension to N7 + 1 characters."""
    head = "0" + code(0x41, 7) + "1" + code(4, 6) + "01" + "0001"

    def ext(k: int) -> str:
        return head + code(k - 13, 5)

    assert decode(pack(ext(30) + FLUSH_6), n7=32) == b"A" * 33
    with pytest.raises(DecodeError, match="longer than N7"):
        decode(pack(ext(31) + FLUSH_6), n7=32)


def test_no_string_longer_than_n7_is_created():
    """Table 2 note: a 32-character string followed by an ordinal gains no 33rd."""
    head = "0" + code(0x41, 7) + "1" + code(4, 6) + "01" + "0001" + code(30 - 13, 5)
    # codeword 5 is the 32-character string; prefix "1", then ordinal B with "0" "0"
    bits = head + "1" + code(5, 6) + "00" + code(0x42, 7) + FLUSH_6
    for n7, created in ((32, False), (33, True)):
        packet = _Packet(V44Decoder(n7=n7), pack(bits), 100)
        assert packet.run() == b"A" * 65 + b"B"
        assert packet.strings[5] == (32, 32)
        assert (6 in packet.strings) is created


# --- bounds ---------------------------------------------------------------------------


def test_output_cap():
    assert decode(II1_OCTETS, limit=len(II1_INPUT)) == II1_INPUT
    with pytest.raises(DecodeError, match="exceeds the limit"):
        decode(II1_OCTETS, limit=len(II1_INPUT) - 1)


def test_bomb_is_bounded():
    """200000 octets in under 1 kB: the cap stops it, not the input."""
    bomb = compress(b"A" * 200_000)
    assert len(bomb) < 1000
    with pytest.raises(DecodeError, match="exceeds the limit"):
        v44_decompressor()(bomb)
    assert len(v44_decompressor(max_output=200_000)(bomb)) == 200_000


def test_history_bound_n8():
    data = bytes(range(256)) * 3
    with pytest.raises(DecodeError, match="N8 = 512"):
        decode(compress(data), n8=512)
    # REINIT is honoured when the history is bounded, and resets the dictionary
    a, b, cw5 = "0" + code(0x41, 7), "0" + code(0x42, 7), "1" + code(5, 6)
    # without REINIT, codeword 4 is "AB" and codeword 5 (= C1) is "B" + "B"
    assert decode(pack(a + b + cw5 + FLUSH_6), n8=512) == b"ABBB"
    with pytest.raises(DecodeError, match="beyond the next codeword"):
        decode(pack(a + "1" + code(3, 6) + b + cw5 + FLUSH_6), n8=512)
    assert decode(pack(a + "1" + code(3, 6) + b + FLUSH_6), n8=512) == b"AB"


def test_random_input_only_raises_decode_error():
    rng = random.Random(44)
    decoder = V44Decoder()
    for _ in range(3000):
        data = rng.randbytes(rng.randrange(1, 64))
        try:
            out = decoder.decompress(data, max_output=4096)
        except DecodeError:
            continue
        assert len(out) <= 4096


# --- parameters and the hook ------------------------------------------------------------


@pytest.mark.parametrize(
    "params",
    [
        {"n2": 255},
        {"n2": 65536},
        {"n7": 31},
        {"n7": 256},
        {"n8": 511},
        {"n8": 65536},
        {"n2": True},
        {"method": "stream"},
        {"method": "multi-packet"},
    ],
)
def test_parameters_validated(params):
    with pytest.raises(ValueError):
        V44Decoder(**params)
    with pytest.raises(ValueError):
        v44_decompressor(**params)


def test_defaults_are_annex_b12():
    decoder = V44Decoder()
    assert (decoder.n2, decoder.n7, decoder.n8, decoder.method) == (1525, 255, None, "packet")
    assert decoder.n1 == 11
    assert V44Decoder(n2=65535).n1 == 16
    assert V44Decoder(n2=256).n1 == 8


def test_hook_defaults_to_unwrap_limit():
    hook = v44_decompressor()
    assert hook(II1_OCTETS) == II1_INPUT
    assert len(hook(compress(b"Z" * MAX_DECOMPRESSED_DEFAULT))) == MAX_DECOMPRESSED_DEFAULT
    with pytest.raises(DecodeError):
        hook(compress(b"Z" * (MAX_DECOMPRESSED_DEFAULT + 1)))
    with pytest.raises(ValueError):
        v44_decompressor(max_output=-1)
