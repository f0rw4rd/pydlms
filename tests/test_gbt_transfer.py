"""General-block-transfer codec and the sans-IO GbtTransfer.

Codec vectors come from the cross-library review (``review-framing.md``
F11 repro bytes), the L+G E450 push headers (esphome-libs/dlms_parser) and
the acknowledgement layout of the Gurux server (``GXDLMSServer.cs``
HandleGeneralBlockTransfer: ``E0 | 80|window | block-number |
block-number-ack | 00``) and the go-dlms server (``server/transport.go``
gbtBlock, window 1, no streaming). No reference implements lost-block
recovery, so recovery is pinned against scripted peers here and the
simulator in ``test_gbt_send.py``.
"""

from __future__ import annotations

import pytest

from pydlms.apdu.gbt import (
    GbtApdu,
    GbtBlock,
    GbtHeader,
    GbtReassembler,
    GbtTransfer,
    decode_gbt,
    encode_gbt,
    gbt_overhead,
    split_gbt,
)
from pydlms.exceptions import DecodeError, ProtocolError


def blk(raw: bytes) -> GbtBlock:
    return decode_gbt(raw)


def ack(number: int, acked: int, window: int = 1, last: bool = True) -> bytes:
    """An acknowledgement-only block from the peer."""
    return encode_gbt(GbtBlock(last, False, window, number, acked, b""))


# --- codec --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("block", "hexed"),
    [
        # REVIEW F11 fixed: the client ack after server block 1, our window 1.
        (GbtBlock(True, False, 1, 2, 1, b""), "e0810002000100"),
        # The Gurux server acknowledgement layout (window 1, block 1 acked).
        (GbtBlock(True, False, 1, 1, 1, b""), "e0810001000100"),
        # go-dlms server acknowledgement: last=0, window 1, its block 0.
        (GbtBlock(False, False, 1, 0, 3, b""), "e0010000000300"),
        # E450 push block 1 header (window 0, streaming), 3 data octets.
        (GbtBlock(False, True, 0, 1, 0, b"\x0f\x00\x01"), "e0400001000003" + "0f0001"),
        # Window 63, streaming, two-octet length form.
        (GbtBlock(False, True, 63, 0xFFFF, 0x1234, bytes(200)), "e07fffff123481c8" + "00" * 200),
    ],
)
def test_gbt_known_vectors(block, hexed):
    raw = bytes.fromhex(hexed)
    assert encode_gbt(block) == raw
    assert decode_gbt(raw) == block


@pytest.mark.parametrize("last", [False, True])
@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("window", [0, 1, 7, 63])
@pytest.mark.parametrize("size", [0, 1, 127, 128, 300])
def test_gbt_round_trip(last, streaming, window, size):
    block = GbtBlock(last, streaming, window, 513, 258, bytes(range(256)) * 2)
    block = GbtBlock(last, streaming, window, 513, 258, block.data[:size])
    raw = encode_gbt(block)
    assert decode_gbt(raw) == block
    parsed = GbtApdu.parse(raw)
    assert (parsed.control.last, parsed.control.streaming, parsed.control.window) == (
        last,
        streaming,
        window,
    )


def test_gbt_header_struct():
    assert GbtHeader.sizeof() == 6
    assert GbtHeader.build(
        {
            "control": {"last": True, "streaming": True, "window": 5},
            "block_number": 2,
            "block_number_ack": 1,
        }
    ) == bytes.fromhex("e0c500020001")
    assert [gbt_overhead(n) for n in (0, 127, 128, 255, 256, 65535, 65536)] == [
        7,
        7,
        8,
        8,
        9,
        9,
        10,
    ]


@pytest.mark.parametrize("cut", range(1, 10))
def test_gbt_every_truncation_is_refused(cut):
    raw = encode_gbt(GbtBlock(True, False, 1, 2, 1, b"abc"))
    with pytest.raises(DecodeError):
        decode_gbt(raw[:-cut])


@pytest.mark.parametrize(
    "hexed",
    [
        "e0810002000103616263ff",  # trailing octet after block-data
        "e081000200018000",  # indefinite length 0x80
        "e0810002000185" + "00" * 5,  # five length octets
        "e1810002000100",  # wrong tag
    ],
)
def test_gbt_malformed(hexed):
    with pytest.raises(DecodeError):
        decode_gbt(bytes.fromhex(hexed))


@pytest.mark.parametrize(
    "block",
    [
        GbtBlock(True, False, 64, 1, 0, b""),
        GbtBlock(True, False, 1, 0x10000, 0, b""),
        GbtBlock(True, False, 1, 1, -1, b""),
    ],
)
def test_gbt_encode_refuses_out_of_range_fields(block):
    with pytest.raises(ValueError):
        encode_gbt(block)


# --- reassembler in recovery mode -----------------------------------------------------


def test_reassembler_recover_drops_past_a_gap():
    blocks = [blk(b) for b in split_gbt(bytes(range(90)), 30)]
    gbt = GbtReassembler(recover=True)
    assert gbt.add(blocks[0]) is None and gbt.last_event == "added"
    assert gbt.add(blocks[2]) is None and gbt.last_event == "gap"
    assert gbt.last_in_order == 1 and gbt.in_progress
    assert gbt.add(blocks[0]) is None and gbt.last_event == "duplicate"
    assert gbt.add(blocks[1]) is None
    assert gbt.add(blocks[2]) == bytes(range(90))


def test_reassembler_recover_does_not_restart_on_block_one():
    gbt = GbtReassembler(recover=True)
    gbt.add(blk(split_gbt(bytes(60), 30)[0]))
    assert gbt.add(blk(split_gbt(b"abc", 30)[0])) is None
    assert gbt.last_event == "duplicate"


def test_reassembler_base_and_cap_reset():
    gbt = GbtReassembler(max_size=40, recover=True)
    gbt.reset(5)
    assert not gbt.in_progress and gbt.expected == 5
    gbt.add(GbtBlock(False, False, 1, 5, 0, bytes(30)))
    with pytest.raises(ProtocolError, match="exceeds 40"):
        gbt.add(GbtBlock(True, False, 1, 6, 0, bytes(30)))
    assert gbt.expected == 5 and not gbt.in_progress


# --- GbtTransfer: send side ---------------------------------------------------------


def test_three_blocks_window_1():
    t = GbtTransfer(window=1)
    first = t.send(bytes(range(30)), 10)
    assert [blk(b) for b in first] == [GbtBlock(False, False, 1, 1, 0, bytes(range(10)))]
    step = t.receive(blk(ack(1, 1)))
    assert [blk(b).block_number for b in step.send] == [2]
    step = t.receive(blk(ack(2, 2)))
    (third,) = (blk(b) for b in step.send)
    assert (third.last, third.streaming, third.block_number) == (True, False, 3)
    assert third.block_number_ack == 2  # last peer block seen
    assert t.sending  # our last block is acknowledged by the answer
    assert t.receive(blk(ack(3, 3))).send == []
    assert not t.sending


def test_three_blocks_window_3_streaming_bits():
    t = GbtTransfer(window=2, peer_window=3)
    blocks = [blk(b) for b in t.send(bytes(30), 10)]
    assert [(b.block_number, b.streaming, b.last) for b in blocks] == [
        (1, True, False),
        (2, True, False),
        (3, False, True),
    ]
    assert {b.window for b in blocks} == {2}  # our window, not the peer's


def test_peer_window_is_learned_from_its_blocks():
    t = GbtTransfer()
    t.send(bytes(70), 10)  # 7 blocks; window 1 until the peer says otherwise
    step = t.receive(blk(ack(1, 1, window=3)))
    assert [(blk(b).block_number, blk(b).streaming) for b in step.send] == [
        (2, True),
        (3, True),
        (4, False),
    ]
    assert t.peer_window == 3


def test_every_block_carries_our_window_and_the_ack():
    t = GbtTransfer(window=5)
    t.send(bytes(30), 10)
    out = t.receive(blk(ack(7, 1))).send + t.receive(blk(ack(8, 2))).send
    assert [(blk(b).window, blk(b).block_number_ack) for b in out] == [(5, 7), (5, 8)]


def test_low_ack_rewinds():
    t = GbtTransfer(peer_window=3)
    t.send(bytes(60), 10)  # blocks 1..3 sent
    step = t.receive(blk(ack(1, 1, window=3)))  # peer has only block 1
    assert [blk(b).block_number for b in step.send] == [2, 3, 4]
    assert t.retransmissions == 1


def test_ack_zero_rewinds_to_block_one():
    t = GbtTransfer(peer_window=3)
    t.send(bytes(60), 10)
    assert [blk(b).block_number for b in t.receive(blk(ack(1, 0, window=3))).send] == [1, 2, 3]


def test_rewinds_are_bounded():
    t = GbtTransfer(peer_window=2, max_retransmissions=2)
    t.send(bytes(60), 10)
    t.receive(blk(ack(1, 1)))
    t.receive(blk(ack(2, 1)))
    with pytest.raises(ProtocolError, match="giving up after 2 retransmissions"):
        t.receive(blk(ack(3, 1)))


def test_ack_of_an_unsent_block_is_refused():
    t = GbtTransfer()
    t.send(bytes(30), 10)
    with pytest.raises(ProtocolError, match="only 1 were sent"):
        t.receive(blk(ack(1, 2)))


def test_stale_ack_is_dropped_and_counted():
    t = GbtTransfer()
    t.send(bytes(30), 10)
    t.receive(blk(ack(1, 1)))
    t.receive(blk(ack(2, 2)))
    assert t.receive(blk(ack(3, 1))).send == [] and t.retransmissions == 1


def test_send_refuses_more_than_65535_blocks():
    with pytest.raises(ProtocolError, match="65535"):
        GbtTransfer().send(bytes(70000), 1)


def test_timeout_resends_the_unacknowledged_window():
    t = GbtTransfer(peer_window=2)
    t.send(bytes(50), 10)
    assert [blk(b).block_number for b in t.on_timeout()] == [1, 2]


# --- GbtTransfer: receive side ------------------------------------------------------


def _response_blocks(
    data: bytes, size: int, first: int = 1, streaming=None, acked: int = 3
) -> list[GbtBlock]:
    """Blocks of ``data``; a push in GBT acknowledges nothing (``acked=0``)."""
    chunks = [data[i : i + size] for i in range(0, len(data), size)]
    flags = streaming or [False] * len(chunks)
    return [
        GbtBlock(i == len(chunks) - 1, flags[i], 1, first + i, acked, c)
        for i, c in enumerate(chunks)
    ]


def test_numbering_continues_from_the_request():
    """Our request was blocks 1..3; the acknowledgements go on from 4."""
    t = GbtTransfer()
    t.send(bytes(30), 10)
    t.receive(blk(ack(1, 1)))
    t.receive(blk(ack(2, 2)))
    response = _response_blocks(bytes(range(25)), 10, first=3)
    acks = [blk(b) for b in t.receive(response[0]).send + t.receive(response[1]).send]
    assert [(a.block_number, a.block_number_ack) for a in acks] == [(4, 3), (5, 4)]
    assert t.receive(response[2]).apdu == bytes(range(25))


def test_receive_gap_is_recovered_at_the_window_end():
    data = bytes(range(50))
    b1, b2, b3, b4, b5 = _response_blocks(data, 10, streaming=[True, True, False, True, False])
    t = GbtTransfer(window=3)
    t.count_block()
    assert t.receive(b1).send == []
    assert t.receive(b3).send == [encode_gbt(GbtBlock(True, False, 3, 2, 1, b""))]
    assert t.retransmissions == 1
    assert t.receive(b2).send == []
    assert [blk(a).block_number_ack for a in t.receive(b3).send] == [3]
    assert t.receive(b4).send == []
    assert t.receive(b5).apdu == data


def test_gap_at_the_last_block_asks_again():
    b1, b2, b3 = _response_blocks(bytes(30), 10, streaming=[True, True, True])
    t = GbtTransfer()
    t.receive(b1)
    assert [blk(a).block_number_ack for a in t.receive(b3).send] == [1]
    t.receive(b2)
    assert t.receive(b3).apdu == bytes(30)


def test_receive_recovery_is_bounded():
    b1, _, b3 = _response_blocks(bytes(30), 10)
    t = GbtTransfer(max_retransmissions=1)
    t.receive(b1)
    t.receive(b3)
    with pytest.raises(ProtocolError, match="giving up"):
        t.receive(b3)


def test_timeout_during_receive_acknowledges_the_last_in_order_block():
    b1, _, _ = _response_blocks(bytes(30), 10, streaming=[True, True, False])
    t = GbtTransfer()
    t.count_block()
    t.receive(b1)
    assert [blk(a).block_number_ack for a in t.on_timeout()] == [1]
    assert GbtTransfer().on_timeout() == []  # nothing owed: the caller re-raises


def test_response_base_follows_the_peer_acknowledgement_numbers():
    """Gurux numbers its acknowledgements 1, 2 and goes on with data at 3."""
    t = GbtTransfer()
    t.send(bytes(30), 10)
    t.receive(blk(ack(1, 1)))
    t.receive(blk(ack(2, 2)))
    first, second = _response_blocks(bytes(range(15)), 10, first=3)
    t.receive(first)
    assert t.receive(second).apdu == bytes(range(15))


def test_interleaved_push_does_not_corrupt_the_response():
    response = _response_blocks(b"R" * 25, 10, streaming=[True, True, True])
    push = _response_blocks(b"P" * 15, 10, streaming=[True, True], acked=0)
    t = GbtTransfer()
    t.count_block()
    order = [response[0], push[0], response[1], push[1], response[2]]
    done = [t.receive(b).apdu for b in order]
    assert done == [None, None, None, b"P" * 15, b"R" * 25]


def test_push_during_our_send_goes_apart():
    t = GbtTransfer()
    t.send(bytes(30), 10)
    (push,) = _response_blocks(b"P" * 5, 10)
    assert t.receive(push).apdu == b"P" * 5
    assert t.sending and [blk(b).block_number for b in t.receive(blk(ack(1, 1))).send] == [2]


def test_peer_numbering_may_go_on_across_exchanges():
    """go-dlms numbers its GBT blocks across exchanges; others start at 1."""
    data = bytes(range(30))
    t = GbtTransfer(peer_last=1)
    t.count_block()
    b2, b3 = _response_blocks(data, 15, first=2)
    assert t.receive(b2).send == [encode_gbt(GbtBlock(True, False, 1, 2, 2, b""))]
    assert t.receive(b3).apdu == data
    assert t.peer_last == 3
    t = GbtTransfer(peer_last=3)
    t.count_block()
    b1, b2 = _response_blocks(data, 15)
    t.receive(b1)
    assert t.receive(b2).apdu == data


def test_gap_before_the_first_block_of_a_numbered_on_stream():
    t = GbtTransfer(peer_last=4)
    t.count_block()
    _, b6, b7 = _response_blocks(bytes(30), 10, first=5)
    assert [blk(a).block_number_ack for a in t.receive(b6).send] == [4]
    assert t.receive(b7).send and t.retransmissions == 2
