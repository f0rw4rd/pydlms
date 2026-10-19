"""General-block-transfer (GBT, tag 0xE0; DLMS UA 1000-2 Ed. 9 9.1.4.4.9, 9.3.5, 9.4.6.13).

::

    E0 | block-control(1) | block-number(2) | block-number-ack(2) | block-data

* block-control: bit 7 last-block, bit 6 streaming, bits 5..0 window size.
* block-data is an A-XDR length-prefixed octet string.

Used by servers to stream long APDUs (the L+G E450 push splits a 0xDB APDU
over three GBT blocks, one per HDLC UI frame) and negotiable for client
requests via the ``general-block-transfer`` conformance bit.

:class:`GbtTransfer` is the sans-IO state of one exchange: it cuts an APDU
into blocks sent a window at a time, rewinds on a low block-number-ack, and
reassembles the peer's blocks, asking again for a lost one.

Per the public DLMS UA 1000-2 Ed. 9 Excerpt: the mechanism is 9.1.4.4.9, the
parameters 9.3.5 and the protocol 9.4.6.13. Figure 40 gives the block-control bits above
(LB bit 7, STR bit 6, window bits 0..5) and BN / BNA; the window is the
number of blocks the sender of the field can receive in a stream
(9.4.6.13.1); BN = 1 with BNA = 0 starts an exchange and STR = 0 with
window 0 marks an unconfirmed (unacknowledged) stream (9.4.6.13.5.1). "If
one party sends a request or a response using GBT, the other party shall
follow" (9.4.6.13.1); the client still accepts a plain answer, which Gurux
servers send. The send and gap-filling sub-procedures are not in the
excerpt, so the recovery details (when to rewind, retries) are
*unverified* and follow the cross-library review (``review-framing.md``
F11).
"""

from __future__ import annotations

from dataclasses import dataclass, field

import construct
from construct import BitsInteger, BitStruct, Const, Flag, GreedyBytes, Int16ub, Prefixed, Struct

from pydlms.apdu.tags import Tag
from pydlms.axdr import DlmsLength, encode_length
from pydlms.debug import get_logger
from pydlms.exceptions import DecodeError, ProtocolError

__all__ = [
    "GbtBlock",
    "GbtHeader",
    "GbtApdu",
    "GbtStep",
    "GbtTransfer",
    "encode_gbt",
    "decode_gbt",
    "gbt_overhead",
    "GbtReassembler",
    "split_gbt",
    "MAX_GBT_APDU",
    "MAX_GBT_WINDOW",
    "MAX_GBT_BLOCK_NUMBER",
]

log = get_logger("apdu")

#: Default limit on one reassembled APDU (16 MiB). Far above any real
#: profile read, it only stops a peer from growing the buffer without end
#: (up to 65535 blocks, each as long as it likes).
MAX_GBT_APDU = 16 << 20
#: The window field is 6 bits wide.
MAX_GBT_WINDOW = 0x3F
#: Block numbers are Unsigned16.
MAX_GBT_BLOCK_NUMBER = 0xFFFF

#: Fixed part of a GBT APDU: tag, block-control, block-number, block-number-ack.
GbtHeader = Struct(
    "tag" / Const(bytes([Tag.GENERAL_BLOCK_TRANSFER])),
    "control"
    / BitStruct(
        "last" / Flag,
        "streaming" / Flag,
        "window" / BitsInteger(6),
    ),
    "block_number" / Int16ub,
    "block_number_ack" / Int16ub,
)
#: A whole GBT APDU: the header, then block-data as an A-XDR octet string
#: that must end the APDU.
GbtApdu = Struct(
    *GbtHeader.subcons,
    "data" / Prefixed(DlmsLength, GreedyBytes),
    construct.Terminated,
)


@dataclass(frozen=True)
class GbtBlock:
    last: bool
    streaming: bool
    window: int
    block_number: int
    block_number_ack: int
    data: bytes

    def control(self) -> int:
        return (0x80 if self.last else 0) | (0x40 if self.streaming else 0) | (self.window & 0x3F)


def gbt_overhead(block_size: int) -> int:
    """Octets a GBT APDU adds around ``block_size`` octets of block-data."""
    return GbtHeader.sizeof() + len(encode_length(block_size))


def encode_gbt(block: GbtBlock) -> bytes:
    for name, value, top in (
        ("window", block.window, MAX_GBT_WINDOW),
        ("block number", block.block_number, MAX_GBT_BLOCK_NUMBER),
        ("block-number-ack", block.block_number_ack, MAX_GBT_BLOCK_NUMBER),
    ):
        if not 0 <= value <= top:
            raise ValueError(f"GBT {name} {value} is outside 0..{top}")
    return GbtApdu.build(
        {
            "control": {
                "last": block.last,
                "streaming": block.streaming,
                "window": block.window,
            },
            "block_number": block.block_number,
            "block_number_ack": block.block_number_ack,
            "data": bytes(block.data),
        }
    )


def decode_gbt(apdu: bytes) -> GbtBlock:
    if len(apdu) < 7 or apdu[0] != Tag.GENERAL_BLOCK_TRANSFER:
        raise DecodeError("not a general-block-transfer APDU")
    try:
        parsed = GbtApdu.parse(apdu)
    except construct.ConstructError as exc:
        raise DecodeError(f"malformed GBT APDU ({len(apdu)} octets): {exc}") from exc
    return GbtBlock(
        last=parsed.control.last,
        streaming=parsed.control.streaming,
        window=parsed.control.window,
        block_number=parsed.block_number,
        block_number_ack=parsed.block_number_ack,
        data=bytes(parsed.data),
    )


def split_gbt(
    apdu: bytes, block_size: int, window: int = 1, streaming: bool = False, first_block: int = 1
) -> list[bytes]:
    """Split ``apdu`` into GBT APDUs of at most ``block_size`` data octets."""
    if block_size < 1:
        raise ValueError("block size must be positive")
    chunks = [apdu[i : i + block_size] for i in range(0, len(apdu), block_size)] or [b""]
    return [
        encode_gbt(GbtBlock(i == len(chunks) - 1, streaming, window, first_block + i, 0, chunk))
        for i, chunk in enumerate(chunks)
    ]


class GbtReassembler:
    """Collect GBT blocks into the APDU they carry.

    An error (a block out of sequence, an APDU over ``max_size``) discards
    the partial APDU, so the next transfer starts clean at block 1. A block
    already received (a retransmission) is dropped.

    With ``recover=True`` (used by :class:`GbtTransfer`, which can ask the
    peer again) a block past a gap is dropped instead of raising, and a
    block 1 does not restart the transfer. :attr:`last_event` then says what
    the last :meth:`add` did: ``"added"``, ``"duplicate"`` or ``"gap"``.
    """

    def __init__(self, max_size: int | None = MAX_GBT_APDU, recover: bool = False) -> None:
        self._data = bytearray()
        self._first = 1
        self._expected = 1
        #: Cap on the reassembled APDU (untrusted peer).
        self.max_size = MAX_GBT_APDU if max_size is None else max_size
        self.recover = recover
        self.last_event: str | None = None

    def reset(self, first: int = 1) -> None:
        """Drop any partial APDU; the next one starts at block ``first``."""
        self._data.clear()
        self._first = self._expected = first

    @property
    def expected(self) -> int:
        """The block number accepted next."""
        return self._expected

    @property
    def last_in_order(self) -> int:
        """The last block received without a gap before it."""
        return self._expected - 1

    def add(self, block: GbtBlock) -> bytes | None:
        """Add a block; returns the complete APDU after the last block.

        A block already received (a retransmission) is dropped; a gap
        raises :class:`ProtocolError` unless the reassembler recovers.
        """
        if not self.recover and block.block_number == 1 and self._expected != 1:
            log.debug("GBT restart at block 1; discarding %d octets", len(self._data))
            self.reset()
        if block.block_number < self._expected:
            log.debug("dropping duplicate GBT block %d", block.block_number)
            self.last_event = "duplicate"
            return None
        if block.block_number != self._expected:
            expected = self._expected
            if self.recover:
                log.debug(
                    "dropping GBT block %d past a gap (expected %d)", block.block_number, expected
                )
                self.last_event = "gap"
                return None
            self.reset()
            raise ProtocolError(
                f"GBT block {block.block_number} out of sequence (expected {expected})"
            )
        if len(self._data) + len(block.data) > self.max_size:
            self.reset(self._first)
            raise ProtocolError(f"GBT APDU exceeds {self.max_size} octets; discarded")
        self._data += block.data
        self._expected += 1
        self.last_event = "added"
        log.debug(
            "GBT block %d%s, %d octets",
            block.block_number,
            " (last)" if block.last else "",
            len(block.data),
        )
        if not block.last:
            return None
        apdu = bytes(self._data)
        self.reset(self._first)
        return apdu

    @property
    def in_progress(self) -> bool:
        return self._expected != self._first


@dataclass
class GbtStep:
    """What :meth:`GbtTransfer.receive` asks of the caller: APDUs to send
    (blocks, retransmissions, acknowledgements), and an APDU the peer's
    blocks completed, if any."""

    send: list[bytes] = field(default_factory=list)
    apdu: bytes | None = None


class GbtTransfer:
    """Sans-IO state of one general-block-transfer exchange.

    Send side (:meth:`send`): the APDU (already protected) is cut into
    blocks numbered on from the blocks this side already used. A window of
    blocks goes at a time, as many as the peer advertised in the window
    field of its own blocks (1 until it did), with the streaming bit on all
    but the last block of the window. Every block carries our receive
    window and the last peer block number seen. The peer's acknowledgement
    names the last block it received in order; a lower one than we sent
    rewinds to the block after it, at most ``max_retransmissions`` times
    in all (then :class:`ProtocolError`).

    Receive side (:meth:`receive`): the peer's blocks are reassembled from
    the block after its last acknowledgement-only block. A block past a gap
    is dropped; at the window end (a block with streaming=0) an
    acknowledgement names the last block received in order, so the peer
    retransmits the rest. Duplicates are dropped (acknowledged again at a
    window end). A block 1 while another stream is in progress opens a
    second, strictly in-order stream: a GBT-wrapped push interleaved with
    the response. Recovery acks, rewinds and timeouts share the bound.
    """

    def __init__(
        self,
        window: int = 1,
        max_retransmissions: int = 3,
        max_size: int | None = MAX_GBT_APDU,
        peer_window: int = 1,
        streaming: bool = True,
        peer_last: int = 0,
    ) -> None:
        if not 1 <= window <= MAX_GBT_WINDOW:
            raise ValueError(f"GBT window must be 1..{MAX_GBT_WINDOW}, got {window}")
        if max_retransmissions < 0:
            raise ValueError("max_retransmissions must not be negative")
        #: Our receive window, advertised in every block we send.
        self.window = window
        #: The peer's receive window (from its blocks): blocks per window we send.
        self.peer_window = max(1, min(peer_window, MAX_GBT_WINDOW))
        #: False: never stream (one block per window, whatever the peer takes).
        self.streaming = streaming
        self.max_retransmissions = max_retransmissions
        #: Rewinds, recovery acknowledgements and timeouts so far.
        self.retransmissions = 0
        self._chunks: list[bytes] = []
        self._base = 0  # number of our block before the first data block
        self._sent = 0  # highest number of our data blocks sent
        self._acked = 0  # highest number of our data blocks acknowledged
        self._number = 0  # last block number we used (data or acknowledgement)
        self._peer_number = 0  # highest number of a peer acknowledgement-only block
        self._peer_acked = False  # the peer sent acknowledgement-only blocks
        # The peer's last block number of an earlier exchange: some peers
        # (go-dlms) number on across exchanges, others start at 1 again.
        self._peer_last = peer_last
        self._peer_seen = peer_last  # last peer block taken in order
        self._rx = GbtReassembler(max_size, recover=True)
        self._side = GbtReassembler(max_size)
        # block-number-ack of the last block each stream took: a push in
        # GBT acknowledges nothing (0), the answer our last block.
        self._rx_ack: int | None = None
        self._side_ack: int | None = None

    # -- state --------------------------------------------------------------------
    def count_block(self) -> None:
        """Count an APDU sent outside GBT as our block (a plain request is
        block 1, so the acknowledgements are numbered from 2)."""
        self._number = self._next_number()

    @property
    def sending(self) -> bool:
        """Our APDU is not yet known to be received in full."""
        return self._acked < self._base + len(self._chunks)

    @property
    def receiving(self) -> bool:
        """A peer APDU is partly reassembled."""
        return self._rx.in_progress

    @property
    def active(self) -> bool:
        """Blocks are still owed in either direction."""
        return self.sending or self._rx.in_progress or self._side.in_progress

    @property
    def last_received(self) -> int:
        """The block-number-ack we would send now."""
        return self._rx.last_in_order if self._rx.in_progress else self._peer_seen

    def _next_number(self) -> int:
        if self._number >= MAX_GBT_BLOCK_NUMBER:
            raise ProtocolError("GBT block numbers exhausted (65535)")
        self._number += 1
        return self._number

    def _bump(self, reason: str) -> None:
        self.retransmissions += 1
        if self.retransmissions > self.max_retransmissions:
            raise ProtocolError(
                f"GBT: {reason}; giving up after {self.max_retransmissions} retransmissions"
            )
        log.info("GBT recovery %d/%d: %s", self.retransmissions, self.max_retransmissions, reason)

    def _ack(self) -> bytes:
        return encode_gbt(
            GbtBlock(True, False, self.window, self._next_number(), self.last_received, b"")
        )

    # -- send side ----------------------------------------------------------------
    def send(self, apdu: bytes, block_size: int) -> list[bytes]:
        """Cut ``apdu`` into blocks of ``block_size`` data octets; return the
        first window to send."""
        if block_size < 1:
            raise ValueError("block size must be positive")
        if self.sending:
            raise ProtocolError("GBT: the previous APDU is still being sent")
        chunks = [apdu[i : i + block_size] for i in range(0, len(apdu), block_size)] or [b""]
        if self._number + len(chunks) > MAX_GBT_BLOCK_NUMBER:
            raise ProtocolError(
                f"APDU of {len(apdu)} octets needs {len(chunks)} GBT blocks of {block_size}; "
                f"block numbers end at {MAX_GBT_BLOCK_NUMBER}"
            )
        self._chunks = chunks
        self._base = self._acked = self._sent = self._number
        log.debug("GBT: sending %d octets in %d blocks", len(apdu), len(chunks))
        return self._window(self._base + 1)

    def _window(self, start: int) -> list[bytes]:
        """Blocks ``start`` .. the window end (block numbers)."""
        final = self._base + len(self._chunks)
        size = self.peer_window if self.streaming else 1
        end = min(start + size - 1, final)
        out = [
            encode_gbt(
                GbtBlock(
                    number == final,
                    number != end,
                    self.window,
                    number,
                    self.last_received,
                    self._chunks[number - self._base - 1],
                )
            )
            for number in range(start, end + 1)
        ]
        self._sent = max(self._sent, end)
        self._number = max(self._number, end)
        return out

    def _on_ack(self, block: GbtBlock) -> GbtStep:
        self._peer_number = max(self._peer_number, block.block_number)
        self._peer_acked = True
        self._peer_seen = block.block_number
        final = self._base + len(self._chunks)
        ack = block.block_number_ack
        if ack > self._sent:
            raise ProtocolError(
                f"GBT acknowledgement of block {ack}, but only {self._sent} were sent"
            )
        if ack < self._acked:
            self._bump(f"stale acknowledgement of block {ack} (have {self._acked})")
            return GbtStep()
        if ack < self._sent:
            self._bump(f"peer lost block {ack + 1}")
            self._acked = ack
            return GbtStep(self._window(ack + 1))
        self._acked = ack
        if ack < final:
            return GbtStep(self._window(ack + 1))
        return GbtStep()

    # -- receive side -------------------------------------------------------------
    def receive(self, block: GbtBlock) -> GbtStep:
        """Take one block from the peer."""
        if block.window:
            self.peer_window = min(block.window, MAX_GBT_WINDOW)
        final = self._base + len(self._chunks)
        if not block.data and not self._rx.in_progress:
            if self._chunks:
                return self._on_ack(block)
            if not block.last:
                # An acknowledgement-only block although we sent no blocks.
                self._peer_number = max(self._peer_number, block.block_number)
                self._peer_acked = True
                self._peer_seen = block.block_number
                return GbtStep()
        if self._sent < final:
            # Data while our APDU is still incomplete cannot be the answer
            # to it: a push in GBT, kept apart from our transfer.
            return self._on_side(block)
        if self.sending:
            # The answer implies the peer has our APDU in full.
            self._acked = final
        return self._on_data(block)

    def _on_side(self, block: GbtBlock) -> GbtStep:
        self._side_ack = block.block_number_ack
        try:
            apdu = self._side.add(block)
        except ProtocolError as exc:
            self._bump(f"interleaved GBT stream dropped: {exc}")
            return GbtStep()
        return GbtStep(apdu=apdu)

    def _on_data(self, block: GbtBlock) -> GbtStep:
        number = block.block_number
        if number == 0:
            raise ProtocolError("GBT data block numbered 0")
        if not self._rx.in_progress:
            self._rx.reset(self._stream_base(number))
        if self._is_side(block):
            return self._on_side(block)
        apdu = self._rx.add(block)
        event = self._rx.last_event
        if event == "added":
            self._peer_seen = number
            self._rx_ack = block.block_number_ack
        if apdu is not None:
            return GbtStep(apdu=apdu)
        window_end = not block.streaming
        if event == "added":
            return GbtStep([self._ack()] if window_end else [])
        if event == "gap" and (window_end or block.last):
            self._bump(f"block {self._rx.expected} lost (got {number})")
            return GbtStep([self._ack()])
        if event == "duplicate" and window_end:
            self._bump(f"block {number} repeated")
            return GbtStep([self._ack()])
        return GbtStep()

    def _stream_base(self, number: int) -> int:
        """The block number a new peer stream starts at: after the peer's
        acknowledgement-only blocks of this exchange; without them, 1 or
        the number after its last block of the previous exchange,
        whichever ``number`` (the first block seen) suggests."""
        if self._peer_acked:
            return self._peer_number + 1
        return self._peer_last + 1 if number > self._peer_last else 1

    @property
    def peer_last(self) -> int:
        """The last block number the peer used, to seed the next exchange."""
        return self._peer_seen

    def _is_side(self, block: GbtBlock) -> bool:
        """Whether ``block`` belongs to the interleaved second stream: it
        starts one (block 1 while the main stream is past it), or it is the
        second stream's next block and not the main one's, or both expect
        it and only the second stream's block-number-ack matches."""
        number = block.block_number
        if number == 1 and self._rx.expected != 1:
            return True
        if not (self._side.in_progress and number == self._side.expected):
            return False
        if number != self._rx.expected:
            return True
        ack = block.block_number_ack
        return ack == self._side_ack and ack != self._rx_ack

    def on_timeout(self) -> list[bytes]:
        """What to send when the peer went quiet: the unacknowledged
        blocks again, or an acknowledgement of the last block received in
        order. Empty when nothing is owed (the caller re-raises)."""
        final = self._base + len(self._chunks)
        if self._sent < final:
            # A window of ours is unacknowledged: send it again.
            self._bump(f"no acknowledgement of block {self._sent}")
            return self._window(self._acked + 1)
        if self.sending or self._rx.in_progress:
            # The answer is due or incomplete: name the last block we have.
            self._bump(f"timeout waiting for block {self.last_received + 1}")
            return [self._ack()]
        return []
