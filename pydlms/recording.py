"""Read session recordings (``--record`` files) back into APDUs.

A recording is the text :meth:`pydlms.debug.FrameRecorder.dump` writes: one
``<direction> <hex>`` line per buffer, ``#`` comments allowed. ``TX``/``RX``
lines are raw transport buffers (HDLC frames, wrapper PDUs or M-Bus frames,
split wherever the transport read them); ``TX-APDU``/``RX-APDU`` lines are the
plaintext APDUs the association saw after deciphering.

:func:`session_apdus` returns the plaintext APDU sequence: the ``*-APDU``
lines when the recording has them, otherwise the APDUs reassembled from the
raw buffers per direction (frames re-joined across reads, HDLC segments and
general-block-transfer blocks reassembled). Ciphered APDUs found that way stay
ciphered; :mod:`pydlms.replay` refuses them and :mod:`pydlms.apduxml` shows
their security header.
"""

from __future__ import annotations

import os
from collections.abc import Iterable

from pydlms.apdu.gbt import GbtReassembler, decode_gbt
from pydlms.apdu.tags import Tag
from pydlms.exceptions import DecodeError

__all__ = ["DIRECTIONS", "parse_recording", "load_recording", "deframe", "session_apdus"]

DIRECTIONS = ("TX", "RX", "TX-APDU", "RX-APDU")


def parse_recording(text: str) -> list[tuple[str | None, bytes]]:
    """Parse recording text into ``(direction, bytes)``.

    A line without a direction prefix (plain hex, e.g. pasted frames) gets
    direction ``None``. Whitespace and ``:`` inside the hex are ignored.
    """
    records: list[tuple[str | None, bytes]] = []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        direction = None
        if parts[0].upper() in DIRECTIONS:
            direction = parts[0].upper()
            parts = parts[1:]
        try:
            records.append((direction, bytes.fromhex("".join(parts).replace(":", ""))))
        except ValueError:
            raise DecodeError(f"recording line {number} is not hex: {line[:40]!r}") from None
    return records


def load_recording(path: str | os.PathLike) -> list[tuple[str | None, bytes]]:
    with open(path, encoding="utf-8") as handle:
        return parse_recording(handle.read())


def _detect(data: bytes) -> str:
    """Framing of the first buffer of a direction. Unlike
    :func:`pydlms.explain.detect_framing` this does not require a whole
    wrapper PDU: a transport read may hold only its start."""
    if data[:1] == b"\x7e":
        return "hdlc"
    if data[:1] == b"\x68" and len(data) > 3 and data[3] == 0x68:
        return "mbus"
    from pydlms.mbus_link import starts_with_mbus_telegram

    if starts_with_mbus_telegram(data):  # E5 or a short frame: a polled M-Bus
        return "mbus"
    if data[:2] == b"\x00\x01":  # wrapper version 1; no APDU tag is 0x00
        return "wrapper"
    return "apdu"


class _Stream:
    """Reassemble the APDUs of one direction from raw transport reads."""

    def __init__(self, framing: str, verify_checksums: bool, hdlc_mode=None) -> None:
        from pydlms.hdlc.framing import FrameReader
        from pydlms.mbus import MbusReader

        self.framing = framing
        self.hdlc = FrameReader(verify_checksums=verify_checksums, tracker=hdlc_mode)
        self.mbus = MbusReader()
        self.buffer = bytearray()
        self.segments = bytearray()
        self.gbt = GbtReassembler()

    def feed(self, data: bytes) -> list[bytes]:
        if self.framing == "auto":
            self.framing = _detect(data)
        framing = self.framing
        if framing == "hdlc":
            apdus = self._hdlc(data)
        elif framing == "mbus":
            apdus = self.mbus.feed(data)
        elif framing == "wrapper":
            apdus = self._wrapper(data)
        else:
            apdus = [data]
        return [a for a in (self._gbt(a) for a in apdus) if a]

    def _hdlc(self, data: bytes) -> list[bytes]:
        from pydlms.hdlc.framing import FrameType, strip_llc

        out = []
        for frame in self.hdlc.feed(data):
            if frame.kind not in (FrameType.I, FrameType.UI) or not frame.info:
                continue  # SNRM/UA parameters, RR/RNR polls, DISC
            first = not self.segments
            self.segments += strip_llc(frame.info) if first else frame.info
            if not frame.segmented:
                out.append(bytes(self.segments))
                self.segments.clear()
        return out

    def _wrapper(self, data: bytes) -> list[bytes]:
        from pydlms.wrapper import HEADER_SIZE, decode_header

        self.buffer += data
        out = []
        while len(self.buffer) >= HEADER_SIZE:
            total = HEADER_SIZE + decode_header(bytes(self.buffer[:HEADER_SIZE])).length
            if len(self.buffer) < total:
                break
            out.append(bytes(self.buffer[HEADER_SIZE:total]))
            del self.buffer[:total]
        return out

    def _gbt(self, apdu: bytes) -> bytes | None:
        if apdu[:1] != bytes([Tag.GENERAL_BLOCK_TRANSFER]):
            return apdu
        return self.gbt.add(decode_gbt(apdu))


def deframe(
    records: Iterable[tuple[str | None, bytes]],
    framing: str = "auto",
    verify_checksums: bool = True,
    hdlc_modulus: int = 8,
) -> list[tuple[str | None, bytes]]:
    """APDUs carried by raw ``TX``/``RX``/undirected buffers, in order.

    ``*-APDU`` records are skipped. Each direction is reassembled on its own,
    so a frame split over two transport reads, or HDLC segments interleaved
    with the other side's RR polls, come out whole.

    HDLC frames are read in ``hdlc_modulus`` numbering until the recording
    shows an SNRME or SNRM answered by UA, which switches both directions
    to modulo 128 or 8 (:class:`~pydlms.hdlc.framing.HdlcModeTracker`).
    """
    from pydlms.hdlc.framing import HdlcModeTracker

    mode = HdlcModeTracker(hdlc_modulus)
    streams: dict[str | None, _Stream] = {}
    out: list[tuple[str | None, bytes]] = []
    for direction, data in records:
        if direction in ("TX-APDU", "RX-APDU") or not data:
            continue
        stream = streams.get(direction)
        if stream is None:
            stream = streams[direction] = _Stream(framing, verify_checksums, mode)
        out += [(direction, apdu) for apdu in stream.feed(data)]
    return out


def session_apdus(
    records: Iterable[tuple[str | None, bytes]],
    framing: str = "auto",
    hdlc_modulus: int = 8,
) -> list[tuple[str | None, bytes]]:
    """Plaintext APDUs of a recording as ``("TX"|"RX"|None, apdu)``.

    Uses the ``*-APDU`` lines when present (the association's plaintext view),
    else :func:`deframe` of the raw buffers (``hdlc_modulus`` as there).
    """
    records = list(records)
    plain = [(d[:2], a) for d, a in records if d in ("TX-APDU", "RX-APDU")]
    return plain if plain else deframe(records, framing, hdlc_modulus=hdlc_modulus)
