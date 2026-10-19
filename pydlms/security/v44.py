"""ITU-T V.44 decompression for compressed xDLMS APDUs (security-control bit 7).

IEC 62056-5-3 has a compressed APDU (SC bit 7) compressed with ITU-T V.44
before it is protected. pydlms never compresses and refuses bit
7 unless :class:`~pydlms.security.context.SecurityContext` has a
``decompressor``; :func:`v44_decompressor` builds one from this module::

    ctx = SecurityContext(ek, ak, decompressor=v44_decompressor())

The hook runs only after the tag verified, so the input here is authentic
meter data, but it is still treated as untrusted: every code is checked and
the output is bounded.

Source: ITU-T Recommendation V.44 (11/2000) "Data compression procedures"
(https://www.itu.int/rec/T-REC-V.44). Implemented,
decoder side only:

* the packet method of annex B.1: each APDU is one packet, the decoder
  dictionary starts in its initial state (7.5.2), the decoded output is the
  history, and the packet ends with a FLUSH control code and zero bits to
  the next octet (B.1.1, 7.13);
* the codes of 6.6: control codes and codewords in C2 bits, ordinals in C5
  bits, string-extension lengths (Tables 3 and 4), the code prefixes of
  Table 5, least significant bit first (6.6, Table 6);
* decoding and string creation (6.4.1, Table 2), including the codeword
  equal to C1 that the decoder has not created yet (6.4.1 rules 3, 4);
* STEPUP of the ordinal size (7.11.1) and of the codeword size (7.11.2);
  no new strings once N2 codewords exist (B.1.1, node-tree full); no string
  longer than N7 (Table 2 note);
* the annex B indicator for a packet sent uncompressed: the ETM control code
  with its prefix in the first octet, then the original octets.

DLMS negotiates none of the V.44 parameters (no AARQ/AARE or InitiateRequest
field carries them), so they are explicit constructor arguments with the
annex B.1.2 packet-method defaults: ``n2`` (number of codewords including
the 4 control codes, Table 10 range 256..65535, default 1525), ``n7``
(maximum string length, 32..255, default 255) and ``n8`` (history size,
"not applicable" in the packet method, default ``None``: the APDU is the
history). A meter using other values needs them set to match.

Deliberately refused with :class:`~pydlms.exceptions.DecodeError`: data that
ends without FLUSH, non-zero padding or any octet after the FLUSH, a
codeword above C1 (7.15) or equal to C1 when no string can be created, a
STEPUP beyond N1 bits or beyond 8-bit ordinals (7.15), a FLUSH, ETM or
REINIT straight after a STEPUP, ETM anywhere but as the first code
(transparent mode is not part of annex B), REINIT unless ``n8`` bounds the
history (B.1.1: the packet-method encoder sends none), a string extension
past N7, and output beyond ``max_output`` or the history beyond ``n8``.

The stream and multi-packet methods (main body, annex B.2) keep the
dictionary from one packet to the next; DLMS defines no such state across
APDUs, so they are not offered.

A bit stream of variable-width codes, least significant bit first, does not
map onto ``construct``; the reader below is a bounded shift over at most four
octets per code. Every code consumes at least one bit, so the loop ends after
at most ``8 * len(data)`` codes.
"""

from __future__ import annotations

from collections.abc import Callable

from pydlms.exceptions import DecodeError
from pydlms.security.ciphering import MAX_DECOMPRESSED_DEFAULT

__all__ = ["V44Decoder", "v44_decompressor"]

#: N5: the number of control codes, so also the first codeword (Table 11).
FIRST_CODEWORD = 4
#: Initial C2 (codeword size) and C5 (ordinal size), 7.5.2.
INITIAL_CODEWORD_BITS = 6
INITIAL_ORDINAL_BITS = 7

# Control codes, Table 8.
_ETM = 0
_FLUSH = 1
_STEPUP = 2
_REINIT = 3
_CONTROL_NAMES = ("ETM", "FLUSH", "STEPUP", "REINIT")

# Kinds of the previous code, for string creation (Table 2).
_NONE = 0  # after initialization or REINIT
_ORDINAL = 1
_CODEWORD = 2
_EXTENSION = 3

#: B.1.2 packet-method defaults and the Table 10 ranges.
DEFAULT_N2 = 1525
DEFAULT_N7 = 255
N2_RANGE = (256, 65535)
N7_RANGE = (32, 255)
N8_RANGE = (512, 65535)


def extension_bits(n7: int) -> int:
    """Width of the last subfield of a string-extension length of 13 or more (Table 4)."""
    if n7 <= 46:
        return 5
    if n7 <= 78:
        return 6
    if n7 <= 142:
        return 7
    return 8


class V44Decoder:
    """V.44 packet-method decoder with explicit parameters.

    ``n2`` is the number of codewords including the control codes (N2R),
    ``n7`` the maximum string length (N7R), ``n8`` the history size (N8R,
    ``None`` for the packet method where the APDU is the history; when set,
    the history since the last REINIT may not exceed it and REINIT is
    accepted). ``method`` must be ``"packet"``. Defaults are those of V.44
    annex B.1.2. The decoder keeps no state between calls.
    """

    def __init__(
        self,
        n2: int = DEFAULT_N2,
        n7: int = DEFAULT_N7,
        n8: int | None = None,
        method: str = "packet",
    ) -> None:
        _check_range("n2", n2, N2_RANGE)
        _check_range("n7", n7, N7_RANGE)
        if n8 is not None:
            _check_range("n8", n8, N8_RANGE)
        if method != "packet":
            raise ValueError(
                f"V.44 method {method!r} is not supported: only 'packet' (annex B.1); "
                "DLMS keeps no compression state between APDUs"
            )
        self.n2 = n2
        self.n7 = n7
        self.n8 = n8
        self.method = method
        #: N1, the maximum codeword size in bits (Table 11: derived from N2).
        self.n1 = (n2 - 1).bit_length()

    def __repr__(self) -> str:
        return f"V44Decoder(n2={self.n2}, n7={self.n7}, n8={self.n8}, method={self.method!r})"

    def decompress(self, data: bytes, *, max_output: int) -> bytes:
        """Decode one packet; raise :class:`DecodeError` if it is malformed or too large."""
        if max_output < 0:
            raise ValueError("max_output must not be negative")
        return _Packet(self, bytes(data), max_output).run()


def v44_decompressor(
    *,
    n2: int = DEFAULT_N2,
    n7: int = DEFAULT_N7,
    n8: int | None = None,
    method: str = "packet",
    max_output: int = MAX_DECOMPRESSED_DEFAULT,
) -> Callable[[bytes], bytes]:
    """A ``SecurityContext(decompressor=...)`` hook decoding V.44 with these parameters.

    ``max_output`` stops the decoder itself (``unwrap`` checks its own limit
    afterwards as well); the default is the largest PDU an InitiateRequest
    can announce.
    """
    decoder = V44Decoder(n2=n2, n7=n7, n8=n8, method=method)
    if max_output < 0:
        raise ValueError("max_output must not be negative")

    def decompress(data: bytes) -> bytes:
        return decoder.decompress(data, max_output=max_output)

    decompress.decoder = decoder  # type: ignore[attr-defined]
    return decompress


def _check_range(name: str, value: int, bounds: tuple[int, int]) -> None:
    low, high = bounds
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise ValueError(f"V.44 {name} must be an integer in {low}..{high}, got {value!r}")


class _Packet:
    """Decoder dictionary and variables (6.2.2, Table 12) for one packet."""

    def __init__(self, params: V44Decoder, data: bytes, max_output: int) -> None:
        self.p = params
        self.data = data
        self.nbits = len(data) * 8
        self.pos = 0
        self.limit = max_output
        self.out = bytearray()
        #: String collection: codeword -> (last-character position, length).
        self.strings: dict[int, tuple[int, int]] = {}
        self._reset()

    def _reset(self) -> None:
        """Initial decoder state (7.5.2); the history starts at the current output."""
        self.base = len(self.out)
        self.strings.clear()
        self.c1 = FIRST_CODEWORD
        self.c2 = INITIAL_CODEWORD_BITS
        self.c5 = INITIAL_ORDINAL_BITS
        self.prev = _NONE
        self.prev_len = 0
        self.prev_cw = 0
        self.after_cw = False
        self.stepup = False  # a STEPUP waits for the next code to say which size

    def _error(self, message: str) -> DecodeError:
        return DecodeError(f"V.44: {message} (at bit {self.pos})")

    def _bits(self, n: int, what: str) -> int:
        """Read ``n`` (at most 16) bits, least significant first."""
        pos = self.pos
        if pos + n > self.nbits:
            raise self._error(f"data ends inside {what}")
        i = pos >> 3
        word = int.from_bytes(self.data[i : i + 4], "little")
        self.pos = pos + n
        return (word >> (pos & 7)) & ((1 << n) - 1)

    def run(self) -> bytes:
        while True:
            if self._step():
                return bytes(self.out)

    def _step(self) -> bool:
        """Decode one code (6.4.1); True once the packet is complete."""
        was_stepup = self.stepup
        if self._bits(1, "a code prefix"):
            if self.stepup:
                # STEPUP then a codeword or control code: C2 grows (7.11.2).
                self.stepup = False
                if self.c2 + 1 > self.p.n1:
                    raise self._error(f"STEPUP beyond the maximum codeword size N1 = {self.p.n1}")
                self.c2 += 1
            value = self._bits(self.c2, "a codeword")
            if value < FIRST_CODEWORD:
                return self._control(value, was_stepup)
            self._codeword(value)
            return False
        if self.after_cw and self._bits(1, "a code prefix"):
            self._extension()
        else:
            self._ordinal()
        return False

    def _control(self, code: int, after_stepup: bool) -> bool:
        """Table 8; after a control code the prefixes are Table 5's "otherwise"."""
        name = _CONTROL_NAMES[code]
        self.after_cw = False
        if after_stepup and code != _STEPUP:
            raise self._error(f"{name} straight after STEPUP")
        if code == _STEPUP:
            self.stepup = True
            return False
        if code == _FLUSH:
            self._end()
            return True
        if code == _ETM:
            # Annex B: ETM with its prefix as the first code says the rest of
            # the packet is the original data, octet-aligned.
            if self.pos != 1 + INITIAL_CODEWORD_BITS or self.out:
                raise self._error("ETM inside a packet (no transparent mode in the packet method)")
            if self._bits(1, "the ETM padding"):
                raise self._error("non-zero padding after ETM")
            raw = self.data[1:]
            if len(raw) > self.limit:
                raise self._error(f"output of {len(raw)} octets exceeds the limit of {self.limit}")
            self.out += raw
            self.pos = self.nbits
            return True
        if self.p.n8 is None:
            raise self._error("REINIT in a packet-method packet (no history to reinitialize)")
        self._reset()
        return False

    def _end(self) -> None:
        """FLUSH ends the packet: zero bits to the octet boundary, then nothing."""
        pad = -self.pos % 8
        if pad and self._bits(pad, "the FLUSH padding"):
            raise self._error("non-zero padding after FLUSH")
        if self.pos != self.nbits:
            raise self._error(f"{(self.nbits - self.pos) // 8} octets after the FLUSH")

    def _room(self, n: int) -> None:
        if len(self.out) + n > self.limit:
            raise self._error(f"output exceeds the limit of {self.limit} octets")
        if self.p.n8 is not None and len(self.out) + n - self.base > self.p.n8:
            raise self._error(f"history would exceed N8 = {self.p.n8} without a REINIT")

    def _create(self, last: int, length: int) -> None:
        """Add a string unless the collection is full (B.1.1) or it exceeds N7 (Table 2)."""
        if self.c1 < self.p.n2 and length <= self.p.n7:
            self.strings[self.c1] = (last, length)
            self.c1 += 1

    def _create_from_previous(self) -> None:
        """Table 2: an ordinal or codeword after an ordinal or codeword extends it by one."""
        if self.prev in (_ORDINAL, _CODEWORD):
            self._create(len(self.out), self.prev_len + 1)

    def _copy(self, start: int, n: int) -> None:
        """Copy ``n`` characters from history position ``start``; overlap repeats (II.2)."""
        self._room(n)
        out = self.out
        if start + n <= len(out):
            out += out[start : start + n]
        else:
            for i in range(start, start + n):
                out.append(out[i])

    def _ordinal(self) -> None:
        if self.stepup:
            self.stepup = False
            if self.c5 == 8:
                raise self._error("STEPUP beyond the 8-bit ordinal size")
            self.c5 = 8
        value = self._bits(self.c5, "an ordinal")
        self._room(1)
        self._create_from_previous()
        self.out.append(value)
        self.prev, self.prev_len, self.after_cw = _ORDINAL, 1, False

    def _codeword(self, cw: int) -> None:
        if cw > self.c1:
            raise self._error(f"codeword {cw} is beyond the next codeword C1 = {self.c1}")
        # Creating the pending string first defines a codeword equal to C1
        # (6.4.1 rules 3 and 4); the overlapping copy repeats its first character.
        self._create_from_previous()
        entry = self.strings.get(cw)
        if entry is None:
            raise self._error(f"codeword {cw} is not defined (C1 = {self.c1})")
        last, length = entry
        self._copy(last - length + 1, length)
        self.prev, self.prev_len, self.prev_cw, self.after_cw = _CODEWORD, length, cw, True

    def _extension(self) -> None:
        """6.4.1 rule 5: copy what followed the previous codeword's string."""
        k = self._extension_length()
        last, length = self.strings[self.prev_cw]
        if length + k > self.p.n7:
            raise self._error(
                f"string extension to {length + k} characters is longer than N7 = {self.p.n7}"
            )
        self._copy(last + 1, k)
        self._create(len(self.out) - 1, length + k)
        self.prev, self.after_cw = _EXTENSION, False

    def _extension_length(self) -> int:
        """Tables 3 and 4."""
        what = "a string-extension length"
        if self._bits(1, what):
            return 1
        value = self._bits(2, what)
        if value:
            return value + 1
        if self._bits(1, what):
            return self._bits(extension_bits(self.p.n7), what) + 13
        return self._bits(3, what) + 5
