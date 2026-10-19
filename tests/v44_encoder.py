"""Test-support V.44 packet-method encoder (ITU-T V.44 (11/2000) 6.3, annex B.1).

Test quality only, not shipped in ``pydlms``: it exists to build round-trip
inputs and compressed APDUs for ``pydlms.security.v44``. It follows the
encoder of 6.3 directly (root array, node-tree of string-segments with
down- and side-indices, the packet as the history): string matching takes
only complete string-segments and then runs the explicit string-extension
procedure of 6.3.2 (the partial-match shortcut of 6.3.1 NOTE 1 is not
used). It reproduces the octets of V.44 Table II.1. It never sends REINIT,
ETM or transparent data, and it is slow on large inputs.
"""

from __future__ import annotations

from pydlms.security.v44 import extension_bits

_FLUSH = 1
_STEPUP = 2


class _BitWriter:
    """Codes least significant bit first (V.44 6.6, Table 6)."""

    def __init__(self) -> None:
        self.out = bytearray()
        self.acc = 0
        self.n = 0

    def put(self, value: int, width: int) -> None:
        assert 0 <= value < 1 << width
        self.acc |= value << self.n
        self.n += width
        while self.n >= 8:
            self.out.append(self.acc & 0xFF)
            self.acc >>= 8
            self.n -= 8

    def align(self) -> bytes:
        if self.n:
            self.out.append(self.acc & 0xFF)
            self.acc = self.n = 0
        return bytes(self.out)


class _Encoder:
    def __init__(self, data: bytes, n2: int, n7: int) -> None:
        self.data = data
        self.n2 = n2
        self.n7 = n7
        self.w = _BitWriter()
        self.root = [-1] * 256
        # node-tree, indexed by codeword (0..3 unused: control codes)
        self.first = [0] * 4
        self.seglen = [0] * 4
        self.down = [-1] * 4
        self.side = [-1] * 4
        self.c1, self.c2, self.c3, self.c5 = 4, 6, 64, 7
        self.after_cw = False

    # -- node-tree -------------------------------------------------------------

    def _new_node(self, first: int, length: int, *, root: int = -1, parent: int = -1) -> None:
        """Create a string-segment (6.3.3) unless the node-tree is full (B.1.1)."""
        if self.c1 >= self.n2:
            return
        cw = self.c1
        self.c1 += 1
        self.first.append(first)
        self.seglen.append(length)
        self.down.append(-1)
        self.side.append(-1)
        head = self.root[root] if root >= 0 else self.down[parent]
        if head < 0:
            if root >= 0:
                self.root[root] = cw
            else:
                self.down[parent] = cw
            return
        while self.side[head] >= 0:
            head = self.side[head]
        self.side[head] = cw

    # -- codes (6.6, Table 5) ----------------------------------------------------

    def _control(self, code: int) -> None:
        self.w.put(1, 1)
        self.w.put(code, self.c2)
        self.after_cw = False

    def _ordinal(self, ch: int) -> None:
        if ch > 127 and self.c5 == 7:  # 7.11.1
            self._control(_STEPUP)
            self.c5 = 8
        self.w.put(0, 2 if self.after_cw else 1)
        self.w.put(ch, self.c5)
        self.after_cw = False

    def _codeword(self, cw: int) -> None:
        while cw >= self.c3:  # 7.11.2
            self._control(_STEPUP)
            self.c2 += 1
            self.c3 *= 2
        self.w.put(1, 1)
        self.w.put(cw, self.c2)
        self.after_cw = True

    def _extension(self, k: int) -> None:
        """String-extension length with its "0" "1" prefix (Tables 3, 4, 5)."""
        assert self.after_cw
        put = self.w.put
        put(0, 1)
        put(1, 1)
        if k == 1:
            put(1, 1)
        elif k <= 4:
            put(0, 1)
            put(k - 1, 2)
        elif k <= 12:
            put(0, 3)
            put(0, 1)
            put(k - 5, 3)
        else:
            put(0, 3)
            put(1, 1)
            put(k - 13, extension_bits(self.n7))
        self.after_cw = False

    # -- 6.3 ------------------------------------------------------------------

    def _match(self, i: int) -> tuple[int, int]:
        """Longest match of complete string-segments: (codeword or -1, end position)."""
        data, n = self.data, len(self.data)
        node, pos, matched = self.root[data[i]], i + 1, -1
        while node >= 0 and pos < n:
            best = -1
            s = node
            while s >= 0:
                f, length = self.first[s], self.seglen[s]
                if pos + length <= n and data[f : f + length] == data[pos : pos + length]:
                    if best < 0 or length > self.seglen[best]:
                        best = s
                s = self.side[s]
            if best < 0:
                break
            matched, pos, node = best, pos + self.seglen[best], self.down[best]
        return matched, pos

    def run(self) -> bytes:
        data, n, i = self.data, len(self.data), 0
        while i < n:
            matched, pos = self._match(i)
            if matched < 0:
                self._ordinal(data[i])
                if i + 1 < n:
                    self._new_node(i + 1, 1, root=data[i])
                i += 1
                continue
            self._codeword(matched)
            total = pos - i
            if total < self.n7 and pos < n:
                f = self.first[matched] + self.seglen[matched]
                k = 0
                while pos + k < n and total + k < self.n7 and data[f + k] == data[pos + k]:
                    k += 1
                if k:
                    self._extension(k)
                    self._new_node(pos, k, parent=matched)
                    pos += k
                else:
                    self._new_node(pos, 1, parent=matched)
            i = pos
        self._control(_FLUSH)
        return self.w.align()


def compress(data: bytes, n2: int = 1525, n7: int = 255) -> bytes:
    """Compress one packet (annex B.1): fresh dictionary, FLUSH and padding at the end."""
    return _Encoder(bytes(data), n2, n7).run()
