"""Load the vendored esphome-libs/dlms_parser meter fixtures (Apache-2.0).

The upstream ``tests/expected/*.h`` headers are kept byte-identical; this
module extracts, with regular expressions only, the raw frame bytes, the
published keys and the expected OBIS -> value maps from them. No upstream code
is executed or translated.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "dlms_parser"
EXPECTED = FIXTURES / "expected"
DUMPS = FIXTURES / "dumps"

_ARRAY = re.compile(r"const\s+uint8_t\s+(\w+)\s*\[[^\]]*\]\s*=\s*\{(.*?)\};", re.S)
_KEY = re.compile(r"const\s+auto\s+(\w+?)_(auth_key|key)\s*=.*?\{(.*?)\}\)", re.S)
_COUNT = re.compile(r"constexpr\s+size_t\s+\w+_expected_count\s*=\s*(\d+)\s*;")
_STRINGS = re.compile(r"_expected_strings\s*=\s*\{(.*?)\};", re.S)
_FLOATS = re.compile(r"_expected_floats\s*=\s*\{(.*?)\};", re.S)
_STR_PAIR = re.compile(r'\{\s*"([^"]+)"\s*,\s*"([^"]*)"\s*\}')
_FLOAT_PAIR = re.compile(r'\{\s*"([^"]+)"\s*,\s*([-+0-9.eE]+)f?\s*\}')
_HEX = re.compile(r"0x([0-9A-Fa-f]{2})")


def _strip_comments(text: str) -> str:
    return re.sub(r"//[^\n]*", "", text)


@dataclass
class MeterFixture:
    name: str
    raw: bytes
    expected_count: int
    expected_strings: dict[str, str] = field(default_factory=dict)
    expected_floats: dict[str, float] = field(default_factory=dict)
    encryption_key: bytes | None = None
    authentication_key: bytes | None = None

    @property
    def transport(self) -> str:
        """``hdlc``, ``mbus`` or ``raw`` (bare APDU), from the file name."""
        return self.name.split("_", 1)[0]


def load(name: str) -> MeterFixture:
    text = (EXPECTED / f"{name}.h").read_text(encoding="utf-8")
    code = _strip_comments(text)
    arrays = {m.group(1): m.group(2) for m in _ARRAY.finditer(code)}
    raw_name = next(
        n
        for n in arrays
        if n.endswith("raw_frame") or n.endswith("_frame") and not re.search(r"frame\d$", n)
    )
    raw = bytes(int(h, 16) for h in _HEX.findall(arrays[raw_name]))
    keys = {
        kind: bytes(int(h, 16) for h in _HEX.findall(body)) for _, kind, body in _KEY.findall(code)
    }
    strings = dict(_STR_PAIR.findall(_STRINGS.search(code).group(1)))
    floats = {k: float(v) for k, v in _FLOAT_PAIR.findall(_FLOATS.search(code).group(1))}
    # Some authentication keys are published only as dumps/<name>.gak.
    for kind, suffix in (("key", "key"), ("auth_key", "gak")):
        path = DUMPS / f"{name}.{suffix}"
        if kind not in keys and path.exists():
            keys[kind] = bytes.fromhex(path.read_text().strip())
    return MeterFixture(
        name=name,
        raw=raw,
        expected_count=int(_COUNT.search(code).group(1)),
        expected_strings=strings,
        expected_floats=floats,
        encryption_key=keys.get("key"),
        authentication_key=keys.get("auth_key"),
    )


def all_names() -> list[str]:
    return sorted(p.stem for p in EXPECTED.glob("*.h"))
