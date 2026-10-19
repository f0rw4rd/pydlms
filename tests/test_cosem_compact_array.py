"""Tests for the compact-array (tag 19) codec.

The vectors are hand-derived from the TypeDescription grammar in
IEC 62056-6-2 (compact-array: content-description then array-contents as a
length-prefixed octet string of untagged elements).
"""

from __future__ import annotations

import pytest

from pydlms.cosem.data import CompactArray, DlmsData, TypeDescription, decode_data, encode_data
from pydlms.cosem.enums import DataType as T
from pydlms.exceptions import DecodeError

U16 = TypeDescription(T.LONG_UNSIGNED)
STRUCT_U16_BOOL = TypeDescription(T.STRUCTURE, members=(U16, TypeDescription(T.BOOLEAN)))


def _ca(desc, items):
    return DlmsData(T.COMPACT_ARRAY, CompactArray(desc, items))


def test_simple_elements_vector():
    obj = _ca(U16, [DlmsData.uint16(1), DlmsData.uint16(2), DlmsData.uint16(0x0304)])
    encoded = bytes.fromhex("13 12 06 0001 0002 0304")
    assert encode_data(obj) == encoded
    value, consumed = decode_data(encoded)
    assert consumed == len(encoded)
    assert value == obj
    assert value.to_python() == [1, 2, 0x0304]


def test_structure_elements_vector():
    obj = _ca(
        STRUCT_U16_BOOL,
        [
            DlmsData.structure([DlmsData.uint16(5), DlmsData.boolean(True)]),
            DlmsData.structure([DlmsData.uint16(6), DlmsData.boolean(False)]),
        ],
    )
    encoded = bytes.fromhex("13 02 02 12 03 06 0005 01 0006 00")
    assert encode_data(obj) == encoded
    assert decode_data(encoded)[0] == obj


def test_array_description_round_trip():
    desc = TypeDescription(T.ARRAY, array_of=(2, TypeDescription(T.UNSIGNED)))
    obj = _ca(desc, [DlmsData.array([DlmsData.uint8(1), DlmsData.uint8(2)])])
    encoded = encode_data(obj)
    assert encoded == bytes.fromhex("13 01 0002 11 02 01 02")
    assert decode_data(encoded)[0] == obj


def test_variable_length_elements():
    desc = TypeDescription(T.OCTET_STRING)
    obj = _ca(desc, [DlmsData.octet_string(b"ab"), DlmsData.octet_string(b"")])
    encoded = encode_data(obj)
    assert encoded == bytes.fromhex("13 09 04 02 6162 00")
    assert decode_data(encoded)[0] == obj


def test_empty_contents():
    obj = _ca(U16, [])
    assert encode_data(obj) == b"\x13\x12\x00"
    assert decode_data(b"\x13\x12\x00")[0] == obj


def test_type_description_of():
    item = DlmsData.structure([DlmsData.uint16(5), DlmsData.boolean(True)])
    assert TypeDescription.of(item) == STRUCT_U16_BOOL


@pytest.mark.parametrize(
    "raw",
    [
        "13",  # no description
        "13 12",  # no contents length
        "13 12 04 0001",  # contents shorter than declared
        "13 12 03 0001 00",  # partial element at the end
        "13 07 00",  # unknown type tag in description
        "13 13 00",  # nested compact array
    ],
)
def test_malformed_rejected(raw):
    with pytest.raises(DecodeError):
        decode_data(bytes.fromhex(raw))


def test_mismatched_item_rejected_on_build():
    with pytest.raises(ValueError):
        encode_data(_ca(U16, [DlmsData.uint8(1)]))


# --- zero-width elements (hostile descriptions) ----------------------------------------
#
# null-data, an empty structure and an array of either encode in 0 octets, so a
# decoder that loops "while octets remain" never advances on them. Each vector
# runs in a child process with a time and memory limit: without the guard it
# spins until memory runs out instead of failing.

_CHILD = """
import resource, sys
resource.setrlimit(resource.RLIMIT_AS, (1 << 29, 1 << 29))
from pydlms.exceptions import DecodeError
kind, raw = sys.argv[1], bytes.fromhex(sys.argv[2])
try:
    if kind == "data":
        from pydlms.cosem.data import decode_data
        decode_data(raw)
    else:
        from pydlms.push import decode_notification
        decode_notification(raw)
except DecodeError as exc:
    print("DecodeError", exc)
"""


def _run_guarded(kind: str, raw: str) -> str:
    import os
    import subprocess  # nosec B404
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    env = {**os.environ, "PYTHONPATH": str(root)}
    proc = subprocess.run(  # nosec B603
        [sys.executable, "-c", _CHILD, kind, bytes.fromhex(raw).hex()],
        capture_output=True,
        text=True,
        timeout=20,
        env=env,
        check=False,
    )
    return proc.stdout + proc.stderr


@pytest.mark.parametrize(
    "raw",
    [
        "13 00 01 00",  # null-data elements
        "13 02 00 01 00",  # empty-structure elements
        "13 01 ffff 00 01 00",  # array of 65535 null-data
        # Each element is one octet but expands to 65535 * 65535 nulls.
        "13 02 02 01 ffff 01 ffff 00 11 01 00",
    ],
)
def test_zero_width_elements_rejected(raw):
    out = _run_guarded("data", raw)
    assert out.startswith("DecodeError"), out


def test_zero_width_elements_in_a_push_rejected():
    out = _run_guarded("push", "0f0000000100 1300 05 0000000000")
    assert out.startswith("DecodeError"), out


def test_null_member_next_to_a_real_one_still_decodes():
    raw = bytes.fromhex("13 02 02 00 11 02 05 06")
    value, consumed = decode_data(raw)
    assert consumed == len(raw)
    assert value.to_python() == [[None, 5], [None, 6]]
