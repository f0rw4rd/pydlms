"""How push bodies get their OBIS labels: the flat-walk heuristics and the
positional decode from a known push setup ``push_object_list``.

Blue Book, Push setup (IC 40): the pushed data are the values of the
``push_object_list`` entries in order; IDIS push lists start with the push
setup's own ``logical_name`` ({40, 0-0:25.9.0.255, 1}).
"""

from __future__ import annotations

import datetime as dt

import pytest

from pydlms.apdu.xdlms import DataNotification
from pydlms.cosem.data import DlmsData as D
from pydlms.cosem.time import CosemDateTime
from pydlms.exceptions import DecodeError
from pydlms.obis import ObisCode
from pydlms.push import PushDecoder, extract_records


def o(text: str) -> D:
    return D.octet_string(ObisCode.parse(text).to_bytes())


STAMP = CosemDateTime.from_datetime(dt.datetime(2026, 1, 1, 12, tzinfo=dt.timezone.utc)).to_bytes()
IDIS_BODY = D.structure(
    [
        o("0.0.25.9.0.255"),
        D.octet_string(b"LGZ1234567890123"),
        D.octet_string(STAMP),
        D.uint32(4711),
    ]
)
IDIS_OBJECTS = [
    (40, "0.0.25.9.0.255", 1),
    (1, "0.0.42.0.0.255", 2),
    (8, "0.0.1.0.0.255", 2),
    (3, "1.0.1.8.0.255", 2),
]


def labels(records):
    return [(str(r.obis) if r.obis else None, r.raw) for r in records]


def test_push_setup_logical_name_does_not_label_the_next_value():
    records = extract_records(IDIS_BODY)
    first = records[0]
    assert str(first.obis) == "0.0.25.9.0.255"
    assert first.class_id == 40 and first.attribute == 1
    assert records[1].obis is None and records[1].raw == b"LGZ1234567890123"
    assert len(records) == 4


def test_obis_followed_by_a_six_octet_value_keeps_its_label():
    body = D.structure(
        [o("0.0.96.1.0.255"), D.octet_string(b"ABCDEF"), o("1.0.1.8.0.255"), D.uint32(5)]
    )
    assert labels(extract_records(body)) == [("0.0.96.1.0.255", b"ABCDEF"), ("1.0.1.8.0.255", 5)]


def test_obis_followed_by_a_six_octet_value_at_the_end():
    body = D.structure(
        [o("1.0.1.8.0.255"), D.uint32(5), o("0.0.96.1.0.255"), D.octet_string(b"ABCDEF")]
    )
    assert labels(extract_records(body)) == [("1.0.1.8.0.255", 5), ("0.0.96.1.0.255", b"ABCDEF")]


def test_lone_six_octet_value_in_a_compact_payload_is_not_an_obis():
    body = D.structure([D.octet_string(bytes(range(1, 7))), D.uint32(7), D.uint16(9)])
    assert labels(extract_records(body)) == [(None, bytes(range(1, 7))), (None, 7), (None, 9)]


def test_single_obis_value_pair_is_still_labelled():
    assert labels(extract_records(D.structure([o("1.0.1.8.0.255"), D.uint32(5)]))) == [
        ("1.0.1.8.0.255", 5)
    ]


@pytest.mark.parametrize(
    "objects",
    [
        IDIS_OBJECTS,
        [(c, ObisCode.parse(ln), a, 0) for c, ln, a in IDIS_OBJECTS],
        D.array(
            [D.structure([D.uint16(c), o(ln), D.int8(a), D.uint16(0)]) for c, ln, a in IDIS_OBJECTS]
        ),
    ],
    ids=["tuples", "tuples-with-index", "push-object-list"],
)
def test_positional_decode_from_the_push_object_list(objects):
    records = extract_records(IDIS_BODY, capture_objects=objects)
    assert labels(records) == [
        ("0.0.25.9.0.255", ObisCode.parse("0.0.25.9.0.255").to_bytes()),
        ("0.0.42.0.0.255", b"LGZ1234567890123"),
        ("0.0.1.0.0.255", STAMP),
        ("1.0.1.8.0.255", 4711),
    ]
    assert [(r.class_id, r.attribute) for r in records] == [(40, 1), (1, 2), (8, 2), (3, 2)]
    assert records[2].datetime is not None


def test_positional_decode_count_mismatch_raises():
    with pytest.raises(DecodeError, match="3 entries"):
        extract_records(IDIS_BODY, capture_objects=IDIS_OBJECTS[:3])


def test_positional_decode_rejects_a_malformed_push_object_list():
    bad = D.array([D.structure([D.uint16(3), D.uint32(5)])])
    with pytest.raises(DecodeError):
        extract_records(D.structure([D.uint32(1)]), capture_objects=bad)


def test_push_decoder_with_capture_objects():
    apdu = DataNotification(1, IDIS_BODY).to_bytes()
    message = PushDecoder("raw", capture_objects=IDIS_OBJECTS).feed(apdu)[0]
    assert message.get("1.0.1.8.0.255") == 4711
    assert message.get("0.0.42.0.0.255") == "LGZ1234567890123"


def test_trailing_octets_after_the_body_mark_the_push_incomplete():
    from pydlms.push import decode_notification

    good = DataNotification(1, D.structure([o("1.0.1.8.0.255"), D.uint32(5)])).to_bytes()
    _, records, complete = decode_notification(good)
    assert complete
    _, records, complete = decode_notification(good + bytes.fromhex("deadbeef"))
    assert not complete
    assert labels(records) == [("1.0.1.8.0.255", 5)]


def test_lenient_body_decode_reports_trailing_octets():
    from pydlms.cosem.data import encode_data
    from pydlms.push import decode_body_lenient

    raw = encode_data(D.structure([D.uint32(5)]))
    assert decode_body_lenient(raw)[1]
    body, complete = decode_body_lenient(raw + b"\x00\x01")
    assert not complete and body.value[0].value == 5
