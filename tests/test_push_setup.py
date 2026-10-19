"""Push decoder from the meter's push setup (IC 40 push_object_list).

The simulator serves a push setup at 0.0.25.9.0.255; the client reads its
attribute 2 and decodes a push positionally with it.
"""

from __future__ import annotations

import pytest

from pydlms.apdu.xdlms import DataNotification
from pydlms.client import DlmsClient
from pydlms.cosem.data import DlmsData as D
from pydlms.cosem.interface_classes import ClassId
from pydlms.exceptions import DecodeError, DlmsError
from pydlms.obis import ObisCode
from pydlms.push import (
    format_capture_objects,
    parse_capture_objects,
    parse_capture_objects_text,
)
from pydlms.simulator import EXAMPLE_PUSH_OBJECTS, example_meter, serve

PUSH_SETUP = "0.0.25.9.0.255"


@pytest.fixture
def meter():
    sim = example_meter()
    servers = []

    def start():
        server = serve(sim)
        servers.append(server)
        host, port = server.server_address
        return host, port

    sim.start = start
    yield sim
    for server in servers:
        server.shutdown()
        server.server_close()


def entry(cid=3, obis="1.0.1.8.0.255", attr=2, index=0, raw=None):
    return D.structure(
        [
            D.uint16(cid),
            D.octet_string(raw if raw is not None else ObisCode.parse(obis).to_bytes()),
            D.int8(attr),
            D.uint16(index),
        ]
    )


def test_decoder_from_meter_decodes_a_push_positionally(meter):
    host, port = meter.start()
    with DlmsClient.tcp(host, port, timeout=3) as m:
        decoder = m.push_decoder_from_meter(framing="raw")
    assert [(c, str(o), a) for c, o, a, _ in decoder.capture_objects] == [
        (c, n, a) for c, n, a in EXAMPLE_PUSH_OBJECTS
    ]
    body = D.structure(
        [
            D.octet_string(ObisCode.parse(PUSH_SETUP).to_bytes()),
            D.visible_string("PYD0000000001"),
            D.uint32(12345678),
            D.uint32(1520),
        ]
    )
    message = decoder.feed(DataNotification(7, body).to_bytes())[0]
    assert message.get("0.0.96.1.0.255") == "PYD0000000001"
    assert message.get("1.0.1.8.0.255") == 12345678
    assert message.get("1.0.1.7.0.255") == 1520


def test_decoder_from_meter_forwards_decoder_kwargs(meter):
    host, port = meter.start()
    with DlmsClient.tcp(host, port, timeout=3) as m:
        decoder = m.push_decoder_from_meter(PUSH_SETUP, framing="mbus", verify_checksums=False)
    assert decoder.framing == "mbus"
    assert decoder.verify_checksums is False


def test_missing_push_setup_is_an_error(meter):
    host, port = meter.start()
    with DlmsClient.tcp(host, port, timeout=3) as m:
        with pytest.raises(DlmsError):
            m.push_decoder_from_meter("0.0.25.9.9.255")


@pytest.mark.parametrize(
    "value",
    [
        D.uint32(5),
        D.array([]),
        D.array([D.uint32(1)]),
        D.array([D.structure([D.uint16(3), D.uint32(5)])]),
        D.array([D.structure([D.uint16(3), D.octet_string(b"12345"), D.int8(2), D.uint16(0)])]),
        D.array([D.structure([D.uint16(3), D.uint32(7), D.int8(2), D.uint16(0)])]),
        D.array(
            [
                D.structure(
                    [D.uint16(3), D.octet_string(bytes(6)), D.visible_string("x"), D.uint16(0)]
                )
            ]
        ),
        D.array([entry(), D.structure([D.uint16(3)])]),
    ],
    ids=[
        "scalar",
        "empty",
        "non-structure",
        "short-structure",
        "obis-5-octets",
        "obis-not-octets",
        "attribute-not-int",
        "second-entry-bad",
    ],
)
def test_malformed_push_object_list_raises(meter, value):
    sim_key = (ClassId.PUSH_SETUP, ObisCode.parse(PUSH_SETUP))
    meter.objects[sim_key][2] = value
    host, port = meter.start()
    with DlmsClient.tcp(host, port, timeout=3) as m:
        with pytest.raises(DecodeError):
            m.push_decoder_from_meter()


# -- capture-object file format -------------------------------------------------------

TEXT = """\
# push setup itself first
40 0.0.25.9.0.255 1
3, 1.0.1.8.0.255, 2   # energy
1 0.0.96.1.0.255 2 5
"""
EXPECTED = [
    (40, ObisCode.parse(PUSH_SETUP), 1, 0),
    (3, ObisCode.parse("1.0.1.8.0.255"), 2, 0),
    (1, ObisCode.parse("0.0.96.1.0.255"), 2, 5),
]


def test_text_file_format():
    assert parse_capture_objects_text(TEXT) == EXPECTED


def test_json_file_format_both_entry_forms():
    text = (
        '[[40, "0.0.25.9.0.255", 1], [3, "1.0.1.8.0.255", 2, 0],'
        ' {"class_id": 1, "logical_name": "0.0.96.1.0.255",'
        ' "attribute_index": 2, "data_index": 5}]'
    )
    assert parse_capture_objects_text(text) == EXPECTED


def test_file_format_round_trip():
    assert parse_capture_objects_text(format_capture_objects(EXPECTED)) == EXPECTED
    assert format_capture_objects(parse_capture_objects_text(TEXT)) == (
        "40 0.0.25.9.0.255 1 0\n3 1.0.1.8.0.255 2 0\n1 0.0.96.1.0.255 2 5\n"
    )
    assert parse_capture_objects(EXPECTED) == EXPECTED


@pytest.mark.parametrize(
    "text",
    [
        "",
        "# only a comment\n",
        "3 1.0.1.8.0.255\n",
        "3 1.0.1.8.0.255 2 0 9\n",
        "x 1.0.1.8.0.255 2\n",
        "3 not-an-obis 2\n",
        "3 1.0.1.8.0.999 2\n",
        "[",
        "{}",
        '[[3, "1.0.1.8.0.255"]]',
        "[[3, 5, 2]]",
        '[[true, "1.0.1.8.0.255", 2]]',
        '[{"class_id": 3}]',
        '["x"]',
    ],
)
def test_malformed_file_raises(text):
    with pytest.raises(DecodeError):
        parse_capture_objects_text(text)
