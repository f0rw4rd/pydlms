"""``pydlms discover-ic --report``: invocation-counter evidence without values."""

from __future__ import annotations

import json

import pytest

from pydlms import cli
from pydlms.apdu.acse import AARQ
from pydlms.client import DlmsClient
from pydlms.cosem.data import DlmsData
from pydlms.cosem.enums import DataAccessResult
from pydlms.cosem.interface_classes import ClassId
from pydlms.counters import VENDOR_LOCATIONS, CounterLocation, register_location
from pydlms.ic_report import ic_report
from pydlms.obis import ObisCode
from pydlms.simulator import example_meter, serve

pytest.importorskip("cryptography")

EK = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
COUNTER = 123456789
SERVER_TITLE = b"PYD\x00\x00\x00\x00\x01"
SECRETS = [
    str(COUNTER),
    hex(COUNTER)[2:],
    "PYD0000000001",  # serial
    "1000000000001",  # logical device name suffix
    SERVER_TITLE.hex(),
    "PYDCLNT1",
    b"PYDCLNT1".hex(),
]


@pytest.fixture
def meter():
    sim = example_meter(encryption_key=EK)
    sim.set_ic_location("0.0.43.1.0.255", last=COUNTER)
    sim.add_object(
        ClassId.SECURITY_SETUP,
        "0.0.43.0.0.255",
        {4: DlmsData.octet_string(b"PYDCLNT1"), 5: DlmsData.octet_string(SERVER_TITLE)},
        version=1,
    )
    sim.add_object(ClassId.DATA, "1.0.0.2.0.255", {2: DlmsData.octet_string(b"FW-1.2.3")})
    server = serve(sim)
    sim.endpoint = "tcp://{}:{}".format(*server.server_address)
    yield sim
    server.shutdown()
    server.server_close()


def _report(meter, capsys, *extra) -> tuple[dict, str]:
    assert cli.main(["discover-ic", meter.endpoint, "--report", *extra]) == 0
    captured = capsys.readouterr()
    for secret in SECRETS:
        assert secret.lower() not in captured.out.lower()
    return json.loads(captured.out), captured.err


def test_report_from_the_object_list(meter, capsys):
    report, _ = _report(meter, capsys)
    assert report["manufacturer"] == "PYD"
    assert report["manufacturer_source"] == "logical device name"
    assert report["firmware_id"] == "FW-1.2.3"
    assert report["object_list"] == "read"
    assert report["invocation_counters"] == [
        {
            "obis": "0.0.43.1.0.255",
            "class_id": 1,
            "attribute": 2,
            "found_by": "object list",
            "readable": True,
            "type": "DOUBLE_LONG_UNSIGNED",
        }
    ]
    assert report["security_setup"] == [{"obis": "0.0.43.0.0.255", "class_id": 64, "version": 1}]
    # Public client 16, no authentication, no ciphering.
    aarq = AARQ.from_bytes(meter.requests[0])
    assert aarq.mechanism is None and aarq.calling_ap_title is None


def test_report_by_blind_probing(meter, capsys):
    original = meter._read

    def no_object_list(cid, obis, attr, access=None):
        if cid == ClassId.ASSOCIATION_LN and attr == 2:
            return DataAccessResult.READ_WRITE_DENIED
        return original(cid, obis, attr, access)

    meter._read = no_object_list
    report, _ = _report(meter, capsys)
    assert report["object_list"] == "unreadable"
    assert report["security_setup"] is None
    assert [(c["obis"], c["found_by"]) for c in report["invocation_counters"]] == [
        ("0.0.43.1.0.255", "blind probe")
    ]


def test_report_from_the_vendor_table(meter, capsys):
    # A vendor counter outside 0.0.43.1.x.255 that the object list does not show,
    # next to the listed standard one.
    register_location(
        "PYD", CounterLocation(ObisCode.parse("0.128.96.1.4.255"), source="test fixture")
    )
    original = meter._read

    def vendor(cid, obis, attr, access=None):
        if obis == ObisCode.parse("0.128.96.1.4.255") and cid == 1 and attr == 2:
            return DlmsData.uint32(COUNTER)
        return original(cid, obis, attr, access)

    meter._read = vendor
    try:
        report, _ = _report(meter, capsys)
    finally:
        VENDOR_LOCATIONS.pop("PYD", None)
    found = {(c["obis"], c["found_by"]) for c in report["invocation_counters"]}
    assert found == {("0.128.96.1.4.255", "vendor table"), ("0.0.43.1.0.255", "object list")}


def test_unreadable_counter_is_reported_without_a_value(meter, capsys):
    meter.set_access(ClassId.DATA, "0.0.43.1.0.255", 2, mode=0)
    report, _ = _report(meter, capsys)
    (counter,) = report["invocation_counters"]
    assert counter["readable"] is False and counter["type"] is None


def test_public_client_is_enforced(meter, capsys):
    _, err = _report(meter, capsys, "--client", "1", "--auth", "lls", "--password", "x")
    assert "public client 16" in err
    aarq = AARQ.from_bytes(meter.requests[0])
    assert aarq.mechanism is None


def test_library_call(meter):
    host, port = meter.endpoint[len("tcp://") :].split(":")
    with DlmsClient.tcp(host, int(port), timeout=5) as client:
        report = ic_report(client)
    assert report["invocation_counters"][0]["obis"] == "0.0.43.1.0.255"
    assert str(COUNTER) not in json.dumps(report)


def test_plain_output(meter, capsys):
    assert cli.main(["discover-ic", meter.endpoint]) == 0
    out = capsys.readouterr().out
    assert "counter 0.0.43.1.0.255 (object list): DOUBLE_LONG_UNSIGNED" in out
    assert "security setup 0.0.43.0.0.255 class 64 v1" in out
    for secret in SECRETS:
        assert secret.lower() not in out.lower()
