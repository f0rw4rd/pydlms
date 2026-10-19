"""OpenMUC jDLMS 1.8.0 against pydlms: codec oracle, server sweep, reverse client.

Needs the ``pydlms-interop-jdlms`` image (``docker build -t pydlms-interop-jdlms
tests/interop/jdlms``).
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import subprocess
import sys
import time

import pytest

from pydlms.apdu.xdlms import entry_descriptor, range_descriptor
from pydlms.client import DlmsClient
from pydlms.cosem.data import DlmsData, decode_data
from pydlms.cosem.enums import DataType
from pydlms.exceptions import AssociationError
from pydlms.security.hls import Mechanism
from tests.interop import compare
from tests.interop.model import answer, data_json
from tests.interop.oracle import Oracle, require_image
from tests.interop.server import running, sweep

pytestmark = pytest.mark.integration

#: ``PYDLMS_JDLMS_IMAGE`` points the tests at another build (e.g. a private
#: tag with a newer adapter) without retagging the shared image.
IMAGE = os.environ.get("PYDLMS_JDLMS_IMAGE", "pydlms-interop-jdlms")
EK = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
AK = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")
LLS_PASSWORD = b"JDLMSLLS"  # tests/interop/jdlms/src/Server.java

_UINT64 = "jDLMS: long64-unsigned is a Java long capped at 2^63-1 (jDLMS defect)"
_DATE_TAG = "jDLMS: DataConverter encodes date-time/date/time as octet-string (jDLMS defect)"
_EXC_IC = "jDLMS: no invocation-counter-error Unsigned32 in ExceptionResponse (jDLMS defect)"
_TAGGED_DT = "date-time sent as 09 0C..: pydlms accepts the real-meter form, jDLMS is strict"

#: Every corpus outcome other than agree / both-reject / unsupported, with its verdict.
KNOWN = {
    "data:hand-03-GetResponseNormal#0": _UINT64,
    "data:hand-03-GetResponseNormal#6": "jDLMS: Integer64 decode drops high octets of negatives",
    "data:hand-03-GetResponseNormal#7": _UINT64,
    "encode-data:hand-03-GetResponseNormal#0": _UINT64,
    "encode-data:hand-03-GetResponseNormal#7": _UINT64,
    "encode-data:hand-03-GetResponseNormal#11": _DATE_TAG,
    "encode-data:hand-03-GetResponseNormal#12": _DATE_TAG,
    "encode-data:hand-03-GetResponseNormal#13": _DATE_TAG,
    "apdu:hand-03-GetResponseNormal": _UINT64,
    "apdu:hand-28-DataNotification": _TAGGED_DT,
    "apdu:notification-tagged-date-time": _TAGGED_DT,
    "apdu:capture-hdlc_kaifa_ma304h3e-0": _TAGGED_DT,
    "push:hdlc_kaifa_ma304h3e-0": _TAGGED_DT,
    "apdu:hand-30-ExceptionResponse": _EXC_IC,
    "apdu:exception-ic": _EXC_IC,
    # error 6 without its counter: pydlms requires the Unsigned32 (7c98299), jDLMS reads none
    **{f"apdu:exception-{s}-6": _EXC_IC for s in range(3)},
    "push:mbus_netz_noe_p1-0": "jDLMS: GcmModule always expects a GCM tag; SC 0x20 has none",
}


@pytest.fixture(scope="module")
def oracle():
    require_image(IMAGE)
    proc = Oracle(IMAGE)
    yield proc
    proc.close()


def test_hello(oracle):
    assert oracle.hello["library"] == "jdlms"
    assert oracle.hello["version"] == "1.8.0"
    assert set(oracle.hello["ops"]) == {"data", "encode-data", "apdu", "push", "decrypt"}


def test_access_apdus_agree_field_by_field(oracle):
    """ACCESS: every ACCESS probe of the corpus decodes to the
    same fields in jDLMS's AccessRequest / AccessResponse ASN.1 classes
    (specification kinds 1..5, the optional request echo, results).
    Adapters built before S5 report the APDU as unsupported."""
    rows = [
        compare.classify(line, oracle) | {"name": name}
        for name, line in compare.lines("apdu")
        if name.startswith("access-")
    ]
    assert len(rows) == 9
    if all(r["outcome"] == "unsupported" for r in rows):
        pytest.skip(f"{IMAGE} predates the ACCESS mapping: rebuild tests/interop/jdlms")
    assert {r["name"]: r["outcome"] for r in rows} == dict.fromkeys(
        (r["name"] for r in rows), "agree"
    )


def test_corpus_disagreements_are_exactly_the_known_ones(oracle):
    rows = compare.run(oracle)
    odd = {
        f"{r['op']}:{r['name']}": r["outcome"]
        for r in rows
        if r["outcome"] not in ("agree", "both-reject", "unsupported")
    }
    assert set(odd) == set(KNOWN)
    # ACCESS APDUs are unsupported by adapters built before ACCESS support
    # (test_access_apdus_agree_field_by_field covers them).
    unsupported = {
        r["name"]
        for r in rows
        if r["outcome"] == "unsupported" and not r["name"].startswith("access-")
    }
    # jDLMS has no compact-array item encoder (CompactArray takes raw contents).
    assert all(
        r["input"].startswith("encode-data") or r["name"].startswith("access-")
        for r in rows
        if r["outcome"] == "unsupported"
    )
    assert len(unsupported) == 7
    agree = sum(r["outcome"] == "agree" for r in rows)
    # 1596 on 2026-10-16; 24 fewer once the simulator listed access rights:
    # its object list spans datablocks, so 14 data and 14 encode-data items
    # left the corpus and 4 apdu items joined it.
    assert agree >= 1572


# jDLMS behaviour outside the corpus, pinned so an image change is noticed. Each
# entry: (line, jDLMS answer, pydlms answer). Verdicts in the findings doc.
PROBES = {
    # Integer64 sign extension shifts an int by 56 (mod 32): wrong for most negatives.
    "long64-neg-high": ("data 14ff00000000000000", 0, -72057594037927936),
    "long64-neg-mid": ("data 14fffffffeffffffff", -2, -4294967297),
    # bcd is Integer8 in the Green Book ASN.1; jDLMS reads it signed.
    "bcd-high": ("data 0d99", -103, 153),
}


def test_jdlms_probe_dont_care(oracle):
    """Green Book Data CHOICE dont-care [255] IMPLICIT NULL; pydlms decodes it since 06ea3d7."""
    got = oracle.ask("data ff")
    assert got["ok"] and got["result"] == {"t": "dont-care", "v": None}
    value, consumed = decode_data(b"\xff")
    assert (value.tag, value.value, consumed) == (DataType.DONT_CARE, None, 1)


@pytest.mark.parametrize("name", sorted(PROBES))
def test_jdlms_probes(oracle, name):
    line, theirs, ours = PROBES[name]
    got = oracle.ask(line)
    assert got["ok"] and got["result"]["v"] == theirs
    mine = answer(line)
    assert (mine["result"]["v"] if mine["ok"] else "reject") == ours


# --- phase 3: pydlms client against the jDLMS DlmsServer --------------------------------

_DENIED = "READ_WRITE_DENIED"
SWEEP_ERRORS = {
    # authenticated-only attributes, correctly denied to the public client
    "public": {
        "0.0.40.0.0.255/15/7": _DENIED,
        **{f"0.0.43.0.0.255/64/{a}": _DENIED for a in (2, 3, 4, 5)},
    },
    "hls5": {},
}


def _hls5(invocation_counter: int = 1) -> dict:
    pytest.importorskip("cryptography")
    from pydlms.security.context import SecurityContext

    return {
        "client_sap": 1,
        "mechanism": Mechanism.HLS_GMAC,
        "security": SecurityContext(
            EK, AK, client_system_title=b"PYDLMS01", invocation_counter=invocation_counter
        ),
    }


CLIENTS = {
    "public": dict,
    "lls": lambda: {"client_sap": 17, "mechanism": Mechanism.LLS, "password": LLS_PASSWORD},
    "hls5": _hls5,
}


@pytest.fixture(scope="module")
def jdlms_server():
    require_image(IMAGE)
    with running(IMAGE, "server", ready="listening") as endpoint:
        yield endpoint


@pytest.mark.parametrize("mode", sorted(SWEEP_ERRORS))
def test_server_sweep(jdlms_server, mode):
    host, port = jdlms_server
    with DlmsClient.tcp(host, port, timeout=10, **CLIENTS[mode]()) as meter:
        report = sweep(meter)
    assert report["objects"] == 13
    expected = SWEEP_ERRORS[mode]
    assert set(report["errors"]) == set(expected)
    for key, code in expected.items():
        assert code in report["errors"][key], (key, report["errors"][key])
    values = report["values"]
    assert values["1.0.1.8.0.255/3/2"] == {"t": "double-long-unsigned", "v": 12345678}
    assert values["1.0.31.7.0.255/3/3"]["v"] == [{"t": "integer", "v": -2}, {"t": "enum", "v": 33}]
    assert values["0.0.96.1.1.255/1/2"]["v"] == bytes(i & 0xFF for i in range(1000)).hex()
    assert len(values["1.0.99.1.0.255/7/2"]["v"]) == 10


def test_server_lls_aare_names_the_ciphered_context(jdlms_server):
    """jDLMS defect (findings doc, defect 11): an accepted LLS AARE names LN-ciphered
    although LN was proposed; pydlms refuses such an AARE since 8c00c42."""
    host, port = jdlms_server
    client = DlmsClient.tcp(host, port, timeout=10, **CLIENTS["lls"]())
    with pytest.raises(AssociationError, match="LN_CIPHERED, but LN was proposed"):
        client.connect()
    client.link.disconnect()


def test_server_profile_selective_access_and_methods(jdlms_server):
    host, port = jdlms_server
    with DlmsClient.tcp(host, port, timeout=10, **_hls5(10)) as meter:
        rows = meter.read_profile("1.0.99.1.0.255", entry_descriptor(2, 3)).rows
        assert [r[1] for r in rows] == [1007, 1014]
        # The range filter is our glue in Server.java, so only the request is under test.
        start = DlmsData.octet_string(bytes.fromhex("07e8050103000000ff800000"))
        end = DlmsData.octet_string(bytes.fromhex("07e8050103001e00ff800000"))
        assert len(meter.read_profile("1.0.99.1.0.255", range_descriptor(start, end)).rows) == 3
        assert meter.get_register("1.0.32.7.0.255").value == pytest.approx(230.1)
        assert meter.get_clock().is_fully_specified
        meter.action("0.0.96.3.10.255", 70, 1, DlmsData.int8(0))
        assert meter.get("0.0.96.3.10.255", 70, 2).value is False
        meter.action("0.0.96.3.10.255", 70, 2, DlmsData.int8(0))
        assert meter.get("0.0.96.3.10.255", 70, 2).value is True


def test_server_rejects_wrong_lls_password(jdlms_server):
    host, port = jdlms_server
    client = DlmsClient.tcp(
        host, port, client_sap=17, mechanism=Mechanism.LLS, password=b"wrong", timeout=10
    )
    with pytest.raises(AssociationError, match="AUTHENTICATION_FAILURE"):
        client.connect()
    client.link.disconnect()


def test_server_accepts_replayed_invocation_counter(jdlms_server):
    """jDLMS defect (findings doc): no invocation-counter floor across associations."""
    host, port = jdlms_server
    for counter in (50, 50, 2):
        with DlmsClient.tcp(host, port, timeout=10, **_hls5(counter)) as meter:
            assert meter.get("0.0.96.1.0.255").value == b"JDLMS-0001"


# --- phase 4: the jDLMS client against `pydlms simulate` --------------------------------


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextlib.contextmanager
def _simulate(*options: str):
    """``pydlms simulate`` on a free loopback port (the jDLMS container uses host network)."""
    port = _free_port()
    proc = subprocess.Popen(  # noqa: S603 - fixed argv, test-only
        [sys.executable, "-m", "pydlms.cli", "simulate", "--host", "127.0.0.1"]
        + ["--port", str(port), *options],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 30
        while True:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                if time.monotonic() > deadline or proc.poll() is not None:
                    pytest.fail("pydlms simulate did not start")
                time.sleep(0.2)
        yield port
    finally:
        proc.terminate()
        proc.wait(timeout=10)


@pytest.fixture(scope="module")
def simulators():
    """Two simulators: ``--key`` makes every ``--client`` ciphered, so LLS needs its own."""
    require_image(IMAGE)
    with (
        _simulate("--client", f"17:1:{LLS_PASSWORD.decode()}") as plain,
        _simulate("--client", "1:5", "--key", EK.hex(), "--auth-key", AK.hex()) as ciphered,
    ):
        yield {"public": plain, "lls": plain, "hls5": ciphered}


REVERSE_MODES = {
    "public": ["none"],
    "lls": ["lls", LLS_PASSWORD.decode()],
    "hls5": ["hls5", EK.hex(), AK.hex()],
}

#: Range selection 00:00..00:30 with from_value hundredths 0xFF (not specified): the
#: simulator compares instants since 7aea433, so the 00:00 row is included.
RANGE_STAMPS = ["07e8050103000000000000ff", "07e8050103000f00000000ff", "07e8050103001e00000000ff"]


def _jdlms_client(port: int, mode: list[str]) -> dict:
    out = subprocess.run(  # noqa: S603,S607 - fixed docker argv, test-only
        ["docker", "run", "--rm", "--network", "host", IMAGE, "client", "127.0.0.1", str(port)]
        + mode,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    return json.loads(out.stdout)


@pytest.mark.parametrize("mode", sorted(REVERSE_MODES))
def test_jdlms_client_reads_pydlms_simulator(simulators, mode):
    port = simulators[mode]
    report = _jdlms_client(port, REVERSE_MODES[mode])
    assert report["associated"] and "error" not in report, report
    reads = report["reads"]
    assert {r["result"] for r in reads.values()} == {"SUCCESS"}
    rows = reads["1.0.99.1.0.255/7/2?entry=1-2"]["value"]["v"]
    assert [r["v"][1]["v"] for r in rows] == [1000, 1007]
    stamps = [r["v"][0]["v"] for r in reads["1.0.99.1.0.255/7/2?range"]["value"]["v"]]
    assert stamps == RANGE_STAMPS
    # Every plain attribute jDLMS read equals what pydlms reads from the same simulator.
    with DlmsClient.tcp("127.0.0.1", port, timeout=10) as meter:
        view = meter.get_association_view()
        assert report["objects"] == [f"{e.class_id}/{e.logical_name}" for e in view]
        for key, got in reads.items():
            if "?" in key or key.endswith("/15/2"):
                continue
            obis, class_id, attribute = key.split("/")
            ours = data_json(meter.get(obis, int(class_id), int(attribute)))
            assert got["value"] == ours, key
