"""Gurux.DLMS.Net (GPL-2.0, commit 6f26301) as an interop oracle and peer.

Phase 2: the codec differential over tests/interop/corpus.py plus decrypt and
targeted probes; phase 3: pydlms's DlmsClient sweeping every template the
Gurux simulator ships; phase 4: Gurux's own client reading ``pydlms
simulate``.

Build: docker build -t pydlms-interop-gurux-net tests/interop/gurux-net
       docker build -t pydlms-gurux-sim tests/integration/gurux   (phase 3)
Run:   pytest -m integration tests/interop/test_gurux_net.py
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from collections import Counter

import pytest

from tests.docker_ready import wait_listening
from tests.interop import compare, corpus
from tests.interop.oracle import Oracle, require_image

pytestmark = pytest.mark.integration

IMAGE = "pydlms-interop-gurux-net"
SIM = os.environ.get("PYDLMS_GURUX_IMAGE", "pydlms-gurux-sim")
COMMIT = "6f263019caab62eb038dad7b1fa130edc7097081"

# --- why each item differs; verdicts and cites in the findings doc -------------------
LONG64 = "Gurux SetData(Int64) calls Convert.ToUInt64 on the value: any negative long64 throws"
LATIN1 = "visible-string U+00E9 U+00FF: Gurux SetString encodes ASCII, silently writes '?'"
COMPACT_ARRAY = (
    "compact-array whose description is an array: Gurux throws (GXCommon.GetCompactArray)"
)
LIST_ERROR = "GetResponseWithList: Gurux drops data-access-result entries (GXDLMS.cs:5061)"
ACTION_LIST = "ActionResponseWithList: the Gurux translator has no decoder ('Invalid Command')"
DN_TAGGED = "DataNotification date-time Data-tagged (09 0C, Kaifa): Gurux reads 09 as the length"
IR_TIME = "InformationReport current-time OPTIONAL flag: Gurux reads a bare length octet"
UNDEFINED_RESULT = (
    "result code not in the Green Book Data-Access-Result/Action-Result: Gurux throws"
)
EXCEPTION = "ExceptionResponse state-error/service-error value undefined: Gurux throws"
EXCEPTION_COUNTER = (
    "ExceptionResponse invocation-counter-error [6] without its Unsigned32: Gurux reads none"
)
CSE = "ConfirmedServiceError value outside its ServiceError ENUMERATED: Gurux KeyNotFound"
CSE_8 = "ServiceError [8] (change-scope) is not used by DLMS: Gurux numbers task as 8"
SET_SELECTIVE = (
    "SetRequestNormal with access selection: Gurux skips the flag, reads selector as value"
)
ATTRIBUTE_ID = "attribute-id 0xFE: Integer8 in the Green Book, pydlms -2, Gurux 254"
WRITE_PARAM = "WriteRequest parameterized-access: the Gurux translator fails ('Invalid data type')"

KNOWN = {
    "data:data-compact-array#0": ("only-oracle-rejects", COMPACT_ARRAY),
    "encode-data:hand-03-GetResponseNormal#0": ("only-oracle-rejects", LONG64),
    "encode-data:hand-03-GetResponseNormal#6": ("only-oracle-rejects", LONG64),
    "encode-data:data-visible-latin1#0": ("disagree", LATIN1),
    "apdu:hand-07-GetResponseWithList": ("disagree", LIST_ERROR),
    "apdu:get-list-error": ("disagree", LIST_ERROR),
    "apdu:hand-25-ActionResponseWithList": ("only-oracle-rejects", ACTION_LIST),
    "apdu:action-list-response": ("only-oracle-rejects", ACTION_LIST),
    "apdu:hand-28-DataNotification": ("only-oracle-rejects", DN_TAGGED),
    "apdu:notification-tagged-date-time": ("only-oracle-rejects", DN_TAGGED),
    "apdu:capture-hdlc_kaifa_ma304h3e-0": ("only-oracle-rejects", DN_TAGGED),
    "push:hdlc_kaifa_ma304h3e-0": ("only-oracle-rejects", DN_TAGGED),
    "apdu:hand-41-InformationReportRequest": ("only-oracle-rejects", IR_TIME),
    "apdu:information-report-time": ("only-oracle-rejects", IR_TIME),
    **{
        f"apdu:{kind}-result-{v}": ("only-oracle-rejects", UNDEFINED_RESULT)
        for kind in ("set", "action")
        for v in (5, 6, 7, 8, 10)
    },
    **{
        f"apdu:exception-{s}-{e}": ("only-oracle-rejects", EXCEPTION)
        for s, e in [(0, i) for i in range(8) if i != 6] + [(1, 0), (1, 7), (2, 0), (2, 7)]
    },
    # exception-0-6: both reject (state-error 0 for Gurux, the missing counter for pydlms).
    **{f"apdu:exception-{s}-6": ("only-pydlms-rejects", EXCEPTION_COUNTER) for s in (1, 2)},
    **{
        f"apdu:cse-{t}-{v}": ("only-oracle-rejects", CSE)
        for t, values in {
            0: (7,),
            1: (5, 6, 7),
            2: (5, 6, 7),
            3: (3, 4, 5, 6, 7),
            4: (4, 5, 6, 7),
            5: (5, 6, 7),
            6: (5, 6, 7),
        }.items()
        for v in values
    },
    # cse-8-{5,6,7}: both reject (pydlms the choice, Gurux the value).
    **{f"apdu:cse-8-{v}": ("only-pydlms-rejects", CSE_8) for v in range(5)},
    "apdu:data-compact-array": ("only-oracle-rejects", COMPACT_ARRAY),
    "apdu:set-selective": ("disagree", SET_SELECTIVE),
    "apdu:get-class-attribute-edge": ("disagree", ATTRIBUTE_ID),
    "apdu:write-parameterised": ("only-oracle-rejects", WRITE_PARAM),
    "apdu:set-list-first-datablock": (
        "only-oracle-rejects",
        "SET choice 5: the translator has no element for it and prints UNKNOWN(49413), "
        "which is not XML",
    ),
    "apdu:sn-read-block-number": (
        "only-oracle-rejects",
        "ReadResponse block-number [3]: the translator keeps block state and expects 1",
    ),
    **{
        f"apdu:access-request-{k}-selection": (
            "only-oracle-rejects",
            "ACCESS get/set-with-selection (kinds 4, 5): HandleAccessRequest accepts kinds "
            "1..3 only ('Invalid access service command type')",
        )
        for k in ("get", "set")
    },
    "apdu:access-response-errors": (
        "only-oracle-rejects",
        "ACCESS response with a non-zero result: the Gurux client reads a second result "
        "octet after it (GXDLMS.HandleAccessResponse) and runs out of data",
    ),
    "apdu:access-response-echo": (
        "only-oracle-rejects",
        "ACCESS response with the request echo: Gurux skips the presence flag only, reads "
        "the echo as data and prints UNKNOWN(55816), which is not XML",
    ),
}

#: Where the adapter answers "unsupported" (the reason is the adapter's error).
UNSUPPORTED = {
    # compact-array nested in a structure: SimpleXml prints the items untyped
    "data:hand-03-GetResponseNormal#0",
    # GXCommon.SetData has no compact-array encoder
    *(
        f"encode-data:{n}#0"
        for n in (
            "data-compact-uint16-empty",
            "data-compact-structure",
            "data-compact-array",
            "data-compact-octets",
            "data-compact-boolean",
            "data-compact-int8",
        )
    ),
    "encode-data:hand-03-GetResponseNormal#18",
    # UnconfirmedWriteRequest: PduToXml prints <Data="..."/>
    "apdu:hand-39-UnconfirmedWriteRequest",
    # ACTION choice 5: the translator prints only the invoke-id in
    # <ActionRequestWithListAndFirstBlock>, which the adapter does not map
    "apdu:action-list-first-pblock",
    # ACCESS: the adapter has no mapping for <AccessRequest> /
    # <AccessResponse> (the translator decodes them; pydlms's Gurux XML dialect
    # is checked against that output in tests/test_gurux_xml.py)
    *(
        f"apdu:access-{n}"
        for n in (
            "f10-request",
            "i2-response",
            "request-kinds",
            "request-date-time",
            "response-kinds",
        )
    ),
}

COUNTS = {
    # 9 ACCESS APDUs, whose 19 data values agree both ways.
    "data": {"agree": 620, "unsupported": 1, "only-oracle-rejects": 1},
    "encode-data": {"agree": 612, "unsupported": 7, "disagree": 1, "only-oracle-rejects": 2},
    "apdu": {
        "agree": 326,
        "unsupported": 7,
        "disagree": 4,
        "only-oracle-rejects": 58,
        "only-pydlms-rejects": 7,
        "both-reject": 8,
    },
    "push": {"agree": 11, "only-oracle-rejects": 1, "both-reject": 4},
}


@pytest.fixture(scope="module")
def oracle():
    require_image(IMAGE)
    o = Oracle(IMAGE)
    yield o
    o.close()


@pytest.fixture(scope="module")
def rows(oracle):
    return compare.run(oracle)


def test_hello_pins_the_commit(oracle):
    assert oracle.hello["library"] == "Gurux.DLMS.Net"
    assert oracle.hello["version"] == COMMIT
    assert set(oracle.hello["ops"]) == {
        "data",
        "encode-data",
        "apdu",
        "push",
        "decrypt",
        "compact-data",
    }


def test_every_disagreement_is_known(rows):
    found = {
        f"{r['op']}:{r['name']}": r["outcome"]
        for r in rows
        if r["outcome"] not in ("agree", "both-reject", "unsupported")
    }
    assert found == {key: outcome for key, (outcome, _) in KNOWN.items()}


def test_unsupported_is_known(rows):
    assert {f"{r['op']}:{r['name']}" for r in rows if r["outcome"] == "unsupported"} == UNSUPPORTED


def test_outcome_counts(rows):
    counts: dict = {}
    for (op, outcome), n in Counter((r["op"], r["outcome"]) for r in rows).items():
        counts.setdefault(op, {})[outcome] = n
    assert counts == COUNTS


def test_push_bodies_agree(rows):
    """Every push both sides decode has the same invoke id, date-time and body."""
    for r in rows:
        if r["op"] == "push" and r["outcome"] == "agree":
            assert r["oracle"]["result"] == {
                k: r["pydlms"]["result"][k] for k in ("long_invoke_id", "date_time", "body")
            }, r["name"]


def _decrypt_lines():
    from tests.gurux_xml_corpus import build

    title = b"ABCDEFGH".hex()  # client system title of the corpus's glo- APDUs
    out = [
        (r["name"], *r["keys"], r["apdu"])
        for r in build()
        if "keys" in r and r["apdu"][:2] not in ("60", "dd", "df")
    ]
    out += [(n, ek, ak, h) for n, h, ek, ak in corpus.pushes() if ek]
    # An empty AK is passed as zeros (the protocol has no "absent" token).
    return [
        (n, f"decrypt {ek} {ak or '00' * 16} {h[4:20] if h.startswith('db08') else title} {h}")
        for n, ek, ak, h in out
    ]


#: Every decrypt agrees (the model gives pydlms the EK as the dedicated key too).
DECRYPT: dict[str, str] = {}


def test_decrypt(oracle):
    got = {name: compare.classify(line, oracle)["outcome"] for name, line in _decrypt_lines()}
    assert got == {name: DECRYPT.get(name, "agree") for name in got}


# Gurux behaviour the corpus (valid values) does not reach.
PROBES = {
    # date-time tag with 5 or 4 octets left: GXCommon.GetDateTime falls back to
    # GetDate/GetTime instead of failing (date-time is 12 octets, Blue Book 4.1.6.1).
    "data 1907e80101ff": "only-pydlms-rejects",
    "data 190c000000": "only-pydlms-rejects",
    # Invalid UTF-8: .NET substitutes U+FFFD; pydlms raises UnicodeDecodeError, not
    # DecodeError (pydlms bug, findings doc).
    "data 0c01ff": "only-pydlms-rejects",
    # Trailing octets after a complete APDU: the translator ignores them.
    "apdu c401c1000600bc614eff": "only-pydlms-rejects",
    "apdu 0e01060100": "only-pydlms-rejects",
    # InformationReport current-time in Gurux's own form (bare length, no OPTIONAL
    # flag; GXDLMS.cs encodes it so): pydlms accepts it as a known deviation.
    "apdu 180c07e6010103000000ff8000000102fa00011105": "agree",
    # set-response-last-datablock-with-list [4]: Gurux has no decoder.
    "apdu c504c102000000000005": "only-oracle-rejects",
    "encode-data " + json.dumps({"t": "long64", "v": -1}): "only-oracle-rejects",
    "encode-data " + json.dumps({"t": "octet-string", "v": "ab" * 200}): "agree",
}


def test_probes(oracle):
    assert {line: compare.classify(line, oracle)["outcome"] for line in PROBES} == PROBES


_STAMP = "07e80501030c000000ff8800"  # 2024-05-01 12:00:00, deviation -120 (UTC+2)
_ARRAY_MEMBER = (
    "an array member in the template: Gurux GetValues reads an element count from "
    "the buffer (GXCommon.GetCompactArray), its own Capture writes none"
)
_ONE_CAPTURE = "pydlms decodes one capture and rejects trailing octets; Gurux returns every row"

#: compact-data cases: (template, buffer) -> expected outcome (reason when not agree).
COMPACT_DATA = {
    # the clock (octet-string) and a register (double-long-unsigned), the
    # layout pydlms's simulator serves at 0.0.66.0.1.255
    ("02020906", "0c" + _STAMP + "00bc614e"): ("agree", ""),
    # a date-time tagged member (12 octets, no length)
    ("02021906", _STAMP + "00000001"): ("agree", ""),
    # integers, boolean, enum, float32 and a visible-string
    ("02091110120f050316170a", "ff8000fffffe0000000a01073fc00000026162"): (
        "agree",
        "",
    ),  # fmt: skip
    # long64 and long64-unsigned, float64
    ("0203141518", "fffffffffffffffe" + "0000000000000003" + "3ff8000000000000"): ("agree", ""),
    # a nested structure
    ("02021202021103", "0005" + "07" + "01"): ("agree", ""),
    ("020101000211", "0102"): ("disagree", _ARRAY_MEMBER),
    ("02020906", "0c" + _STAMP + "00bc614e" + "0c" + _STAMP + "00bc614f"): (
        "only-pydlms-rejects",
        _ONE_CAPTURE,
    ),
    ("02020906", "0c" + _STAMP + "00bc61"): ("both-reject", ""),  # truncated
    ("02020906", "-"): ("both-reject", ""),  # nothing captured
    ("06", "00bc614e"): ("both-reject", ""),  # the template is not a structure
}


def test_compact_data_against_gurux_get_values(oracle):
    """pydlms.cosem.compact_data.decode_compact_buffer against
    GXDLMSCompactData.GetValues (no template_id octet in either; Blue Book
    layout unverified)."""
    got = {
        key: compare.classify(f"compact-data {key[0]} {key[1]}", oracle)["outcome"]
        for key in COMPACT_DATA
    }
    assert got == {key: outcome for key, (outcome, _) in COMPACT_DATA.items()}


def test_empty_structure_compact_array_hangs_gurux():
    """1302000100: compact-array of an empty structure, one content octet. Every
    element is 0 octets wide; GXCommon.GetCompactArray loops forever (pydlms too:
    findings doc). The adapter answers nothing within 20 s."""
    require_image(IMAGE)
    name = f"gxnet-hang-{time.monotonic_ns()}"
    proc = subprocess.Popen(  # noqa: S603,S607 - fixed docker argv, test-only
        ["docker", "run", "--rm", "-i", "--network", "none", "--name", name, IMAGE],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        proc.stdin.write("hello\ndata 1302000100\n")
        proc.stdin.flush()
        assert json.loads(proc.stdout.readline())["ok"]  # the adapter is up
        time.sleep(20)
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)  # noqa: S603,S607
        out, _ = proc.communicate(timeout=120)
    assert out == ""


# --- phase 3: pydlms sweeps every template of the Gurux simulator ------------------------

EK = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
AK = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")
TEMPLATES = [
    "GMacWithAuthenticationEncyption.xml",
    "LN-v2-GMac.xml",
    "LN-v2-GMacWithAuthenticationEncyption.xml",
    "LN-v2-GMacWithAuthenticationEncyption1.xml",
    "LN-v2-GMacWithAuthenticationEncyption2.xml",
    "LN-v2-High.xml",
    "LN-v2-Low.xml",
    "LN-v2-Md5.xml",
    "LN-v2-Sha1.xml",
    "LN-v2-Sha256.xml",
    "LN-v2-Sha256WithAuthenticationEncyption.xml",
    "LN-v2-Sha256WithAuthenticationEncyption1.xml",
    "LN-v2-Sha256WithAuthenticationEncyption2.xml",
    "LN-v3-GMac.xml",
    "LN-v3-High.xml",
    "LN-v3-Low.xml",
    "LN-v3-Md5.xml",
    "LN-v3-Sha1.xml",
    "LN-v3-Sha256.xml",
    "crystal.xml",
]

DENIED_SECRET = {"0.0.40.0.0.255/15/7", "0.0.40.0.1.255/15/7"}
DENIED_CERTS = {"0.0.43.0.0.255/64/6"}
#: (template, client SAP) -> (objects, attributes read, error keys). Every error is
#: READ_WRITE_DENIED from the template's access rights (findings doc).
SWEEP = {
    ("GMacWithAuthenticationEncyption.xml", 18): (12, 76, DENIED_CERTS),
    ("GMacWithAuthenticationEncyption.xml", 16): (8, 48, set()),
    ("GMacWithAuthenticationEncyption.xml", 1): (5, 32, set()),
    ("LN-v2-GMac.xml", 16): (3, 24, set()),
    ("LN-v2-GMac.xml", 1): (4, 27, {"0.0.40.0.0.255/15/7", "0.0.40.0.2.255/15/7"}),
    ("LN-v2-GMacWithAuthenticationEncyption.xml", 16): (4, 26, set()),
    ("LN-v2-GMacWithAuthenticationEncyption.xml", 1): (5, 31, set()),
    ("LN-v2-GMacWithAuthenticationEncyption1.xml", 16): (4, 26, set()),
    ("LN-v2-GMacWithAuthenticationEncyption1.xml", 1): (5, 32, set()),
    ("LN-v2-GMacWithAuthenticationEncyption2.xml", 16): (4, 26, set()),
    ("LN-v2-GMacWithAuthenticationEncyption2.xml", 1): (5, 31, DENIED_CERTS),
    ("LN-v2-High.xml", 18): (3, 22, DENIED_SECRET),
    ("LN-v2-Low.xml", 17): (3, 24, set()),
    ("LN-v2-Md5.xml", 1): (3, 22, DENIED_SECRET),
    ("LN-v2-Sha1.xml", 1): (3, 22, DENIED_SECRET),
    ("LN-v2-Sha256.xml", 1): (3, 22, DENIED_SECRET),
    ("LN-v2-Sha256WithAuthenticationEncyption.xml", 16): (4, 26, set()),
    ("LN-v2-Sha256WithAuthenticationEncyption.xml", 1): (5, 31, set()),
    ("LN-v2-Sha256WithAuthenticationEncyption1.xml", 16): (4, 26, set()),
    ("LN-v2-Sha256WithAuthenticationEncyption1.xml", 1): (5, 31, DENIED_CERTS),
    ("LN-v2-Sha256WithAuthenticationEncyption2.xml", 16): (4, 26, set()),
    ("LN-v2-Sha256WithAuthenticationEncyption2.xml", 1): (5, 31, DENIED_CERTS),
    ("LN-v3-GMac.xml", 1): (3, 22, DENIED_SECRET),
    ("LN-v3-High.xml", 18): (3, 22, DENIED_SECRET),
    ("LN-v3-Low.xml", 18): (3, 24, set()),
    ("LN-v3-Md5.xml", 1): (3, 22, DENIED_SECRET),
    ("LN-v3-Sha1.xml", 1): (3, 22, DENIED_SECRET),
    ("LN-v3-Sha256.xml", 1): (3, 22, DENIED_SECRET),
    ("crystal.xml", 16): (9, 35, {f"0.0.40.0.{i}.255/15/{a}" for i in (0, 1) for a in (7, 9)}),
}


def _template(name: str) -> str:
    return subprocess.run(  # noqa: S603,S607
        ["docker", "run", "--rm", "--entrypoint", "cat", SIM, f"/templates/{name}"],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    ).stdout.lstrip("﻿")


def associations(xml: str) -> list[dict]:
    """Each GXDLMSAssociationLogicalName: client SAP, mechanism, context, secret, keys."""
    root = ET.fromstring(xml)
    setups = {
        s.findtext("LN"): s for s in root.iter("GXDLMSSecuritySetup") if s.find("Guek") is not None
    }
    out = []
    for a in root.findall("GXDLMSAssociationLogicalName"):
        mech = a.find("AuthenticationMechanismName")
        secret = (a.findtext("Secret") or "").replace(" ", "")
        setup = setups.get(a.findtext("SecuritySetupReference") or "")
        out.append(
            {
                "client": int(a.findtext("ClientSAP")),
                "mechanism": int(mech.findtext("MechanismId") or 0) if mech is not None else 0,
                "context": int(a.find("ApplicationContextName").findtext("ContextId")),
                "secret": bytes.fromhex(secret) if secret else None,
                "suite": int(setup.findtext("SecuritySuite") or 0) if setup is not None else 0,
                "ek": bytes.fromhex(setup.findtext("Guek")) if setup is not None else EK,
                "ak": bytes.fromhex(setup.findtext("Gak")) if setup is not None else AK,
            }
        )
    return out


def _connect(host: str, port: int, a: dict, **extra):
    from pydlms.client import DlmsClient
    from pydlms.security.context import SecurityContext
    from pydlms.security.hls import Mechanism

    kw = {"client_sap": a["client"], "mechanism": Mechanism(a["mechanism"]), "timeout": 15}
    if a["secret"]:
        kw["password"] = a["secret"]
    if a["mechanism"] == Mechanism.HLS_SHA256:
        kw["client_system_title"] = b"PYDLMS01"
    if a["context"] == 3 or a["mechanism"] == Mechanism.HLS_GMAC:
        kw["security"] = SecurityContext(
            a["ek"], a["ak"], client_system_title=b"PYDLMS01", suite=a["suite"]
        )
        kw["ciphered_context"] = a["context"] == 3
        kw["invocation_counter_retry"] = True  # from 0, retried at the meter's counter
    kw.update(extra)
    return DlmsClient.tcp(host, port, **kw)


@pytest.fixture(scope="module")
def simulator():
    pytest.importorskip("cryptography")
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    found = subprocess.run(  # noqa: S603,S607
        ["docker", "image", "inspect", SIM], capture_output=True, check=False
    )
    if found.returncode:
        pytest.skip(f"image {SIM} missing: docker build -t {SIM} tests/integration/gurux")


def _sweep(host: str, port: int, a: dict, **extra) -> tuple[int, int, set[str]]:
    from tests.interop.server import sweep

    with _connect(host, port, a, **extra) as client:
        report = sweep(client)
    return report["objects"], report["read"], set(report["errors"])


@pytest.mark.parametrize("template", TEMPLATES)
def test_sweep_template(simulator, template):
    from tests.interop.server import running

    found = {}
    env = {"SIM_TEMPLATE": template}
    with running(SIM, port=4060, ready="simulator start in", env=env) as (host, port):
        for a in associations(_template(template)):
            key = (template, a["client"])
            if a["mechanism"] == 7:
                continue  # ECDSA: test_sweep_ecdsa (the shipped keys are not usable)
            found[key] = _sweep(host, port, a)
    assert found == {k: v for k, v in SWEEP.items() if k[0] == template}


def test_sweep_default_template_over_hdlc(simulator):
    from tests.interop.server import running

    env = {"SIM_TEMPLATE": TEMPLATES[0], "SIM_IFACE": "HDLC"}
    public = {"client": 16, "mechanism": 0, "context": 1, "secret": None}
    with running(SIM, port=4060, ready="simulator start in", env=env) as (host, port):
        assert _sweep(host, port, public, hdlc=True) == SWEEP[(TEMPLATES[0], 16)]


@contextlib.contextmanager
def _mounted(directory, template: str):
    """running() with a template mounted from the host (it has no volume option)."""
    cid = subprocess.run(  # noqa: S603,S607
        ["docker", "run", "-d", "--rm", "-p", "127.0.0.1::4060", "-v", f"{directory}:/custom:ro"]
        + ["-e", f"SIM_TEMPLATE=/custom/{template}", SIM],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    ).stdout.strip()
    try:
        port = subprocess.run(  # noqa: S603,S607
            ["docker", "port", cid, "4060"], capture_output=True, text=True, check=True
        ).stdout.splitlines()[0]
        for _ in range(180):
            logs = subprocess.run(  # noqa: S603,S607
                ["docker", "logs", cid], capture_output=True, text=True, check=False
            )
            if "simulator start in" in logs.stdout:
                break
            time.sleep(0.5)
        wait_listening(int(port.rsplit(":", 1)[1]), "Gurux simulator")
        yield "127.0.0.1", int(port.rsplit(":", 1)[1])
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True, check=False)  # noqa: S603,S607


def test_sweep_ecdsa(simulator, tmp_path):
    """Client 44 (HLS-ECDSA, suite 1) with a test identity patched into the default
    template, as in tests/integration/test_gurux_suite1.py."""
    from pydlms.client import DlmsClient
    from pydlms.security.hls import Mechanism
    from tests.integration.gurux_ecdsa import CLIENT_TITLE, build
    from tests.interop.server import sweep

    tmp_path.chmod(0o755)
    ident = build(_template(TEMPLATES[0]), tmp_path)
    with _mounted(tmp_path, ident.template.name) as (host, port):
        client = DlmsClient.tcp(
            host,
            port,
            client_sap=44,
            mechanism=Mechanism.HLS_ECDSA,
            signing_key=ident.signing_key,
            server_public_key=ident.server_signing_public,
            client_system_title=CLIENT_TITLE,
            timeout=15,
        )
        with client:
            report = sweep(client)
    assert (report["objects"], report["read"], set(report["errors"])) == ECDSA_SWEEP


ECDSA_SWEEP = (4, 30, set())


# --- phase 4: Gurux's client reads pydlms simulate --------------------------------------

EK_HEX, AK_HEX = EK.hex(), AK.hex()


def _reverse(mode: str):
    from pydlms.security.hls import Mechanism
    from pydlms.simulator import ClientProfile, example_meter, serve

    keys = {}
    if mode == "gmac":
        keys = {"encryption_key": EK, "authentication_key": AK}
    meter = example_meter(**keys)
    if mode == "gmac":
        meter.clients[1] = ClientProfile(Mechanism.HLS_GMAC, ciphered=True)
    if mode == "lls":
        meter.clients[17] = ClientProfile(Mechanism.LLS, secret=b"12345678")
    args = {"none": ["none"], "gmac": ["gmac", EK_HEX, AK_HEX], "lls": ["lls", "12345678"]}
    server = serve(meter, "127.0.0.1", 0)
    try:
        out = subprocess.run(  # noqa: S603,S607 - fixed docker argv, test-only
            ["docker", "run", "--rm", "--network", "host", IMAGE, "client", "127.0.0.1"]
            + [str(server.server_address[1]), *args[mode]],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    finally:
        server.shutdown()
        server.server_close()
    return meter, [json.loads(line) for line in out.stdout.splitlines()]


#: Attributes Gurux's client asks for that the simulator does not hold: the
#: simulator answers object-unavailable (Data-Access-Result 11).
UNHELD = {("0.0.1.0.0.255", 8, a) for a in (4, 5, 6, 7, 8, 9)} | {
    ("0.0.96.3.10.255", 70, 4),
    *(("1.0.99.1.0.255", 7, a) for a in (6, 8)),
    # The example push setup holds only push_object_list (attribute 2).
    *(("0.0.25.9.0.255", 40, a) for a in (3, 4, 5, 6, 7)),
}

#: Attributes the simulator sends as held but Gurux's client fails to parse.
#: Compact data capture_objects: GXDLMSCompactData.SetCaptureObjects demands
#: 5-element definitions (with a restriction) for class version 1, while
#: its own GetCaptureObjects writes 4 elements; the simulator serves the
#: 4-element form that read_compact_data and Profile generic use.
PARSE_FAILS = {("0.0.66.0.1.255", 62, 3): "Invalid structure format."}


@pytest.mark.parametrize("mode", ["none", "lls", "gmac"])
def test_reverse_gurux_client_reads_simulator(oracle, mode):
    from pydlms.cosem.data import encode_data
    from pydlms.obis import ObisCode

    meter, steps = _reverse(mode)
    by_step = Counter(s["step"] for s in steps)
    assert by_step["associate"] == 1 and steps[0]["ok"], steps[:1]
    listing = next(s for s in steps if s["step"] == "object-list")
    assert listing["ok"]
    assert {(o["ln"], o["class_id"]) for o in listing["objects"]} == {
        (str(obis), cid) for cid, obis in meter.objects
    }
    for s in (s for s in steps if s["step"] == "read"):
        key = (s["ln"], s["class_id"], s["attribute"])
        held = meter.objects[(s["class_id"], ObisCode.parse(s["ln"]))]
        if s["attribute"] == 1:
            assert s["raw"] == "0906" + ObisCode.parse(s["ln"]).to_bytes().hex(), key
        elif key in UNHELD:
            assert s == {**s, "ok": False, "data_access_result": 11}, key
        elif key in PARSE_FAILS:
            assert not s["ok"] and PARSE_FAILS[key] in s["error"], key
            assert s["raw"] == encode_data(held[s["attribute"]]).hex(), key
        elif key == ("0.0.43.1.0.255", 1, 2):
            # The client's invocation counter: it moves on with every request.
            assert s["ok"] and s["raw"].startswith("06"), key
        else:
            assert s["ok"] and s["raw"] == encode_data(held[s["attribute"]]).hex(), key
    entry = next(s for s in steps if s["step"] == "profile-entry")
    profile = meter.objects[(7, ObisCode.parse("1.0.99.1.0.255"))][2]
    from pydlms.cosem.data import DlmsData

    assert entry["raw"] == encode_data(DlmsData.array(profile.value[1:4])).hex()
    # 01:00 to 02:00 UTC, day-of-week 0xFF (not specified): the five rows 01:00,
    # 01:15, 01:30, 01:45 and 02:00 of the 15-minute profile.
    in_range = profile.value[4:9]
    assert [bytes(r.value[0].value)[5:7].hex() for r in in_range] == [
        "0100",
        "010f",
        "011e",
        "012d",
        "0200",
    ]
    assert (
        next(s for s in steps if s["step"] == "profile-range")["raw"]
        == encode_data(DlmsData.array(in_range)).hex()
    )
    assert steps[-1] == {"step": "release", "ok": True}
