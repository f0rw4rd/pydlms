"""dlms-cosem (pwitab, last MIT commit 0747b15) as an interop oracle.

Phase 2 (codec differential over tests/interop/corpus.py), the decipher
check, a few targeted probes, and phase 4 (dlms-cosem's TCP client reading
the pydlms simulator).

Build: docker build -t pydlms-interop-dlms-cosem tests/interop/dlms-cosem
Run:   pytest -m integration tests/interop/test_dlms_cosem.py
"""

from __future__ import annotations

import json
import subprocess
from collections import Counter

import pytest

from tests.interop import compare, corpus
from tests.interop.model import data_json
from tests.interop.oracle import Oracle, require_image

pytestmark = pytest.mark.integration

IMAGE = "pydlms-interop-dlms-cosem"

# --- why each item differs; verdicts and Green/Blue Book cites in the findings doc ---
DATETIME = (
    "dlms-cosem keeps date-time as a Python datetime: day-of-week, 0xFF (not specified) "
    "hundredths and the clock status do not survive (Blue Book 4.1.6.1); pydlms keeps octets"
)
VISIBLE = "visible-string octet 0xE9: dlms-cosem decodes ASCII only, pydlms latin-1 by design"
ARRAY_ENC = (
    "dlms-cosem DataArray.to_bytes appends bytes to a bytearray (TypeError; upstream a1107ba)"
)
BITS_ENC = "dlms-cosem writes the bit-string length in octets; A-XDR counts bits"
LEN_ENC = "dlms-cosem writes a length as one octet (no 0x8N long form): 256 overflows"
ENUM = "code undefined in the Green Book ENUMERATED: dlms-cosem's IntEnum rejects the APDU"
EXC_IC = (
    "ExceptionResponse service-error 6 without its mandatory Unsigned32: dlms-cosem invents 0, "
    "pydlms rejects it (fixed in 7c98299)"
)
CSE_SCOPE = (
    "ServiceError choice [8] (change-scope) is not used by DLMS: pydlms rejects it "
    "(120f85e), dlms-cosem reads it as DataScopeError"
)
CSE_SERVICE = "ConfirmedServiceError service [10]: dlms-cosem knows only initiate/read/write"
CONF = "reserved or SN conformance bit: dlms-cosem's Conformance (LN only) drops it"
QOS_ABSENT = "absent quality-of-service: dlms-cosem reports 0 instead of absent"
QOS_PRESENT = "present quality-of-service: dlms-cosem's positional InitiateRequest parser fails"
SN_VAA = "InitiateResponse vaa-name 0xFA00 (SN): dlms-cosem accepts only 0x0007"
RELEASE_EMPTY = "RLRQ/RLRE with no fields (all OPTIONAL): dlms-cosem IndexError"
CLASS_ID = "class_id not in dlms-cosem's CosemInterface enum rejects the whole APDU"
DN_TAGGED = (
    "DataNotification date-time sent Data-tagged (09 0C, Kaifa): dlms-cosem reads the first "
    "octet as a presence flag and misparses; pydlms accepts it deliberately"
)
ENC_ONLY = "security control without authentication (no GCM tag, no AK): dlms-cosem cannot decipher"

KNOWN = {
    "data:hand-03-GetResponseNormal#11": ("disagree", DATETIME),
    "data:data-visible-latin1#0": ("only-oracle-rejects", VISIBLE),
    "encode-data:session-06-RX#0": ("only-oracle-rejects", ARRAY_ENC),
    # Since the simulator lists real access rights the object list spans
    # datablocks, so the empty array is first seen in the hand corpus.
    "encode-data:data-array-empty#0": ("only-oracle-rejects", ARRAY_ENC),
    # the two arrays of the Table F.10 ACCESS request
    "encode-data:access-f10-request#2": ("only-oracle-rejects", ARRAY_ENC),
    "encode-data:access-f10-request#19": ("only-oracle-rejects", ARRAY_ENC),
    "encode-data:hand-03-GetResponseNormal#3": ("disagree", BITS_ENC),
    "encode-data:hand-03-GetResponseNormal#15": ("only-oracle-rejects", ARRAY_ENC),
    "encode-data:data-visible-latin1#0": ("only-oracle-rejects", VISIBLE),
    "encode-data:data-bits-9#0": ("disagree", BITS_ENC),
    "encode-data:data-array-300#0": ("only-oracle-rejects", ARRAY_ENC),
    "encode-data:data-nested#0": ("only-oracle-rejects", ARRAY_ENC),
    "encode-data:capture-hdlc_landis_gyr_e450_cyprus-0#0": ("only-oracle-rejects", ARRAY_ENC),
    "encode-data:capture-hdlc_landis_gyr_e450_cyprus-0#1": ("only-oracle-rejects", ARRAY_ENC),
    "encode-data:capture-hdlc_landis_gyr_e450_cyprus_2-0#0": ("only-oracle-rejects", ARRAY_ENC),
    "encode-data:capture-hdlc_landis_gyr_e450_cyprus_2-0#1": ("only-oracle-rejects", ARRAY_ENC),
    "encode-data:capture-hdlc_norway_han_1phase-0#0": ("only-oracle-rejects", ARRAY_ENC),
    "encode-data:capture-hdlc_norway_han_3phase-0#0": ("only-oracle-rejects", ARRAY_ENC),
    "encode-data:capture-raw_energomera-0#0": ("only-oracle-rejects", ARRAY_ENC),
    "encode-data:capture-raw_energomera-0#1": ("only-oracle-rejects", ARRAY_ENC),
    "encode-data:edge-bits-12": ("disagree", BITS_ENC),
    "encode-data:edge-octets-long-len": ("only-oracle-rejects", LEN_ENC),
    "encode-data:edge-array-long-len": ("only-oracle-rejects", ARRAY_ENC),
    "apdu:hand-28-DataNotification": ("only-oracle-rejects", DN_TAGGED),
    "apdu:hand-33-InitiateRequest": ("disagree", QOS_ABSENT),
    "apdu:set-result-5": ("only-oracle-rejects", ENUM),
    "apdu:action-result-5": ("only-oracle-rejects", ENUM),
    "apdu:set-result-6": ("only-oracle-rejects", ENUM),
    "apdu:action-result-6": ("only-oracle-rejects", ENUM),
    "apdu:set-result-7": ("only-oracle-rejects", ENUM),
    "apdu:action-result-7": ("only-oracle-rejects", ENUM),
    "apdu:set-result-8": ("only-oracle-rejects", ENUM),
    "apdu:action-result-8": ("only-oracle-rejects", ENUM),
    "apdu:set-result-10": ("only-oracle-rejects", ENUM),
    "apdu:action-result-10": ("only-oracle-rejects", ENUM),
    "apdu:action-result-17": ("only-oracle-rejects", ENUM),
    "apdu:action-result-18": ("only-oracle-rejects", ENUM),
    "apdu:action-result-19": ("only-oracle-rejects", ENUM),
    "apdu:exception-0-0": ("only-oracle-rejects", ENUM),
    "apdu:exception-0-1": ("only-oracle-rejects", ENUM),
    "apdu:exception-0-2": ("only-oracle-rejects", ENUM),
    "apdu:exception-0-3": ("only-oracle-rejects", ENUM),
    "apdu:exception-0-4": ("only-oracle-rejects", ENUM),
    "apdu:exception-0-5": ("only-oracle-rejects", ENUM),
    "apdu:exception-0-7": ("only-oracle-rejects", ENUM),
    "apdu:exception-1-0": ("only-oracle-rejects", ENUM),
    "apdu:exception-1-6": ("only-pydlms-rejects", EXC_IC),
    "apdu:exception-1-7": ("only-oracle-rejects", ENUM),
    "apdu:exception-2-0": ("only-oracle-rejects", ENUM),
    "apdu:exception-2-6": ("only-pydlms-rejects", EXC_IC),
    "apdu:exception-2-7": ("only-oracle-rejects", ENUM),
    "apdu:cse-0-7": ("only-oracle-rejects", ENUM),
    "apdu:cse-1-5": ("only-oracle-rejects", ENUM),
    "apdu:cse-1-6": ("only-oracle-rejects", ENUM),
    "apdu:cse-1-7": ("only-oracle-rejects", ENUM),
    "apdu:cse-2-5": ("only-oracle-rejects", ENUM),
    "apdu:cse-2-6": ("only-oracle-rejects", ENUM),
    "apdu:cse-2-7": ("only-oracle-rejects", ENUM),
    "apdu:cse-3-3": ("only-oracle-rejects", ENUM),
    "apdu:cse-3-4": ("only-oracle-rejects", ENUM),
    "apdu:cse-3-5": ("only-oracle-rejects", ENUM),
    "apdu:cse-3-6": ("only-oracle-rejects", ENUM),
    "apdu:cse-3-7": ("only-oracle-rejects", ENUM),
    "apdu:cse-4-4": ("only-oracle-rejects", ENUM),
    "apdu:cse-4-5": ("only-oracle-rejects", ENUM),
    "apdu:cse-4-6": ("only-oracle-rejects", ENUM),
    "apdu:cse-4-7": ("only-oracle-rejects", ENUM),
    "apdu:cse-5-5": ("only-oracle-rejects", ENUM),
    "apdu:cse-5-6": ("only-oracle-rejects", ENUM),
    "apdu:cse-5-7": ("only-oracle-rejects", ENUM),
    "apdu:cse-6-5": ("only-oracle-rejects", ENUM),
    "apdu:cse-6-6": ("only-oracle-rejects", ENUM),
    "apdu:cse-6-7": ("only-oracle-rejects", ENUM),
    "apdu:cse-8-0": ("only-pydlms-rejects", CSE_SCOPE),
    "apdu:cse-service-10": ("only-oracle-rejects", CSE_SERVICE),
    "apdu:conformance-5": ("disagree", CONF),
    "apdu:conformance-8": ("disagree", CONF),
    "apdu:conformance-16": ("disagree", CONF),
    "apdu:conformance-18": ("disagree", CONF),
    "apdu:conformance-19": ("disagree", CONF),
    "apdu:conformance-20": ("disagree", CONF),
    "apdu:conformance-23": ("disagree", CONF),
    "apdu:aare-0-1-15": ("only-oracle-rejects", ENUM),
    "apdu:aare-1-1-15": ("only-oracle-rejects", ENUM),
    "apdu:aare-2-1-15": ("only-oracle-rejects", ENUM),
    "apdu:aarq-qos": ("only-oracle-rejects", QOS_PRESENT),
    "apdu:aare-sn": ("only-oracle-rejects", SN_VAA),
    "apdu:rlrq-None": ("only-oracle-rejects", RELEASE_EMPTY),
    "apdu:rlre-None": ("only-oracle-rejects", RELEASE_EMPTY),
    "apdu:data-visible-latin1": ("only-oracle-rejects", VISIBLE),
    "apdu:data-date-time": ("disagree", DATETIME),
    "apdu:get-class-attribute-edge": ("only-oracle-rejects", CLASS_ID),
    "apdu:notification-date-time": ("disagree", DATETIME),
    "apdu:notification-tagged-date-time": ("only-oracle-rejects", DN_TAGGED),
    "apdu:initiate-no-response": ("disagree", QOS_ABSENT),
    "apdu:initiate-qos": ("only-oracle-rejects", QOS_PRESENT),
    "apdu:initiate-dedicated-key": ("disagree", QOS_ABSENT),
    "apdu:capture-hdlc_iskra550-0": ("disagree", DATETIME),
    "apdu:capture-hdlc_kaifa_ma304h3e-0": ("only-oracle-rejects", DN_TAGGED),
    "apdu:capture-hdlc_landis_gyr_e450_cyprus-0": ("disagree", DATETIME),
    "apdu:capture-hdlc_landis_gyr_e450_cyprus_2-0": ("disagree", DATETIME),
    "apdu:capture-raw_energomera-0": ("disagree", DATETIME),
    "apdu:capture-raw_salzburg_netz-0": ("disagree", DATETIME),
    "push:hdlc_iskra550-0": ("disagree", DATETIME),
    "push:hdlc_kaifa_ma304h3e-0": ("only-oracle-rejects", DN_TAGGED),
    "push:hdlc_kamstrup_omnipower-0": ("disagree", DATETIME),
    "push:hdlc_landis_gyr_e450-0": ("disagree", DATETIME),
    "push:hdlc_landis_gyr_e450_cyprus-0": ("disagree", DATETIME),
    "push:hdlc_landis_gyr_e450_cyprus_2-0": ("disagree", DATETIME),
    "push:hdlc_lgz_e450_2-0": ("disagree", DATETIME),
    "push:mbus_netz_noe_p1-0": ("only-oracle-rejects", ENC_ONLY),
    "push:raw_energomera-0": ("disagree", DATETIME),
    "push:raw_salzburg_netz-0": ("disagree", DATETIME),
}

COUNTS = {
    # ACCESS support added 9 ACCESS APDUs: their 19 data values, 17 more
    # encodings agree (2 hit ARRAY_ENC), and dlms-cosem has no ACCESS APDU
    # (9 more unsupported).
    "data": {"agree": 599, "unsupported": 21, "disagree": 1, "only-oracle-rejects": 1},
    "encode-data": {"agree": 569, "unsupported": 32, "disagree": 3, "only-oracle-rejects": 18},
    "apdu": {
        "agree": 259,
        "unsupported": 60,
        "disagree": 17,
        "only-oracle-rejects": 60,
        "only-pydlms-rejects": 3,
        "both-reject": 11,
    },
    "push": {"agree": 2, "disagree": 8, "only-oracle-rejects": 2, "both-reject": 4},
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


def test_hello_pins_the_mit_commit(oracle):
    assert oracle.hello["library"] == "dlms-cosem"
    assert oracle.hello["version"] == "21.3.2+0747b15"


def test_every_disagreement_is_known(rows):
    found = {
        f"{r['op']}:{r['name']}": r["outcome"]
        for r in rows
        if r["outcome"] not in ("agree", "both-reject", "unsupported")
    }
    assert found == {key: outcome for key, (outcome, _) in KNOWN.items()}


def test_outcome_counts(rows):
    counts: dict = {}
    for (op, outcome), n in Counter((r["op"], r["outcome"]) for r in rows).items():
        counts.setdefault(op, {})[outcome] = n
    assert counts == COUNTS


def test_push_bodies_all_agree(rows):
    """date_time is lossy in dlms-cosem; every push it can decipher has the same body."""
    for r in rows:
        if r["op"] == "push" and r["pydlms"]["ok"] and r["oracle"]["ok"]:
            assert r["oracle"]["result"]["body"] == r["pydlms"]["result"]["body"], r["name"]


def _decrypt_lines():
    from tests.gurux_xml_corpus import build

    out = [(r["name"], *r["keys"], r["apdu"]) for r in build() if "keys" in r]
    out += [(n, ek, ak, h) for n, h, ek, ak in corpus.pushes() if ek]
    # The title argument is unused for general-glo (it carries its own); an empty AK
    # is passed as zeros so the encryption-only frames reach the decipher step.
    return [(n, f"decrypt {ek} {ak or '00' * 16} {'00' * 8} {h}") for n, ek, ak, h in out]


DECRYPT = {
    "ciphered-general-glo": "agree",
    "capture-hdlc_kamstrup_omnipower-0": "agree",
    "capture-hdlc_landis_gyr_e450-0": "agree",
    "capture-hdlc_lgz_e450_2-0": "agree",
    "hdlc_kamstrup_omnipower-0": "agree",
    "hdlc_landis_gyr_e450-0": "agree",
    "hdlc_lgz_e450_2-0": "agree",
    # ENC_ONLY: SC 0x21 / 0x20, no authentication tag on the wire.
    "capture-mbus_kaifa_ma309m-0": "only-oracle-rejects",
    "capture-mbus_netz_noe_p1-0": "only-oracle-rejects",
    "mbus_kaifa_ma309m-0": "only-oracle-rejects",
    "mbus_netz_noe_p1-0": "only-oracle-rejects",
}


def test_decrypt(oracle):
    got = {name: compare.classify(line, oracle)["outcome"] for name, line in _decrypt_lines()}
    # glo-/ded-/general-ciphering/-signing and ciphered AARQ: dlms-cosem has no decoder.
    assert got == {name: DECRYPT.get(name, "unsupported") for name in got}


# dlms-cosem defects that the corpus (valid values only) does not reach.
PROBES = {
    # A-XDR value shorter than its type: dlms-cosem fills in instead of rejecting.
    "data 0f": "only-pydlms-rejects",
    "data 12ff": "only-pydlms-rejects",
    "data 0905aabb": "only-pydlms-rejects",
    "data 0104110111": "only-pydlms-rejects",  # missing elements become null-data
    "apdu c401c1000600bc": "only-pydlms-rejects",
    # A trailing octet after a complete APDU is ignored.
    "apdu c401c1000600bc614eff": "only-pydlms-rejects",
    "apdu 0e01060100": "only-pydlms-rejects",
    # A-XDR long-form length 0x81 C8: dlms-cosem writes C8.
    "encode-data " + json.dumps({"t": "octet-string", "v": "ab" * 200}): "disagree",
}


def test_probes(oracle):
    assert {line: compare.classify(line, oracle)["outcome"] for line in PROBES} == PROBES


# --- phase 4: dlms-cosem's client against pydlms simulate ------------------------------

EK = "000102030405060708090a0b0c0d0e0f"
AK = "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"


def _reverse(*args: str):
    from pydlms.security.hls import Mechanism
    from pydlms.simulator import ClientProfile, example_meter, serve

    keys = {}
    if args and args[0] == "gmac":
        keys = {"encryption_key": bytes.fromhex(EK), "authentication_key": bytes.fromhex(AK)}
    meter = example_meter(**keys)
    if keys:
        meter.clients[1] = ClientProfile(Mechanism.HLS_GMAC, ciphered=True)
    server = serve(meter, "127.0.0.1", 0)
    try:
        port = server.server_address[1]
        out = subprocess.run(  # noqa: S603,S607 - fixed docker argv, test-only
            ["docker", "run", "--rm", "--network", "host", "--entrypoint", "python", IMAGE, "-I"]
            + ["/opt/oracle/client_reverse.py", "127.0.0.1", str(port), *args],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    finally:
        server.shutdown()
        server.server_close()
    steps = {}
    for line in out.stdout.splitlines():
        obj = json.loads(line)
        steps[obj.pop("step")] = obj
    return meter, steps


def _expected(meter) -> dict:
    from pydlms.cosem.interface_classes import ClassId
    from pydlms.obis import ObisCode

    def value(cid, obis, attr):
        return data_json(meter.objects[(cid, ObisCode.parse(obis))][attr])

    return {
        "register-value": value(ClassId.REGISTER, "1.0.1.8.0.255", 2),
        "register-scaler-unit": value(ClassId.REGISTER, "1.0.1.8.0.255", 3),
        "clock": value(ClassId.CLOCK, "0.0.1.0.0.255", 2),
        "profile-all": value(ClassId.PROFILE_GENERIC, "1.0.99.1.0.255", 2),
    }


def _check_session(meter, steps, mechanism):
    assert steps["associate"]["ok"] and steps["associate"]["result"] == 0, steps
    assert steps["associate"]["mechanism"] == mechanism
    expected = _expected(meter)
    # Range 00:00 to 01:00 UTC with day-of-week 0xFF: the first five 15-minute rows,
    # both bounds inclusive (empty before 7aea433 compared the bounds as instants).
    expected["profile-range"] = {"t": "array", "v": expected["profile-all"]["v"][:5]}
    for step, want in expected.items():
        assert steps[step]["ok"], (step, steps[step])
        assert steps[step]["value"] == want, step
    assert len(steps["profile-all"]["value"]["v"]) == 96
    assert steps["release"] == {"ok": True, "reason": 0}


def test_reverse_no_security(oracle):
    meter, steps = _reverse("none")
    _check_session(meter, steps, None)


def test_reverse_hls_gmac_rejects_first_server_ic_zero(oracle):
    """dlms-cosem's default "last seen" meter IC is 0 and it demands IC > last seen,
    so it refuses the simulator's first ciphered response (IC 0)."""
    _, steps = _reverse("gmac", EK, AK)
    assert steps["associate"]["ok"] is False
    assert "invocation counter is not larger" in steps["associate"]["error"]


def test_reverse_hls_gmac(oracle):
    meter, steps = _reverse("gmac", EK, AK, "-1")
    _check_session(meter, steps, 5)
    assert steps["associate"]["server_system_title"] == meter.system_title.hex()
