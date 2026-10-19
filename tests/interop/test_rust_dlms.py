"""Interop with the Rust DLMS crates.

One image, ``pydlms-interop-rust-dlms`` (``docker build -t pydlms-interop-rust-dlms
tests/interop/rust-dlms``), hosts four roles:

- the default command: a PROTOCOL.md oracle over dlms-cosem-rs 0.1.0 (hupe1980);
- ``push-parser``: a PROTOCOL.md oracle over dlms_cosem 0.2.0 (reitermarkus);
- ``server [--ciphered]``: a dlms-cosem-rs ``Server`` on the TCP wrapper (phase 3);
- ``client HOST:PORT [--ciphered]``: a dlms-cosem-rs ``ClientSession`` run against
  ``pydlms simulate`` (phase 4).

Every outcome other than agree / both-reject / unsupported is listed below with its
verdict and asserted exactly, so a new disagreement (or a fixed one) fails the test.
"""

from __future__ import annotations

import json
import os
import subprocess

import pytest

from tests.interop import compare, corpus
from tests.interop.oracle import Oracle, require_image

pytestmark = pytest.mark.integration

#: ``PYDLMS_RUST_DLMS_IMAGE`` points the tests at another build without
#: retagging the shared image.
IMAGE = os.environ.get("PYDLMS_RUST_DLMS_IMAGE", "pydlms-interop-rust-dlms")
EK = bytes(range(16))
AK = bytes(range(0xD0, 0xE0))
#: Sender system title of the Gurux-generated glo-/ded- vectors in the XML corpus.
GURUX_TITLE = "4142434445464748"

_UNDEFINED_SERVICE_ERROR = (
    "only-pydlms-rejects",
    "ServiceError choice [8] is not in the Green Book ServiceError CHOICE ([0]-[7], task "
    "[9], other-error [10]); pydlms rejects it since 120f85e, dlms-cosem-rs accepts any "
    "choice octet. pydlms follows the ASN.1.",
)
_EXCEPTION_NO_COUNTER = (
    "only-pydlms-rejects",
    "ExceptionResponse service-error invocation-counter-error [6] is IMPLICIT Unsigned32 "
    "(Green Book xDLMS ASN.1), so the 4 counter octets are required; pydlms enforces that "
    "since 7c98299, dlms-cosem-rs reports invocation_counter None. pydlms follows the ASN.1.",
)
_TAGGED_DATE_TIME = (
    "only-oracle-rejects",
    "Kaifa sends the Data-Notification date-time as 09 0c <12 octets> (a Data-typed "
    "octet-string); the Green Book ASN.1 has a bare A-XDR OCTET STRING there, so 09 is "
    "read as a length of 9. dlms-cosem-rs is strict (0 or 12 octets), pydlms tolerates "
    "the vendor form on purpose (date_time_tagged).",
)

#: dlms-cosem-rs: "op:name" -> (outcome, verdict).
KNOWN_COSEM_RS = {
    # Undefined Data-Access-Result / Action-Result values (D1) agree since 286fe74.
    **{f"apdu:cse-8-{v}": _UNDEFINED_SERVICE_ERROR for v in range(8)},
    **{f"apdu:exception-{s}-6": _EXCEPTION_NO_COUNTER for s in range(3)},
    "apdu:hand-28-DataNotification": _TAGGED_DATE_TIME,
    "apdu:notification-tagged-date-time": _TAGGED_DATE_TIME,
    "apdu:capture-hdlc_kaifa_ma304h3e-0": _TAGGED_DATE_TIME,
    "push:hdlc_kaifa_ma304h3e-0": _TAGGED_DATE_TIME,
    "apdu:sn-read-block-number": (
        "disagree",
        "Adapter naming only: the ReadResponse block-number [3] result is kind "
        "'read-result-block-number' there and 'read-result' in pydlms; block_number agrees.",
    ),
    **{
        f"apdu:access-request-{k}-selection": (
            "only-oracle-rejects",
            "ACCESS get/set-with-selection: dlms-cosem-rs reads the access-selection with an "
            "OPTIONAL flag (its AttributeDescriptorWithSelection, as in GET-with-list); the "
            "jDLMS ASN.1 classes, cB-Sigma and pydlms have a plain Selective-Access-Descriptor "
            "there (Green Book clause not read).",
        )
        for k in ("get", "set")
    },
}

#: Adapters built before ACCESS support map only the ACCESS data list, as
#: "values"; such rows are left out of the comparison (rebuild the image).
_OLD_ACCESS_ADAPTER = ".values: pydlms has no such field"

_NO_EMPTY_DATE_TIME = (
    "only-oracle-rejects",
    "dlms_cosem defect: a zero-length Data-Notification date-time (allowed: OCTET STRING, "
    "0 octets = not given) fails DateTime::parse.",
)
_TAG_NOT_STRIPPED = (
    "only-oracle-rejects",
    "dlms_cosem defect: general-glo-ciphering with authentication (SC 0x30) keeps the "
    "12-octet GCM tag in the 'plaintext' (CTR-only decrypt, no tag check), so the "
    "all_consuming APDU parse fails.",
)
#: dlms_cosem (reitermarkus): "op:name" -> (outcome, verdict).
KNOWN_PUSH_PARSER = {
    "data:edge-octets-long-len": (
        "only-oracle-rejects",
        "dlms_cosem defect: A-XDR length read as one octet; 0x82 0x01 0x00 (256) is taken "
        "as 130 and the rest is left over.",
    ),
    "push:hdlc_kaifa_ma304h3e-0": _TAGGED_DATE_TIME,
    "push:hdlc_landis_gyr_e450-0": _TAG_NOT_STRIPPED,
    "push:hdlc_lgz_e450_2-0": _TAG_NOT_STRIPPED,
    "push:hdlc_norway_han_1phase-0": _NO_EMPTY_DATE_TIME,
    "push:hdlc_norway_han_3phase-0": _NO_EMPTY_DATE_TIME,
}

_SHOWN = ("agree", "both-reject", "unsupported")


@pytest.fixture(scope="module")
def image():
    require_image(IMAGE)
    return IMAGE


def _run(*args: str) -> list[dict]:
    oracle = Oracle(IMAGE, *args)
    try:
        return compare.run(oracle)
    finally:
        oracle.close()


def _findings(rows: list[dict]) -> dict[str, str]:
    return {
        f"{r['op']}:{r['name']}": r["outcome"]
        for r in rows
        if r["outcome"] not in _SHOWN and _OLD_ACCESS_ADAPTER not in (r.get("diff") or "")
    }


def test_dlms_cosem_rs_codec_matrix(image):
    rows = _run()
    assert _findings(rows) == {k: v[0] for k, v in KNOWN_COSEM_RS.items()}
    by = {(r["op"], r["outcome"]) for r in rows}
    assert ("data", "agree") in by and ("push", "agree") in by
    data = [r for r in rows if r["op"] == "data"]
    assert len(data) == len(corpus.data_values())
    assert all(r["outcome"] == "agree" for r in data)
    # The only thing it cannot do: build a compact array from values.
    unsupported = [r for r in rows if r["outcome"] == "unsupported"]
    assert unsupported and all(
        r["op"] == "encode-data" and "compact-array" in r["oracle"]["error"] for r in unsupported
    )


def test_push_parser_matrix(image):
    rows = _run("push-parser")
    assert _findings(rows) == {k: v[0] for k, v in KNOWN_PUSH_PARSER.items()}
    assert {r["op"] for r in rows} == {"data", "push"}  # no apdu / encode-data in the crate
    for r in rows:
        if r["outcome"] == "unsupported":
            assert r["oracle"]["error"].startswith("dlms_cosem panics: not implemented")


def _decrypt_vectors():
    from tests.gurux_xml_corpus import build

    return [(r["name"], r["apdu"], *r["keys"]) for r in build() if "keys" in r and r["keys"][1]]


#: name -> expected outcome for `decrypt` (all others: agree).
DECRYPT_KNOWN_COSEM_RS = {
    # ciphered-ded-get agrees since the harness uses the EK as the dedicated key (H3).
    "ciphered-aarq": "both-reject",
    # dlms-cosem-rs refuses general-ciphering / general-signing by name.
    "ciphered-general-ciphering": "unsupported",
    "ciphered-general-signing": "unsupported",
    "ciphered-static-unified": "unsupported",
}


def test_dlms_cosem_rs_decrypt(image):
    oracle = Oracle(IMAGE)
    try:
        got = {
            name: compare.classify(f"decrypt {ek} {ak} {GURUX_TITLE} {apdu}", oracle)["outcome"]
            for name, apdu, ek, ak in _decrypt_vectors()
        }
    finally:
        oracle.close()
    expected = {name: DECRYPT_KNOWN_COSEM_RS.get(name, "agree") for name in got}
    assert got == expected


@pytest.mark.parametrize(
    "name,unauthenticated",
    [
        # Octet 0, the glo- tag, is outside the GCM input (AAD = SC || AK, Green Book
        # 9.2.7.2.4): C8 -> C9 (glo-set-request) still opens, to the unchanged GET
        # plaintext. pydlms's decrypt behaves the same; the inner tag is the check.
        ("ciphered-glo-get", [0]),
        ("ciphered-general-glo", []),
    ],
)
def test_dlms_cosem_rs_rejects_every_tampered_byte(image, name, unauthenticated):
    """Flip each octet of an authenticated+encrypted APDU: no altered plaintext comes back."""
    _, apdu, ek, ak = next(v for v in _decrypt_vectors() if v[0] == name)
    raw = bytes.fromhex(apdu)
    oracle = Oracle(IMAGE)
    try:
        plain = oracle.ask(f"decrypt {ek} {ak} {GURUX_TITLE} {apdu}")["result"]["plaintext"]
        accepted = []
        for i in range(len(raw)):
            bad = bytearray(raw)
            bad[i] ^= 0x01
            reply = oracle.ask(f"decrypt {ek} {ak} {GURUX_TITLE} {bad.hex()}")
            if reply["ok"]:
                assert reply["result"]["plaintext"] == plain
                accepted.append(i)
    finally:
        oracle.close()
    assert accepted == unauthenticated


def test_push_parser_does_not_verify_the_gcm_tag(image):
    """dlms_cosem 0.2.0 defect, pinned: a frame with a corrupted tag still 'decrypts'."""
    _, apdu, ek, ak = next(v for v in _decrypt_vectors() if v[0] == "ciphered-general-glo")
    bad = bytearray.fromhex(apdu)
    bad[-1] ^= 0xFF  # last octet of the GCM tag
    oracle = Oracle(IMAGE, "push-parser")
    try:
        reply = oracle.ask(f"decrypt {ek} {ak} {GURUX_TITLE} {bad.hex()}")
    finally:
        oracle.close()
    assert reply["ok"]
    plain = reply["result"]["plaintext"]
    # The real plaintext, followed by the 12 tag octets run through the key stream.
    assert plain.startswith("c001c100030100010800ff0200") and len(plain) == 2 * (13 + 12)


# --- phase 3: pydlms DlmsClient against the dlms-cosem-rs Server ------------------------


def _security(ic: int = 0, ak: bytes = AK):
    pytest.importorskip("cryptography")
    from pydlms.security.context import SecurityContext

    return SecurityContext(EK, ak, client_system_title=b"PYDLMS01", invocation_counter=ic)


#: Association LN version 1 has 9 attributes (Blue Book 4.4.3); the server does not
#: implement 7 (secret, write-only) and 9 (security_setup_reference). Since bd1749f
#: pydlms describes class 15 v1 by its own layout and no longer asks for 10/11 (P2).
SWEEP_ERRORS = {f"0.0.40.0.0.255/15/{a}" for a in (7, 9)}


def _check_sweep(report: dict) -> None:
    assert report["objects"] == 7
    assert set(report["errors"]) == SWEEP_ERRORS
    assert all("OBJECT_UNDEFINED" in e for e in report["errors"].values())
    values = report["values"]
    assert values["1.0.1.8.0.255/3/2"] == {"t": "double-long-unsigned", "v": 12345678}
    assert values["1.0.1.8.0.255/3/3"]["v"] == [
        {"t": "integer", "v": 0},
        {"t": "enum", "v": 30},
    ]
    assert values["0.0.96.1.0.255/1/2"] == {"t": "visible-string", "v": "RST0000000001"}
    assert values["0.0.1.0.0.255/8/2"] == {"t": "octet-string", "v": "07e80501030c000000ff8880"}
    rows = values["1.0.99.1.0.255/7/2"]["v"]  # ~2 KiB: block transfer from the server
    assert len(rows) == 96 and rows[1]["v"][1] == {"t": "double-long-unsigned", "v": 1007}


def test_sweep_dlms_cosem_rs_server_public(image):
    from pydlms.client import DlmsClient
    from tests.interop.server import running, sweep

    with running(IMAGE, "server", ready="listening") as (host, port):
        with DlmsClient.tcp(host, port, timeout=10) as meter:
            _check_sweep(sweep(meter))


def test_sweep_dlms_cosem_rs_server_hls_gmac_ciphered(image):
    from pydlms.client import DlmsClient
    from pydlms.exceptions import AssociationError, InvocationCounterError
    from pydlms.security.hls import Mechanism
    from tests.interop.server import running, sweep

    gmac = {"client_sap": 1, "mechanism": Mechanism.HLS_GMAC, "timeout": 10}
    with running(IMAGE, "server", "--ciphered", ready="listening") as (host, port):
        security = _security()
        with DlmsClient.tcp(host, port, security=security, **gmac) as meter:
            _check_sweep(sweep(meter))
        assert security.server_system_title == b"RST\x00\x00\x00\x00\x01"
        assert security.invocation_counter > 40  # every GET went out ciphered

        # The server keeps the replay window across associations: a restarted counter is
        # refused at the AARQ with invocation-counter-error, and pydlms's retry recovers.
        stale = DlmsClient.tcp(host, port, security=_security(), **gmac)
        with pytest.raises(InvocationCounterError):
            stale.connect()
        stale.link.disconnect()
        retry = _security()
        with DlmsClient.tcp(
            host, port, security=retry, invocation_counter_retry=True, **gmac
        ) as meter:
            assert meter.get("1.0.1.8.0.255", 3, 2).value == 12345678

        wrong = DlmsClient.tcp(host, port, security=_security(10_000, bytes(16)), **gmac)
        with pytest.raises(AssociationError, match="AUTHENTICATION_FAILURE"):
            wrong.connect()
        wrong.link.disconnect()


# --- phase 4: the dlms-cosem-rs ClientSession against pydlms simulate --------------------


def _client_report(*flags: str) -> dict:
    from pydlms.security.hls import Mechanism
    from pydlms.simulator import ClientProfile, example_meter, serve

    if "--ciphered" in flags:
        sim = example_meter(encryption_key=EK, authentication_key=AK)
        sim.clients[1] = ClientProfile(Mechanism.HLS_GMAC, ciphered=True)
    else:
        sim = example_meter()
    server = serve(sim, host="127.0.0.1", port=0)
    try:
        port = server.server_address[1]
        proc = subprocess.run(  # noqa: S603,S607 - fixed docker argv, test-only
            ["docker", "run", "--rm", "--network", "host", IMAGE, "client", f"127.0.0.1:{port}"]
            + list(flags),
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    finally:
        server.shutdown()
        server.server_close()
    assert proc.stdout, proc.stderr[-2000:]
    return json.loads(proc.stdout)


def _check_client(report: dict) -> None:
    assert report["associate"] == "Established", report
    assert report["get_with_list"] == [
        {"t": "double-long-unsigned", "v": 12345678},
        {"t": "long-unsigned", "v": 4321},
        {"t": "long-unsigned", "v": 1520},
    ]
    assert "1.0.99.1.0.255/7/0" in report["object_list"]
    reads = report["reads"]
    assert reads["0.0.96.1.0.255/1/2"] == {"t": "visible-string", "v": "PYD0000000001"}
    assert reads["1.0.32.7.0.255/3/3"]["v"] == [{"t": "integer", "v": -1}, {"t": "enum", "v": 35}]
    assert report["profile_all"]["rows"] == 96 and report["profile_all"]["blocks"] > 1
    assert report["profile_entries_1_10"]["rows"] == 10
    assert report["profile_entries_1_10"]["last"]["v"][1]["v"] == 1000 + 9 * 7
    assert report["action"].startswith("ActionResult { result: Success")
    assert report["breaker_after"] == {"t": "boolean", "v": False}
    assert report["release"] == "Released"


def test_dlms_cosem_rs_client_reads_pydlms_simulate(image):
    _check_client(_client_report())


def test_dlms_cosem_rs_client_hls_gmac_ciphered_reads_pydlms_simulate(image):
    report = _client_report("--ciphered")
    _check_client(report)
    assert report["server_system_title"] == b"PYD\x00\x00\x00\x00\x01".hex()
