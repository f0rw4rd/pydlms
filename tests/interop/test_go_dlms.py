"""github.com/cB-Sigma/dlms (Go) against pydlms: codec oracle, its server, its client.

Image: ``docker build -t pydlms-interop-go-dlms tests/interop/go-dlms`` (commit
pinned in the Dockerfile). Findings and the spec argument for every entry
below.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess

import pytest

from tests.interop import compare
from tests.interop.oracle import Oracle, require_image

pytestmark = pytest.mark.integration
IMAGE = "pydlms-interop-go-dlms"

#: Every corpus row that is not agree/both-reject/unsupported: (outcome, reason).
KNOWN = {
    # gosem keeps date/time/date-time only as a Go time.Time: wildcards,
    # "deviation not specified" and the clock status are lost, the weekday
    # is recomputed (IEC 62056-6-2 4.1.6.1 date and time formats).
    "data/hand-03-GetResponseNormal#0": ("disagree", "gosem date-time loses ff/8000/status"),
    "data/hand-03-GetResponseNormal#11": ("disagree", "gosem date-time loses ff/8000/status"),
    "data/hand-03-GetResponseNormal#12": ("disagree", "gosem date: day-of-week ff recomputed"),
    "encode-data/hand-03-GetResponseNormal#11": ("disagree", "gosem date-time round trip"),
    "encode-data/hand-03-GetResponseNormal#12": ("disagree", "gosem date round trip"),
    "apdu/hand-03-GetResponseNormal": ("disagree", "gosem date-time loses ff/8000/status"),
    "apdu/data-date-time": ("disagree", "gosem date-time loses ff/8000/status"),
    # compact-array with an array type-description (Blue Book 4.1.5
    # TypeDescription array): gosem reads only simple types and structures.
    "data/data-compact-array#0": ("only-oracle-rejects", "gosem: array type-description"),
    "apdu/data-compact-array": ("only-oracle-rejects", "gosem: array type-description"),
    # visible-string is ISO 646: gosem refuses octets > 0x7F on encode,
    # pydlms writes them latin-1 (deliberate, lossless).
    "encode-data/data-visible-latin1#0": ("only-oracle-rejects", "visible-string > 0x7F"),
    # gosem DecodeAttributeDescriptorWithSelection wants 11 octets; an item
    # without selective access is 10 (off by one).
    "apdu/session-19-TX": ("only-oracle-rejects", "gosem with-list descriptor off by one"),
    "apdu/hand-02-GetRequestWithList": ("only-oracle-rejects", "gosem with-list off by one"),
    # DataBlock-SA raw-data is an A-XDR octet string: gosem reads a one-octet
    # length, so 81 e0 (224) is read as 129.
    "apdu/session-22-RX": ("only-oracle-rejects", "gosem DataBlock-SA one-octet length"),
    "apdu/session-24-RX": ("only-oracle-rejects", "gosem DataBlock-SA one-octet length"),
    "apdu/session-26-RX": ("only-oracle-rejects", "gosem DataBlock-SA one-octet length"),
    # date-time of a DataNotification is an OCTET STRING (length 0 or 12);
    # 09 0c ... is the tagged form some meters send. gosem's xDLMS decoder
    # is strict; the library's own push decoder tolerates it.
    "apdu/hand-28-DataNotification": ("only-oracle-rejects", "tagged date-time (09 0c)"),
    "apdu/notification-tagged-date-time": ("only-oracle-rejects", "tagged date-time (09 0c)"),
    "apdu/capture-hdlc_kaifa_ma304h3e-0": ("only-oracle-rejects", "tagged date-time (09 0c)"),
    # invocation-counter-error carries the expected IC (Unsigned32); gosem
    # reads state and service only and leaves 4 octets.
    "apdu/hand-30-ExceptionResponse": ("only-oracle-rejects", "gosem ignores the IC"),
    "apdu/exception-ic": ("only-oracle-rejects", "gosem ignores the IC"),
    # ... and so accepts invocation-counter-error without its Unsigned32,
    # which pydlms refuses as truncated since 7c98299.
    **{
        f"apdu/exception-{state}-6": ("only-pydlms-rejects", "IC-error without its IC")
        for state in (0, 1, 2)
    },
    # ServiceError [8] (change-scope) is commented out of the Green Book
    # ASN.1; gosem accepts it, pydlms refuses it since 120f85e.
    **{
        f"apdu/cse-8-{n}": ("only-pydlms-rejects", "ServiceError choice 8 undefined")
        for n in range(8)
    },
    # Data-Access-Result / Action-Result values the enumerations do not
    # define (5-8, 10; actions also 17-19): gosem refuses, pydlms keeps them.
    **{
        f"apdu/{kind}-result-{n}": ("only-oracle-rejects", "undefined result enumeration value")
        for kind, numbers in (("set", (5, 6, 7, 8, 10)), ("action", (5, 6, 7, 8, 10, 17, 18, 19)))
        for n in numbers
    },
    # Damaged or non-standard captures: gosem turns an unknown tag into
    # null-data without consuming it and the library's push decoder ignores
    # the octets left over, so garbage is accepted.
    "push/hdlc_landis_gyr_zmf100-0": ("only-pydlms-rejects", "damaged capture accepted"),
    "push/mbus_kaifa_ma309m-0": ("only-pydlms-rejects", "damaged capture accepted"),
    "push/raw_egd_example-0": ("only-pydlms-rejects", "unknown tag 0x2a read as null"),
    "push/raw_sagemcom_xt211-0": ("only-pydlms-rejects", "unknown tag 0x60 read as null"),
}

#: What the library has no decoder for (adapter answers "unsupported").
UNSUPPORTED = {
    "encode-data": "compact-array (gosem: not yet implemented)",
    "apdu": "short-name services, InformationReport, RLRQ, general-block-transfer",
}

#: Extra lines outside the corpus: line -> (outcome, reason).
PROBES = {
    # weekday: gosem EncodeDate writes Go's Sunday 0 (DLMS: 1..7, 7 Sunday).
    "data 1a07e80107ff": ("disagree", "gosem date: Sunday written as 00"),
    "data 1b0c0000ff": ("disagree", "gosem time: hundredths ff written as 00"),
    # A-XDR length 0x80 is not a definite length; gosem reads it as 128.
    "data 0980" + "00" * 128: ("only-pydlms-rejects", "gosem: length 0x80 read as 128"),
    # unknown tag 08 inside a push body: null-data, octet not consumed.
    "push 0f0000000100020108": ("only-pydlms-rejects", "unknown tag read as null-data"),
    "data 020108": ("both-reject", "adapter trailing-octet check catches it"),
    # bcd [13] IMPLICIT Integer8: gosem signed, pydlms the raw octet.
    "data 0d99": ("disagree", "bcd representation (-103 vs 153)"),
    # An IC after service error 1: neither reads it (pydlms only for error 6
    # since 7c98299), so both leave 4 octets.
    "apdu d80101000004d2": ("both-reject", "no IC after service error 1"),
    "data 098100": ("agree", "two-octet length form"),
    # glo-get-response, IEC 62056-5-3:2023 Table 30 glo-get-request (all
    # three policies), and a tampered tag.
    "decrypt 000102030405060708090a0b0c0d0e0f d0d1d2d3d4d5d6d7d8d9dadbdcdddedf "
    "474f444c4d533031 cc1a3000000005c3be35295d742c72746fa36bfddfffee04ded4307b": (
        "agree",
        "glo-get-response",
    ),
    "decrypt 000102030405060708090a0b0c0d0e0f d0d1d2d3d4d5d6d7d8d9dadbdcdddedf "
    "474f444c4d533031 cc1a3000000005c3be35295d742c72746fa36bfddfffee04ded4307c": (
        "both-reject",
        "tampered tag",
    ),
    "decrypt 000102030405060708090a0b0c0d0e0f d0d1d2d3d4d5d6d7d8d9dadbdcdddedf "
    "4d4d4d0000bc614e c81e3001234567411312ff935a47566827c467bc7d825c3be4a77c3fcc056b6b": (
        "agree",
        "Table 30 auth+enc",
    ),
    "decrypt 000102030405060708090a0b0c0d0e0f d0d1d2d3d4d5d6d7d8d9dadbdcdddedf "
    "4d4d4d0000bc614e c81e1001234567c0010000080000010000ff020006725d910f9221d263877516": (
        "agree",
        "Table 30 auth only",
    ),
    "decrypt 000102030405060708090a0b0c0d0e0f d0d1d2d3d4d5d6d7d8d9dadbdcdddedf "
    "4d4d4d0000bc614e c8122001234567411312ff935a47566827c467bc": ("agree", "Table 30 enc only"),
}


@pytest.fixture(scope="module")
def oracle():
    require_image(IMAGE)
    o = Oracle(IMAGE)
    yield o
    o.close()


def test_hello(oracle):
    assert oracle.hello["ok"]
    assert oracle.hello["version"].startswith("26360a13e5d8f1da0fba1758118adaaa00be2ccf")


def test_corpus_disagreements_are_the_known_ones(oracle):
    rows = compare.run(oracle)
    odd = {
        f"{r['op']}/{r['name']}": r["outcome"]
        for r in rows
        if r["outcome"] not in ("agree", "both-reject", "unsupported")
    }
    assert odd == {name: outcome for name, (outcome, _) in KNOWN.items()}
    unsupported_ops = {r["op"] for r in rows if r["outcome"] == "unsupported"}
    assert unsupported_ops == set(UNSUPPORTED)
    assert sum(r["outcome"] == "agree" for r in rows) > 1500


@pytest.mark.parametrize("line", list(PROBES), ids=[reason for _, reason in PROBES.values()])
def test_probe(oracle, line):
    assert compare.classify(line, oracle)["outcome"] == PROBES[line][0]


# --- phase 3: its server, read by pydlms --------------------------------------------------

EK16 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
AK16 = bytes.fromhex("d0d1d2d3d4d5d6d7d8d9dadbdcdddedf")
EK32 = bytes(range(32))
AK32 = bytes.fromhex("d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef")
HLS_SECRET = b"0123456789ABCDEF"
_ORDER = {
    1: 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    2: int(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
        16,
    ),
}


def ec_key(label: str, suite: int):
    """The fixed test keys of adapter/main.go testKey (d = H(label) mod (n-1) + 1)."""
    from cryptography.hazmat.primitives.asymmetric import ec

    digest = (hashlib.sha384 if suite == 2 else hashlib.sha256)(label.encode()).digest()
    curve = ec.SECP384R1() if suite == 2 else ec.SECP256R1()
    return ec.derive_private_key(int.from_bytes(digest, "big") % (_ORDER[suite] - 1) + 1, curve)


def security(suite: int, **kw):
    from pydlms.security.context import SecurityContext

    ek, ak = (EK32, AK32) if suite == 2 else (EK16, AK16)
    extra = {"master_key": bytes([0x31]) * len(ek)}
    if suite:
        extra.update(
            signing_key=ec_key(f"client-sign-{suite}", suite),
            key_agreement_key=ec_key(f"client-ka-{suite}", suite),
            peer_signing_key=ec_key(f"server-sign-{suite}", suite).public_key(),
            peer_key_agreement_key=ec_key(f"server-ka-{suite}", suite).public_key(),
        )
    return SecurityContext(
        ek, ak, client_system_title=b"PYDLMS01", suite=suite, invocation_counter=1, **extra, **kw
    )


def ecdsa(suite: int) -> dict:
    from pydlms.security.hls import Mechanism

    return {
        "mechanism": Mechanism.HLS_ECDSA,
        "signing_key": ec_key(f"client-sign-{suite}", suite),
        "server_public_key": ec_key(f"server-sign-{suite}", suite).public_key(),
    }


def server_cases() -> tuple[dict, dict]:
    """(working, failing): name -> DlmsClient.tcp settings (SAPs as in adapter/main.go)."""
    from pydlms.security.general import KeyInfo
    from pydlms.security.hls import Mechanism

    gmac = {"mechanism": Mechanism.HLS_GMAC}
    cases = {
        "none": {"client_sap": 16},
        "lls": {"client_sap": 17, "mechanism": Mechanism.LLS, "password": b"12345678"},
        "hls2": {"client_sap": 18, "mechanism": Mechanism.HLS, "password": HLS_SECRET},
        "hls-md5": {"client_sap": 19, "mechanism": Mechanism.HLS_MD5, "password": HLS_SECRET},
        "hls-sha1": {"client_sap": 20, "mechanism": Mechanism.HLS_SHA1, "password": HLS_SECRET},
        "hls-sha256": {
            "client_sap": 21,
            "mechanism": Mechanism.HLS_SHA256,
            "password": HLS_SECRET,
            "client_system_title": b"PYDLMS01",
        },
        "s0-gmac-glo": {"client_sap": 1, **gmac, "security": security(0)},
        "s0-gmac-general-glo": {
            "client_sap": 1,
            **gmac,
            "security": security(0),
            "protection": "general-glo",
        },
        "s0-gmac-ded": {
            "client_sap": 1,
            **gmac,
            "security": security(0),
            "use_dedicated_key": True,
        },
        "s1-gmac-glo": {"client_sap": 2, **gmac, "security": security(1)},
    }
    for sap, suite in ((3, 1), (5, 2)):
        cases[f"s{suite}-ecdsa-glo"] = {
            "client_sap": sap,
            **ecdsa(suite),
            "security": security(suite),
        }
        cases[f"s{suite}-ecdsa-general-glo"] = {
            "client_sap": sap,
            **ecdsa(suite),
            "security": security(suite),
            "protection": "general-glo",
        }
    gc = {"protection": "general-ciphering"}
    failing = {
        "s0-gmac-gc-identified": {
            "client_sap": 1,
            **gmac,
            "security": security(0),
            **gc,
            "key_info": KeyInfo("identified", 0),
        },
        "s0-gmac-gc-wrapped": {
            "client_sap": 1,
            **gmac,
            "security": security(0),
            **gc,
            "key_info": KeyInfo("wrapped"),
        },
        "s1-ecdsa-gc-agreed-one-pass": {
            "client_sap": 3,
            **ecdsa(1),
            "security": security(1),
            **gc,
            "key_info": KeyInfo("agreed", 0, 1),
        },
        "s1-ecdsa-gc-agreed-static": {
            "client_sap": 3,
            **ecdsa(1),
            "security": security(1),
            **gc,
            "key_info": KeyInfo("agreed", 0, 2),
        },
        "s1-ecdsa-glo+signing": {
            "client_sap": 3,
            **ecdsa(1),
            "security": security(1),
            "protection": "glo+signing",
        },
        "s1-signing-required-glo": {"client_sap": 4, **ecdsa(1), "security": security(1)},
    }
    return cases, failing


def opt_in_cases() -> dict:
    """The failing general-ciphering/-signing cases with the cB-Sigma forms opted in.

    Same SAPs and keys as :func:`server_cases`; only the context's
    ``general_aad`` / ``signing_form`` differ. SAP 4 now works too: it requires signing on every
    request.
    """
    from pydlms.security.general import GeneralAad, SigningForm

    hdr = {"general_aad": GeneralAad.WITH_HEADER}
    prefixed = {"signing_form": SigningForm.LENGTH_PREFIXED_CONTENT}
    _, failing = server_cases()
    cases = {}
    for name, settings in failing.items():
        kw = hdr if "-gc-" in name else prefixed
        suite = int(settings["security"].suite)
        cases[name] = {**settings, "security": security(suite, **kw)}
    cases["s1-signing-required-glo"]["protection"] = "glo+signing"
    return cases


#: Sweep cases that fail: name -> (pydlms exception, message part, reason).
SERVER_FAILURES = {
    "s0-gmac-gc-identified": (
        "AssociationError",
        "DECIPHERING_ERROR",
        "general-ciphering AAD: go-dlms adds the header fields, pydlms SC||AK",
    ),
    "s0-gmac-gc-wrapped": ("AssociationError", "DECIPHERING_ERROR", "same AAD question"),
    "s1-ecdsa-gc-agreed-one-pass": (
        "AssociationError",
        "DECIPHERING_ERROR",
        "AAD (pydlms signs X||Y since 5c6c664, as annex I.2 does)",
    ),
    "s1-ecdsa-gc-agreed-static": ("AssociationError", "DECIPHERING_ERROR", "same AAD question"),
    "s1-ecdsa-glo+signing": (
        "AssociationError",
        "DECIPHERING_ERROR",
        "general-signing: go-dlms signs the content with its length, pydlms without",
    ),
    "s1-signing-required-glo": (
        "AssociationError",
        "SERVICE_NOT_ALLOWED",
        "correct: the association requires general-signing",
    ),
}

#: Attributes the server refuses on every association (Association LN v3).
ASSOCIATION_REFUSALS = {
    "0.0.40.0.0.255/15/7": "READ_WRITE_DENIED",  # secret: write only, correct
    "0.0.40.0.0.255/15/10": "OBJECT_UNDEFINED",  # user_list not implemented
    "0.0.40.0.0.255/15/11": "OBJECT_UNDEFINED",  # current_user not implemented
}


@pytest.fixture(scope="module")
def go_server():
    pytest.importorskip("cryptography")
    require_image(IMAGE)
    from tests.interop.server import running

    with running(IMAGE, "server", ready="godlms server listening") as endpoint:
        yield endpoint


def _client(endpoint, settings):
    from pydlms.client import DlmsClient

    host, port = endpoint
    return DlmsClient.tcp(host, port, timeout=10, **settings)


def test_server_sweeps(go_server):
    from tests.interop.server import sweep

    cases, _ = server_cases()
    for name, settings in cases.items():
        with _client(go_server, settings) as meter:
            report = sweep(meter)
        assert (report["objects"], report["read"]) == (9, 43), name
        errors = {k: v.rsplit(": ", 1)[-1] for k, v in report["errors"].items()}
        assert errors == ASSOCIATION_REFUSALS, name
        values = report["values"]
        assert values["1.0.32.7.0.255/3/3"]["v"] == [
            {"t": "integer", "v": -1},
            {"t": "enum", "v": 35},
        ]
        assert values["0.0.1.0.0.255/8/2"]["v"] == "07e80501030c000000ff8800"
        assert len(values["1.0.99.1.0.255/7/2"]["v"]) == 96


def test_server_known_failures(go_server):
    from pydlms import exceptions

    _, failing = server_cases()
    assert set(failing) == set(SERVER_FAILURES)
    for name, settings in failing.items():
        kind, part, _ = SERVER_FAILURES[name]
        client = _client(go_server, settings)
        with pytest.raises(getattr(exceptions, kind), match=part):
            client.connect()
            client.get_association_view()
        client.link.disconnect()


def test_server_opt_in_forms_interoperate(go_server):
    """Every default-form failure above except a missing signature passes with the opt-in."""
    from tests.interop.server import sweep

    for name, settings in opt_in_cases().items():
        with _client(go_server, settings) as meter:
            report = sweep(meter)
        assert (report["objects"], report["read"]) == (9, 43), name
        errors = {k: v.rsplit(": ", 1)[-1] for k, v in report["errors"].items()}
        assert errors == ASSOCIATION_REFUSALS, name


def test_server_selective_access(go_server):
    import datetime as dt

    from pydlms.apdu.xdlms import date_time_value, entry_descriptor, range_descriptor
    from pydlms.obis import ObisCode

    utc = dt.timezone.utc
    with _client(go_server, {"client_sap": 16}) as meter:
        rows = meter.read_profile("1.0.99.1.0.255", entry_descriptor(2, 5)).rows
        assert [r[1] for r in rows] == [1007, 1014, 1021, 1028]
        rows = meter.read_profile("1.0.99.1.0.255", entry_descriptor(1, 3, 2, 2)).rows
        assert rows == [[1000], [1007], [1014]]
        span = (
            date_time_value(dt.datetime(2024, 5, 1, 1, 0, tzinfo=utc)),
            date_time_value(dt.datetime(2024, 5, 1, 2, 0, tzinfo=utc)),
        )
        rows = meter.read_profile("1.0.99.1.0.255", range_descriptor(*span)).rows
        assert [r[1] for r in rows] == [1028, 1035, 1042, 1049, 1056]
        column = [(3, ObisCode.parse("1.0.1.8.0.255"), 2, 0)]
        rows = meter.read_profile(
            "1.0.99.1.0.255", range_descriptor(*span, selected_values=column)
        ).rows
        assert rows == [[1028], [1035], [1042], [1049], [1056]]


# --- phase 4: its client reading pydlms simulate ---------------------------------------------

GMAC_ARGS = ["-client", "1", "-auth", "hls-gmac", "-security", "authenticated-encrypted"]
GMAC_ARGS += ["-key", EK16.hex(), "-auth-key", AK16.hex()]
ECDSA_ARGS = ["-client", "3", "-auth", "hls-ecdsa", "-suite", "1"]
ECDSA_ARGS += ["-security", "authenticated-encrypted", "-key", EK16.hex(), "-auth-key", AK16.hex()]

REVERSE = {
    "public": (0, []),
    "lls": (0, ["-client", "17", "-auth", "low", "-password", "12345678"]),
    "gmac-glo": (0, GMAC_ARGS),
    "gmac-general-glo": (0, [*GMAC_ARGS, "-ciphering", "general-glo"]),
    "ecdsa-glo": (1, ECDSA_ARGS),
    "ecdsa-general-glo": (1, [*ECDSA_ARGS, "-ciphering", "general-glo"]),
    # IC per key since c05a2ea: the client's own dedicated-key IC is accepted.
    "gmac-ded": (0, [*GMAC_ARGS, "-dedicated"]),
    "gmac-general-ded": (0, [*GMAC_ARGS, "-dedicated", "-ciphering", "general-ded"]),
}

#: name -> (suite, client args, error key, message part, reason).
REVERSE_FAILURES = {
    "gmac-general-identified": (
        0,
        [*GMAC_ARGS, "-ciphering", "general", "-general-key", "identified"],
        "associate",
        "refused our answer",
        "general-ciphering AAD",
    ),
    "ecdsa-signing": (
        1,
        [*ECDSA_ARGS, "-signing"],
        "associate",
        "refused our answer",
        "general-signing signed data (content length)",
    ),
}


#: The REVERSE_FAILURES cases with the simulator using the cB-Sigma form.
REVERSE_OPT_IN = {
    "gmac-general-identified": ("general_aad", "with-header"),
    "ecdsa-signing": ("signing_form", "length-prefixed-content"),
}


def _simulated_meter(suite: int, **forms):
    from pydlms.security.context import SecurityContext
    from pydlms.security.hls import Mechanism
    from pydlms.simulator import ClientProfile, example_meter

    sim = example_meter(encryption_key=EK16, authentication_key=AK16)
    if suite:
        sim.security = SecurityContext(
            EK16,
            AK16,
            client_system_title=sim.system_title,
            suite=suite,
            signing_key=ec_key("server-sign-1", 1),
            peer_signing_key=ec_key("client-sign-1", 1).public_key(),
        )
        sim.signing_key = ec_key("server-sign-1", 1)
    sim.clients[1] = ClientProfile(Mechanism.HLS_GMAC, ciphered=True)
    sim.clients[3] = ClientProfile(
        Mechanism.HLS_ECDSA,
        ciphered=True,
        client_public_key=ec_key("client-sign-1", 1).public_key(),
    )
    sim.clients[17] = ClientProfile(Mechanism.LLS, secret=b"12345678")
    if forms:
        from pydlms.security.general import GeneralAad, SigningForm

        types = {"general_aad": GeneralAad, "signing_form": SigningForm}
        for name, value in forms.items():
            setattr(sim.security, name, types[name](value))
    return sim


def _go_client(suite: int, args: list[str], **forms) -> dict:
    from pydlms.simulator import serve

    server = serve(_simulated_meter(suite, **forms), "0.0.0.0", 0)  # noqa: S104 - container on host net
    try:
        out = subprocess.run(  # noqa: S603,S607 - fixed argv, test-only
            ["docker", "run", "--rm", "--network", "host", IMAGE, "client"]
            + ["-port", str(server.server_address[1]), *args],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    finally:
        server.shutdown()
        server.server_close()
    return json.loads(out.stdout)


@pytest.fixture
def go_client_image():
    pytest.importorskip("cryptography")
    require_image(IMAGE)


def _reverse_cases():
    cases = [pytest.param(name, {}, id=name) for name in REVERSE]
    for name, (option, value) in REVERSE_OPT_IN.items():
        cases.append(pytest.param(name, {option: value}, id=f"{name}-opt-in"))
    return cases


@pytest.mark.parametrize(("name", "forms"), _reverse_cases())
def test_go_client_reads_the_simulator(go_client_image, name, forms):
    suite, args = REVERSE[name] if name in REVERSE else REVERSE_FAILURES[name][:2]
    report = _go_client(suite, args, **forms)
    assert report["errors"] == {}
    assert report["associated"]
    names = {o["logical_name"] for o in report["objects"]}
    assert {"0.0.1.0.0.255", "1.0.1.8.0.255", "1.0.99.1.0.255"} <= names
    values = report["values"]
    assert values["1.0.1.8.0.255/3/2"] == {"t": "double-long-unsigned", "v": 12345678}
    assert values["1.0.32.7.0.255/scaler"] == {"Exponent": -1, "Unit": "V", "OK": True}
    assert values["0.0.1.0.0.255/8/2"]["v"] == "07e80501030c000000ff88ff"
    assert [r["v"][1]["v"] for r in report["profile_range"]] == [1000, 1007, 1014, 1021, 1028]


@pytest.mark.parametrize("name", list(REVERSE_FAILURES))
def test_go_client_known_failures(go_client_image, name):
    suite, args, key, part, _ = REVERSE_FAILURES[name]
    report = _go_client(suite, args)
    assert part in report["errors"][key]


# --- general-block-transfer -----------------------------------------------------------------

#: The image to run with ``server -gbt`` (an adapter flag added for S6).
GBT_IMAGE = os.environ.get("PYDLMS_GO_DLMS_IMAGE", IMAGE)


@pytest.fixture(scope="module")
def go_gbt_server():
    pytest.importorskip("cryptography")
    require_image(GBT_IMAGE)
    from tests.interop.server import running

    usage = subprocess.run(  # noqa: S603,S607 - fixed docker argv, test-only
        ["docker", "run", "--rm", GBT_IMAGE, "server", "-h"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if "-gbt" not in usage.stdout + usage.stderr:
        pytest.skip(f"{GBT_IMAGE} has no server -gbt flag: rebuild tests/interop/go-dlms")
    with running(GBT_IMAGE, "server", "-gbt", ready="godlms server listening") as endpoint:
        yield endpoint


@pytest.mark.parametrize("name", ["none", "s0-gmac-glo", "s0-gmac-general-glo"])
def test_server_takes_client_gbt(go_gbt_server, name):
    """The go-dlms server (window 1, no streaming, block numbers going on
    across exchanges) takes requests longer than its 1024-octet PDU in GBT
    and answers long responses in GBT; pydlms proposes GBT on request."""
    from pydlms.cosem.data import DlmsData

    settings = dict(server_cases()[0][name], propose_gbt=True)
    with _client(go_gbt_server, settings) as meter:
        assoc = meter.association
        assert assoc.uses_gbt and assoc.server_max_pdu == 1024
        values = meter.get_many([("1.0.1.8.0.255", 3, 2)] * 150)  # 1.5 kB request
        assert {v.value for v in values} == {12345678}
        text = "GBT" * 500
        meter.set("0.0.96.1.0.255", 1, 2, DlmsData.visible_string(text))
        assert meter.get("0.0.96.1.0.255").value == text  # GBT answer, numbered on
        assert len(meter.read_profile("1.0.99.1.0.255").rows) == 96
        assert assoc._gbt_peer_window == 1


# --- ACCESS -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["none", "lls", "s0-gmac-glo", "s0-gmac-general-glo", "s0-gmac-ded", "s1-ecdsa-glo"],
)
def test_server_takes_access(go_server, name):
    """The go-dlms server (DecodeAccessRequest, bit 17 in its default LN
    conformance) runs ACCESS gets, sets, get-with-selection and actions;
    under protection "glo" pydlms sends it as general-glo / general-ded."""
    from pydlms import AccessAction, AccessGet, AccessSet
    from pydlms.apdu.xdlms import entry_descriptor
    from pydlms.cosem.data import DlmsData
    from pydlms.cosem.enums import DataAccessResult

    settings = dict(server_cases()[0][name], propose_access=True)
    with _client(go_server, settings) as meter:
        assert meter.association.access_negotiated
        out = meter.access(
            [
                AccessGet("0.0.96.1.0.255"),
                AccessGet("1.0.1.8.0.255", 3, 2),
                AccessSet("0.0.96.1.0.255", 1, 2, DlmsData.visible_string("GOD0000000001")),
                AccessGet("1.0.99.1.0.255", 7, 2, entry_descriptor(1, 2)),
                AccessGet("9.9.9.9.9.9", 1, 2),
            ]
        )
        assert [o.ok for o in out] == [True, True, True, True, False]
        assert out[0].data.value == "GOD0000000001"
        assert out[1].data.value == 12345678
        assert len(out[3].data.value) == 2
        assert out[4].result == DataAccessResult.OBJECT_UNDEFINED
        # break-on-error: the server stops and answers OTHER_REASON (250)
        out = meter.access(
            [AccessGet("9.9.9.9.9.9", 1, 2), AccessGet("0.0.96.1.0.255")], break_on_error=True
        )
        assert [int(o.result) for o in out] == [int(DataAccessResult.OBJECT_UNDEFINED), 250]
        # Clock adjust_to_quarter and a read, in one request
        clock = meter.access(
            [AccessAction("0.0.1.0.0.255", 8, 1, DlmsData.int8(0)), AccessGet("0.0.1.0.0.255", 8)]
        )
        assert clock[0].ok and clock[0].data == DlmsData.null()
        assert clock[1].data.value.hex() == "07e80501030c000000ff8800"


# --- third-party layers (IEC 62056-5-3:2023 annex J) ------------------------------------------
#
# The adapter's meter knows the third party TPHEAD01 on SAPs 6 (suite 1,
# answers signed), 7 (suite 1, answers unsigned: annex J.3 for a third
# party that only signs) and 8 (suite 2). pydlms nests the third party's
# layers (the meter opens them) and unnests the meter's answers. cB-Sigma
# uses its forms (general_aad WITH_HEADER, signing_form
# LENGTH_PREFIXED_CONTENT) for the third party's layers too.

TP_IMAGE = os.environ.get("PYDLMS_GO_DLMS_IMAGE", IMAGE)
TP_TITLE = b"TPHEAD01"
CB_FORMS = {"general_aad": "with-header", "signing_form": "length-prefixed-content"}


def third_party(suite: int, forms=CB_FORMS, **kw):
    from pydlms.security.thirdparty import ThirdParty

    return ThirdParty(
        TP_TITLE,
        signing_key=ec_key(f"tp-sign-{suite}", suite),
        key_agreement_key=ec_key(f"tp-ka-{suite}", suite),
        authentication_key=AK32 if suite == 2 else AK16,
        **forms,
        **kw,
    )


def tp_settings(sap: int, suite: int, protection: str = "general-glo", ctx=None, **kw) -> dict:
    return {
        "client_sap": sap,
        **ecdsa(suite),
        "security": security(suite, **(ctx or {})),
        "protection": protection,
        "third_party": third_party(suite, **kw),
    }


def _tp_cases() -> dict:
    from pydlms.security.suites import SecurityPolicy

    ae, auth = SecurityPolicy.AUTHENTICATED_ENCRYPTED, SecurityPolicy.AUTHENTICATED
    enc = SecurityPolicy.ENCRYPTED
    hdr = {"general_aad": "with-header"}
    return {
        "s1-sign": tp_settings(6, 1),
        "s1-sign+ae-one-pass": tp_settings(6, 1, policy=ae),
        "s1-sign+ae-static": tp_settings(6, 1, policy=ae, key_agreement=2),
        "s1-ae-static": tp_settings(6, 1, sign=False, policy=ae, key_agreement=2),
        "s1-auth-static": tp_settings(6, 1, sign=False, policy=auth, key_agreement=2),
        "s1-enc-one-pass": tp_settings(6, 1, sign=False, policy=enc),
        "s1-sign-in-general-ciphering": tp_settings(6, 1, "general-ciphering", ctx=hdr),
        "s1-sign+ae-in-general-ciphering": tp_settings(
            6, 1, "general-ciphering", ctx=hdr, policy=ae
        ),
        "s1-j3-opt-in": tp_settings(
            7, 1, signed_responses=False, accept_unprotected_responses=True
        ),
        "s1-unsigned-ae-answer": tp_settings(7, 1, policy=ae, signed_responses=False),
        "s2-sign+ae-one-pass": tp_settings(8, 2, policy=ae),
        "s2-ae-static": tp_settings(8, 2, sign=False, policy=ae, key_agreement=2),
    }


@pytest.fixture(scope="module")
def go_tp_server():
    pytest.importorskip("cryptography")
    require_image(TP_IMAGE)
    from tests.interop.server import running

    with running(TP_IMAGE, "server", ready="godlms server listening") as endpoint:
        yield endpoint


TP_CASES = [
    "s1-sign",
    "s1-sign+ae-one-pass",
    "s1-sign+ae-static",
    "s1-ae-static",
    "s1-auth-static",
    "s1-enc-one-pass",
    "s1-sign-in-general-ciphering",
    "s1-sign+ae-in-general-ciphering",
    "s1-j3-opt-in",
    "s1-unsigned-ae-answer",
    "s2-sign+ae-one-pass",
    "s2-ae-static",
]


def test_third_party_case_list():
    assert list(_tp_cases()) == TP_CASES


@pytest.mark.parametrize("name", TP_CASES)
def test_third_party_layers_interoperate(go_tp_server, name):
    """Our layers open in its meter; its layers for the third party open in pydlms."""
    with _client(go_tp_server, _tp_cases()[name]) as meter:
        assert meter.get("1.0.1.8.0.255", 3, 2).value == 12345678
        assert meter.get("0.0.42.0.0.255").value == b"GODLMS0000000001"


def _tp_refused(endpoint, settings, kind, match=None):
    client = _client(endpoint, settings)
    with pytest.raises(kind, match=match):
        client.connect()
        client.get("1.0.1.8.0.255", 3, 2)
    client.link.disconnect()


def test_third_party_failures(go_tp_server):
    from pydlms.exceptions import AuthenticationError, DlmsError
    from pydlms.security.suites import SecurityPolicy

    ae = SecurityPolicy.AUTHENTICATED_ENCRYPTED
    # The J.3 answer is refused without the opt-in.
    _tp_refused(go_tp_server, tp_settings(7, 1, signed_responses=False), AuthenticationError, "J.3")
    # A signature is required but SAP 7 does not sign its answers.
    _tp_refused(go_tp_server, tp_settings(7, 1, policy=ae), AuthenticationError, "did not sign")
    # A ciphered answer is required but the request was only signed.
    _tp_refused(
        go_tp_server,
        tp_settings(6, 1, ciphered_responses=True),
        AuthenticationError,
        "did not cipher",
    )
    # pydlms' default forms: the meter cannot verify our signature.
    _tp_refused(go_tp_server, tp_settings(6, 1, forms={}), DlmsError)
    # A signing key the meter does not know.
    settings = tp_settings(6, 1)
    settings["third_party"].signing_key = ec_key("intruder", 1)
    _tp_refused(go_tp_server, settings, DlmsError)


def _go_tp_client(args: list[str], sign_answers: bool = True) -> dict:
    """Its client, as the third party's client, reading the simulator whose
    services sit behind the test meter side of tests/crypto/thirdparty_meter."""
    from pydlms.apdu.tags import Tag
    from pydlms.security.general import GeneralAad, SigningForm
    from pydlms.security.hls import Mechanism
    from pydlms.simulator import ClientProfile, serve
    from tests.crypto.thirdparty_meter import TpMeter

    sim = _simulated_meter(1)
    # No HLS: its client puts the third party's layers on HLS pass 3 too,
    # which pydlms' simulator does not unwrap before the association.
    sim.clients[16] = ClientProfile(Mechanism.NONE, ciphered=True)
    tp = TpMeter(
        suite=1,
        meter_title=sim.system_title,
        tp_title=TP_TITLE,
        meter_sign=ec_key("server-sign-1", 1),
        meter_ka=ec_key("server-ka-1", 1),
        tp_sign_pub=ec_key("tp-sign-1", 1).public_key(),
        tp_ka_pub=ec_key("tp-ka-1", 1).public_key(),
        ak=AK16,
        sign_answers=sign_answers,
        general_aad=GeneralAad.WITH_HEADER,
        signing_form=SigningForm.LENGTH_PREFIXED_CONTENT,
    )
    service, opened = sim._service, []

    def wrapped(plain, session):
        if plain and plain[0] in (Tag.GENERAL_CIPHERING, Tag.GENERAL_SIGNING):
            inner, tx = tp.open(plain)
            opened.append(tx)
            response = service(inner, session)
            return None if response is None else tp.answer(tx, response)
        return service(plain, session)

    sim._service = wrapped
    server = serve(sim, "0.0.0.0", 0)  # noqa: S104 - container on host net
    try:
        out = subprocess.run(  # noqa: S603,S607 - fixed argv, test-only
            ["docker", "run", "--rm", "--network", "host", TP_IMAGE, "client"]
            + ["-port", str(server.server_address[1]), *args],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    finally:
        server.shutdown()
        server.server_close()
    report = json.loads(out.stdout)
    report["tp_opened"] = len(opened)
    return report


TP_ARGS = ["-client", "16", "-suite", "1", "-security", "authenticated-encrypted"]
TP_ARGS += ["-key", EK16.hex(), "-auth-key", AK16.hex(), "-ciphering", "general-glo", "-tp"]


@pytest.mark.parametrize(
    ("args", "sign_answers"),
    [
        pytest.param([], True, id="sign"),
        pytest.param(
            ["-tp-security", "authenticated-encrypted", "-tp-ciphered-responses"],
            True,
            id="sign+ae-one-pass",
        ),
        pytest.param(
            ["-tp-sign=false", "-tp-signed-responses=false", "-tp-ciphered-responses"]
            + ["-tp-security", "authenticated-encrypted", "-tp-key", "agreed-static"],
            True,
            id="ae-static",
        ),
        pytest.param(["-tp-signed-responses=false"], False, id="j3-answer"),
    ],
)
def test_go_client_third_party_reads_the_simulator(args, sign_answers):
    """Its third party's layers open in pydlms (as the meter side), and the
    meter answers built from pydlms' primitives open in its client."""
    pytest.importorskip("cryptography")
    require_image(TP_IMAGE)
    report = _go_tp_client([*TP_ARGS, *args], sign_answers)
    assert report["associated"], report["errors"]
    assert report["values"]["1.0.1.8.0.255/3/2"] == {"t": "double-long-unsigned", "v": 12345678}
    assert report["tp_opened"] > 10
