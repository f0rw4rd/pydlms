"""Two C DLMS servers against pydlms: GuruxDLMS.c and opendlms.

Images (commits pinned in the Dockerfiles):
  docker build -t pydlms-interop-gurux-c  tests/interop/c-servers/gurux-c
  docker build -t pydlms-interop-opendlms tests/interop/c-servers/opendlms
"""

from __future__ import annotations

import pytest

from tests.interop import compare
from tests.interop.oracle import Oracle, require_image

pytestmark = pytest.mark.integration

GURUX_C = "pydlms-interop-gurux-c"
OPENDLMS = "pydlms-interop-opendlms"

EK = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
AK = bytes.fromhex("d0d1d2d3d4d5d6d7d8d9dadbdcdddedf")


# --- GuruxDLMS.c: codec oracle (op data) -------------------------------------------------

#: Every corpus row the GuruxDLMS.c codec adapter does not agree on.
GURUX_C_KNOWN = {
    # [13] bcd is IMPLICIT Integer8 (one octet) in Blue Book 4.1.5. The C
    # library's dlms_getData() reads it as a variable-length packed-BCD
    # string: getBcd() takes a leading length octet (0x12 = 18) and then
    # wants 2*18 more octets, so it reports the value as incomplete.
    # pydlms reads the single octet. pydlms is right.
    "data/hand-03-GetResponseNormal#14": ("only-oracle-rejects", "bcd read as packed-BCD string"),
    "data/hand-03-GetResponseNormal#0": ("only-oracle-rejects", "bcd inside the structure"),
    # dlms_getData() flattens a compact-array to an array and drops the
    # type description, which the JSON model needs; the adapter says so.
    "data/hand-03-GetResponseNormal#18": ("unsupported", "compact-array: no type description"),
    "data/data-compact-array#0": ("unsupported", "compact-array: no type description"),
    "data/data-compact-boolean#0": ("unsupported", "compact-array: no type description"),
    "data/data-compact-int8#0": ("unsupported", "compact-array: no type description"),
    "data/data-compact-octets#0": ("unsupported", "compact-array: no type description"),
    "data/data-compact-structure#0": ("unsupported", "compact-array: no type description"),
    "data/data-compact-uint16-empty#0": ("unsupported", "compact-array: no type description"),
}


@pytest.fixture(scope="module")
def gurux_c_oracle():
    require_image(GURUX_C)
    o = Oracle(GURUX_C)
    yield o
    o.close()


def test_gurux_c_hello(gurux_c_oracle):
    assert gurux_c_oracle.hello["ok"]
    assert gurux_c_oracle.hello["library"] == "GuruxDLMS.c"
    assert gurux_c_oracle.hello["version"].startswith("11a4fefe")
    assert gurux_c_oracle.hello["ops"] == ["data"]


def test_gurux_c_codec_disagreements_are_the_known_ones(gurux_c_oracle):
    rows = compare.run(gurux_c_oracle, ops=("data",))
    odd = {
        f"{r['op']}/{r['name']}": r["outcome"]
        for r in rows
        if r["outcome"] not in ("agree", "both-reject")
    }
    assert odd == {name: outcome for name, (outcome, _) in GURUX_C_KNOWN.items()}
    assert sum(r["outcome"] == "agree" for r in rows) > 500


# --- GuruxDLMS.c: the example server, read by pydlms -------------------------------------
#
# GuruxDLMSServerExample ports (main.c startServers): 4061 LN/HDLC,
# 4063 LN/wrapper. Credentials from exampleserver.c: LLS/HLS secret "Gurux"
# (SAP 17/18), HLS-GMAC suite 0 keys EK/AK above, client title "Gurux123",
# server title GRX\0\0\0\0\1 (SAP 1).

#: Attributes the example server refuses or mis-encodes on every association.
#: key -> a stable substring of "ExceptionType: ...".
GURUX_C_SERVER_ERRORS = {
    # Attributes the example leaves unpopulated; it answers HARDWARE_FAULT.
    "0.0.2.2.0.255/28/7": "HARDWARE_FAULT",
    "0.0.24.8.0.255/76/12": "HARDWARE_FAULT",
    # Classes 90-92 (G3-PLC) used to be unknown, so the sweep probed one
    # attribute past the last (90/11, 91/27, 92/24: the first failure). With
    # the X3 layouts the sweep stops at the registered count and those
    # overshoot probes are gone.
    "0.0.18.0.0.255/123/3": "HARDWARE_FAULT",
    "0.0.25.11.0.255/151/4": "HARDWARE_FAULT",
    # The example's svr_preRead fills the value AND the framework appends its
    # own, so the GET-Response data field carries the value twice. pydlms
    # rejects the trailing octets (one Data per result, Green Book 9.4.2.2);
    # the lenient Gurux .NET client reads the first and ignores the rest.
    "0.0.1.0.0.255/8/2": "trailing octets after GET_RESPONSE",
    "1.0.99.1.0.255/7/2": "trailing octets after block-transferred data",
    "1.0.99.98.0.255/7/2": "trailing octets after GET_RESPONSE",
}

#: Working auth/security levels: name -> DlmsClient.tcp settings.
GURUX_C_SERVER_CASES = {
    "none": {"client_sap": 16},
    "lls": {"client_sap": 17, "mechanism": "_lls", "password": b"Gurux"},
    "hls2": {"client_sap": 18, "mechanism": "_hls", "password": b"Gurux"},
    "hls-gmac": {"client_sap": 1, "mechanism": "_gmac"},
}


def _gurux_c_settings(name):
    from pydlms.security.context import SecurityContext
    from pydlms.security.hls import Mechanism

    settings = dict(GURUX_C_SERVER_CASES[name])
    mech = settings.pop("mechanism", None)
    if mech == "_lls":
        settings["mechanism"] = Mechanism.LLS
    elif mech == "_hls":
        settings["mechanism"] = Mechanism.HLS
    elif mech == "_gmac":
        settings["mechanism"] = Mechanism.HLS_GMAC
        settings["security"] = SecurityContext(
            EK, AK, client_system_title=b"Gurux123", invocation_counter=1
        )
        # The server validates the invocation counter against its stored
        # minimum; recover it and retry once (pydlms.counters).
        settings["invocation_counter_retry"] = True
    return settings


@pytest.fixture(scope="module")
def gurux_c_server():
    require_image(GURUX_C)
    from tests.interop.server import running

    # LN over the IEC 62056-47 wrapper (port 4063), the no-input "server" cmd.
    with running(GURUX_C, "server", port=4063, ready="Logical Name DLMS Server") as endpoint:
        yield endpoint


@pytest.mark.parametrize("name", list(GURUX_C_SERVER_CASES))
def test_gurux_c_server_sweep(gurux_c_server, name):
    if name in ("hls-gmac",):
        pytest.importorskip("cryptography")
    from pydlms.client import DlmsClient
    from tests.interop.server import sweep

    host, port = gurux_c_server
    with DlmsClient.tcp(host, port, timeout=15, **_gurux_c_settings(name)) as meter:
        report = sweep(meter)
    assert report["objects"] == 52, name
    errors = report["errors"]
    assert set(errors) == set(GURUX_C_SERVER_ERRORS), name
    for key, part in GURUX_C_SERVER_ERRORS.items():
        assert part in errors[key], (name, key, errors[key])
    # A scalar that round-trips on every level: the logical device name.
    assert report["values"]["0.0.42.0.0.255/1/2"]["v"] == b"GRX0000000123456".hex()


def test_gurux_c_rejects_wrong_lls_secret(gurux_c_server):
    from pydlms.client import DlmsClient
    from pydlms.exceptions import AssociationError
    from pydlms.security.hls import Mechanism

    host, port = gurux_c_server
    client = DlmsClient.tcp(
        host, port, client_sap=17, mechanism=Mechanism.LLS, password=b"wrong", timeout=15
    )
    with pytest.raises(AssociationError, match="AUTHENTICATION_FAILURE"):
        client.connect()
    client.link.disconnect()


# --- opendlms: the meter simulator, read by pydlms --------------------------------------
#
# examples/metersimulator, TCP wrapper on 4063. Associations (main.c
# assos_config): SAP 16 public, SAP 1 management. The meter HAL LLS password
# (cosem_server_hal.c default_password) is eight 0x00 octets; the cDefaultSap
# table ("00000001", keys EK/AK, server title ABCDEFGH) is unused (FIXME).


@pytest.fixture(scope="module")
def opendlms_server():
    require_image(OPENDLMS)
    from tests.interop.server import running

    with running(OPENDLMS, port=4063, ready="TCP Server started") as endpoint:
        yield endpoint


def test_opendlms_object_list_is_rejected(opendlms_server):
    # db_cosem_associations.c writes the object_list structure members
    # (class_id u16, version u8, logical_name, access bytes) as RAW integers
    # with no A-XDR type tag. The result is not valid COSEM Data (IEC
    # 62056-6-2: association_ln object_list is an array of structures of
    # tagged Data), so pydlms stops at the untagged class-id high byte.
    from pydlms.client import DlmsClient
    from pydlms.exceptions import DecodeError

    host, port = opendlms_server
    with DlmsClient.tcp(host, port, timeout=10) as meter:
        with pytest.raises(DecodeError, match="unknown COSEM data type tag 0x08"):
            meter.get_association_view()


def test_opendlms_reads_a_tagged_scalar(opendlms_server):
    # Individual attributes are returned as proper tagged Data; the clock
    # (0.0.1.0.0.255 attribute 2) decodes to a 12-octet date-time.
    from pydlms.client import DlmsClient

    host, port = opendlms_server
    with DlmsClient.tcp(host, port, timeout=10) as meter:
        clock = meter.get("0.0.1.0.0.255", 8, 2)
        assert clock.tag.name == "OCTET_STRING"
        assert len(clock.value) == 12


def test_opendlms_lls_zero_password(opendlms_server):
    # The meter HAL accepts the all-zero LLS password on SAP 1; a non-zero
    # one is refused (AUTHENTICATION_FAILURE).
    from pydlms.client import DlmsClient
    from pydlms.exceptions import AssociationError
    from pydlms.security.hls import Mechanism

    host, port = opendlms_server
    with DlmsClient.tcp(
        host, port, client_sap=1, mechanism=Mechanism.LLS, password=bytes(8), timeout=10
    ) as meter:
        assert meter.get("0.0.1.0.0.255", 8, 2).tag.name == "OCTET_STRING"

    client = DlmsClient.tcp(
        host, port, client_sap=1, mechanism=Mechanism.LLS, password=b"wrongpwd", timeout=10
    )
    with pytest.raises(AssociationError, match="AUTHENTICATION_FAILURE"):
        client.connect()
    client.link.disconnect()


def test_opendlms_gmac_needs_a_plaintext_context(opendlms_server):
    # opendlms's ACSE decoder cannot parse a ciphered InitiateRequest
    # (glo-initiateRequest, tag 0x21): it logs "Bad InitiateRequest tag" and
    # refuses. HLS-GMAC therefore works only with a non-ciphered application
    # context (ciphered_context=False); then pass 3/4 and GET succeed.
    pytest.importorskip("cryptography")
    from pydlms.client import DlmsClient
    from pydlms.exceptions import DlmsError
    from pydlms.security.context import SecurityContext
    from pydlms.security.hls import Mechanism

    host, port = opendlms_server

    def ctx():
        return SecurityContext(EK, AK, client_system_title=b"PYDLMS01", invocation_counter=1)

    with DlmsClient.tcp(
        host,
        port,
        client_sap=1,
        mechanism=Mechanism.HLS_GMAC,
        security=ctx(),
        ciphered_context=False,
        timeout=10,
    ) as meter:
        assert meter.get("0.0.1.0.0.255", 8, 2).tag.name == "OCTET_STRING"

    client = DlmsClient.tcp(
        host, port, client_sap=1, mechanism=Mechanism.HLS_GMAC, security=ctx(), timeout=10
    )
    with pytest.raises(DlmsError):
        client.connect()
    client.link.disconnect()
