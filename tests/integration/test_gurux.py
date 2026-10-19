"""Interop against the Gurux DLMS simulator: an independent implementation.

Our AARQs, HLS passes, ciphered APDUs (glo-, suite 0)
and HDLC/wrapper framing are accepted by a server we did not write, and its
answers decode and decipher in pydlms. Self-consistent unit tests cannot
catch a shared misreading of the standard; this can.

Needs the ``pydlms-gurux-sim`` image (``docker build -t pydlms-gurux-sim
tests/integration/gurux``, see the README there). Each template runs in its
own container on a random loopback port. Set ``PYDLMS_GURUX_IMAGE`` to use
another tag.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time

import pytest

from pydlms.client import DlmsClient
from pydlms.cosem.interface_classes import ClassId
from pydlms.cosem.profile import is_timestamp_column
from pydlms.cosem.scaler import RegisterValue
from pydlms.cosem.time import CosemDateTime
from pydlms.exceptions import AssociationError
from pydlms.security.hls import Mechanism
from tests.docker_ready import wait_listening

pytestmark = pytest.mark.integration

IMAGE = os.environ.get("PYDLMS_GURUX_IMAGE", "pydlms-gurux-sim")
SECRET = b"Gurux"
EK = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
AK = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")
SERVER_TITLE = bytes.fromhex("4752580000000001")


def _docker(*args: str) -> str:
    return subprocess.run(  # noqa: S603 - fixed docker argv in tests
        ["docker", *args], check=True, capture_output=True, text=True, timeout=120
    ).stdout.strip()


class Gurux:
    def __init__(self) -> None:
        self.containers: dict[tuple[str, str, str], int] = {}

    def endpoint(
        self, template: str, iface: str = "WRAPPER", instance: str = ""
    ) -> tuple[str, int]:
        """``instance`` forces a separate container (fresh server state)."""
        key = (template, iface, instance)
        if key not in self.containers:
            cid = _docker(
                "run",
                "-d",
                "--rm",
                "-p",
                "127.0.0.1::4060",
                "-e",
                f"SIM_TEMPLATE={template}",
                "-e",
                f"SIM_IFACE={iface}",
                IMAGE,
            )
            port = int(_docker("port", cid, "4060").splitlines()[0].rsplit(":", 1)[1])
            self.containers[key] = port
            self._cids = [*getattr(self, "_cids", []), cid]
            _wait_ready(cid, port)
        return "127.0.0.1", self.containers[key]

    def stop(self) -> None:
        for cid in getattr(self, "_cids", []):
            subprocess.run(["docker", "rm", "-f", cid], capture_output=True, timeout=60)  # noqa: S603,S607


def _wait_ready(cid: str, port: int) -> None:
    """Wait for the simulator's start banner, then until a connection is held
    open (Docker's proxy accepts and drops connections before the server
    listens; tests/docker_ready.py).

    A protocol probe cannot be used: HDLC listeners and templates without a
    public client never answer a wrapper AARQ from SAP 16.
    """
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        logs = subprocess.run(  # noqa: S603,S607
            ["docker", "logs", cid], capture_output=True, text=True, timeout=30
        )
        if "simulator start in" in logs.stdout + logs.stderr:
            wait_listening(port, f"Gurux simulator {cid[:12]}")
            return
        time.sleep(0.5)
    pytest.fail(f"Gurux simulator {cid[:12]} on port {port} did not come up")


@pytest.fixture(scope="module")
def gurux():
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    try:
        _docker("image", "inspect", IMAGE)
    except subprocess.CalledProcessError:
        pytest.skip(f"image {IMAGE} missing: docker build -t {IMAGE} tests/integration/gurux")
    sims = Gurux()
    yield sims
    sims.stop()


def _security(ic: int):
    pytest.importorskip("cryptography")
    from pydlms.security.context import SecurityContext

    return SecurityContext(EK, AK, client_system_title=b"PYDLMS01", invocation_counter=ic)


DEFAULT = "GMacWithAuthenticationEncyption.xml"


@pytest.mark.parametrize("hdlc", [False, True], ids=["wrapper", "hdlc"])
def test_public_client_reads(gurux, hdlc):
    host, port = gurux.endpoint(DEFAULT, "HDLC" if hdlc else "WRAPPER")
    with DlmsClient.tcp(host, port, hdlc=hdlc, timeout=10) as meter:
        view = meter.get_association_view()
        assert {str(e.logical_name) for e in view} >= {"0.0.42.0.0.255", "0.0.1.0.0.255"}
        assert all(e.rights is not None and e.rights.version == 2 for e in view)  # LN v2
        assert meter.can_read("0.0.1.0.0.255", ClassId.CLOCK, "time") is True
        assert meter.get("0.0.42.0.0.255").value == b"GRX2"
        clock = meter.get_clock()
        assert clock.is_fully_specified
        profile = next(e for e in view if e.class_id == ClassId.PROFILE_GENERIC)
        buffer = meter.read_profile(profile.logical_name, typed=True, scalers=True)
        clocks = [i for i, c in enumerate(buffer.columns) if is_timestamp_column(c)]
        assert clocks, buffer.columns
        stamps = [row[clocks[0]] for row in buffer.rows]
        assert stamps and all(isinstance(s, CosemDateTime) for s in stamps)
        moments = [s.to_datetime() for s in stamps]
        assert moments == sorted(moments)  # Gurux sorts FIFO
        registers = [i for i, c in enumerate(buffer.columns) if c[0] == ClassId.REGISTER]
        assert all(isinstance(row[i], RegisterValue) for row in buffer.rows for i in registers)


@pytest.mark.parametrize(
    "template,client,mechanism,with_title",
    [
        ("LN-v2-Low.xml", 17, Mechanism.LLS, False),
        ("LN-v2-High.xml", 18, Mechanism.HLS, False),
        (DEFAULT, 18, Mechanism.HLS, False),
        ("LN-v2-Md5.xml", 1, Mechanism.HLS_MD5, False),
        ("LN-v2-Sha1.xml", 1, Mechanism.HLS_SHA1, False),
        ("LN-v2-Sha256.xml", 1, Mechanism.HLS_SHA256, True),
    ],
    ids=["LLS", "HLS2", "HLS2-default", "MD5", "SHA1", "SHA256"],
)
def test_authentication_levels(gurux, template, client, mechanism, with_title):
    host, port = gurux.endpoint(template)
    extra = {"client_system_title": b"PYDLMS01"} if with_title else {}
    with DlmsClient.tcp(
        host, port, client_sap=client, mechanism=mechanism, password=SECRET, timeout=10, **extra
    ) as meter:
        assert meter.get_association_view()


def test_wrong_secret_rejected(gurux):
    host, port = gurux.endpoint("LN-v2-High.xml")
    client = DlmsClient.tcp(
        host, port, client_sap=18, mechanism=Mechanism.HLS, password=b"wrong", timeout=10
    )
    with pytest.raises(AssociationError):
        client.connect()
    client.link.disconnect()


def test_hls_gmac_ciphered_suite0(gurux):
    """Crypto interop: our glo- APDUs are accepted and theirs decipher."""
    host, port = gurux.endpoint(DEFAULT)
    with DlmsClient.tcp(host, port, timeout=10) as public:
        counter = public.get("0.0.43.1.0.255").value  # the meter's expected IC floor
    security = _security(counter + 1)
    with DlmsClient.tcp(
        host, port, client_sap=1, mechanism=Mechanism.HLS_GMAC, security=security, timeout=10
    ) as meter:
        assert security.server_system_title == SERVER_TITLE
        view = meter.get_association_view()
        assert view
        assert meter.get("0.0.42.0.0.255").value == b"GRX2"
    assert security.invocation_counter > counter + 3


def test_hls_gmac_in_a_plain_context(gurux):
    """LN-v2-GMac: HLS-GMAC authentication in the LN context *without*
    ciphering. The keys only compute f(StoC)/f(CtoS); xDLMS APDUs travel in
    clear both ways (pydlms used to glo-cipher them and refuse the clear
    answers)."""
    host, port = gurux.endpoint("LN-v2-GMac.xml")
    security = _security(1)
    with DlmsClient.tcp(
        host,
        port,
        client_sap=1,
        mechanism=Mechanism.HLS_GMAC,
        security=security,
        ciphered_context=False,
        timeout=10,
    ) as meter:
        assert meter.get("0.0.42.0.0.255").value == b"GRX2"
        assert meter.association.state.value == "associated"


def test_stale_invocation_counter_is_reported(gurux):
    host, port = gurux.endpoint(DEFAULT)
    client = DlmsClient.tcp(
        host, port, client_sap=1, mechanism=Mechanism.HLS_GMAC, security=_security(0), timeout=10
    )
    with pytest.raises(AssociationError, match="INVOCATION_COUNTER_ERROR"):
        client.connect()
    client.link.disconnect()


def test_invocation_counter_discovery_against_gurux(gurux):
    # Own container: after refusing a stale association the Gurux server
    # addresses its next reply to the previous client SAP (server-side state
    # leak), which pydlms correctly rejects.
    host, port = gurux.endpoint(DEFAULT, instance="discovery")
    security = _security(0)  # stale on purpose; discovery must fix it
    with DlmsClient.tcp(
        host,
        port,
        client_sap=1,
        mechanism=Mechanism.HLS_GMAC,
        security=security,
        discover_invocation_counter=True,
        timeout=10,
    ) as meter:
        assert meter.get("0.0.42.0.0.255").value == b"GRX2"


def test_invocation_counter_retry_against_gurux(gurux):
    host, port = gurux.endpoint(DEFAULT)
    with DlmsClient.tcp(
        host,
        port,
        client_sap=1,
        mechanism=Mechanism.HLS_GMAC,
        security=_security(0),
        invocation_counter_retry=True,
        timeout=10,
    ) as meter:
        assert meter.get_association_view()


@pytest.mark.parametrize(
    "tx,rx,works",
    [
        # Gurux refuses an SNRM proposing 16-octet information fields with an
        # FRMR carrying no information field.
        (16, 16, False),
        # A small transmit size is fine: our AARQ goes in 32-octet segments.
        (32, 128, True),
        # Gurux defect: when its AARE (43 octets) has to be segmented, the
        # second segment carries control 0x97 (FRMR) instead of an I-frame
        # control, so the link ends. 48 octets fit the AARE and work, and
        # larger segmented responses (the object list) are fine.
        (128, 32, False),
        (128, 40, False),
        (48, 48, True),
    ],
)
def test_small_hdlc_information_fields(gurux, tx, rx, works):
    from pydlms.exceptions import FrameRejectError
    from pydlms.hdlc.connection import HdlcParameters

    host, port = gurux.endpoint(DEFAULT, "HDLC")
    params = HdlcParameters(max_info_tx=tx, max_info_rx=rx)
    meter = DlmsClient.tcp(host, port, hdlc=True, timeout=5, hdlc_parameters=params)
    if works:
        with meter:
            assert meter.link.negotiated.max_info_rx == rx
            assert meter.get_association_view()
        return
    with pytest.raises(FrameRejectError):
        meter.connect()
    meter.link.transport.close()
