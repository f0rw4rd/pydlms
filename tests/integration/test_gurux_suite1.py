"""Suite 1 (ECDH/ECDSA, AES-GCM-128) interop against the Gurux server.

Uses the Gurux template's suite-1 association (client SAP 44, security setup
0.0.43.0.1.255) with a test-generated client identity
(``tests/integration/gurux_ecdsa.py``). What is proven here against an
independent implementation:

* HLS mechanism 7 (ECDSA): Gurux verifies our f(StoC), we verify its f(CtoS).
* Suite-1 glo- ciphering both ways (SC 0x31).
* general-ciphering with an agreed key (one-pass DH): Gurux derives the same
  content key from our ephemeral key (ECDH + SP 800-56A KDF) and accepts the
  APDU - the first independent check of the suite 1/2 KDF.
* general-signing: Gurux verifies our signature over a glo- APDU.

Gurux defects found on the way (pydlms behaves correctly in each case):

* its ECDSA association ships with an empty object list, so its keys never
  load (patched in the test template);
* it answers a stale invocation counter with ``<IC> D8 01 06`` (counter
  before the ExceptionResponse tag);
* it emits general-signing replies without a signature when its own signing
  mode is unset - pydlms rejects them (asserted below);
* it crashes (NullReference) building a general-ciphering reply to a GET.
"""

from __future__ import annotations

import shutil
import subprocess
import time

import pytest

from pydlms.client import DlmsClient
from pydlms.exceptions import DecodeError
from pydlms.security.hls import Mechanism
from tests.docker_ready import wait_listening

pytestmark = pytest.mark.integration
IMAGE = "pydlms-gurux-sim"
EK = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
AK = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")
KEK = bytes.fromhex("31" * 16)  # <Kek> of the Gurux simulator templates


def _docker(*args: str) -> str:
    return subprocess.run(  # noqa: S603,S607
        ["docker", *args], check=True, capture_output=True, text=True, timeout=120
    ).stdout.strip()


@pytest.fixture(scope="module")
def suite1(tmp_path_factory):
    pytest.importorskip("cryptography")
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    try:
        _docker("image", "inspect", IMAGE)
    except subprocess.CalledProcessError:
        pytest.skip(f"image {IMAGE} missing: docker build -t {IMAGE} tests/integration/gurux")
    from tests.integration.gurux_ecdsa import build

    template = _docker(
        "run",
        "--rm",
        "--entrypoint",
        "cat",
        IMAGE,
        "/templates/GMacWithAuthenticationEncyption.xml",
    )
    started = []

    def start(ciphered_context: bool):
        directory = tmp_path_factory.mktemp("tpl")
        directory.chmod(0o755)
        ident = build(template, directory, ciphered_context=ciphered_context)
        cid = _docker(
            "run",
            "-d",
            "--rm",
            "-p",
            "127.0.0.1::4060",
            "-v",
            f"{directory}:/custom:ro",
            "-e",
            "SIM_TEMPLATE=/custom/ecdsa.xml",
            IMAGE,
        )
        started.append(cid)
        port = int(_docker("port", cid, "4060").splitlines()[0].rsplit(":", 1)[1])
        for _ in range(180):
            if (
                "simulator start in"
                in subprocess.run(  # noqa: S603,S607
                    ["docker", "logs", cid], capture_output=True, text=True
                ).stdout
            ):
                break
            time.sleep(0.5)
        wait_listening(port, "Gurux simulator")
        return ident, port

    yield start
    for cid in started:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True)  # noqa: S603,S607


def _client(ident, port, protection=None, key_info=None, **kw) -> DlmsClient:
    from pydlms.security.context import SecurityContext
    from pydlms.security.general import KeyInfo
    from tests.integration.gurux_ecdsa import CLIENT_TITLE

    settings = {
        "client_sap": 44,
        "mechanism": Mechanism.HLS_ECDSA,
        "signing_key": ident.signing_key,
        "server_public_key": ident.server_signing_public,
        "client_system_title": CLIENT_TITLE,
        "timeout": 15,
    }
    if protection is not None:
        settings["security"] = SecurityContext(
            EK,
            AK,
            client_system_title=CLIENT_TITLE,
            suite=1,
            invocation_counter=1000,
            signing_key=ident.signing_key,
            key_agreement_key=ident.agreement_key,
            peer_signing_key=ident.server_signing_public,
            peer_key_agreement_key=ident.server_agreement_public,
            master_key=KEK,
        )
        settings.update(protection=protection, key_info=key_info or KeyInfo("agreed"))
    settings.update(kw)
    return DlmsClient.tcp("127.0.0.1", port, **settings)


def test_ecdsa_authentication_plain_context(suite1):
    ident, port = suite1(ciphered_context=False)
    with _client(ident, port) as meter:
        assert meter.get("0.0.42.0.0.255").value == b"GRX2"


def test_suite1_glo_ciphering_round_trip(suite1):
    ident, port = suite1(ciphered_context=True)
    with _client(ident, port, protection="glo") as meter:
        assert meter.get("0.0.42.0.0.255").value == b"GRX2"
        assert meter.association.security.server_system_title == bytes.fromhex("4752580000000001")


# Only the agreed-key forms: the Gurux server parses key-info as a fixed
# agreed-key header (GXSecure.cs:651-660 @ 6f263019) and never answers an
# identified-key, wrapped-key or absent key-info general-ciphering APDU
# (observed: no reply). Those forms are covered against our own simulator.
@pytest.mark.parametrize(
    "key_info",
    [
        ("agreed", 0, 1),  # one-pass Diffie-Hellman
        ("agreed", 0, 2),  # static unified model, with a transaction-id
    ],
    ids=["one-pass-dh", "static-unified"],
)
def test_general_ciphering_key_info_accepted_by_gurux(suite1, key_info):
    """HLS pass 3 travels as general-ciphering with the given key-info; the
    association only completes if Gurux established the same content key
    (for agreed keys: ECDH + KDF interop; wrapped: RFC 3394 under the KEK)."""
    from pydlms.security.general import KeyInfo

    kind, key_id, scheme = key_info
    ident, port = suite1(ciphered_context=True)
    client = _client(
        ident, port, protection="general-ciphering", key_info=KeyInfo(kind, key_id, scheme)
    )
    client.connect()
    try:
        assert client.association.state.value == "associated"
        assert client.association.security.invocation_counter > 1001
    finally:
        client.link.disconnect()


def test_general_signing_verified_by_gurux_and_unsigned_reply_rejected(suite1):
    ident, port = suite1(ciphered_context=True)
    client = _client(ident, port, protection="glo+signing")
    client.connect()  # pass 3 is signed: Gurux verified our signature
    try:
        with pytest.raises(DecodeError, match="no signature"):
            client.get("0.0.42.0.0.255")
    finally:
        client.link.disconnect()
