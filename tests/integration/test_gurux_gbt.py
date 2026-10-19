"""General-block-transfer against the Gurux server.

No shipped Gurux template grants general-block-transfer, so the test
patches a copy of ``GMacWithAuthenticationEncyption.xml`` at test time
(nothing of it is vendored): every association's conformance gains the
Gurux ``GeneralBlockTransfer`` bit (0x4 in its enumeration,
``Enums/Conformance.cs``).

What this shows against an independent server:

* a SET longer than its 1024-octet PDU goes in GBT blocks of our making
  (window 1: Gurux advertises window 1 in its acknowledgements; the
  simulator's ``-W`` sets its client-side window, not the server's), and
  Gurux answers it in plain (a GBT request does not force a GBT answer
  there);
* Gurux numbers its acknowledgement blocks, which pydlms follows;
* the association view, longer than one block, still reads afterwards.

Known Gurux limitation, pinned: a ciphered (glo-) request in GBT is never
answered. Its server reassembles the blocks but hands the ciphered APDU to
a command switch with no glo- cases (``GXDLMSServer.HandleCommand``), so
nothing comes back; after the timeout pydlms sends one recovery
acknowledgement, which Gurux answers with an empty wrapper PDU.
"""

from __future__ import annotations

import shutil
import subprocess
import time

import pytest

from pydlms.client import DlmsClient
from pydlms.cosem.data import DlmsData
from pydlms.debug import FrameRecorder
from pydlms.exceptions import DecodeError
from pydlms.security.hls import Mechanism
from pydlms.wrapper import HEADER_SIZE
from tests.docker_ready import wait_listening

pytestmark = pytest.mark.integration
IMAGE = "pydlms-gurux-sim"
TEMPLATE = "/templates/GMacWithAuthenticationEncyption.xml"
SECRET = b"Gurux"
EK = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
AK = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")
#: Gurux Conformance: GET | SET | SELECTIVE_ACCESS | EVENT_NOTIFICATION |
#: ACTION, and GET alone (public client); 0x4 is GeneralBlockTransfer.
_PATCH = {"16252928": "16252932", "524288": "524292"}


def _docker(*args: str) -> str:
    return subprocess.run(  # noqa: S603,S607
        ["docker", *args], check=True, capture_output=True, text=True, timeout=120
    ).stdout.strip()


def _patch(template: str) -> str:
    for old, new in _PATCH.items():
        tag = f"<Conformance>{old}</Conformance>"
        if tag not in template:
            raise ValueError(f"template has no {tag}")
        template = template.replace(tag, f"<Conformance>{new}</Conformance>")
    return template


@pytest.fixture(scope="module")
def template_dir(tmp_path_factory):
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    try:
        _docker("image", "inspect", IMAGE)
    except subprocess.CalledProcessError:
        pytest.skip(f"image {IMAGE} missing: docker build -t {IMAGE} tests/integration/gurux")
    template = _docker("run", "--rm", "--entrypoint", "cat", IMAGE, TEMPLATE).lstrip("﻿")
    directory = tmp_path_factory.mktemp("tpl-gbt")
    directory.chmod(0o755)
    path = directory / "gbt.xml"
    path.write_text(_patch(template), encoding="utf-8")
    path.chmod(0o644)
    return directory


def _start(directory, *args: str) -> tuple[str, int]:
    cid = _docker(
        "run",
        "-d",
        "--rm",
        "-p",
        "127.0.0.1::4060",
        "-v",
        f"{directory}:/custom:ro",
        "-e",
        "SIM_TEMPLATE=/custom/gbt.xml",
        IMAGE,
        *args,
    )
    port = int(_docker("port", cid, "4060").splitlines()[0].rsplit(":", 1)[1])
    for _ in range(180):
        logs = subprocess.run(  # noqa: S603,S607
            ["docker", "logs", cid], capture_output=True, text=True, timeout=30
        )
        if "simulator start in" in logs.stdout + logs.stderr:
            wait_listening(port, "Gurux simulator")
            return cid, port
        time.sleep(0.5)
    _docker("rm", "-f", cid)
    pytest.fail("Gurux simulator did not come up")


@pytest.fixture(scope="module")
def gurux_gbt(template_dir):
    cid, port = _start(template_dir)
    yield port
    subprocess.run(["docker", "rm", "-f", cid], capture_output=True, timeout=60)  # noqa: S603,S607


def _apdus(recorder: FrameRecorder, direction: str) -> list[bytes]:
    """Wrapper APDUs of one direction (each transport write/read is one PDU
    here, except reads, which come as header then body)."""
    data = b"".join(d for kind, d in recorder.frames if kind == direction)
    out = []
    while len(data) >= HEADER_SIZE:
        length = int.from_bytes(data[6:8], "big")
        out.append(data[HEADER_SIZE : HEADER_SIZE + length])
        data = data[HEADER_SIZE + length :]
    return out


def test_long_set_goes_in_gbt(gurux_gbt):
    port = gurux_gbt
    recorder = FrameRecorder()
    meter = DlmsClient.tcp(
        "127.0.0.1",
        port,
        timeout=10,
        client_sap=18,
        mechanism=Mechanism.HLS,
        password=SECRET,
        propose_gbt=True,
    )
    meter.link.transport.recorder = recorder
    with meter:
        assoc = meter.association
        assert assoc.uses_gbt and assoc.server_max_pdu == 1024
        # Association LN secret (attribute 7, write-only): 4000 octets.
        meter.set("0.0.40.0.0.255", 15, 7, DlmsData.octet_string(b"Q" * 4000))
        assert assoc._gbt_peer_window == 1
        view = meter.get_association_view()
        assert len(view) >= 10
    sent = [a for a in _apdus(recorder, "TX") if a[:1] == b"\xe0"]
    flags = [(a[1] & 0x40 != 0, a[1] & 0x80 != 0) for a in sent]
    assert flags[-1] == (False, True) and len(sent) == 4  # 4017 octets / 1015
    assert not any(streaming for streaming, _ in flags)
    acks = [a for a in _apdus(recorder, "RX") if a[:1] == b"\xe0" and a[6] == 0]
    assert [(a[1], a[2:4], a[4:6]) for a in acks] == [
        (0x81, n.to_bytes(2, "big"), n.to_bytes(2, "big")) for n in (1, 2, 3)
    ]


def test_ciphered_gbt_request_is_not_answered(template_dir):
    """Pinned Gurux limitation (see the module docstring)."""
    pytest.importorskip("cryptography")
    from pydlms.security.context import SecurityContext

    cid, port = _start(template_dir)
    try:
        security = SecurityContext(EK, AK, client_system_title=b"PYDLMS01", invocation_counter=100)
        with DlmsClient.tcp(
            "127.0.0.1",
            port,
            timeout=2,
            client_sap=1,
            mechanism=Mechanism.HLS_GMAC,
            security=security,
            propose_gbt=True,
        ) as meter:
            assert meter.association.uses_gbt
            with pytest.raises(DecodeError, match="empty response APDU"):
                meter.set("0.0.40.0.0.255", 15, 7, DlmsData.octet_string(b"Q" * 1500))
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True, timeout=60)  # noqa: S603,S607
