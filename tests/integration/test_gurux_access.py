"""The ACCESS service against the Gurux server.

No shipped Gurux template grants ACCESS, so a copy of
``GMacWithAuthenticationEncyption.xml`` is patched at test time (nothing
of it is vendored): every association's conformance gains the Gurux
``Access`` bit (0x20000 in its enumeration, ``Enums/Conformance.cs``; ASN.1
bit 17). Gurux's ``HandleAccessRequest`` takes kinds 1..3 (get, set,
action) only; it answers gets correctly, plain and in general-glo, and
sets and actions with a response pydlms must refuse (see below).
"""

from __future__ import annotations

import itertools
import shutil
import subprocess

import pytest

from pydlms import AccessAction, AccessGet, AccessSet
from pydlms.client import DlmsClient
from pydlms.cosem.data import DlmsData
from pydlms.cosem.enums import DataAccessResult
from pydlms.debug import FrameRecorder
from pydlms.exceptions import DecodeError
from pydlms.security.hls import Mechanism
from tests.integration import test_gurux_gbt as gbt

pytestmark = pytest.mark.integration
_COUNTERS = itertools.count(1000, 1000)
#: GET | SET | SELECTIVE_ACCESS | EVENT_NOTIFICATION | ACTION (and GET
#: alone for the public client) plus Access 0x20000.
_PATCH = {"16252928": str(16252928 | 0x20000), "524288": str(524288 | 0x20000)}


@pytest.fixture(scope="module")
def template_dir(tmp_path_factory):
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    try:
        gbt._docker("image", "inspect", gbt.IMAGE)
    except subprocess.CalledProcessError:
        pytest.skip(
            f"image {gbt.IMAGE} missing: docker build -t {gbt.IMAGE} tests/integration/gurux"
        )
    template = gbt._docker("run", "--rm", "--entrypoint", "cat", gbt.IMAGE, gbt.TEMPLATE)
    template = template.lstrip("\ufeff")
    for old, new in _PATCH.items():
        tag = f"<Conformance>{old}</Conformance>"
        if tag not in template:
            raise ValueError(f"template has no {tag}")
        template = template.replace(tag, f"<Conformance>{new}</Conformance>")
    directory = tmp_path_factory.mktemp("tpl-access")
    directory.chmod(0o755)
    path = directory / "gbt.xml"  # the name gbt._start mounts
    path.write_text(template, encoding="utf-8")
    path.chmod(0o644)
    return directory


@pytest.fixture(scope="module")
def gurux_access(template_dir):
    cid, port = gbt._start(template_dir)
    yield port
    subprocess.run(["docker", "rm", "-f", cid], capture_output=True, timeout=60)  # noqa: S603,S607


def _meter(port: int, **kw) -> DlmsClient:
    if not kw:
        kw = {"client_sap": 18, "mechanism": Mechanism.HLS, "password": gbt.SECRET}
    return DlmsClient.tcp("127.0.0.1", port, timeout=10, propose_access=True, **kw)


def _ciphered(protection: str) -> dict:
    pytest.importorskip("cryptography")
    from pydlms.security.context import SecurityContext

    # one server for the module: every association continues the counter
    counter = next(_COUNTERS)
    security = SecurityContext(
        gbt.EK, gbt.AK, client_system_title=b"PYDLMS01", invocation_counter=counter
    )
    return {
        "client_sap": 1,
        "mechanism": Mechanism.HLS_GMAC,
        "security": security,
        "protection": protection,
    }


@pytest.mark.parametrize("protection", ["plain", "glo", "general-glo"])
def test_access_get_kind_1(gurux_access, protection):
    """Gurux answers ACCESS gets, plain and ciphered (pydlms sends general-glo
    under ``protection="glo"``; Gurux answers in the same envelope). The
    clock's time is read-protected in this template for both clients."""
    recorder = FrameRecorder()
    meter = _meter(gurux_access, **({} if protection == "plain" else _ciphered(protection)))
    meter.link.transport.recorder = recorder
    with meter:
        assert meter.association.access_negotiated
        out = meter.access([AccessGet("0.0.42.0.0.255", 1, 2), AccessGet("0.0.1.0.0.255", 8, 2)])
    assert out[0].ok and out[0].data == DlmsData.octet_string(b"GRX2")
    assert out[1].result == DataAccessResult.READ_WRITE_DENIED
    assert out[1].data == DlmsData.null()
    tx = [f for kind, f in recorder.frames if kind == "TX-APDU" and f[:1] == b"\xd9"]
    assert tx and tx[0][1:5] == bytes.fromhex("c0000001")
    if protection != "plain":
        wire = b"".join(f for kind, f in recorder.frames if kind == "TX")
        assert b"\xd9\xc0\x00\x00\x01" not in wire  # ciphered, never in clear


@pytest.mark.parametrize(
    "op",
    [
        AccessSet("0.0.42.0.0.255", 1, 2, DlmsData.octet_string(b"GRX2")),
        AccessAction("0.0.1.0.0.255", 8, 1, DlmsData.int8(0)),
    ],
    ids=["set", "action"],
)
def test_access_set_and_action_answers_are_malformed(gurux_access, op):
    """Pinned Gurux defect: ``HandleAccessRequest`` writes a result for a
    set or an action but no Data for it in the access-response-list-of-data
    (``DA c0000001 00 00 01 | 01 02 00``: one data announced, none sent), so
    the counts cannot hold and pydlms refuses the response rather than
    guess. (It also answers Success without running the set or action.)"""
    with _meter(gurux_access) as meter, pytest.raises(DecodeError):
        meter.access([op])
