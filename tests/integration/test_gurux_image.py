"""Image transfer (IC 18) against the Gurux server.

The Gurux template ``GMacWithAuthenticationEncyption.xml`` holds an image
transfer object (0.0.44.0.0.255, block size 512), but no association lists
it and its methods have no access, so every GET is read-write-denied. The
test patches a copy of the template (at test time, nothing of it is
vendored): the public client's object list (SAP 16) gains the object and
the object's method access becomes 1111.

What this proves against an independent server:

* the full process, verify and activate, with Gurux's status values and its
  attr 7 entry naming the initiated identifier;
* the attr 3 bit order: after blocks 1 and 9 of 10 only, Gurux's bit-string
  decodes to bits 1 and 9 set, i.e. bit n = block n, numbered from the most
  significant bit (still unverified against a real meter);
* Gurux's attr 4 is the block after the highest one received (10 here, with
  blocks 0 and 2..8 missing), not the first missing block, so a resume from
  attr 4 alone would skip holes; the attr 3 round after it closes them.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import time

import pytest

from pydlms.client import DlmsClient
from pydlms.cosem.data import DlmsData
from pydlms.cosem.enums import DataType
from pydlms.cosem.interface_classes import ClassId
from pydlms.cosem.model import ImageTransferStatus
from pydlms.image import missing_blocks, transfer_image
from tests.docker_ready import wait_listening

pytestmark = pytest.mark.integration
IMAGE = "pydlms-gurux-sim"
TEMPLATE = "/templates/GMacWithAuthenticationEncyption.xml"
OBIS = "0.0.44.0.0.255"


def _docker(*args: str) -> str:
    return subprocess.run(  # noqa: S603,S607
        ["docker", *args], check=True, capture_output=True, text=True, timeout=120
    ).stdout.strip()


def _patch(template: str) -> str:
    """List the image transfer object for the public client, methods allowed."""
    public = template.index("<ClientSAP>16</ClientSAP>")
    start = template.rindex("<ObjectList>", 0, public)
    entry = (
        "<GXDLMSImageTransfer><LN>0.0.44.0.0.255</LN><Access>1333333</Access>"
        "<MethodAccess>1111</MethodAccess></GXDLMSImageTransfer>"
    )
    text = template[: start + len("<ObjectList>")] + entry + template[start + len("<ObjectList>") :]
    text, count = re.subn(
        r"(<LN>0\.0\.44\.0\.0\.255</LN>\s*<Access>\d+</Access>\s*)<MethodAccess>0000</MethodAccess>",
        r"\1<MethodAccess>1111</MethodAccess>",
        text,
    )
    if count != 1:
        raise ValueError("template has no image transfer object with method access 0000")
    return text


@pytest.fixture(scope="module")
def gurux_port(tmp_path_factory):
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    try:
        _docker("image", "inspect", IMAGE)
    except subprocess.CalledProcessError:
        pytest.skip(f"image {IMAGE} missing: docker build -t {IMAGE} tests/integration/gurux")
    template = _docker("run", "--rm", "--entrypoint", "cat", IMAGE, TEMPLATE).lstrip("﻿")
    directory = tmp_path_factory.mktemp("tpl")
    directory.chmod(0o755)
    path = directory / "image.xml"
    path.write_text(_patch(template), encoding="utf-8")
    path.chmod(0o644)
    cid = _docker(
        "run",
        "-d",
        "--rm",
        "-p",
        "127.0.0.1::4060",
        "-v",
        f"{directory}:/custom:ro",
        "-e",
        "SIM_TEMPLATE=/custom/image.xml",
        IMAGE,
    )
    try:
        port = int(_docker("port", cid, "4060").splitlines()[0].rsplit(":", 1)[1])
        for _ in range(180):
            logs = subprocess.run(  # noqa: S603,S607
                ["docker", "logs", cid], capture_output=True, text=True, timeout=30
            )
            if "simulator start in" in logs.stdout + logs.stderr:
                break
            time.sleep(0.5)
        else:
            pytest.fail("Gurux simulator did not come up")
        wait_listening(port, "Gurux simulator")
        yield port
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True, timeout=60)  # noqa: S603,S607


def _u32(value: int) -> DlmsData:
    return DlmsData(DataType.DOUBLE_LONG_UNSIGNED, value)


def test_transfer_verify_and_activate(gurux_port):
    image = bytes(range(256)) * 5  # 1280 octets: 3 blocks of 512
    with DlmsClient.tcp("127.0.0.1", gurux_port, timeout=10) as meter:
        result = transfer_image(meter, image, b"PYDTEST", activate=True, poll=0.1, timeout=30)
        assert meter.get(OBIS, ClassId.IMAGE_TRANSFER, 3).value == [True] * 3
    assert (result.block_size, result.blocks, result.sent, result.rounds) == (512, 3, 3, 1)
    assert result.status == ImageTransferStatus.ACTIVATION_SUCCESSFUL
    assert result.activation_confirmed
    assert [
        (i.image_to_activate_size, i.image_to_activate_identification)
        for i in result.images_to_activate
    ] == [(len(image), b"PYDTEST")]


def test_bit_string_order_and_attr_4(gurux_port):
    image = bytes(512 * 10)
    with DlmsClient.tcp("127.0.0.1", gurux_port, timeout=10) as meter:
        meter.action(
            OBIS,
            ClassId.IMAGE_TRANSFER,
            1,
            DlmsData.structure([DlmsData.octet_string(b"BITS"), _u32(len(image))]),
        )
        for n in (1, 9):
            meter.action(
                OBIS,
                ClassId.IMAGE_TRANSFER,
                2,
                DlmsData.structure([_u32(n), DlmsData.octet_string(image[:512])]),
            )
        bits = meter.get(OBIS, ClassId.IMAGE_TRANSFER, 3)
        assert missing_blocks(bits, 10) == [0, 2, 3, 4, 5, 6, 7, 8]
        assert meter.get(OBIS, ClassId.IMAGE_TRANSFER, 4).value == 10
