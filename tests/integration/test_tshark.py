"""Wireshark's DLMS dissector as an independent decoder of what we send.

A real pydlms session against the simulator is recorded, written to a pcap
and dissected by tshark >= 4.6 (``pydlms-tshark`` image, see
``tests/integration/tshark/Dockerfile``). Wireshark's dissector is a separate
reading of the standard: if it flags a frame as malformed or names a
different service, one of us is wrong.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from pydlms.apdu.xdlms import (
    AttributeDescriptor,
    DataNotification,
    EventNotificationRequest,
    entry_descriptor,
)
from pydlms.client import DlmsClient
from pydlms.cosem.data import DlmsData
from pydlms.cosem.interface_classes import ClassId
from pydlms.debug import FrameRecorder
from pydlms.obis import ObisCode
from pydlms.simulator import example_meter, serve
from pydlms.wrapper import HEADER_SIZE, decode_header, encode_wrapper
from tests.integration.pcap import write_pcap

pytestmark = pytest.mark.integration
IMAGE = "pydlms-tshark"


def _image_available() -> bool:
    if shutil.which("docker") is None:
        return False
    result = subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True)  # noqa: S603,S607
    return result.returncode == 0


def _wrapper_pdus(frames: list[tuple[str, bytes]]) -> list[tuple[str, bytes]]:
    """Regroup transport reads/writes into whole wrapper PDUs per direction."""
    out = []
    buffers = {"TX": bytearray(), "RX": bytearray()}
    for direction, data in frames:
        if direction not in buffers:  # TX-APDU/RX-APDU plaintext lines
            continue
        buf = buffers[direction]
        buf += data
        while len(buf) >= HEADER_SIZE:
            total = HEADER_SIZE + decode_header(bytes(buf[:HEADER_SIZE])).length
            if len(buf) < total:
                break
            out.append((direction, bytes(buf[:total])))
            del buf[:total]
    return out


@pytest.fixture(scope="module")
def dissection(tmp_path_factory):
    if not _image_available():
        pytest.skip(
            f"docker image {IMAGE} missing: docker build -t {IMAGE} tests/integration/tshark"
        )
    sim = example_meter(max_pdu=256)
    sim.add_method(  # return data larger than one APDU: action-response-with-pblock
        ClassId.DATA, "0.0.42.0.0.255", 1, lambda s, p: DlmsData.octet_string(bytes(600))
    )
    server = serve(sim)
    recorder = FrameRecorder()
    meter = DlmsClient.tcp(*server.server_address, timeout=5)
    meter.link.transport.recorder = recorder
    try:
        with meter:
            meter.get_register("1.0.1.8.0.255")
            meter.read_profile("1.0.99.1.0.255", entry_descriptor(1, 40))  # block transfer
            meter.set("0.0.96.1.0.255", ClassId.DATA, 2, DlmsData.visible_string("TSHARK"))
            meter.action("0.0.96.3.10.255", ClassId.DISCONNECT_CONTROL, 1, DlmsData.int8(0))
            meter.get_many([("1.0.1.8.0.255", 3, 2), ("1.0.2.8.0.255", 3, 2)])
            meter.set_many(
                [
                    ("0.0.96.1.0.255", ClassId.DATA, 2, DlmsData.visible_string("A")),
                    ("0.0.42.0.0.255", ClassId.DATA, 2, DlmsData.octet_string(b"B")),
                ]
            )
            meter.action_many(
                [
                    ("0.0.96.3.10.255", ClassId.DISCONNECT_CONTROL, 2, DlmsData.int8(0)),
                    ("0.0.96.3.10.255", ClassId.DISCONNECT_CONTROL, 1, DlmsData.int8(0)),
                ]
            )
            meter.action("0.0.42.0.0.255", ClassId.DATA, 1, DlmsData.int8(0))
    finally:
        server.shutdown()
        server.server_close()
    directory = tmp_path_factory.mktemp("pcap")
    directory.chmod(0o755)
    pcap = directory / "session.pcap"
    # Unsolicited pushes the meter would send: DataNotification and
    # EventNotification-Request, built by pydlms.
    pushes = [
        DataNotification(7, DlmsData.structure([DlmsData.uint32(1234)])).to_bytes(),
        EventNotificationRequest(
            AttributeDescriptor(ClassId.DATA, ObisCode.parse("0.0.96.11.0.255"), 2),
            DlmsData.uint16(42),
        ).to_bytes(),
    ]
    pdus = _wrapper_pdus(recorder.frames) + [("RX", encode_wrapper(1, 16, p)) for p in pushes]
    write_pcap(pcap, pdus)
    pcap.chmod(0o644)
    result = subprocess.run(  # noqa: S603,S607
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{directory}:/work:ro",
            IMAGE,
            "-r",
            "/work/session.pcap",
            "-O",
            "dlms,cosem",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    return result.stdout


def test_no_frame_is_malformed(dissection):
    assert "Malformed" not in dissection
    assert "Not implemented in the DLMS dissector" not in dissection


@pytest.mark.parametrize(
    "needle",
    [
        "APDU: aarq (96)",
        "2.16.756.5.8.1.1 (Logical Name Referencing, Without Ciphering)",
        "Conformance: 007e1f",
        "APDU: aare (97)",
        "result: accepted (0)",
        "get-request-normal",
        "get-response-normal",
        "get-request-next",
        "get-response-with-datablock",
        "set-request-normal",
        "set-response-normal",
        "action-request-normal",
        "action-response-normal",
        "get-request-with-list",
        "get-response-with-list",
        "set-request-with-list",
        "set-response-with-list",
        "action-request-with-list",
        "action-response-with-list",
        "action-response-with-pblock",
        "action-request-next-pblock",
        "data-notification",
        "event-notification-request",
        "APDU: rlrq (98)",
        "APDU: rlre (99)",
    ],
)
def test_wireshark_names_every_service(dissection, needle):
    assert needle in dissection


# --- HDLC frames built by pydlms ------------------------------------------------

# set-request-normal with the unconfirmed service class (Invoke-Id 0x81).
_UNCONFIRMED_SET = bytes.fromhex("c10181000100006001 00ff02000a0141".replace(" ", ""))


@pytest.fixture(scope="module")
def hdlc_dissection(tmp_path_factory):
    """UI frames (unconfirmed, broadcast, push trigger) and SNRMs with the
    two-octet max-info layout and a user data subfield, dissected by
    Wireshark's HDLC reading (it does not decode the APDU of a UI frame)."""
    if not _image_available():
        pytest.skip(
            f"docker image {IMAGE} missing: docker build -t {IMAGE} tests/integration/tshark"
        )
    from pydlms.hdlc.address import HdlcAddress
    from pydlms.hdlc.connection import HdlcLink, HdlcParameters
    from pydlms.hdlc.framing import FrameType, HdlcFrame, encode_frame
    from pydlms.transports.base import LoopbackTransport

    transport = LoopbackTransport()
    transport.open()
    link = HdlcLink(transport, timeout=0.01)
    link.send_unconfirmed(_UNCONFIRMED_SET)
    link.send_unconfirmed(_UNCONFIRMED_SET, broadcast=True)
    link.trigger_pushes()
    frames = list(transport.sent)
    for params, user_data in (
        (HdlcParameters(1024, 1024), b"\x01\x02"),
        (HdlcParameters(256, 128), b""),
    ):
        frames.append(
            encode_frame(
                HdlcFrame(
                    HdlcAddress.server(1),
                    HdlcAddress.client(16),
                    FrameType.SNRM | 0x10,
                    params.to_bytes(user_data),
                )
            )
        )
    directory = tmp_path_factory.mktemp("pcap-hdlc")
    directory.chmod(0o755)
    pcap = directory / "hdlc.pcap"
    write_pcap(pcap, [("TX", frame) for frame in frames])
    pcap.chmod(0o644)
    result = subprocess.run(  # noqa: S603,S607
        ["docker", "run", "--rm", "-v", f"{directory}:/work:ro", IMAGE]
        + ["-r", "/work/hdlc.pcap", "-O", "dlms"],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    return result.stdout


def test_hdlc_frames_are_not_malformed(hdlc_dissection):
    assert "Malformed" not in hdlc_dissection
    assert hdlc_dissection.count("UI (Unnumbered Information) (3)") == 3
    assert hdlc_dissection.count("SNRM (Set Normal Response Mode) (131)") == 2


@pytest.mark.parametrize(
    "needle,count",
    [
        ("...0 .... = Poll/Final: 0", 2),  # unconfirmed and broadcast UI
        ("Upper HDLC Address: 127", 1),  # broadcast to the all-station address
        ("Maximum Information Field Length Transmit: 1024", 1),
        ("Maximum Information Field Length Receive: 1024", 1),
        ("Maximum Information Field Length Transmit: 256", 1),
        ("Maximum Information Field Length Receive: 128", 1),
        ("Window Size Transmit: 1", 2),
    ],
)
def test_wireshark_reads_our_hdlc_fields(hdlc_dissection, needle, count):
    assert hdlc_dissection.count(needle) == count


# --- general-block-transfer --------------------------------------------------------


@pytest.fixture(scope="module")
def gbt_dissection(tmp_path_factory):
    """A session with GBT both ways: a SET longer than the simulator's PDU
    sent in GBT blocks, a profile read answered in GBT blocks."""
    if not _image_available():
        pytest.skip(
            f"docker image {IMAGE} missing: docker build -t {IMAGE} tests/integration/tshark"
        )
    from pydlms.apdu.xdlms import Conformance

    sim = example_meter(max_pdu=256)
    sim.conformance |= Conformance.GENERAL_BLOCK_TRANSFER
    server = serve(sim)
    recorder = FrameRecorder()
    meter = DlmsClient.tcp(
        *server.server_address, timeout=5, propose_gbt=True, max_receive_pdu_size=512
    )
    meter.link.transport.recorder = recorder
    try:
        with meter:
            meter.set("0.0.42.0.0.255", ClassId.DATA, 2, DlmsData.octet_string(bytes(600)))
            meter.read_profile("1.0.99.1.0.255")
    finally:
        server.shutdown()
        server.server_close()
    pdus = _wrapper_pdus(recorder.frames)
    directory = tmp_path_factory.mktemp("pcap-gbt")
    directory.chmod(0o755)
    pcap = directory / "gbt.pcap"
    write_pcap(pcap, pdus)
    pcap.chmod(0o644)
    result = subprocess.run(  # noqa: S603,S607
        ["docker", "run", "--rm", "-v", f"{directory}:/work:ro", IMAGE]
        + ["-r", "/work/gbt.pcap", "-O", "dlms,cosem"],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    gbt = sum(pdu[HEADER_SIZE] == 0xE0 for _, pdu in pdus)
    return result.stdout, gbt


def test_gbt_frames_are_not_malformed(gbt_dissection):
    """Wireshark 4.6 has no GBT decoder: it shows each GBT APDU as
    "Unknown (224)" and does not flag it. Its conformance bit 2 (our
    general-block-transfer) is still called reserved2 there, so it pins the
    bit position only."""
    text, gbt = gbt_dissection
    assert "Malformed" not in text
    assert gbt > 4 and text.count("APDU: Unknown (224)") == gbt
    assert "Conformance: 207e1f" in text
    assert "..1. .... = reserved2: True" in text
