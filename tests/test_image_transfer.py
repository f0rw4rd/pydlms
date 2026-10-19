"""Image transfer (IC 18) client, end to end against the simulator's
stateful image transfer object.

The process (enable check, block size, initiate, blocks, missing-block
bit-string, verify, activate) follows the Blue Book IC 18 description as
far as it is known here; the clause text was not read (*unverified*), the
order was cross-checked against the cB-Sigma client (Apache-2.0).
"""

from __future__ import annotations

import os

import pytest

from pydlms.apdu.tags import Tag
from pydlms.client import DlmsClient
from pydlms.cosem.data import DlmsData, encode_data
from pydlms.cosem.enums import DataType
from pydlms.cosem.interface_classes import ClassId
from pydlms.cosem.model import ImageTransferStatus
from pydlms.exceptions import (
    DecodeError,
    DlmsTimeoutError,
    ProtocolError,
    ServiceError,
)
from pydlms.image import ImageTransferResult, missing_blocks, transfer_image
from pydlms.obis import ObisCode
from pydlms.simulator import ImageTransferTarget, example_meter, serve

OBIS = "0.0.44.0.0.255"
IMAGE = bytes(range(256)) * 2 + b"tail"  # 516 octets: 9 blocks of 64, last of 4
IDENT = b"PYD-FW-2.0"


@pytest.fixture
def meter():
    sim = example_meter()
    servers = []

    def start(target: ImageTransferTarget | None = None, sn: bool = False):
        if target is not None:
            target.install(sim, OBIS, base_name=0x5000 if sn else None)
        server = serve(sim)
        servers.append(server)
        return server.server_address

    sim.start = start
    yield sim
    for server in servers:
        server.shutdown()
        server.server_close()


def connect(meter, target, **kw) -> DlmsClient:
    sn = kw.get("logical_names") is False
    host, port = meter.start(target, sn=sn)
    return DlmsClient.tcp(host, port, timeout=3, **kw)


def block_requests(meter) -> int:
    """ACTION-Request-Normal calls of method 2 on the IC 18 object."""
    prefix = bytes([Tag.ACTION_REQUEST, 1])
    method = bytes([0, ClassId.IMAGE_TRANSFER]) + bytes([0, 0, 44, 0, 0, 255, 2])
    return sum(1 for r in meter.requests if r.startswith(prefix) and r[3:12] == method)


# --- happy path -------------------------------------------------------------------------


def test_transfer_verifies_and_reports(meter):
    target = ImageTransferTarget()
    seen = []
    with connect(meter, target) as client:
        result = transfer_image(
            client, IMAGE, IDENT, progress=lambda n, total: seen.append((n, total))
        )
    assert isinstance(result, ImageTransferResult)
    assert target.image() == IMAGE
    assert target.identifier == IDENT and target.size == len(IMAGE)
    assert target.status == ImageTransferStatus.VERIFICATION_SUCCESSFUL
    assert (result.block_size, result.blocks, result.sent, result.rounds) == (64, 9, 9, 1)
    assert result.resumed is False
    assert result.status == ImageTransferStatus.VERIFICATION_SUCCESSFUL
    assert result.activated is False and result.activation_confirmed is False
    assert [
        (i.image_to_activate_size, i.image_to_activate_identification)
        for i in result.images_to_activate
    ] == [(len(IMAGE), IDENT)]
    assert seen == [(n, 9) for n in range(1, 10)]
    assert block_requests(meter) == 9


def test_result_repr_never_shows_image_bytes(meter):
    secret = b"\xde\xad\xbe\xef" * 40
    target = ImageTransferTarget()
    with connect(meter, target) as client:
        result = transfer_image(client, secret, IDENT)
    assert "deadbeef" not in repr(result).lower() and "\\xde\\xad" not in repr(result)


def test_exact_multiple_of_the_block_size(meter):
    target = ImageTransferTarget(block_size=16)
    with connect(meter, target) as client:
        result = transfer_image(client, bytes(64), IDENT)
    assert result.blocks == 4 and target.image() == bytes(64)


def test_never_logs_image_content(meter, caplog):
    marker = b"SECRETFIRMWARE!!" * 8
    target = ImageTransferTarget()
    caplog.set_level("DEBUG")
    with connect(meter, target) as client:
        transfer_image(client, marker, IDENT)
    text = caplog.text
    assert "SECRETFIRMWARE" not in text
    assert marker.hex()[:32] not in text.lower()


# --- resume -----------------------------------------------------------------------------


def test_resume_after_an_interrupted_transfer(meter):
    target = ImageTransferTarget(drop_blocks={5: 99})
    with connect(meter, target) as client:
        with pytest.raises(ServiceError, match="after 1 round"):
            transfer_image(client, IMAGE, IDENT, max_rounds=1)
    target.drop_blocks.clear()
    target.received.clear()
    with connect(meter, target) as client:
        result = transfer_image(client, IMAGE, IDENT)
    assert result.resumed is True
    assert target.received == [5, 6, 7, 8]  # attr 4 said: from block 5
    assert target.image() == IMAGE


def test_resume_from_the_meters_first_missing_block(meter):
    target = ImageTransferTarget(resume_from=3)
    with connect(meter, target) as client:
        result = transfer_image(client, IMAGE, IDENT)
    assert result.resumed is True and result.sent == 6
    assert target.received == list(range(3, 9))


# --- lost blocks -------------------------------------------------------------------------


def test_lost_blocks_are_resent_from_the_bit_string(meter):
    target = ImageTransferTarget(drop_blocks=[1, 4, 8])
    with connect(meter, target) as client:
        result = transfer_image(client, IMAGE, IDENT)
    assert target.image() == IMAGE
    assert result.rounds == 2 and result.sent == 12
    assert target.received[-3:] == [1, 4, 8]


def test_progress_counts_blocks_held_across_rounds(meter):
    target = ImageTransferTarget(drop_blocks=[1, 4], resume_from=2)
    seen = []
    with connect(meter, target) as client:
        transfer_image(client, IMAGE, IDENT, progress=lambda n, total: seen.append(n))
    # resumed at block 2 (2 held), 7 sent, then 4 resent (1 was claimed)
    assert seen == [3, 4, 5, 6, 7, 8, 9, 9]


def test_lost_blocks_found_through_attr_4_without_a_bit_string(meter):
    target = ImageTransferTarget(drop_blocks=[6])
    with connect(meter, target) as client:
        meter_attrs = meter.objects[(ClassId.IMAGE_TRANSFER, ObisCode.parse(OBIS))]
        del meter_attrs[3]  # attr 3 unavailable: fall back to attr 4
        result = transfer_image(client, IMAGE, IDENT)
    assert target.image() == IMAGE
    assert result.rounds == 2 and target.received[-3:] == [6, 7, 8]


def test_persistent_loss_fails_after_max_rounds(meter):
    target = ImageTransferTarget(drop_blocks={2: 99})
    with connect(meter, target) as client:
        with pytest.raises(ServiceError, match="block 2") as err:
            transfer_image(client, IMAGE, IDENT, max_rounds=3)
    assert "3 rounds" in str(err.value)
    assert target.received.count(2) == 0
    assert block_requests(meter) == 9 + 1 + 1
    assert target.status == ImageTransferStatus.INITIATED  # never verified


# --- verify -----------------------------------------------------------------------------


def test_verify_polls_through_temporary_failure(meter):
    target = ImageTransferTarget(verify_steps=3)
    with connect(meter, target) as client:
        result = transfer_image(client, IMAGE, IDENT, poll=0)
    assert result.status == ImageTransferStatus.VERIFICATION_SUCCESSFUL


@pytest.mark.parametrize("steps", [0, 2])
def test_verify_failed(meter, steps):
    target = ImageTransferTarget(verify_steps=steps, fail_verify=True)
    with connect(meter, target) as client:
        with pytest.raises(ServiceError, match="verif"):
            transfer_image(client, IMAGE, IDENT, poll=0, activate=True)
    assert not target.activated


def test_verify_polling_times_out(meter):
    target = ImageTransferTarget(verify_steps=10**9)
    with connect(meter, target) as client:
        with pytest.raises(DlmsTimeoutError):
            transfer_image(client, IMAGE, IDENT, poll=0, timeout=0.2)


def test_unexpected_status_while_verifying(meter):
    target = ImageTransferTarget(verify_steps=1)
    with connect(meter, target) as client:
        target.overrides[6] = DlmsData.enum(ImageTransferStatus.ACTIVATION_FAILED)
        with pytest.raises(ProtocolError, match="status"):
            transfer_image(client, IMAGE, IDENT, poll=0)


def test_image_to_activate_info_mismatch_is_refused(meter):
    target = ImageTransferTarget()
    target.overrides[7] = DlmsData.array(
        [
            DlmsData.structure(
                [
                    DlmsData.uint32(len(IMAGE)),
                    DlmsData.octet_string(b"OTHER"),
                    DlmsData.octet_string(b""),
                ]
            )
        ]
    )
    with connect(meter, target) as client:
        with pytest.raises(ServiceError, match="image_to_activate_info"):
            transfer_image(client, IMAGE, IDENT, activate=True)
        assert not target.activated
        result = transfer_image(client, IMAGE, IDENT, check_info=False)
    assert result.status == ImageTransferStatus.VERIFICATION_SUCCESSFUL


# --- activate ---------------------------------------------------------------------------


@pytest.mark.parametrize("steps", [0, 2])
def test_activate(meter, steps):
    target = ImageTransferTarget(activate_steps=steps)
    with connect(meter, target) as client:
        result = transfer_image(client, IMAGE, IDENT, activate=True, poll=0)
    assert target.activated
    assert result.activated and result.activation_confirmed
    assert result.status == ImageTransferStatus.ACTIVATION_SUCCESSFUL


@pytest.mark.parametrize("steps", [0, 2])
def test_activate_failed(meter, steps):
    target = ImageTransferTarget(activate_steps=steps, fail_activate=True)
    with connect(meter, target) as client:
        with pytest.raises(ServiceError, match="activat"):
            transfer_image(client, IMAGE, IDENT, activate=True, poll=0)
    assert target.status == ImageTransferStatus.ACTIVATION_FAILED


def test_activate_with_an_association_drop_is_unconfirmed(meter):
    target = ImageTransferTarget(drop_on_activate=True)
    client = connect(meter, target).connect()
    try:
        result = transfer_image(client, IMAGE, IDENT, activate=True, poll=0)
    finally:
        client.link.disconnect()
    assert target.activated
    assert result.activated is True and result.activation_confirmed is False


# --- refusals before anything is written ---------------------------------------------


def test_disabled_object_is_refused(meter):
    target = ImageTransferTarget(enabled=False)
    with connect(meter, target) as client:
        with pytest.raises(ServiceError, match="not enabled"):
            transfer_image(client, IMAGE, IDENT)
    assert target.identifier is None


@pytest.mark.parametrize("size", [0, 4096])
def test_block_size_zero_or_oversize_is_refused(meter, size):
    target = ImageTransferTarget(block_size=size)
    with connect(meter, target) as client:
        with pytest.raises(ProtocolError, match="block size"):
            transfer_image(client, IMAGE, IDENT)
    assert target.identifier is None


def test_largest_block_that_fits_the_pdu_is_accepted(meter):
    # 1024-octet server PDU: request header 7+9+1 ... leaves room for 1000.
    target = ImageTransferTarget(block_size=1000)
    with connect(meter, target) as client:
        result = transfer_image(client, IMAGE * 3, IDENT)
    assert result.blocks == 2 and target.image() == IMAGE * 3


@pytest.mark.parametrize(
    "image,identifier,kw",
    [
        (b"", IDENT, {}),
        (IMAGE, b"", {}),
        (IMAGE, IDENT, {"max_rounds": 0}),
        (IMAGE, IDENT, {"poll": -1}),
    ],
)
def test_bad_arguments(meter, image, identifier, kw):
    target = ImageTransferTarget()
    with connect(meter, target) as client:
        with pytest.raises(ValueError):
            transfer_image(client, image, identifier, **kw)
    assert target.identifier is None


# --- untrusted meter values ---------------------------------------------------------


@pytest.mark.parametrize(
    "attr,value,error",
    [
        (5, DlmsData.uint8(1), DecodeError),
        (2, DlmsData.boolean(True), DecodeError),
        (4, DlmsData.uint32(10), ProtocolError),  # beyond the 9 blocks
        (4, DlmsData.int8(-1), ProtocolError),
        (3, DlmsData.uint8(1), DecodeError),
        (3, DlmsData(DataType.BIT_STRING, [True] * 8), DecodeError),  # 8 < 9 blocks
        (6, DlmsData.octet_string(b"\x03"), DecodeError),
        (7, DlmsData.uint32(1), DecodeError),
    ],
)
def test_malformed_meter_values(meter, attr, value, error):
    target = ImageTransferTarget(verify_steps=1)
    target.overrides[attr] = value
    with connect(meter, target) as client:
        with pytest.raises(error):
            transfer_image(client, IMAGE, IDENT, poll=0)


def test_longer_bit_string_is_accepted(meter):
    target = ImageTransferTarget()
    target.overrides[3] = DlmsData(DataType.BIT_STRING, [True] * 9 + [False] * 7)
    with connect(meter, target) as client:
        result = transfer_image(client, IMAGE, IDENT)
    assert result.rounds == 1


# --- bit order -----------------------------------------------------------------------


def test_bit_string_bit_n_is_block_n_msb_first():
    """attr 3 bit n is block n, bits numbered MSB first within each octet.

    Pinned vector, *unverified* against a meter: blocks 0, 1 and 9 of 11
    transferred encode as ``04 0B C0 40`` (bit-string, 11 bits).
    """
    bits = DlmsData(DataType.BIT_STRING, [n in (0, 1, 9) for n in range(11)])
    assert encode_data(bits) == bytes.fromhex("040BC040")
    assert missing_blocks(bits, 11) == [2, 3, 4, 5, 6, 7, 8, 10]


def test_missing_blocks_validates_the_bit_string():
    with pytest.raises(DecodeError):
        missing_blocks(DlmsData(DataType.BIT_STRING, [True] * 3), 4)
    with pytest.raises(DecodeError):
        missing_blocks(DlmsData.octet_string(b"\xff"), 4)


# --- short names ------------------------------------------------------------------------


def test_short_name_referencing(meter):
    target = ImageTransferTarget(drop_blocks=[3], verify_steps=1)
    with connect(meter, target, logical_names=False) as client:
        result = transfer_image(client, IMAGE, IDENT, activate=True, poll=0)
    assert target.image() == IMAGE and target.activated
    assert result.rounds == 2 and result.activation_confirmed


def test_random_image_round_trip(meter):
    image = os.urandom(1500)
    target = ImageTransferTarget(block_size=200, drop_blocks=[0, 7])
    with connect(meter, target) as client:
        transfer_image(client, image, IDENT)
    assert target.image() == image
