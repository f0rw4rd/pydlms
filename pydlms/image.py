"""Image transfer (IC 18): send a firmware image to a meter.

:func:`transfer_image` runs the client side of the image transfer process on
an open :class:`~pydlms.client.DlmsClient` (LN or SN referencing):

1. ``image_transfer_enabled`` (attr 5) must be true, else nothing is sent.
2. ``image_block_size`` (attr 2) must be non-zero and small enough that one
   ``image_block_transfer`` request fits the negotiated PDU.
3. ``image_transfer_initiate`` (method 1) with ``{identifier, size}``.
4. ``image_first_not_transferred_block_number`` (attr 4) says where to
   start: a meter holding part of the same image resumes.
5. ``image_block_transfer`` (method 2) ``{n, octets}`` per block. After
   each round ``image_transferred_blocks_status`` (attr 3, a bit-string)
   names the blocks still missing (attr 4 when attr 3 is not readable);
   they are sent again, up to ``max_rounds`` rounds.
6. ``image_verify`` (method 3). A meter that verifies in the background
   answers temporary-failure; ``image_transfer_status`` (attr 6) is polled
   until verification succeeded or failed.
7. ``image_to_activate_info`` (attr 7), when readable and not empty, must
   list the image just sent (``check_info``).
8. Optionally ``image_activate`` (method 4) with the same polling. A meter
   that restarts into the new image may drop the association instead of
   answering; that is reported as an unconfirmed activation, not an error.

Sources: DLMS UA 1000-1 (Blue Book) IC 18 attribute and method list as
modelled in :mod:`pydlms.cosem.model`; the step order is per DLMS UA 1000-1
Ed. 13 Excerpt 4.4.6.2 (steps 1 and 6 optional, verification and
activation initiated by the client or by the server on its own) and
ImageBlocks are numbered from 0 (3.1); the temporary-failure polling was
cross-checked against the cB-Sigma client (Apache-2.0, ``cosem/image.go``),
not copied. The IC specification (4.4.6.3) is not in the public excerpts,
so the following are *unverified*: the bit order of attr 3 (bit n = block
n, bits numbered from the most significant bit of the first octet, the
A-XDR bit-string order of :mod:`pydlms.cosem.data`; the excerpt only notes
that the bit-string size "may be dynamic"), that verify/activate take
``integer(0)``, and the status values that may be seen while the meter is
still working. Of the ``image_transfer_status`` values only 3 = "Image
verification successful" is restated publicly (DSMR P3 4.2.2, Netbeheer
Nederland 2014, 5.12).

Every value the meter supplies is validated before use. Image contents are
never logged; only block numbers and sizes are.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace

from pydlms.apdu import sn, xdlms
from pydlms.cosem.data import DlmsData
from pydlms.cosem.enums import DataType
from pydlms.cosem.interface_classes import ClassId
from pydlms.cosem.model import ImageToActivate, ImageTransferStatus, spec_for
from pydlms.debug import get_logger
from pydlms.exceptions import (
    DecodeError,
    DlmsTimeoutError,
    ProtocolError,
    ServiceError,
    TransportError,
)
from pydlms.obis import ObisCode

__all__ = ["ImageTransferResult", "missing_blocks", "transfer_image"]

log = get_logger("image")

_IC = ClassId.IMAGE_TRANSFER
_TEMPORARY_FAILURE = 2  # Action-Result and Data-Access-Result share the code
_S = ImageTransferStatus


@dataclass(frozen=True)
class ImageTransferResult:
    """What :func:`transfer_image` did. Holds no image content."""

    identifier: bytes
    image_size: int
    block_size: int
    #: Blocks in the image.
    blocks: int
    #: ``image_block_transfer`` calls made, resends included.
    sent: int
    #: Rounds of block sending (1 when nothing had to be sent again).
    rounds: int
    #: The meter already held the first blocks of this image.
    resumed: bool
    #: Last transfer status known (attr 6, or implied by a SUCCESS answer).
    status: ImageTransferStatus | int
    #: ``image_activate`` was sent and not refused.
    activated: bool = False
    #: The meter confirmed the activation (SUCCESS or status
    #: activation-successful); False after an association drop.
    activation_confirmed: bool = False
    #: ``image_to_activate_info`` (attr 7) as read after verification.
    images_to_activate: list[ImageToActivate] = field(default_factory=list)


def transfer_image(
    client,
    image: bytes,
    identifier: bytes,
    obis: ObisCode | str = "0.0.44.0.0.255",
    activate: bool = False,
    poll: float = 1.0,
    timeout: float = 300.0,
    progress: Callable[[int, int], None] | None = None,
    max_rounds: int = 3,
    check_info: bool = True,
) -> ImageTransferResult:
    """Send ``image`` to the Image transfer object ``obis`` and verify it.

    ``identifier`` is the image_identifier of ``image_transfer_initiate``.
    ``progress(done, total)`` is called after each block sent: ``done`` is
    the number of blocks the meter should now hold (it restarts below
    ``total`` when a round resends missing blocks), ``total`` the count.
    ``poll`` is the pause between status reads and ``timeout`` bounds each
    wait for verification or activation (:class:`DlmsTimeoutError`).

    Raises :class:`ServiceError` when the meter refuses (transfer disabled,
    blocks still missing after ``max_rounds``, verification or activation
    failed), :class:`ProtocolError` for an unusable block size or block
    number and :class:`DecodeError` for a malformed attribute value.
    """
    image = bytes(image)
    identifier = bytes(identifier)
    if not image:
        raise ValueError("the image is empty")
    if len(image) > 0xFFFFFFFF:
        raise ValueError("the image exceeds the 32-bit image_size")
    if not identifier:
        raise ValueError("the image identifier is empty")
    if max_rounds < 1:
        raise ValueError("max_rounds must be at least 1")
    if poll < 0 or timeout <= 0:
        raise ValueError("poll must be >= 0 and timeout > 0")
    obis = ObisCode.parse(obis) if isinstance(obis, str) else obis
    transfer = _Transfer(client, obis)

    if not transfer.attribute(5):
        raise ServiceError(f"image transfer is not enabled in {obis} (image_transfer_enabled)")
    block_size = transfer.attribute(2)
    if block_size <= 0:
        raise ProtocolError(f"the meter's image block size is {block_size}")
    room = transfer.largest_block()
    if block_size > room:
        raise ProtocolError(
            f"the meter's image block size {block_size} does not fit the negotiated PDU "
            f"(at most {room} octets per block)"
        )
    blocks = -(-len(image) // block_size)
    log.info(
        "image transfer %s: %d octets in %d blocks of %d", obis, len(image), blocks, block_size
    )

    transfer.action(
        1,
        DlmsData.structure(
            [DlmsData.octet_string(identifier), DlmsData(DataType.DOUBLE_LONG_UNSIGNED, len(image))]
        ),
        "image_transfer_initiate",
    )
    first = transfer.first_missing(blocks)
    missing = list(range(first, blocks))
    resumed = first > 0
    if resumed:
        log.info("image transfer resumes at block %d", first)

    rounds = sent = 0
    while missing:
        if rounds == max_rounds:
            raise ServiceError(
                f"the meter still misses {len(missing)} block(s), first block {missing[0]}, "
                f"after {max_rounds} round{'s' if max_rounds > 1 else ''}"
            )
        rounds += 1
        if rounds > 1:
            log.info("image transfer round %d: resending %d block(s)", rounds, len(missing))
        held = blocks - len(missing)
        for number in missing:
            chunk = image[number * block_size : (number + 1) * block_size]
            transfer.action(
                2,
                DlmsData.structure(
                    [DlmsData(DataType.DOUBLE_LONG_UNSIGNED, number), DlmsData.octet_string(chunk)]
                ),
                f"image_block_transfer {number}",
            )
            sent += 1
            held += 1
            log.debug("image block %d/%d sent (%d octets)", number + 1, blocks, len(chunk))
            if progress is not None:
                progress(held, blocks)
        missing = transfer.missing(blocks)

    status: ImageTransferStatus | int
    if transfer.deferred(3, "image_verify"):
        status = transfer.wait(
            _S.VERIFICATION_SUCCESSFUL,
            _S.VERIFICATION_FAILED,
            (_S.INITIATED, _S.VERIFICATION_INITIATED),
            poll,
            timeout,
            "verification",
        )
    else:
        status = _S.VERIFICATION_SUCCESSFUL
    log.info("image %s verified", identifier.hex())

    info = transfer.activate_info()
    if (
        check_info
        and info
        and not any(
            e.image_to_activate_identification == identifier
            and e.image_to_activate_size == len(image)
            for e in info
        )
    ):
        raise ServiceError(
            "the meter's image_to_activate_info does not list the image just verified "
            f"({identifier.hex()}, {len(image)} octets)"
        )
    result = ImageTransferResult(
        identifier=identifier,
        image_size=len(image),
        block_size=block_size,
        blocks=blocks,
        sent=sent,
        rounds=rounds,
        resumed=resumed,
        status=status,
        images_to_activate=info,
    )
    if not activate:
        return result

    lost = False
    try:
        deferred = transfer.deferred(4, "image_activate")
    except TransportError as exc:
        log.warning("association lost on image_activate (%s); activation unconfirmed", exc)
        deferred, lost = False, True
    if deferred:
        polled = transfer.wait(
            _S.ACTIVATION_SUCCESSFUL,
            _S.ACTIVATION_FAILED,
            (_S.VERIFICATION_SUCCESSFUL, _S.ACTIVATION_INITIATED),
            poll,
            timeout,
            "activation",
            lost_ok=True,
        )
        if polled is None:
            lost = True
        else:
            status = polled
    elif not lost:
        status = _S.ACTIVATION_SUCCESSFUL
    if not lost:
        log.info("image %s activated", identifier.hex())
    return replace(result, status=status, activated=True, activation_confirmed=not lost)


def missing_blocks(bits: DlmsData, blocks: int) -> list[int]:
    """Block numbers ``image_transferred_blocks_status`` reports missing.

    Bit n is block n, numbered from the most significant bit of the first
    octet (*unverified* against a meter). The bit-string must cover every
    block; bits beyond the image are ignored.
    """
    if bits.tag != DataType.BIT_STRING:
        raise DecodeError(f"image_transferred_blocks_status is {bits.tag.name}, not a bit-string")
    flags = list(bits.value)
    if len(flags) < blocks:
        raise DecodeError(
            f"image_transferred_blocks_status has {len(flags)} bits for {blocks} blocks"
        )
    return [n for n in range(blocks) if not flags[n]]


class _Transfer:
    """GET/ACTION on one Image transfer object, with value validation."""

    def __init__(self, client, obis: ObisCode) -> None:
        self.client = client
        self.obis = obis
        self.spec = spec_for(_IC)
        assert self.spec is not None

    def get(self, attribute: int) -> DlmsData:
        return self.client.get(self.obis, _IC, attribute)

    def attribute(self, index: int):
        """Attr 2, 4 (non-negative integers) or 5 (boolean), validated."""
        spec = self.spec.attribute(index)
        value = spec.type.decode(self.get(index), spec.name)
        if index != 5 and value < 0:
            raise ProtocolError(f"{spec.name} is negative ({value})")
        return value

    def largest_block(self) -> int:
        """Most octets one image_block_transfer request can carry."""
        association = self.client.association
        empty = self._block_request(b"")
        # The A-XDR length of the octet-string grows from 1 to 3 octets.
        return max(0, association.max_plain_request() - len(empty) - 2)

    def _block_request(self, chunk: bytes) -> bytes:
        params = DlmsData.structure(
            [DlmsData(DataType.DOUBLE_LONG_UNSIGNED, 0), DlmsData.octet_string(chunk)]
        )
        if self.client.association.settings.logical_names:
            descriptor = xdlms.MethodDescriptor(int(_IC), self.obis, 2)
            return xdlms.ActionRequestNormal(0, descriptor, params).to_bytes()
        return sn.ReadRequest([sn.ParameterizedAccess(0, 0, params)]).to_bytes()

    def action(self, method: int, params: DlmsData, what: str) -> None:
        try:
            self.client.action(self.obis, _IC, method, params)
        except ServiceError as exc:
            raise ServiceError(f"{what} refused: {exc}", exc.result) from exc

    def deferred(self, method: int, what: str) -> bool:
        """Run verify/activate; True when the meter answered temporary-failure."""
        try:
            self.client.action(self.obis, _IC, method, DlmsData.int8(0))
        except ServiceError as exc:
            if exc.result is not None and int(exc.result) == _TEMPORARY_FAILURE:
                log.debug("%s in progress, polling image_transfer_status", what)
                return True
            raise ServiceError(f"{what} failed: {exc}", exc.result) from exc
        return False

    def first_missing(self, blocks: int) -> int:
        first = self.attribute(4)
        if first > blocks:
            raise ProtocolError(
                f"image_first_not_transferred_block_number {first} is beyond the {blocks} blocks"
            )
        return first

    def missing(self, blocks: int) -> list[int]:
        try:
            bits = self.get(3)
        except ServiceError as exc:
            log.debug("image_transferred_blocks_status not readable (%s); using attr 4", exc)
            return list(range(self.first_missing(blocks), blocks))
        return missing_blocks(bits, blocks)

    def status(self) -> ImageTransferStatus | int:
        spec = self.spec.attribute(6)
        return spec.type.decode(self.get(6), spec.name)

    def wait(self, good, bad, working, poll, timeout, what, lost_ok=False):
        """Poll attr 6 until ``good``; None when the association is lost
        and ``lost_ok`` (a meter restarting into a new image)."""
        deadline = time.monotonic() + timeout
        while True:
            try:
                status = self.status()
            except TransportError as exc:
                if not lost_ok:
                    raise
                log.warning("association lost during image %s (%s); unconfirmed", what, exc)
                return None
            if status == good:
                return status
            if status == bad:
                raise ServiceError(f"image {what} failed (image_transfer_status {status})")
            if status not in working:
                raise ProtocolError(f"unexpected image_transfer_status {status} during {what}")
            if time.monotonic() >= deadline:
                raise DlmsTimeoutError(
                    f"image {what} still in progress after {timeout:g} s (status {status})"
                )
            time.sleep(poll)

    def activate_info(self) -> list[ImageToActivate]:
        try:
            value = self.get(7)
        except ServiceError as exc:
            log.debug("image_to_activate_info not readable (%s)", exc)
            return []
        spec = self.spec.attribute(7)
        return list(spec.type.decode(value, spec.name))
