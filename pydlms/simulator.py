"""A small DLMS/COSEM meter simulator (server side), for tests and debugging.

Not a conformance-tested server: it implements just enough of the server role
to exercise every client feature end to end without hardware:

* AARQ/AARE with no security, LLS, HLS MD5/SHA-1/SHA-256/GMAC, ciphered
  (glo-) associations and dedicated keys; RLRQ/RLRE (ciphered in a ciphered
  context).
* GET (normal, with-list, with-datablock for large values), SET (normal,
  block, with-list and with-list-and-first-datablock), ACTION (normal,
  pblock, with-list and with-list-and-first-pblock), selective access by
  entry on a profile.
* Short-Name READ/WRITE on the same object model, including requests sent
  in read-/write-data-block-access parts.
* Wrapper framing over TCP and HDLC framing over TCP or any byte stream.
* Pushes on the association's connection ahead of the next response
  (:meth:`MeterSimulator.push_before_response`): plain or ciphered, to the
  client's or another wPort, as HDLC UI frame or I-frame.

Objects are stored as ``{(class_id, obis): {attribute: DlmsData}}``; methods
are Python callables. Run one with ``python -m pydlms.simulator --port 4059``.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hmac
import logging
import os
import socketserver
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from pydlms.apdu import sn, xdlms
from pydlms.apdu.acse import AARE, AARQ, RLRE, RLRQ
from pydlms.apdu.gbt import GbtTransfer, decode_gbt, gbt_overhead
from pydlms.apdu.tags import Tag
from pydlms.apdu.xdlms import Conformance, InitiateRequest, InitiateResponse
from pydlms.cosem.data import (
    DlmsData,
    TypeDescription,
    decode_data,
    encode_data,
    encode_type_description,
    encode_untagged,
)
from pydlms.cosem.enums import ActionResult, DataAccessResult, DataType
from pydlms.cosem.interface_classes import ClassId
from pydlms.cosem.time import CosemDateTime
from pydlms.debug import get_logger
from pydlms.exceptions import DlmsError, ProtocolError
from pydlms.hdlc.address import HdlcAddress
from pydlms.hdlc.connection import HdlcParameters, max_window
from pydlms.hdlc.framing import (
    LLC_RESPONSE,
    MODULO_128,
    PF_BIT,
    SEQ_MODULUS,
    FrameReader,
    FrameType,
    HdlcFrame,
    control_i,
    control_rej,
    control_rr,
    encode_frame,
    seq_add,
    strip_llc,
)
from pydlms.mbus import MbusFrame, MbusReader, decode_mbus_frame, encode_mbus_frame
from pydlms.mbus_link import (
    ADDRESS_BROADCAST,
    ADDRESS_NETWORK_LAYER,
    ADDRESS_TEST,
    C_FCB,
    C_FCV,
    C_REQ_UD2,
    C_RSP_UD,
    C_SND_NKE,
    C_SND_UD,
    CI_SELECT,
    decode_link_frame,
    encode_long_frame,
)
from pydlms.obis import ObisCode
from pydlms.security.hls import Mechanism, default_challenge_length
from pydlms.wrapper import HEADER_SIZE, decode_header, encode_wrapper

__all__ = [
    "MeterSimulator",
    "ClientProfile",
    "SimulatedPush",
    "HdlcServer",
    "MbusServer",
    "serve",
    "serve_mbus",
    "example_meter",
]

log = get_logger("simulator")

#: CI of the RSP_UD a :class:`MbusServer` sends while no DLMS response is
#: queued: 0x72, variable data respond (M-Bus documentation 4.8 Table 4,
#: OMS Vol. 2 Table 1), here the 12-octet fixed data header (doc 4.8
#: 6.3.1) and no data records.
CI_VARIABLE_DATA = 0x72

ASSOCIATION_LN = ObisCode(0, 0, 40, 0, 0, 255)


@dataclass
class ClientProfile:
    """How the simulator accepts one client SAP."""

    mechanism: Mechanism = Mechanism.NONE
    secret: bytes | None = None
    ciphered: bool = False
    #: Client's ECDSA public key (mechanism 7).
    client_public_key: object | None = None
    #: f(challenge, secret) for mechanism 2 (default: AES-128-ECB convention).
    hls2_function: object | None = None


@dataclass
class _Session:
    client_sap: int = 16
    associated: bool = False
    hls_pending: bool = False
    profile: ClientProfile | None = None
    ctos: bytes = b""
    stoc: bytes = b""
    client_title: bytes | None = None
    ciphered: bool = False
    dedicated: bool = False
    logical_names: bool = True
    client_max_pdu: int = 0xFFFF
    #: Plain InitiateResponse of the AARE, ciphered again in the RLRE.
    initiate_response: bytes = b""
    block: list[bytes] = field(default_factory=list)
    block_invoke: int = 0
    set_buffer: bytearray = field(default_factory=bytearray)
    action_buffer: bytearray = field(default_factory=bytearray)
    pending_action: object = None
    action_reply: list[bytes] = field(default_factory=list)
    action_reply_invoke: int = 0
    #: SN read-/write-data-block-access transfer: parts so far, the block
    #: number expected next (0: none in progress) and the request tag.
    sn_parts: bytearray = field(default_factory=bytearray)
    sn_part_next: int = 0
    sn_part_tag: int = 0
    #: General-block-transfer: negotiated in the AARE, the exchange in
    #: progress and the client's receive window as last advertised.
    gbt_negotiated: bool = False
    gbt: GbtTransfer | None = None
    gbt_peer_window: int = 1
    #: The ACCESS service (conformance bit 17) was negotiated.
    access_negotiated: bool = False


@dataclass(frozen=True)
class SimulatedPush:
    """A push the server loops send just before the next response."""

    #: The APDU as sent (already ciphered when asked for).
    apdu: bytes
    #: Wrapper destination wPort; None: the requesting client's wPort.
    wport: int | None = None
    #: HDLC: ``"ui"`` (UI frame) or ``"i"`` (I-frame ahead of the response).
    hdlc_frame: str = "ui"


_ONE = _dt.timedelta(seconds=1)


class ActionFailure(DlmsError):
    """Raised by a method handler to answer the ACTION with ``result``.

    Without it every handled ACTION answers SUCCESS. Over SN referencing the
    READ on the method address carries the data-access-result with the same
    code and name (the enumerations agree on 0..14), else other-reason.
    """

    def __init__(self, result: ActionResult | int) -> None:
        if result == ActionResult.SUCCESS:
            raise ValueError("ActionFailure needs a non-success result")
        super().__init__(f"action refused: {result}")
        self.result = result


def _sn_method_error(result: int) -> DataAccessResult:
    """The data-access-result with the same code and meaning as ``result``."""
    try:
        twin = DataAccessResult(int(result))
        same = twin.name == ActionResult(int(result)).name
    except ValueError:
        return DataAccessResult.OTHER_REASON
    return twin if same else DataAccessResult.OTHER_REASON


def _instant(value: DlmsData) -> _dt.datetime | None:
    """A date-time value as a comparable instant, or None when it has none.

    Blue Book 4.1.6.1: day-of-week, seconds and hundredths may be "not
    specified" without changing the instant; the deviation shifts it to UTC.
    Without a deviation the local wall clock is compared as is.
    """
    try:
        stamp = CosemDateTime.from_bytes(bytes(value.value))
        if not stamp.is_fully_specified:
            return None
        when = stamp.to_datetime()
    except (TypeError, ValueError):
        return None
    if when.tzinfo is not None:
        when = when.astimezone(_dt.timezone.utc).replace(tzinfo=None)
    return when


class MeterSimulator:
    """In-memory COSEM server. ``handle(apdu, session)`` returns the response."""

    def __init__(
        self,
        system_title: bytes = b"PYD\x00\x00\x00\x00\x01",
        encryption_key: bytes | None = None,
        authentication_key: bytes | None = None,
        max_pdu: int = 1024,
        conformance: Conformance | None = None,
    ) -> None:
        self.objects: dict[tuple[int, ObisCode], dict[int, DlmsData]] = {}
        self.versions: dict[tuple[int, ObisCode], int] = {}
        self.base_names: dict[tuple[int, ObisCode], int] = {}
        self.methods: dict[tuple[int, ObisCode, int], Callable] = {}
        self.clients: dict[int, ClientProfile] = {16: ClientProfile()}
        self.system_title = system_title
        self.encryption_key = encryption_key
        self.authentication_key = authentication_key
        self.max_pdu = max_pdu
        self.conformance = conformance or (
            Conformance.default_ln()
            | Conformance.GENERAL_PROTECTION
            | Conformance.DATA_NOTIFICATION
            | Conformance.ACCESS
        )
        self.security = None
        if encryption_key:
            from pydlms.security.context import SecurityContext

            self.security = SecurityContext(
                encryption_key, authentication_key, client_system_title=system_title
            )
        self.lock = threading.Lock()
        self.requests: list[bytes] = []
        #: Where the client's invocation counter is exposed to the public
        #: client (standard 0.0.43.1.0.255; tests move it to mimic vendors).
        self.ic_obis = ObisCode(0, 0, 43, 1, 0, 255)
        self._last_client_ic = 0
        self._ic_seen = False  # a fresh meter accepts any first counter
        self.last_client_ic = 0  # publishes the counter object when ciphering
        #: Server ECDSA private key (mechanism 7); set by the caller.
        self.signing_key = None
        #: Methods handled by the typed-model default: (class, obis, name, value).
        self.calls: list[tuple] = []
        #: Association LN class version the object list's access rights are
        #: encoded for (0: boolean method modes, 3: bit maps). When set, the
        #: view also lists the association 0.0.40.0.0.255 with that version.
        self.association_version: int | None = None
        #: Access overrides ``(class_id, obis, attribute) -> mode`` (and the
        #: same for methods), enforced on GET/SET/ACTION; ``None`` leaves the
        #: item out of the view. Others: attribute 1 read-only, the rest
        #: read-and-write, every method accessible. See :meth:`set_access`.
        self.attribute_access: dict[tuple[int, ObisCode, int], int | None] = {}
        self.method_access: dict[tuple[int, ObisCode, int], int | None] = {}
        #: Pushes to send ahead of the next response (push_before_response).
        self.pending_pushes: list[SimulatedPush] = []
        #: General-block-transfer (when the client negotiates it): our
        #: receive window, whether we stream a window (False: one block at
        #: a time), and the recovery bound.
        self.gbt_window = 1
        self.gbt_streaming = True
        self.gbt_max_retransmissions = 3
        #: Test hooks: numbers of our own GBT blocks to lose once on the way
        #: out, and of the client's GBT blocks to ignore once on the way in.
        self.drop_gbt_blocks: set[int] = set()
        self.drop_gbt_requests: set[int] = set()

    def push_before_response(
        self,
        apdu: bytes,
        *,
        protection: str | None = None,
        wport: int | None = None,
        hdlc_frame: str = "ui",
    ) -> bytes:
        """Send ``apdu`` (a notification) on the connection just before the
        next response, as a meter pushing during a request does.

        ``protection``: None (as given), ``"glo"`` (key-specific glo-, for
        EventNotification / InformationReport) or ``"general-glo"``, with the
        simulator's keys and its own outbound invocation counter, taken now.
        Returns the APDU as it will be sent.
        """
        if hdlc_frame not in ("ui", "i"):
            raise ValueError(f"hdlc_frame must be 'ui' or 'i', not {hdlc_frame!r}")
        if protection is not None:
            from pydlms.security.ciphering import wrap, wrap_general_glo

            if self.security is None:
                raise ValueError("a ciphered push needs the simulator's keys")
            if protection == "glo":
                apdu = wrap(self.security, apdu)
            elif protection == "general-glo":
                apdu = wrap_general_glo(self.security, apdu)
            else:
                raise ValueError(f"unknown protection {protection!r}")
        with self.lock:
            self.pending_pushes.append(SimulatedPush(apdu, wport, hdlc_frame))
        return apdu

    def take_pushes(self) -> list[SimulatedPush]:
        """Hand the pending pushes to a server loop (and forget them)."""
        with self.lock:
            pushes, self.pending_pushes = self.pending_pushes, []
        return pushes

    def set_ic_location(self, obis: str | ObisCode, last: int | None = None) -> None:
        """Expose the client invocation counter at another OBIS (vendor style).

        ``last`` pretends the meter already accepted that counter.
        """
        if last is not None:
            self._ic_seen = True
        self.objects.pop((ClassId.DATA, self.ic_obis), None)
        self.versions.pop((ClassId.DATA, self.ic_obis), None)
        self.ic_obis = ObisCode.parse(obis) if isinstance(obis, str) else obis
        self.last_client_ic = self._last_client_ic if last is None else last

    @property
    def last_client_ic(self) -> int:
        return self._last_client_ic

    @last_client_ic.setter
    def last_client_ic(self, value: int) -> None:
        self._last_client_ic = value
        if self.security is not None:
            self.objects[(ClassId.DATA, self.ic_obis)] = {
                1: DlmsData.octet_string(self.ic_obis.to_bytes()),
                2: DlmsData.uint32(value),
            }
            self.versions[(ClassId.DATA, self.ic_obis)] = 0

    # -- object model ------------------------------------------------------------
    def add_object(
        self,
        class_id: int,
        obis: str | ObisCode,
        attributes: dict[int, DlmsData],
        version: int = 0,
        base_name: int | None = None,
    ) -> None:
        key = (int(class_id), ObisCode.parse(obis) if isinstance(obis, str) else obis)
        attrs = {1: DlmsData.octet_string(key[1].to_bytes())}
        attrs.update(attributes)
        self.objects[key] = attrs
        self.versions[key] = version
        if base_name is not None:
            self.base_names[key] = base_name

    def add_method(self, class_id: int, obis: str | ObisCode, method: int, fn: Callable) -> None:
        obis = ObisCode.parse(obis) if isinstance(obis, str) else obis
        self.methods[(int(class_id), obis, method)] = fn

    def set_access(
        self,
        class_id: int,
        obis: str | ObisCode,
        attribute: int | None = None,
        mode: int | None = 0,
        method: int | None = None,
    ) -> None:
        """Set the access mode of one attribute (or, with ``method``, one
        method) in the view, read as :attr:`association_version` defines it.
        ``mode=None`` leaves the item out of the view (access unknown)."""
        obis = ObisCode.parse(obis) if isinstance(obis, str) else obis
        if method is not None:
            self.method_access[(int(class_id), obis, method)] = mode
        elif attribute is not None:
            self.attribute_access[(int(class_id), obis, attribute)] = mode
        else:
            raise ValueError("set_access needs an attribute or a method")

    def _version(self) -> int:
        return 1 if self.association_version is None else self.association_version

    def _denied(self, cid: int, obis: ObisCode, attr: int, write: bool) -> bool:
        from pydlms.cosem.access import AccessMode3, AttributeAccessMode

        mode = self.attribute_access.get((cid, obis, attr))
        if mode is None:
            return False
        try:
            decoded = (AccessMode3 if self._version() >= 3 else AttributeAccessMode)(mode)
        except ValueError:
            return True
        return not (decoded.writable if write else decoded.readable)

    def _method_denied(self, cid: int, obis: ObisCode, method: int) -> bool:
        mode = self.method_access.get((cid, obis, method))
        return mode is not None and not mode & 1

    def access_rights(self, cid: int, obis: ObisCode, attributes, methods) -> DlmsData:
        """The ``access_rights`` of one object, with overrides applied."""
        from pydlms.cosem.access import AccessRights, AttributeAccess, MethodAccess

        version = self._version()
        listed = []
        for attr in sorted(
            set(attributes) | {a for c, o, a in self.attribute_access if (c, o) == (cid, obis)}
        ):
            mode = self.attribute_access.get((cid, obis, attr), 1 if attr == 1 else 3)
            if mode is None:
                continue
            selectors = (1, 2) if cid == ClassId.PROFILE_GENERIC and attr == 2 else None
            listed.append(AttributeAccess(attr, mode, selectors))
        calls = []
        for index in sorted(
            set(methods) | {m for c, o, m in self.method_access if (c, o) == (cid, obis)}
        ):
            mode = self.method_access.get((cid, obis, index), 1)
            if mode is None:
                continue
            calls.append(MethodAccess(index, bool(mode) if version == 0 else mode))
        return AccessRights(tuple(listed), tuple(calls), version).to_data()

    def _methods_of(self, cid: int, obis: ObisCode) -> set[int]:
        from pydlms.cosem.model import spec_for

        spec = spec_for(cid)
        known = {m.index for m in spec.methods.values()} if spec else set()
        return known | {m for c, o, m in self.methods if (c, o) == (cid, obis)}

    def object_list(self) -> DlmsData:
        entries = []
        if self.association_version is not None:
            entries.append(
                DlmsData.structure(
                    [
                        DlmsData.uint16(ClassId.ASSOCIATION_LN),
                        DlmsData.uint8(self.association_version),
                        DlmsData.octet_string(ASSOCIATION_LN.to_bytes()),
                        self.access_rights(ClassId.ASSOCIATION_LN, ASSOCIATION_LN, {1, 2}, {1}),
                    ]
                )
            )
        for (cid, obis), attrs in sorted(self.objects.items(), key=lambda kv: (kv[0][1], kv[0][0])):
            entries.append(
                DlmsData.structure(
                    [
                        DlmsData.uint16(cid),
                        DlmsData.uint8(self.versions[(cid, obis)]),
                        DlmsData.octet_string(obis.to_bytes()),
                        self.access_rights(cid, obis, attrs, self._methods_of(cid, obis)),
                    ]
                )
            )
        return DlmsData.array(entries)

    def sn_object_list(self) -> DlmsData:
        entries = []
        for (cid, obis), bn in sorted(self.base_names.items(), key=lambda kv: kv[1]):
            entries.append(
                DlmsData.structure(
                    [
                        DlmsData.int16(bn - 0x10000 if bn >= 0x8000 else bn),
                        DlmsData.uint16(cid),
                        DlmsData.uint8(self.versions[(cid, obis)]),
                        DlmsData.octet_string(obis.to_bytes()),
                    ]
                )
            )
        return DlmsData.array(entries)

    def _read(
        self, cid: int, obis: ObisCode, attr: int, access=None
    ) -> DlmsData | DataAccessResult:
        if cid == ClassId.ASSOCIATION_LN and obis == ASSOCIATION_LN and attr == 2:
            return self.object_list()
        attrs = self.objects.get((cid, obis))
        if attrs is None:
            return DataAccessResult.OBJECT_UNDEFINED
        if self._denied(cid, obis, attr, write=False):
            return DataAccessResult.READ_WRITE_DENIED
        value = attrs.get(attr)
        if value is None:
            return DataAccessResult.OBJECT_UNAVAILABLE
        if access is not None and cid == ClassId.PROFILE_GENERIC and attr == 2:
            return self._select(value, access, attrs.get(3))
        if callable(value):
            return value()
        return value

    @staticmethod
    def _select(buffer: DlmsData, access, capture=None) -> DlmsData | DataAccessResult:
        rows = buffer.value
        if access.selector == 2:
            frm, to, col_from, col_to = (v.value for v in access.parameters.value)
            to = len(rows) if to == 0 else to
            selected = rows[frm - 1 : to]
            if col_from > 1 or col_to:
                end = None if col_to == 0 else col_to
                selected = [DlmsData.structure(r.value[col_from - 1 : end]) for r in selected]
            return DlmsData.array(selected)
        if access.selector == 1:
            _, frm, to, selected = access.parameters.value
            lo, hi = _instant(frm), _instant(to)
            if lo is None or hi is None:
                return DataAccessResult.OTHER_REASON
            picked = [r for r in rows if lo <= (_instant(r.value[0]) or lo - _ONE) <= hi]
            if selected.value and capture is not None:
                # selected_values: only the listed capture objects, in that order
                keys = [tuple(v.value for v in c.value[:3]) for c in capture.value]
                try:
                    cols = [keys.index(tuple(v.value for v in c.value[:3])) for c in selected.value]
                except ValueError:
                    return DataAccessResult.OTHER_REASON
                picked = [DlmsData.structure([r.value[i] for i in cols]) for r in picked]
            return DlmsData.array(picked)
        return DataAccessResult.OTHER_REASON

    def _write(self, cid: int, obis: ObisCode, attr: int, value: DlmsData) -> DataAccessResult:
        attrs = self.objects.get((cid, obis))
        if attrs is None:
            return DataAccessResult.OBJECT_UNDEFINED
        if attr == 1 or self._denied(cid, obis, attr, write=True):
            return DataAccessResult.READ_WRITE_DENIED
        attrs[attr] = value
        return DataAccessResult.SUCCESS

    # -- dispatch ---------------------------------------------------------------------
    def handle(self, apdu: bytes, session: _Session) -> bytes | None:
        """The one response to ``apdu`` (no general-block-transfer)."""
        with self.lock:
            self.requests.append(apdu)
            return self._handle_one(apdu, session)

    def _handle_one(self, apdu: bytes, session: _Session) -> bytes | None:
        try:
            return self._handle(apdu, session)
        except DlmsError as exc:
            log.warning("simulator rejected APDU: %s", exc)
            return xdlms.ExceptionResponse(1, 3).to_bytes()

    def handle_all(self, apdu: bytes, session: _Session) -> list[bytes]:
        """Every APDU to send for ``apdu``, in order: what the server loops use.

        With general-block-transfer negotiated, GBT requests are reassembled
        (and unprotected after reassembly), non-final blocks acknowledged at
        each window end, lost ones asked for again; a response longer than
        the client's max PDU, and every answer to a GBT request, goes in
        GBT blocks, a window at a time.
        """
        with self.lock:
            self.requests.append(apdu)
            if apdu and apdu[0] == Tag.GENERAL_BLOCK_TRANSFER and session.associated:
                try:
                    return self._gbt_in(apdu, session)
                except DlmsError as exc:
                    log.warning("simulator rejected GBT block: %s", exc)
                    session.gbt = None
                    return [xdlms.ExceptionResponse(1, 3).to_bytes()]
            response = self._handle_one(apdu, session)
            if response is None:
                return []
            return self._gbt_out(response, session, via_gbt=False)

    def _gbt_in(self, apdu: bytes, session: _Session) -> list[bytes]:
        if not session.gbt_negotiated:
            return [xdlms.ExceptionResponse(2, 2).to_bytes()]
        block = decode_gbt(apdu)
        if block.data and block.block_number in self.drop_gbt_requests:
            self.drop_gbt_requests.discard(block.block_number)
            log.info("simulator: losing GBT request block %d", block.block_number)
            return []
        transfer = session.gbt
        if transfer is None or (block.data and block.block_number == 1 and not transfer.receiving):
            transfer = session.gbt = GbtTransfer(
                self.gbt_window,
                self.gbt_max_retransmissions,
                peer_window=session.gbt_peer_window,
                streaming=self.gbt_streaming,
            )
        step = transfer.receive(block)
        session.gbt_peer_window = transfer.peer_window
        out = list(step.send)
        if step.apdu is not None:
            response = self._handle_one(step.apdu, session)
            if response is not None:
                out += self._gbt_out(response, session, via_gbt=True)
            return out
        return self._lose(out)

    def _gbt_out(self, response: bytes, session: _Session, via_gbt: bool) -> list[bytes]:
        """``response`` as it goes out: as is, or in GBT blocks (the first
        window) when it answers a GBT request or is longer than the
        client's max PDU and GBT was negotiated."""
        limit = session.client_max_pdu
        if not via_gbt and (not session.gbt_negotiated or len(response) <= limit):
            return [response]
        transfer = session.gbt if via_gbt and session.gbt is not None else None
        if transfer is None:
            transfer = session.gbt = GbtTransfer(
                self.gbt_window,
                self.gbt_max_retransmissions,
                peer_window=session.gbt_peer_window,
                streaming=self.gbt_streaming,
            )
        return self._lose(transfer.send(response, limit - gbt_overhead(limit)))

    def _lose(self, blocks: list[bytes]) -> list[bytes]:
        """Drop the GBT blocks named in :attr:`drop_gbt_blocks` (once each)."""
        out = []
        for raw in blocks:
            if raw[:1] == bytes([Tag.GENERAL_BLOCK_TRANSFER]):
                number = decode_gbt(raw).block_number
                if number in self.drop_gbt_blocks and decode_gbt(raw).data:
                    self.drop_gbt_blocks.discard(number)
                    log.info("simulator: losing GBT block %d", number)
                    continue
            out.append(raw)
        return out

    def _handle(self, apdu: bytes, session: _Session) -> bytes | None:
        tag = apdu[0]
        if tag == Tag.AARQ:
            return self._aarq(AARQ.from_bytes(apdu), session)
        if tag == Tag.RLRQ:
            rlrq = RLRQ.from_bytes(apdu)
            rlre = RLRE(0)
            if session.associated and session.ciphered and rlrq.user_information:
                rlre = self._ciphered_rlre(rlrq, session)
            session.associated = False
            return rlre.to_bytes()
        if not session.associated:
            return xdlms.ExceptionResponse(1, 2).to_bytes()
        plain, ciphered = apdu, False
        from pydlms.security.ciphering import is_ciphered_apdu

        if is_ciphered_apdu(apdu):
            from pydlms.security.ciphering import unwrap

            try:
                result = unwrap(self.security, apdu)
                plain = result.plaintext
                self.last_client_ic = max(self.last_client_ic, result.invocation_counter)
            except DlmsError:
                return xdlms.ExceptionResponse(1, 5).to_bytes()  # deciphering error
            ciphered = True
        elif session.ciphered:
            return xdlms.ExceptionResponse(1, 1).to_bytes()
        if session.hls_pending and plain[0] not in (Tag.ACTION_REQUEST, Tag.READ_REQUEST):
            return xdlms.ExceptionResponse(1, 1).to_bytes()
        response = self._service(plain, session)
        if response is None:
            return None
        if ciphered:
            return self._protect_like(apdu, response, session)
        return response

    def _protect_like(self, request: bytes, response: bytes, session: _Session) -> bytes:
        """Protect the response in the same envelope the client used:
        glo-/ded-, general-glo, general-ciphering (identified global key)
        and/or general-signing around either."""
        from pydlms.security.ciphering import wrap, wrap_general_glo
        from pydlms.security.general import (
            IDENTIFIED_UNICAST,
            verify_general_signing,
            wrap_general_ciphering,
            wrap_general_signing,
        )

        signed = request[0] == Tag.GENERAL_SIGNING
        inner = verify_general_signing(self.security, request)[1] if signed else request
        client = session.client_title or self.security.server_system_title
        if inner[0] == Tag.GENERAL_CIPHERING:
            if client is None:
                raise ProtocolError("general-ciphering reply needs the client system title")
            out = wrap_general_ciphering(self.security, response, client, IDENTIFIED_UNICAST)
        elif inner[0] in (Tag.GENERAL_GLO_CIPHERING, Tag.GENERAL_DED_CIPHERING):
            out = wrap_general_glo(self.security, response, dedicated=session.dedicated)
        else:
            out = wrap(self.security, response, dedicated=session.dedicated)
        if signed:
            if client is None:
                raise ProtocolError("general-signing reply needs the client system title")
            out = wrap_general_signing(self.security, out, client)
        return out

    def _service(self, plain: bytes, session: _Session) -> bytes | None:
        tag = plain[0]
        if tag in (Tag.READ_REQUEST, Tag.WRITE_REQUEST):
            return self._sn(plain, session)
        request = xdlms.decode_apdu(plain)
        if isinstance(request, xdlms.GetRequestNormal):
            a = request.attribute
            value = self._read(a.class_id, a.instance_id, a.attribute_id, request.access)
            if isinstance(value, DataAccessResult):
                return xdlms.GetResponseNormal(
                    request.invoke_id, xdlms.GetDataResult(error=value)
                ).to_bytes()
            response = xdlms.GetResponseNormal(request.invoke_id, xdlms.GetDataResult(data=value))
            raw = response.to_bytes()
            limit = min(self.max_pdu, session.client_max_pdu) - 32
            if len(raw) > limit + 32 and not session.gbt_negotiated:
                encoded = encode_data(value)
                session.block = [encoded[i : i + limit] for i in range(0, len(encoded), limit)]
                session.block_invoke = request.invoke_id
                return self._next_block(1, session)
            return raw
        if isinstance(request, xdlms.GetRequestNext):
            return self._next_block(request.block_number + 1, session)
        if isinstance(request, xdlms.GetRequestWithList):
            results = []
            for a, access in request.items:
                value = self._read(a.class_id, a.instance_id, a.attribute_id, access)
                results.append(
                    xdlms.GetDataResult(error=value)
                    if isinstance(value, DataAccessResult)
                    else xdlms.GetDataResult(data=value)
                )
            raw = xdlms.GetResponseWithList(request.invoke_id, results).to_bytes()
            limit = min(self.max_pdu, session.client_max_pdu) - 32
            if len(raw) > limit + 32 and not session.gbt_negotiated:
                # Too long for one APDU: send the SEQUENCE OF Get-Data-Result
                # in data blocks, like a single large value.
                encoded = xdlms.encode_get_data_results(results)
                session.block = [encoded[i : i + limit] for i in range(0, len(encoded), limit)]
                session.block_invoke = request.invoke_id
                return self._next_block(1, session)
            return raw
        if isinstance(request, xdlms.SetRequestNormal):
            a = request.attribute
            result = self._write(a.class_id, a.instance_id, a.attribute_id, request.value)
            return xdlms.SetResponseNormal(request.invoke_id, result).to_bytes()
        if isinstance(request, xdlms.SetRequestWithFirstDatablock):
            session.set_buffer = bytearray(request.raw_data)
            session.pending_action = request.attribute
            if request.last_block:
                return self._finish_set(request.invoke_id, request.block_number, session)
            return xdlms.SetResponseDatablock(request.invoke_id, request.block_number).to_bytes()
        if isinstance(request, xdlms.SetRequestWithDatablock):
            session.set_buffer += request.raw_data
            if request.last_block:
                return self._finish_set(request.invoke_id, request.block_number, session)
            return xdlms.SetResponseDatablock(request.invoke_id, request.block_number).to_bytes()
        if isinstance(request, xdlms.SetRequestWithListAndFirstDatablock):
            # No server available for testing implements choice 5; this
            # follows the single-attribute datablock exchange.
            session.set_buffer = bytearray(request.raw_data)
            session.pending_action = list(request.items)
            if request.last_block:
                return self._finish_set(request.invoke_id, request.block_number, session)
            return xdlms.SetResponseDatablock(request.invoke_id, request.block_number).to_bytes()
        if isinstance(request, xdlms.SetRequestWithList):
            results = [
                self._write(a.class_id, a.instance_id, a.attribute_id, v)
                for a, _, v in request.items
            ]
            return xdlms.SetResponseWithList(request.invoke_id, results).to_bytes()
        if isinstance(request, xdlms.ActionRequestNormal):
            return self._action(request.invoke_id, request.method, request.parameters, session)
        if isinstance(request, xdlms.ActionRequestNextPblock):
            return self._action_reply_block(request.block_number + 1, session)
        if isinstance(request, xdlms.ActionRequestWithList):
            results = []
            for method, params in request.items:
                reply = xdlms.decode_apdu(self._action_normal(request.invoke_id, method, params))
                results.append((reply.result, reply.return_data))
            return xdlms.ActionResponseWithList(request.invoke_id, results).to_bytes()
        if isinstance(request, xdlms.ActionRequestWithFirstPblock):
            session.action_buffer = bytearray(request.raw_data)
            session.pending_action = request.method
            if request.last_block:
                return self._finish_action(request.invoke_id, session)
            return xdlms.ActionResponseNextPblock(
                request.invoke_id, request.block_number
            ).to_bytes()
        if isinstance(request, xdlms.ActionRequestWithListAndFirstPblock):
            session.action_buffer = bytearray(request.raw_data)
            session.pending_action = list(request.methods)
            if request.last_block:
                return self._finish_action(request.invoke_id, session)
            return xdlms.ActionResponseNextPblock(
                request.invoke_id, request.block_number
            ).to_bytes()
        if isinstance(request, xdlms.ActionRequestWithPblock):
            session.action_buffer += request.raw_data
            if request.last_block:
                return self._finish_action(request.invoke_id, session)
            return xdlms.ActionResponseNextPblock(
                request.invoke_id, request.block_number
            ).to_bytes()
        if isinstance(request, xdlms.AccessRequest):
            return self._access(request, session)
        return xdlms.ExceptionResponse(2, 2).to_bytes()

    def _access(self, request: xdlms.AccessRequest, session: _Session) -> bytes | None:
        """Run the operations of an ACCESS request in order, with the
        GET/SET/ACTION paths. With break-on-error, the operations after the
        first failure are not run; their result code is OTHER_REASON (as the
        cB-Sigma server answers). The public Green Book excerpt (DLMS UA
        1000-2 Ed. 9 9.3.9.1.6) only says the client controls whether later
        requests run; the code for skipped ones is *unverified*. An
        unconfirmed request runs and gets no answer."""
        if not session.access_negotiated:
            return xdlms.ExceptionResponse(1, 2).to_bytes()  # not allowed / not supported
        data: list[DlmsData] = []
        results: list = []
        failed = False
        for spec, value in zip(request.specifications, request.data, strict=True):
            out = DlmsData.null()
            if isinstance(spec, xdlms.AccessRequestAction):
                if failed:
                    result: ActionResult | DataAccessResult = ActionResult.OTHER_REASON
                else:
                    m = spec.method
                    reply = xdlms.decode_apdu(self._action_normal(0, m, value))
                    result = reply.result
                    if reply.return_data is not None and reply.return_data.ok:
                        out = reply.return_data.data
                results.append(xdlms.AccessResponseAction(result))
            elif isinstance(spec, (xdlms.AccessRequestGet, xdlms.AccessRequestGetWithSelection)):
                a = spec.attribute
                result = DataAccessResult.OTHER_REASON
                if not failed:
                    read = self._read(
                        a.class_id, a.instance_id, a.attribute_id, getattr(spec, "access", None)
                    )
                    result = (
                        read if isinstance(read, DataAccessResult) else DataAccessResult.SUCCESS
                    )
                    if not isinstance(read, DataAccessResult):
                        out = read
                results.append(xdlms.AccessResponseGet(result))
            else:  # set; the selection is ignored, as for SET-Request-Normal
                a = spec.attribute
                result = DataAccessResult.OTHER_REASON
                if not failed:
                    result = self._write(a.class_id, a.instance_id, a.attribute_id, value)
                results.append(xdlms.AccessResponseSet(result))
            data.append(out)
            if result != 0 and request.processing_option == xdlms.ProcessingOption.BREAK_ON_ERROR:
                failed = True
        if not request.confirmed:
            return None
        return xdlms.AccessResponse(request.long_invoke_id, None, None, data, results).to_bytes()

    def _default_method(self, method):
        """Accept any method the typed class model knows, validating the
        parameter shape against it, and record the call in :attr:`calls`."""
        from pydlms.cosem.model import spec_for

        spec = spec_for(method.class_id)
        if spec is None or not any(m.index == method.method_id for m in spec.methods.values()):
            return None
        method_spec = spec.method(method.method_id)

        def handler(meter, params):
            value = params
            if method_spec.params is not None and params is not None:
                value = method_spec.params.decode(params, method_spec.name)  # raises on mismatch
            meter.calls.append((method.class_id, method.instance_id, method_spec.name, value))
            if method_spec.returns is not None:
                return _sample_return(method_spec.returns)
            return None

        return handler

    def _finish_set(self, invoke_id, block_number, session):
        if isinstance(session.pending_action, list):  # with-list (choice 5)
            items = session.pending_action
            values = xdlms.decode_data_list(bytes(session.set_buffer))
            if len(values) != len(items):
                return xdlms.ExceptionResponse(2, 2).to_bytes()
            results = [
                self._write(a.class_id, a.instance_id, a.attribute_id, v)
                for (a, _), v in zip(items, values, strict=True)
            ]
            return xdlms.SetResponseLastDatablockWithList(
                invoke_id, results, block_number
            ).to_bytes()
        value, _ = decode_data(bytes(session.set_buffer))
        a = session.pending_action
        result = self._write(a.class_id, a.instance_id, a.attribute_id, value)
        return xdlms.SetResponseLastDatablock(invoke_id, result, block_number).to_bytes()

    def _finish_action(self, invoke_id, session):
        if isinstance(session.pending_action, list):  # with-list (choice 5)
            methods = session.pending_action
            params = xdlms.decode_data_list(bytes(session.action_buffer))
            if len(params) != len(methods):
                return xdlms.ExceptionResponse(2, 2).to_bytes()
            results = []
            for method, value in zip(methods, params, strict=True):
                reply = xdlms.decode_apdu(self._action_normal(invoke_id, method, value))
                results.append((reply.result, reply.return_data))
            return xdlms.ActionResponseWithList(invoke_id, results).to_bytes()
        params, _ = decode_data(bytes(session.action_buffer))
        return self._action(invoke_id, session.pending_action, params, session)

    def _next_block(self, number: int, session: _Session) -> bytes:
        if not 1 <= number <= len(session.block):
            return xdlms.GetResponseWithDatablock(
                session.block_invoke, True, number, error=DataAccessResult.DATA_BLOCK_NUMBER_INVALID
            ).to_bytes()
        last = number == len(session.block)
        return xdlms.GetResponseWithDatablock(
            session.block_invoke, last, number, raw_data=session.block[number - 1]
        ).to_bytes()

    def _action(self, invoke_id, method, params, session):
        if (method.class_id, method.instance_id, method.method_id) == (
            ClassId.ASSOCIATION_LN,
            ASSOCIATION_LN,
            1,
        ):
            return self._hls_reply(invoke_id, params, session)
        raw = self._action_normal(invoke_id, method, params)
        limit = min(self.max_pdu, session.client_max_pdu) - 32
        reply = xdlms.decode_apdu(raw)
        if (
            len(raw) > limit + 32
            and not session.gbt_negotiated
            and reply.return_data is not None
            and reply.return_data.ok
        ):
            # Return data too long for one APDU: Action-Response-With-Pblock
            # carrying the bare return Data, fetched with Next-Pblock.
            encoded = encode_data(reply.return_data.data)
            session.action_reply = [encoded[i : i + limit] for i in range(0, len(encoded), limit)]
            session.action_reply_invoke = invoke_id
            return self._action_reply_block(1, session)
        return raw

    def _action_reply_block(self, number: int, session: _Session) -> bytes:
        if not 1 <= number <= len(session.action_reply):
            return xdlms.ActionResponseNormal(
                session.action_reply_invoke, ActionResult.DATA_BLOCK_UNAVAILABLE
            ).to_bytes()
        return xdlms.ActionResponseWithPblock(
            session.action_reply_invoke,
            number == len(session.action_reply),
            number,
            session.action_reply[number - 1],
        ).to_bytes()

    def _action_normal(self, invoke_id, method, params) -> bytes:
        if self._method_denied(method.class_id, method.instance_id, method.method_id):
            return xdlms.ActionResponseNormal(invoke_id, ActionResult.READ_WRITE_DENIED).to_bytes()
        fn = self.methods.get((method.class_id, method.instance_id, method.method_id))
        if fn is None and (method.class_id, method.instance_id) in self.objects:
            fn = self._default_method(method)
        if fn is None:
            return xdlms.ActionResponseNormal(invoke_id, ActionResult.OBJECT_UNAVAILABLE).to_bytes()
        try:
            result = fn(self, params)
        except ActionFailure as failure:
            return xdlms.ActionResponseNormal(invoke_id, failure.result).to_bytes()
        data = None if result is None else xdlms.GetDataResult(data=result)
        return xdlms.ActionResponseNormal(invoke_id, ActionResult.SUCCESS, data).to_bytes()

    # -- association ----------------------------------------------------------------
    def _aarq(self, aarq: AARQ, session: _Session) -> bytes:
        profile = self.clients.get(session.client_sap)
        context = aarq.application_context
        mech = Mechanism(aarq.mechanism or 0)

        def reject(diagnostic: int, result: int = 1) -> bytes:
            return AARE(context, result, 1, diagnostic).to_bytes()

        if profile is None:
            return reject(1)
        if context.ciphered != profile.ciphered:
            return reject(2)
        if mech != profile.mechanism:
            return reject(11)
        if mech == Mechanism.LLS and aarq.calling_authentication_value != profile.secret:
            return reject(13)
        user_info = aarq.user_information
        session.dedicated = False
        if context.ciphered:
            from pydlms.axdr import decode_length
            from pydlms.security.ciphering import unwrap

            _, pos = decode_length(user_info, 1)
            ic = int.from_bytes(user_info[pos + 1 : pos + 5], "big")
            last = self.last_client_ic
            if self._ic_seen and ic <= last:
                # Like real meters: refuse a stale counter and report ours.
                return xdlms.ExceptionResponse(1, 6, last).to_bytes()
            self.security.server_system_title = aarq.calling_ap_title
            result = unwrap(self.security, user_info)
            user_info = result.plaintext
            self.last_client_ic = result.invocation_counter
            self._ic_seen = True
        initiate = InitiateRequest.from_bytes(user_info)
        if initiate.dlms_version < 6:
            return AARE(
                context, 1, 1, 1, user_information=xdlms.ConfirmedServiceError(1, 6, 1).to_bytes()
            ).to_bytes()
        if initiate.dedicated_key:
            self.security.set_dedicated_key(initiate.dedicated_key)
            session.dedicated = True
        session.profile = profile
        session.ciphered = context.ciphered
        session.logical_names = context.logical_names
        session.client_max_pdu = initiate.max_receive_pdu_size or 0xFFFF
        session.gbt_negotiated = bool(
            self.conformance & initiate.conformance & Conformance.GENERAL_BLOCK_TRANSFER
        )
        session.access_negotiated = bool(
            self.conformance & initiate.conformance & Conformance.ACCESS
        )
        session.gbt = None
        session.associated = True
        session.hls_pending = mech.is_hls
        session.ctos = aarq.calling_authentication_value or b""
        session.client_title = aarq.calling_ap_title
        session.stoc = os.urandom(default_challenge_length(mech)) if mech.is_hls else b""
        response = InitiateResponse(
            self.conformance & initiate.conformance,
            self.max_pdu,
            vaa_name=0x0007 if context.logical_names else 0xFA00,
        ).to_bytes()
        session.initiate_response = response
        if context.ciphered:
            from pydlms.security.ciphering import wrap
            from pydlms.security.suites import SecurityControl, SecurityPolicy

            # The answer to a dedicated key is protected like the key itself.
            sc = (
                SecurityControl.for_policy(
                    SecurityPolicy.AUTHENTICATED_ENCRYPTED, int(self.security.suite)
                )
                if initiate.dedicated_key
                else None
            )
            response = wrap(self.security, response, sc=sc)
        return AARE(
            context,
            0,
            1,
            14 if mech.is_hls else 0,
            responding_ap_title=(
                self.system_title if context.ciphered or mech >= Mechanism.HLS_GMAC else None
            ),
            mechanism=int(mech) or None,
            responding_authentication_value=session.stoc or None,
            user_information=response,
        ).to_bytes()

    def _ciphered_rlre(self, rlrq: RLRQ, session: _Session) -> RLRE:
        """Answer a ciphered RLRQ: check its InitiateRequest like the AARQ's
        and return the InitiateResponse ciphered again, authenticated and
        encrypted when the association uses a dedicated key (the annex E.8
        form, global key)."""
        from pydlms.security.ciphering import unwrap, wrap
        from pydlms.security.suites import SecurityControl, SecurityPolicy

        try:
            result = unwrap(self.security, rlrq.user_information)
        except DlmsError as exc:
            log.warning("simulator: RLRQ user-information refused: %s", exc)
            return RLRE(0)
        self.last_client_ic = max(self.last_client_ic, result.invocation_counter)
        sc = (
            SecurityControl.for_policy(
                SecurityPolicy.AUTHENTICATED_ENCRYPTED, int(self.security.suite)
            )
            if session.dedicated
            else None
        )
        return RLRE(0, wrap(self.security, session.initiate_response, sc=sc))

    def _hls_reply(self, invoke_id, params, session) -> bytes:
        from pydlms.security import hls

        if not session.hls_pending or params is None:
            return xdlms.ActionResponseNormal(invoke_id, ActionResult.READ_WRITE_DENIED).to_bytes()
        reply = bytes(params.value)
        profile = session.profile
        mech = profile.mechanism
        secret = profile.secret or b""
        st_c = session.client_title
        st_s = self.system_title
        ok = False
        answer = b""
        if mech in (Mechanism.HLS, Mechanism.HLS_MD5, Mechanism.HLS_SHA1):
            fn = profile.hls2_function or hls.hls_manufacturer_aes
            if mech != Mechanism.HLS:
                fn = lambda chal, sec: hls.hash_response(mech, chal, sec)  # noqa: E731
            ok = hmac.compare_digest(fn(session.stoc, secret), reply)
            answer = fn(session.ctos, secret)
        elif mech == Mechanism.HLS_SHA256:
            if st_c is not None:
                ok = hmac.compare_digest(
                    hls.hls_sha256(secret, st_c, st_s, session.stoc, session.ctos), reply
                )
                answer = hls.hls_sha256(secret, st_s, st_c, session.ctos, session.stoc)
        elif mech == Mechanism.HLS_GMAC:
            try:
                hls.verify_hls_gmac(
                    self.encryption_key, self.authentication_key, st_c, session.stoc, reply
                )
                ok = True
            except DlmsError:
                ok = False
            answer = hls.hls_gmac(
                self.encryption_key,
                self.authentication_key,
                self.system_title,
                self.security.next_invocation_counter(),
                session.ctos,
            )
        elif mech == Mechanism.HLS_ECDSA:
            try:
                hls.hls_ecdsa_verify(
                    profile.client_public_key, st_c, st_s, session.stoc, session.ctos, reply
                )
                ok = True
            except (DlmsError, TypeError, AttributeError):
                ok = False
            if ok:
                answer = hls.hls_ecdsa_sign(
                    self.signing_key, st_s, st_c, session.ctos, session.stoc
                )
        if not ok:
            session.associated = False
            return xdlms.ActionResponseNormal(invoke_id, ActionResult.OTHER_REASON).to_bytes()
        session.hls_pending = False
        return xdlms.ActionResponseNormal(
            invoke_id, ActionResult.SUCCESS, xdlms.GetDataResult(data=DlmsData.octet_string(answer))
        ).to_bytes()

    # -- short names ---------------------------------------------------------------------
    def _sn_lookup(self, address: int):
        if 0xFA00 <= address < 0xFA00 + 0x60:
            return ("assoc", address - 0xFA00)
        for key, base in self.base_names.items():
            if base <= address < base + 0x100:
                return (key, address - base)
        return None

    def _sn_block(self, number: int, session: _Session) -> sn.ReadResult:
        if not 1 <= number <= len(session.block):
            return sn.ReadResult(error=DataAccessResult.DATA_BLOCK_NUMBER_INVALID)
        return sn.ReadResult(
            block_last=number == len(session.block),
            block_number=number,
            raw_data=session.block[number - 1],
        )

    #: Cap on a request reassembled from SN data-block-access parts.
    MAX_SN_REQUEST = 1 << 20

    def _sn_parts(self, request, session: _Session) -> bytes | None:
        """Collect one read-/write-data-block-access part, the way the
        GuruxDLMS servers do: block 1 starts a transfer, every further part
        must carry the next number (else data-block-number-invalid and the
        transfer is dropped), non-final parts are acknowledged with their
        number and the joined parts are then served as one request."""
        kinds = (sn.ReadDataBlockAccess, sn.WriteDataBlockAccess)
        if not any(isinstance(item, kinds) for item in request.items):
            return None
        write = isinstance(request, sn.WriteRequest)
        tag = Tag.WRITE_REQUEST if write else Tag.READ_REQUEST

        def fail(code: DataAccessResult) -> bytes:
            session.sn_parts, session.sn_part_next = bytearray(), 0
            if write:
                return sn.WriteResponse([code]).to_bytes()
            return sn.ReadResponse([sn.ReadResult(error=code)]).to_bytes()

        spec = request.items[0]
        wanted = sn.WriteDataBlockAccess if write else sn.ReadDataBlockAccess
        if len(request.items) != 1 or not isinstance(spec, wanted):
            return fail(DataAccessResult.DATA_BLOCK_UNAVAILABLE)
        if write:
            values = request.values
            if len(values) != 1 or values[0].tag != DataType.OCTET_STRING:
                return fail(DataAccessResult.DATA_BLOCK_UNAVAILABLE)
            part = bytes(values[0].value)
        else:
            part = spec.raw_data
        if spec.block_number == 1:
            session.sn_parts, session.sn_part_next, session.sn_part_tag = bytearray(), 1, tag
        if spec.block_number != session.sn_part_next or tag != session.sn_part_tag:
            return fail(DataAccessResult.DATA_BLOCK_NUMBER_INVALID)
        session.sn_parts += part
        if len(session.sn_parts) > self.MAX_SN_REQUEST:
            return fail(DataAccessResult.DATA_BLOCK_UNAVAILABLE)
        if not spec.last_block:
            session.sn_part_next += 1
            if write:
                return sn.WriteResponse([sn.WriteBlockNumber(spec.block_number)]).to_bytes()
            return sn.ReadResponse([sn.ReadResult(block_number=spec.block_number)]).to_bytes()
        whole = bytes([tag]) + bytes(session.sn_parts)
        session.sn_parts, session.sn_part_next = bytearray(), 0
        if any(isinstance(item, kinds) for item in sn.decode_sn_apdu(whole).items):
            return fail(DataAccessResult.DATA_BLOCK_UNAVAILABLE)
        return self._sn(whole, session)

    def _sn(self, plain: bytes, session: _Session) -> bytes:
        request = sn.decode_sn_apdu(plain)
        if isinstance(request, (sn.ReadRequest, sn.WriteRequest)):
            reply = self._sn_parts(request, session)
            if reply is not None:
                return reply
        if isinstance(request, sn.ReadRequest):
            results = []
            for spec in request.items:
                if isinstance(spec, sn.BlockNumberAccess):
                    results.append(self._sn_block(spec.block_number + 1, session))
                    continue
                found = self._sn_lookup(spec.name) if hasattr(spec, "name") else None
                if found is None:
                    results.append(sn.ReadResult(error=DataAccessResult.OBJECT_UNDEFINED))
                    continue
                key, offset = found
                if key == "assoc":
                    if offset == 0x08:
                        results.append(sn.ReadResult(data=self.sn_object_list()))
                    elif offset == 0x58 and isinstance(spec, sn.ParameterizedAccess):
                        raw = self._hls_reply(0, spec.parameter, session)
                        resp = xdlms.decode_apdu(raw)
                        if resp.result == ActionResult.SUCCESS:
                            results.append(sn.ReadResult(data=resp.return_data.data))
                        else:
                            results.append(sn.ReadResult(error=DataAccessResult.OTHER_REASON))
                    else:
                        results.append(sn.ReadResult(error=DataAccessResult.OBJECT_UNAVAILABLE))
                    continue
                from pydlms.sn_methods import method_offset

                first_method = method_offset(key[0], self.versions.get(key))
                if (
                    isinstance(spec, sn.ParameterizedAccess)
                    and first_method
                    and offset >= first_method
                ):
                    # SN method invocation: READ with parameters on the method address.
                    method = xdlms.MethodDescriptor(
                        key[0], key[1], (offset - first_method) // 8 + 1
                    )
                    resp = xdlms.decode_apdu(self._action(0, method, spec.parameter, session))
                    if resp.result != ActionResult.SUCCESS:
                        results.append(sn.ReadResult(error=_sn_method_error(resp.result)))
                    else:
                        data = resp.return_data.data if resp.return_data else DlmsData.null()
                        results.append(sn.ReadResult(data=data))
                    continue
                value = self._read(key[0], key[1], offset // 8 + 1)
                if isinstance(value, DataAccessResult):
                    results.append(sn.ReadResult(error=value))
                    continue
                encoded = encode_data(value)
                limit = min(self.max_pdu, session.client_max_pdu) - 32
                if len(encoded) > limit and len(request.items) == 1:
                    session.block = [encoded[i : i + limit] for i in range(0, len(encoded), limit)]
                    results.append(self._sn_block(1, session))
                    continue
                results.append(sn.ReadResult(data=value))
            return sn.ReadResponse(results).to_bytes()
        if isinstance(request, sn.WriteRequest):
            results = []
            for spec, value in zip(request.items, request.values, strict=True):
                found = self._sn_lookup(spec.name)
                if found is None or found[0] == "assoc":
                    results.append(DataAccessResult.OBJECT_UNDEFINED)
                    continue
                key, offset = found
                results.append(self._write(key[0], key[1], offset // 8 + 1, value))
            return sn.WriteResponse(results).to_bytes()
        return xdlms.ExceptionResponse(2, 2).to_bytes()


class ImageTransferTarget:
    """A stateful Image transfer object (IC 18) for the simulator.

    Models the server side of the Blue Book image transfer process
    (DLMS UA 1000-1 Ed. 13 Excerpt 4.4.6.2 steps 1 to 7, blocks numbered
    from 0 per 3.1; the attribute and method details are *unverified*,
    built from the cB-Sigma client): initiate, block transfer, verify and
    activate, the transferred-blocks bit-string (attr 3, bit n = block n)
    and the first-not-transferred block (attr 4).

    Knobs for tests:

    * ``drop_blocks``: block numbers the meter loses; an iterable loses each
      once, a mapping ``{block: times}`` that many times (a large count is a
      persistent loss). A lost block is acknowledged but not stored.
    * ``verify_steps`` / ``activate_steps``: 0 answers the method at once;
      ``n`` answers temporary-failure and keeps the status at
      verification-/activation-initiated for ``n`` reads of attr 6.
    * ``fail_verify`` / ``fail_activate``: the outcome is failure.
    * ``drop_on_activate``: activation succeeds but the connection is
      closed without an answer (a meter rebooting into the new image).
    * ``block_size``, ``enabled``: attrs 2 and 5.
    * ``resume_from``: on initiating a new image the meter claims blocks
      below this number already (their content is unknown to it).
    * ``overrides``: ``{attr: DlmsData}`` served instead of the state, to
      feed malformed values.

    Initiating the image the meter already holds part of (same identifier
    and size) keeps the received blocks, so a second transfer resumes.
    """

    #: Placeholder for blocks claimed through ``resume_from``.
    CLAIMED = b""

    def __init__(
        self,
        block_size: int = 64,
        enabled: bool = True,
        drop_blocks=(),
        verify_steps: int = 0,
        activate_steps: int = 0,
        fail_verify: bool = False,
        fail_activate: bool = False,
        drop_on_activate: bool = False,
        resume_from: int = 0,
    ) -> None:
        self.block_size = block_size
        self.enabled = enabled
        self.drop_blocks: dict[int, int] = (
            dict(drop_blocks) if isinstance(drop_blocks, dict) else dict.fromkeys(drop_blocks, 1)
        )
        self.verify_steps = verify_steps
        self.activate_steps = activate_steps
        self.fail_verify = fail_verify
        self.fail_activate = fail_activate
        self.drop_on_activate = drop_on_activate
        self.resume_from = resume_from
        self.overrides: dict[int, DlmsData] = {}
        self.identifier: bytes | None = None
        self.size = 0
        self.blocks: dict[int, bytes] = {}
        #: Block numbers stored, in arrival order (resends included).
        self.received: list[int] = []
        self.status = 0
        self._pending: list = []  # [reads left, final status] while working

    # -- state -------------------------------------------------------------------
    @property
    def activated(self) -> bool:
        return self.status == 6

    @property
    def block_count(self) -> int:
        if not self.block_size:
            return 0
        return -(-self.size // self.block_size)

    def image(self) -> bytes | None:
        """The received image, or None while blocks are missing or claimed."""
        parts = [self.blocks.get(n) for n in range(self.block_count)]
        if any(p is None or p is self.CLAIMED for p in parts):
            return None
        return b"".join(parts)  # type: ignore[arg-type]

    def _complete(self) -> bool:
        return all(n in self.blocks for n in range(self.block_count))

    def _attr(self, attr: int, fn: Callable[[], DlmsData]) -> Callable[[], DlmsData]:
        return lambda: self.overrides[attr] if attr in self.overrides else fn()

    def _status(self) -> DlmsData:
        if self._pending:
            self._pending[0] -= 1
            if self._pending[0] <= 0:
                self.status = self._pending[1]
                self._pending = []
        return DlmsData.enum(self.status)

    def _info(self) -> DlmsData:
        if self.status not in (3, 5, 6, 7) or self.identifier is None:
            return DlmsData.array([])
        return DlmsData.array(
            [
                DlmsData.structure(
                    [
                        DlmsData.uint32(self.size),
                        DlmsData.octet_string(self.identifier),
                        DlmsData.octet_string(b""),
                    ]
                )
            ]
        )

    def install(
        self,
        sim: MeterSimulator,
        obis: str | ObisCode = "0.0.44.0.0.255",
        base_name: int | None = None,
    ) -> ImageTransferTarget:
        """Add the object and its four methods to ``sim``."""
        attrs = {
            2: self._attr(2, lambda: DlmsData.uint32(self.block_size)),
            3: self._attr(
                3,
                lambda: DlmsData(
                    DataType.BIT_STRING, [n in self.blocks for n in range(self.block_count)]
                ),
            ),
            4: self._attr(4, lambda: DlmsData.uint32(self._first_missing())),
            5: self._attr(5, lambda: DlmsData.boolean(self.enabled)),
            6: self._attr(6, self._status),
            7: self._attr(7, self._info),
        }
        sim.add_object(ClassId.IMAGE_TRANSFER, obis, attrs, base_name=base_name)  # type: ignore[arg-type]
        for method, fn in enumerate(
            (self._initiate, self._block, self._verify, self._activate), start=1
        ):
            sim.add_method(ClassId.IMAGE_TRANSFER, obis, method, fn)
        return self

    def _first_missing(self) -> int:
        return next((n for n in range(self.block_count) if n not in self.blocks), self.block_count)

    # -- methods -----------------------------------------------------------------
    @staticmethod
    def _fields(params, *tags: DataType) -> list:
        if params is None or params.tag != DataType.STRUCTURE or len(params.value) != len(tags):
            raise ActionFailure(ActionResult.TYPE_UNMATCHED)
        if any(v.tag != t for v, t in zip(params.value, tags, strict=True)):
            raise ActionFailure(ActionResult.TYPE_UNMATCHED)
        return [v.value for v in params.value]

    def _initiate(self, meter, params):
        identifier, size = self._fields(
            params, DataType.OCTET_STRING, DataType.DOUBLE_LONG_UNSIGNED
        )
        if not self.enabled:
            raise ActionFailure(ActionResult.READ_WRITE_DENIED)
        identifier = bytes(identifier)
        same = identifier == self.identifier and size == self.size and self.status == 1
        self.identifier, self.size, self.status = identifier, size, 1
        self._pending = []
        if not same:
            self.blocks = dict.fromkeys(
                range(min(self.resume_from, self.block_count)), self.CLAIMED
            )
        return None

    def _block(self, meter, params):
        number, value = self._fields(params, DataType.DOUBLE_LONG_UNSIGNED, DataType.OCTET_STRING)
        if self.status != 1 or number >= self.block_count:
            raise ActionFailure(ActionResult.OTHER_REASON)
        expected = min(self.block_size, self.size - number * self.block_size)
        if len(value) != expected:
            raise ActionFailure(ActionResult.OTHER_REASON)
        if self.drop_blocks.get(number, 0) > 0:
            self.drop_blocks[number] -= 1
            return None
        self.blocks[number] = bytes(value)
        self.received.append(number)
        return None

    def _work(self, steps: int, fail: bool, working: int, good: int, bad: int):
        if steps:
            self.status = working
            self._pending = [steps, bad if fail else good]
            raise ActionFailure(ActionResult.TEMPORARY_FAILURE)
        self.status = bad if fail else good
        if fail:
            raise ActionFailure(ActionResult.OTHER_REASON)

    def _verify(self, meter, params):
        if self.status not in (1, 2, 3, 4) or not self._complete():
            self.status = 4 if self.status == 1 else self.status
            raise ActionFailure(ActionResult.OTHER_REASON)
        self._work(self.verify_steps, self.fail_verify, 2, 3, 4)
        return None

    def _activate(self, meter, params):
        if self.status not in (3, 5, 6, 7):
            raise ActionFailure(ActionResult.OTHER_REASON)
        if self.drop_on_activate:
            self.status = 6
            raise ConnectionResetError("meter restarts into the new image")
        self._work(self.activate_steps, self.fail_activate, 5, 6, 7)
        return None


def _sample_return(kind):
    """A plausible return value for methods the default handler accepts."""
    from pydlms.cosem import types as T

    if isinstance(kind, T.OctetString):
        return DlmsData.octet_string(b"\x01\x02")
    if isinstance(kind, T.Integer):
        return T.Integer(kind.tag).encode(1)
    if isinstance(kind, T.Array):
        return DlmsData.array([])
    return DlmsData.null()


# --- framing servers ---------------------------------------------------------------------


class HdlcServer:
    """Server side of HDLC for one connection over a socket-like object.

    ``window`` is the receive window the server offers in the UA (its
    ``window_rx``, capped by the client's proposed ``window_tx``); the
    server sends one response I-frame per poll (``window_tx`` 1). Received
    I-frames are acknowledged only when they carry P=1, with RR, or with REJ
    after a gap that ``reject`` caused; a go-back-N receiver discards every
    frame after a gap until the client resends from N(R) (ISO/IEC 13239,
    IEC 62056-46 6.4.4.4.3.4-6 via cB-Sigma, *unverified*).

    Fault injection counts received I-frames from 1 per connection
    (retransmissions included): frames numbered in ``drop`` are lost on the
    line (the next poll is answered RR with the old N(R)), frames in
    ``reject`` arrive damaged (the next poll is answered REJ).
    ``window_overruns`` counts I-frames beyond the window without a poll.

    ``modulo128`` makes the server take SNRME (ISO/IEC 13239 extended
    numbering, two-octet I and S control fields, ``window`` up to 127);
    without it SNRME is answered with DM, so a client can fall back to SNRM
    (cB-Sigma ``hdlc/station.go`` behaves the same, *unverified* against the
    standard). IEC 62056-46 defines modulo 8 only.
    """

    def __init__(
        self,
        simulator: MeterSimulator,
        sock,
        server_address: int = 1,
        max_info: int = 128,
        window: int = 1,
        drop: Iterable[int] = (),
        reject: Iterable[int] = (),
        modulo128: bool = False,
    ) -> None:
        limit = max_window(MODULO_128 if modulo128 else SEQ_MODULUS)
        if not 1 <= window <= limit:
            raise ValueError(f"HDLC window {window} outside 1..{limit}")
        self.modulo128 = modulo128
        #: Numbering of the link set up last (128 after an accepted SNRME).
        self.modulus = SEQ_MODULUS
        self.sim = simulator
        self.sock = sock
        self.server = HdlcAddress.server(server_address)
        self.client = HdlcAddress.client(16)
        self.reader = FrameReader()
        self.max_info = max_info
        self.window = window
        self.window_rx = 1
        self.drop = set(drop)
        self.reject = set(reject)
        self.received = 0
        self.window_overruns = 0
        self._since_poll = 0
        #: The most I-frames received between two polls (window use).
        self.max_burst = 0
        #: Why frames are being discarded: None, "drop" or "reject".
        self._gap: str | None = None
        self.vs = self.vr = 0
        self.session = _Session()
        self.rx = bytearray()
        self.tx: list[HdlcFrame] = []

    def _send(self, control: int, info: bytes = b"", segmented: bool = False) -> None:
        self.sock.sendall(
            encode_frame(
                HdlcFrame(self.client, self.server, control, info, segmented, self.modulus)
            )
        )

    def feed(self, data: bytes) -> None:
        for frame in self.reader.feed(data):
            self._frame(frame)

    def _frame(self, f: HdlcFrame) -> None:
        if f.dest.upper != self.server.upper:
            return
        # Answer from the address we were called by, so a client using a
        # 2- or 4-octet address (physical part, any value) gets its match.
        self.server = f.dest
        self.client = f.src
        kind = f.kind
        if kind == FrameType.SNRME and not self.modulo128:
            self._send(FrameType.DM | PF_BIT)
        elif kind in (FrameType.SNRM, FrameType.SNRME):
            self.modulus = MODULO_128 if kind == FrameType.SNRME else SEQ_MODULUS
            self.reader.modulus = self.modulus
            params = HdlcParameters.from_bytes(f.info, self.modulus)
            self.max_info = min(self.max_info, params.max_info_rx)
            self.window_rx = min(self.window, params.window_tx)
            self.vs = self.vr = 0
            self.received = self._since_poll = 0
            self._gap = None
            self.rx.clear()
            self.session = _Session(client_sap=f.src.upper)
            self._send(
                FrameType.UA | PF_BIT,
                HdlcParameters(
                    self.max_info, self.max_info, window_rx=self.window_rx, modulus=self.modulus
                ).to_bytes(),
            )
        elif kind == FrameType.DISC:
            self.session = _Session()
            self._send(FrameType.UA | PF_BIT)
        elif kind == FrameType.I:
            self._i_frame(f)
        elif kind == FrameType.RR:
            if self.tx:
                self._next()
            elif f.poll_final:  # nothing to send: report N(R) (and any gap)
                self._acknowledge()

    def _acknowledge(self) -> None:
        """Answer a poll with RR, or REJ after a damaged frame; F=1."""
        reject = self._gap == "reject"
        self._gap = None
        self._since_poll = 0
        control = control_rej if reject else control_rr
        self._send(control(self.vr, True, self.modulus))

    def _i_frame(self, f: HdlcFrame) -> None:
        self.received += 1
        if self.received in self.drop:
            log.debug("HDLC simulator: dropping I-frame #%d N(S)=%d", self.received, f.ns)
            self._gap = self._gap or "drop"
            return
        self._since_poll += 1
        self.max_burst = max(self.max_burst, self._since_poll)
        if self._since_poll > self.window_rx:
            self.window_overruns += 1
            log.warning("HDLC simulator: %d I-frames without a poll", self._since_poll)
        if self.received in self.reject:
            log.debug("HDLC simulator: rejecting I-frame #%d N(S)=%d", self.received, f.ns)
            self._gap = "reject"
        elif f.ns != self.vr:  # after a gap: go-back-N discards it
            log.debug("HDLC simulator: out-of-sequence N(S)=%d, V(R)=%d", f.ns, self.vr)
            self._gap = self._gap or "reject"
        else:
            self.vr = seq_add(self.vr, 1, self.modulus)
            self.rx += f.info
            if not f.segmented:
                self._since_poll = 0
                self._respond()
                return
        if f.poll_final:
            self._acknowledge()

    def _respond(self) -> None:
        apdu = strip_llc(bytes(self.rx))
        self.rx.clear()
        responses = self.sim.handle_all(apdu, self.session)
        if responses:
            self.tx = []
            for push in self.sim.take_pushes():
                if push.hdlc_frame == "ui":
                    self._send(FrameType.UI, LLC_RESPONSE + push.apdu)
                else:  # one I-frame each; the next waits for the client's RR
                    self.tx += self._i_frames(push.apdu)
            for response in responses:
                self.tx += self._i_frames(response)
            self._next()

    def _i_frames(self, apdu: bytes) -> list[HdlcFrame]:
        payload = LLC_RESPONSE + apdu
        chunks = [payload[i : i + self.max_info] for i in range(0, len(payload), self.max_info)]
        return [
            HdlcFrame(self.client, self.server, 0, c, i < len(chunks) - 1, self.modulus)
            for i, c in enumerate(chunks)
        ]

    def _next(self) -> None:
        if not self.tx:
            return
        frame = self.tx.pop(0)
        frame.control = control_i(self.vs, self.vr, True, self.modulus)
        self.vs = seq_add(self.vs, 1, self.modulus)
        self.sock.sendall(encode_frame(frame))


class MbusServer:
    """A wired M-Bus slave (EN 13757-2 link layer) in front of the simulator.

    Answers SND_NKE with E5, SND_UD with E5 (DLMS segments CI 0x00..0x1F or
    one CI 0x60/0x61 frame are collected until the APDU is complete) and
    REQ_UD2 with the next RSP_UD segment of the DLMS response, following the
    FCB rules of the M-Bus documentation 4.8 5.5: a SND_UD or REQ_UD2 with
    FCV set and the same FCB as the last one is a repetition, so a SND_UD
    is acknowledged again without taking its data twice and a REQ_UD2 gets
    the last RSP_UD again. Telegrams to ``address``, to 254 (test address)
    and, after a selection by ``secondary`` (8 octets in line order, CI
    0x52 to 253), to 253 are answered; 255 is never answered.

    With no DLMS response queued, a REQ_UD2 is answered with an RSP_UD that
    carries no DLMS data (CI 0x72, fixed data header, no records), or with E5 when
    ``idle_ack`` is set (*unverified*: no public source says what a DLMS
    slave answers before its response is ready). ``not_ready`` makes that
    many polls after each request see the idle answer before the response.

    Fault injection counts received telegrams of a kind from 1 per
    connection, repetitions included: SND_UD numbered in ``drop_ack`` is
    taken but its E5 is lost; REQ_UD2 numbered in ``drop_response`` gets no
    answer, in ``corrupt_response`` an answer with a wrong checksum, in
    ``repeat_response`` the previous RSP_UD again whatever its FCB (a
    duplicate the master has to drop).
    """

    def __init__(
        self,
        simulator: MeterSimulator,
        sock,
        address: int = 1,
        max_segment: int = 250,
        secondary: bytes | None = None,
        idle_ack: bool = False,
        not_ready: int = 0,
        drop_ack: Iterable[int] = (),
        drop_response: Iterable[int] = (),
        corrupt_response: Iterable[int] = (),
        repeat_response: Iterable[int] = (),
    ) -> None:
        if not 0 <= address <= 250:
            raise ValueError(f"M-Bus primary address {address} outside 0..250")
        self.sim = simulator
        self.sock = sock
        self.address = address
        self.max_segment = max_segment
        self.secondary = secondary
        self.idle_ack = idle_ack
        self.not_ready = not_ready
        self.drop_ack = set(drop_ack)
        self.drop_response = set(drop_response)
        self.corrupt_response = set(corrupt_response)
        self.repeat_response = set(repeat_response)
        self.selected = False
        self.session = _Session()
        self.buffer = bytearray()
        self.reassembly = MbusReader()
        #: RSP_UD frames waiting for REQ_UD2, the one sent last, and how
        #: many polls still get the idle answer.
        self.tx: list[bytes] = []
        self.last_response: bytes | None = None
        self._idle_polls = 0
        #: Last FCB seen with FCV set, per direction; None after SND_NKE.
        self.last_fcb_send: bool | None = None
        self.last_fcb_request: bool | None = None
        self.snd_ud_count = 0
        self.req_ud2_count = 0
        self.access_number = 0
        #: Repeated SND_UD (same FCB) acknowledged without taking the data.
        self.duplicates = 0
        #: Telegrams that failed the checksum or framing checks (no answer).
        self.bad_frames = 0
        self.log: list[str] = []

    def feed(self, data: bytes) -> None:
        self.buffer += data
        buf = self.buffer
        while buf:
            first = buf[0]
            if first == 0x10:
                if len(buf) < 5:
                    return
                raw = bytes(buf[:5])
            elif first == 0x68:
                if len(buf) < 4:
                    return
                if buf[1] != buf[2] or buf[3] != 0x68:
                    del buf[:1]
                    self.bad_frames += 1
                    continue
                if len(buf) < buf[1] + 6:
                    return
                raw = bytes(buf[: buf[1] + 6])
            else:
                del buf[:1]  # E5 or noise from the master: nothing to answer
                continue
            del buf[: len(raw)]
            try:
                frame = decode_link_frame(raw)
            except DlmsError as exc:
                # A corrupt telegram is not answered (doc 4.8 5.4).
                self.bad_frames += 1
                log.debug("M-Bus simulator: ignoring a bad telegram (%s)", exc)
                continue
            self._telegram(frame)

    def _for_us(self, address: int) -> bool:
        return address in (self.address, ADDRESS_TEST) or (
            address == ADDRESS_NETWORK_LAYER and self.selected
        )

    def _reset(self) -> None:
        """SND_NKE: clear the FCB memories and any half-done exchange."""
        self.last_fcb_send = self.last_fcb_request = None
        self.tx.clear()
        self.last_response = None
        self.reassembly = MbusReader()
        self.session = _Session()

    def _ack(self) -> None:
        self.sock.sendall(b"\xe5")

    def _telegram(self, frame) -> None:
        if not frame.from_master:
            return
        control = frame.control
        function = control & ~(C_FCB | C_FCV)
        fcv = bool(control & C_FCV)
        fcb = bool(control & C_FCB)
        if frame.kind == "short" and control == C_SND_NKE:
            self.log.append(f"SND_NKE A={frame.address}")
            if frame.address == ADDRESS_NETWORK_LAYER:
                # Deselects (doc 4.8 7.1); the selected slave acknowledges.
                answer, self.selected = self.selected, False
            else:
                answer = self._for_us(frame.address)
            if answer or frame.address == ADDRESS_BROADCAST:
                self._reset()
            if answer:
                self._ack()
            return
        if (
            frame.kind == "long"
            and function == C_SND_UD & ~C_FCV
            and frame.address == ADDRESS_NETWORK_LAYER
            and frame.ci == CI_SELECT
        ):
            self._select(frame)
            return
        if not self._for_us(frame.address):
            return
        if frame.kind == "long" and function == C_SND_UD & ~C_FCV:
            self.snd_ud_count += 1
            self.log.append(f"SND_UD #{self.snd_ud_count} C=0x{control:02X} CI=0x{frame.ci:02X}")
            repeated = fcv and self.last_fcb_send is not None and fcb == self.last_fcb_send
            if fcv:
                self.last_fcb_send = fcb
            if repeated:
                self.duplicates += 1
                log.debug("M-Bus simulator: SND_UD repeated (FCB unchanged); data not taken")
            else:
                self._take(frame.raw)
            if self.snd_ud_count in self.drop_ack:
                log.debug("M-Bus simulator: losing the E5 of SND_UD #%d", self.snd_ud_count)
                return
            self._ack()
        elif frame.kind == "short" and function == C_REQ_UD2 & ~C_FCV:
            self.req_ud2_count += 1
            n = self.req_ud2_count
            self.log.append(f"REQ_UD2 #{n} C=0x{control:02X}")
            repeated = fcv and self.last_fcb_request is not None and fcb == self.last_fcb_request
            if fcv:
                self.last_fcb_request = fcb
            if (repeated or n in self.repeat_response) and self.last_response is not None:
                response = self.last_response
            else:
                response = self._next_response()
            if n in self.drop_response:
                log.debug("M-Bus simulator: no answer to REQ_UD2 #%d", n)
                return
            if response is None:
                self._ack()
                return
            self.log.append(f"RSP_UD CI=0x{response[6]:02X}")
            if n in self.corrupt_response:
                log.debug("M-Bus simulator: corrupting the answer to REQ_UD2 #%d", n)
                self.sock.sendall(response[:-2] + bytes([(response[-2] + 1) & 0xFF]) + b"\x16")
                return
            self.sock.sendall(response)

    def _select(self, frame) -> None:
        mine = self.secondary
        match = mine is not None and len(frame.data) == 8 and _match_secondary(frame.data, mine)
        self.log.append(f"select {frame.data.hex()} -> {match}")
        self.selected = match
        if match:
            self.last_fcb_send = self.last_fcb_request = None
            self._ack()

    def _next_response(self) -> bytes | None:
        """The next RSP_UD: a DLMS segment, else the idle answer (None = E5)."""
        if self.tx and self._idle_polls <= 0:
            response = self.tx.pop(0)
        else:
            self._idle_polls -= 1
            if self.idle_ack:
                self.last_response = None
                return None
            self.access_number = (self.access_number + 1) & 0xFF
            # Ident. No 4, manufacturer 2, version, medium (the secondary
            # address), access number, status, signature 2 (doc 4.8 6.3.1).
            header = (self.secondary or bytes(8)) + bytes([self.access_number, 0, 0, 0])
            response = encode_long_frame(C_RSP_UD, self.address, CI_VARIABLE_DATA, header)
        self.last_response = response
        return response

    def _take(self, raw: bytes) -> None:
        frame = decode_mbus_frame(raw)
        self.session.client_sap = frame.stsap
        for apdu in self.reassembly.feed(raw):
            responses = self.sim.handle_all(apdu, self.session)
            if not responses:
                continue
            pushes = [p.apdu for p in self.sim.take_pushes()]
            self.tx = []
            for response in pushes + responses:
                chunks = [
                    response[i : i + self.max_segment]
                    for i in range(0, len(response), self.max_segment)
                ] or [b""]
                for seq, chunk in enumerate(chunks):
                    # The sequence rolls over after 15 (KSMWest H1 p. 6).
                    ci = (seq & 0x0F) | (0x10 if seq == len(chunks) - 1 else 0)
                    self.tx.append(
                        encode_mbus_frame(
                            MbusFrame(C_RSP_UD, self.address, ci, frame.dtsap, frame.stsap, chunk)
                        )
                    )
            self._idle_polls = self.not_ready


def _match_secondary(selection: bytes, mine: bytes) -> bool:
    """Compare a selection with a secondary address: wildcard nibbles F in
    the identification, wildcard octets FF elsewhere (doc 4.8 7.1)."""
    for i in range(4):
        for shift in (0, 4):
            want = (selection[i] >> shift) & 0x0F
            if want != 0x0F and want != (mine[i] >> shift) & 0x0F:
                return False
    return all(s in (0xFF, m) for s, m in zip(selection[4:], mine[4:], strict=True))


def serve_mbus(
    sim: MeterSimulator,
    host: str = "127.0.0.1",
    port: int = 0,
    address: int = 1,
    **options,
):
    """Start a threaded TCP server whose connections speak wired M-Bus to an
    :class:`MbusServer` (``address`` and ``options`` as its keywords), as an
    M-Bus gateway would pass the bus through. Returns the server; the
    :class:`MbusServer` of each connection is appended to
    ``server.mbus_servers``."""
    mbus_servers: list[MbusServer] = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            server = MbusServer(sim, self.request, address, **options)
            mbus_servers.append(server)
            try:
                while True:
                    data = self.request.recv(4096)
                    if not data:
                        return
                    server.feed(data)
            except (ConnectionError, OSError):
                return

    class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True
        daemon_threads = True

    server = Server((host, port), Handler)
    server.mbus_servers = mbus_servers  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    log.info("M-Bus simulator listening on %s:%d (address %d)", *server.server_address[:2], address)
    return server


def _wrapper_loop(sim: MeterSimulator, conn) -> None:
    session = _Session()
    buf = bytearray()
    while True:
        data = conn.recv(4096)
        if not data:
            return
        buf += data
        while len(buf) >= HEADER_SIZE:
            header = decode_header(bytes(buf[:HEADER_SIZE]))
            if len(buf) < HEADER_SIZE + header.length:
                break
            apdu = bytes(buf[HEADER_SIZE : HEADER_SIZE + header.length])
            del buf[: HEADER_SIZE + header.length]
            session.client_sap = header.source
            responses = sim.handle_all(apdu, session)
            if responses:
                for push in sim.take_pushes():
                    port = header.source if push.wport is None else push.wport
                    conn.sendall(encode_wrapper(header.destination, port, push.apdu))
            for response in responses:
                conn.sendall(encode_wrapper(header.destination, header.source, response))


def serve(
    sim: MeterSimulator,
    host: str = "127.0.0.1",
    port: int = 0,
    hdlc: bool = False,
    hdlc_window: int = 1,
    hdlc_modulo128: bool = False,
):
    """Start a threaded TCP server; returns it (``server.server_address``).

    With ``hdlc`` the connections are HDLC; ``hdlc_window`` (1-7, or 1-127
    with ``hdlc_modulo128``) is the receive window offered in the UA
    (:class:`HdlcServer` ``window``); ``hdlc_modulo128`` makes the server
    take SNRME (:class:`HdlcServer` ``modulo128``). The
    :class:`HdlcServer` of each connection is appended to
    ``server.hdlc_servers``.
    """
    limit = max_window(MODULO_128 if hdlc_modulo128 else SEQ_MODULUS)
    if not 1 <= hdlc_window <= limit:
        raise ValueError(f"HDLC window {hdlc_window} outside 1..{limit}")
    hdlc_servers: list[HdlcServer] = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                if hdlc:
                    server = HdlcServer(
                        sim, self.request, window=hdlc_window, modulo128=hdlc_modulo128
                    )
                    hdlc_servers.append(server)
                    while True:
                        data = self.request.recv(4096)
                        if not data:
                            return
                        server.feed(data)
                else:
                    _wrapper_loop(sim, self.request)
            except (ConnectionError, OSError):
                return

    class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True
        daemon_threads = True

    server = Server((host, port), Handler)
    server.hdlc_servers = hdlc_servers  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    log.info(
        "simulator listening on %s:%d (%s)",
        *server.server_address[:2],
        "HDLC" if hdlc else "wrapper",
    )
    return server


# (class_id, logical_name, attribute) of the example meter's push_object_list.
EXAMPLE_PUSH_OBJECTS = [
    (40, "0.0.25.9.0.255", 1),
    (1, "0.0.96.1.0.255", 2),
    (3, "1.0.1.8.0.255", 2),
    (3, "1.0.1.7.0.255", 2),
]


def example_meter(**kw) -> MeterSimulator:
    """A meter with typical electricity objects, a clock and a load profile."""
    import datetime as dt

    sim = MeterSimulator(**kw)
    sim.add_object(
        ClassId.DATA,
        "0.0.96.1.0.255",
        {2: DlmsData.visible_string("PYD0000000001")},
        base_name=0x0100,
    )
    sim.add_object(
        ClassId.DATA,
        "0.0.42.0.0.255",
        {2: DlmsData.octet_string(b"PYD1000000000001")},
        base_name=0x0200,
    )
    for obis, value, scaler, unit in [
        ("1.0.1.8.0.255", 12345678, 0, 30),
        ("1.0.2.8.0.255", 4321, 0, 30),
        ("1.0.1.7.0.255", 1520, 0, 27),
        ("1.0.32.7.0.255", 2301, -1, 35),
        ("1.0.31.7.0.255", 523, -2, 33),
    ]:
        sim.add_object(
            ClassId.REGISTER,
            obis,
            {
                2: DlmsData.uint32(value) if value >= 0x10000 else DlmsData.uint16(value),
                3: DlmsData.structure([DlmsData.int8(scaler), DlmsData.enum(unit)]),
            },
            base_name=0x1000 + 0x100 * len(sim.base_names),
        )
    now = CosemDateTime.from_datetime(
        dt.datetime(2024, 5, 1, 12, 0, 0, tzinfo=dt.timezone(dt.timedelta(hours=2)))
    )
    sim.add_object(
        ClassId.CLOCK,
        "0.0.1.0.0.255",
        {2: DlmsData.octet_string(now.to_bytes()), 3: DlmsData.int16(-60)},
        base_name=0x2000,
    )
    rows = []
    start = dt.datetime(2024, 5, 1, 0, 0, tzinfo=dt.timezone.utc)
    for i in range(96):
        stamp = CosemDateTime.from_datetime(start + dt.timedelta(minutes=15 * i))
        rows.append(
            DlmsData.structure(
                [DlmsData.octet_string(stamp.to_bytes()), DlmsData.uint32(1000 + i * 7)]
            )
        )
    sim.add_object(
        ClassId.PROFILE_GENERIC,
        "1.0.99.1.0.255",
        {
            2: DlmsData.array(rows),
            3: DlmsData.array(
                [
                    DlmsData.structure(
                        [
                            DlmsData.uint16(8),
                            DlmsData.octet_string(ObisCode(0, 0, 1, 0, 0, 255).to_bytes()),
                            DlmsData.int8(2),
                            DlmsData.uint16(0),
                        ]
                    ),
                    DlmsData.structure(
                        [
                            DlmsData.uint16(3),
                            DlmsData.octet_string(ObisCode(1, 0, 1, 8, 0, 255).to_bytes()),
                            DlmsData.int8(2),
                            DlmsData.uint16(0),
                        ]
                    ),
                ]
            ),
            4: DlmsData.uint32(900),
            5: DlmsData.enum(1),  # sort_method FIFO
            7: DlmsData.uint32(96),
        },
        version=1,
        base_name=0x3000,
    )
    # Compact data (IC 62): one capture of the clock and the active energy
    # register. The template_id is not one of its capture objects, so it is
    # not in compact_buffer (the Blue Book Ed. 13 4.3.10.2 examples capture
    # it first; the decoder takes either).
    captured = [
        sim.objects[(ClassId.CLOCK, ObisCode(0, 0, 1, 0, 0, 255))][2],
        sim.objects[(ClassId.REGISTER, ObisCode(1, 0, 1, 8, 0, 255))][2],
    ]
    template = TypeDescription(DataType.STRUCTURE, members=tuple(map(TypeDescription.of, captured)))
    sim.add_object(
        ClassId.COMPACT_DATA,
        "0.0.66.0.1.255",
        {
            2: DlmsData.octet_string(encode_untagged(DlmsData.structure(captured), template)),
            3: DlmsData.array(
                [
                    DlmsData.structure(
                        [
                            DlmsData.uint16(cid),
                            DlmsData.octet_string(ObisCode.parse(name).to_bytes()),
                            DlmsData.int8(2),
                            DlmsData.uint16(0),
                        ]
                    )
                    for cid, name in ((ClassId.CLOCK, "0.0.1.0.0.255"), (3, "1.0.1.8.0.255"))
                ]
            ),
            4: DlmsData.uint8(1),
            5: DlmsData.octet_string(encode_type_description(template)),
            6: DlmsData.enum(0),  # capture on the capture method
        },
        version=1,
        base_name=0x7000,
    )
    sim.add_object(
        ClassId.DISCONNECT_CONTROL,
        "0.0.96.3.10.255",
        {2: DlmsData.boolean(True), 3: DlmsData.enum(1)},
        base_name=0x4000,
    )
    # Push setup (IC 40, Blue Book): push_object_list is attribute 2; the
    # list names the push setup itself first, as IDIS pushes do, then objects
    # that exist above.
    sim.add_object(
        ClassId.PUSH_SETUP,
        "0.0.25.9.0.255",
        {
            2: DlmsData.array(
                [
                    DlmsData.structure(
                        [
                            DlmsData.uint16(cid),
                            DlmsData.octet_string(ObisCode.parse(name).to_bytes()),
                            DlmsData.int8(attr),
                            DlmsData.uint16(0),
                        ]
                    )
                    for cid, name, attr in EXAMPLE_PUSH_OBJECTS
                ]
            )
        },
        base_name=0x6000,
    )

    def disconnect(meter, params):
        meter.objects[(ClassId.DISCONNECT_CONTROL, ObisCode.parse("0.0.96.3.10.255"))][2] = (
            DlmsData.boolean(False)
        )
        return None

    sim.add_method(ClassId.DISCONNECT_CONTROL, "0.0.96.3.10.255", 1, disconnect)
    return sim


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="pydlms meter simulator")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4059)
    parser.add_argument("--hdlc", action="store_true", help="HDLC over TCP instead of wrapper")
    parser.add_argument(
        "--hdlc-window",
        type=int,
        default=1,
        metavar="N",
        help="HDLC receive window to offer, 1-7 or 1-127 with --hdlc-modulo 128 "
        "(default 1; needs --hdlc)",
    )
    parser.add_argument(
        "--hdlc-modulo",
        type=int,
        choices=(8, 128),
        default=8,
        help="128: also take SNRME (modulo-128 numbering, outside IEC 62056-46); "
        "8 (default) answers SNRME with DM (needs --hdlc)",
    )
    parser.add_argument("--replay", help="answer from a --record file (pydlms.replay)")
    parser.add_argument("--key", help="global encryption key (hex) for ciphered clients")
    parser.add_argument("--auth-key", help="authentication key (hex)")
    parser.add_argument(
        "--client",
        action="append",
        default=[],
        metavar="SAP:MECHANISM[:SECRET]",
        help="accept a client SAP, e.g. 1:5 (HLS-GMAC) or 32:1:12345678 (LLS); "
        "repeatable; with --key every listed client is ciphered",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def meter_from_args(args: argparse.Namespace) -> MeterSimulator:
    """The meter :func:`main` serves: the example meter, or a
    :class:`~pydlms.replay.ReplayMeter` with ``--replay``."""
    keys = {
        "encryption_key": bytes.fromhex(args.key) if args.key else None,
        "authentication_key": bytes.fromhex(args.auth_key) if args.auth_key else None,
    }
    if args.replay:
        from pydlms.replay import ReplayMeter

        meter: MeterSimulator = ReplayMeter(args.replay, **keys)
    else:
        meter = example_meter(**keys)
    for spec in args.client:
        sap, mech, *secret = spec.split(":", 2)
        meter.clients[int(sap)] = ClientProfile(
            Mechanism(int(mech)),
            secret=secret[0].encode() if secret else None,
            ciphered=bool(args.key),
        )
    return meter


def check_hdlc_options(args: argparse.Namespace) -> None:
    """SystemExit for ``--hdlc-window`` / ``--hdlc-modulo`` without
    ``--hdlc`` or a window outside the numbering's range."""
    for option, used in (
        ("--hdlc-window", args.hdlc_window != 1),
        ("--hdlc-modulo", args.hdlc_modulo != SEQ_MODULUS),
    ):
        if used and not args.hdlc:
            raise SystemExit(f"{option} needs --hdlc")
    limit = max_window(args.hdlc_modulo)
    if not 1 <= args.hdlc_window <= limit:
        raise SystemExit(f"--hdlc-window must be 1-{limit}, got {args.hdlc_window}")


def main(argv=None) -> None:  # pragma: no cover - manual tool
    args = _parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)
    check_hdlc_options(args)
    server = serve(
        meter_from_args(args),
        args.host,
        args.port,
        args.hdlc,
        args.hdlc_window,
        args.hdlc_modulo == MODULO_128,
    )
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":  # pragma: no cover
    main()
