"""Replay a recorded meter session: a simulator that answers from a recording.

:class:`ReplayMeter` turns a ``--record`` file into a meter you can point the
client (or any DLMS client) at, so a field problem becomes a reproducible
test without the meter::

    pydlms read tcp://meter ... --record session.hex      # once, at the meter
    pydlms simulate --replay session.hex --port 4059      # any time later

It is a :class:`~pydlms.simulator.MeterSimulator` that runs the association
itself (AARQ/AARE, LLS/HLS, ciphering with the keys *you* give it, invocation
counters) and answers every service request with the response recorded for the
same request. Matching ignores the invoke-id, which is patched into the reply.
Requests are matched in recorded order first, so repeated reads of a changing
value (a clock) replay in sequence; once a request's recorded answers are used
up, the last one is repeated. A request that was never recorded gets
``object-undefined`` (GET) or an ExceptionResponse, and is listed in
:attr:`ReplayMeter.misses`.

The session parameters come from the recorded AARE: the server system title,
the negotiated conformance and max PDU size. Ciphered sessions replay from the
``TX-APDU``/``RX-APDU`` plaintext lines that current recordings carry; a
recording with only ciphered raw frames is refused, because answering from it
would need the meter's keys *and* its exact counters.
"""

from __future__ import annotations

import os
from collections.abc import Iterable

from pydlms.apdu import xdlms
from pydlms.apdu.acse import AARE
from pydlms.apdu.tags import Tag, tag_name
from pydlms.cosem.enums import DataAccessResult
from pydlms.debug import get_logger
from pydlms.exceptions import DecodeError, DlmsError
from pydlms.recording import load_recording, session_apdus
from pydlms.security.ciphering import is_ciphered_apdu
from pydlms.simulator import MeterSimulator, _Session

__all__ = ["ReplayMeter"]

log = get_logger("simulator")

#: Confirmed requests/responses whose third octet is the invoke-id-and-priority.
_INVOKE_REQUESTS = {Tag.GET_REQUEST, Tag.SET_REQUEST, Tag.ACTION_REQUEST}
_INVOKE_RESPONSES = {Tag.GET_RESPONSE, Tag.SET_RESPONSE, Tag.ACTION_RESPONSE}
_ACSE = {Tag.AARQ, Tag.AARE, Tag.RLRQ, Tag.RLRE}


def _key(request: bytes) -> bytes:
    if request[0] in _INVOKE_REQUESTS and len(request) >= 3:
        return request[:2] + request[3:]
    return request


class ReplayMeter(MeterSimulator):
    """Simulator answering service requests from a recorded session.

    ``recording`` is a path to a ``--record`` file or already parsed
    ``(direction, bytes)`` records (:func:`pydlms.recording.parse_recording`).
    Keyword arguments go to :class:`~pydlms.simulator.MeterSimulator` and
    override what the recorded AARE says (``system_title``, ``max_pdu``,
    ``conformance``, keys). Add client profiles for secured SAPs as with the
    simulator: ``meter.clients[1] = ClientProfile(Mechanism.HLS_GMAC, ...)``.
    """

    def __init__(
        self, recording: str | os.PathLike | Iterable[tuple[str | None, bytes]], **kwargs
    ) -> None:
        records = (
            load_recording(recording) if isinstance(recording, (str, os.PathLike)) else recording
        )
        self.pairs: list[tuple[bytes, bytes]] = []
        self.recorded_aare: AARE | None = None
        pending: bytes | None = None
        for direction, apdu in session_apdus(records):
            if not apdu:
                continue
            if apdu[0] == Tag.AARE:
                self._take_aare(apdu, kwargs)
            if apdu[0] in _ACSE or apdu[0] in (Tag.GENERAL_BLOCK_TRANSFER,):
                pending = None
                continue
            if is_ciphered_apdu(apdu):
                raise DecodeError(
                    f"recording holds a ciphered {tag_name(apdu[0])} without its plaintext; "
                    "record the session again with this pydlms version (it adds "
                    "TX-APDU/RX-APDU lines) to replay it"
                )
            if direction == "TX":
                pending = apdu
            elif direction == "RX" and pending is not None:
                self.pairs.append((pending, apdu))
                pending = None
        if not self.pairs:
            raise DecodeError("recording holds no request/response pairs to replay")
        super().__init__(**kwargs)
        self._used = [False] * len(self.pairs)
        self._cursor = 0
        #: Requests the recording had no answer for, in arrival order.
        self.misses: list[bytes] = []

    def _take_aare(self, apdu: bytes, kwargs: dict) -> None:
        try:
            aare = AARE.from_bytes(apdu)
        except DlmsError:
            return
        self.recorded_aare = aare
        if aare.responding_ap_title and len(aare.responding_ap_title) == 8:
            kwargs.setdefault("system_title", aare.responding_ap_title)
        info = aare.user_information
        if info and info[0] == Tag.INITIATE_RESPONSE:
            initiate = xdlms.InitiateResponse.from_bytes(info)
            kwargs.setdefault("conformance", initiate.conformance)
            kwargs.setdefault("max_pdu", initiate.max_receive_pdu_size)

    # -- answering -----------------------------------------------------------------
    def _lookup(self, request: bytes) -> bytes | None:
        key = _key(request)
        for i in range(self._cursor, len(self.pairs)):
            if not self._used[i] and _key(self.pairs[i][0]) == key:
                self._used[i] = True
                self._cursor = i + 1
                return self.pairs[i][1]
        # Used up (or recorded earlier than the cursor): repeat the last answer.
        for i in range(len(self.pairs) - 1, -1, -1):
            if _key(self.pairs[i][0]) == key:
                return self.pairs[i][1]
        return None

    def _service(self, plain: bytes, session: _Session) -> bytes | None:
        if session.hls_pending:  # HLS pass 3/4 is computed, never recorded
            return super()._service(plain, session)
        response = self._lookup(plain)
        if response is None:
            self.misses.append(plain)
            log.warning("replay: no recorded answer for %s", plain.hex())
            if plain[0] == Tag.GET_REQUEST and plain[1] == 1 and len(plain) >= 3:
                return xdlms.GetResponseNormal(
                    plain[2], xdlms.GetDataResult(error=DataAccessResult.OBJECT_UNDEFINED)
                ).to_bytes()
            return xdlms.ExceptionResponse(2, 1).to_bytes()  # service-unknown/not possible
        if response[0] in _INVOKE_RESPONSES and plain[0] in _INVOKE_REQUESTS:
            response = response[:2] + plain[2:3] + response[3:]
        return response
