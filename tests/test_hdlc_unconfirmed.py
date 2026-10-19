"""Unconfirmed and broadcast sends, and the push trigger.

HDLC: an unconfirmed APDU goes in one UI frame with P=0 to the server
address, or to the all-station address for a broadcast, and needs no link
(IEC 62056-53:2006 annex B.2.6.1 Table B.1 and B.2.6.2, public as IS/IEC
62056-53; behaviour as cB-Sigma ``hdlc/client.go`` ``SendBroadcast``). An
empty UI frame with P=1 gives the server the right to send its pending UI
frames (IEC 62056-53:2006 B.2.6.4, Figure B.4). Wrapper: a broadcast goes
to the all-station wPort 0x007F (*unverified*).
"""

from __future__ import annotations

import pytest

from pydlms.apdu import xdlms
from pydlms.association import Association, AssociationState
from pydlms.exceptions import ProtocolError
from pydlms.hdlc.address import HdlcAddress
from pydlms.hdlc.connection import HdlcLink, HdlcParameters, HdlcState
from pydlms.hdlc.crc import fcs_bytes
from pydlms.hdlc.framing import (
    LLC_RESPONSE,
    PF_BIT,
    FrameType,
    HdlcFrame,
    decode_frame,
    encode_frame,
)
from pydlms.link import ApduLink
from pydlms.transports.base import LoopbackTransport
from pydlms.wrapper import WPORT_BROADCAST, WrapperLink, decode_wrapper
from tests.test_association import AARE_OK, ScriptedLink
from tests.test_hdlc import FakeMeter, make_link

# set-request-normal, Invoke-Id-And-Priority 0x81 (high priority, service
# class unconfirmed, invoke id 1), Data 0.0.96.1.0.255 attribute 2, no
# selective access, visible-string "A".
UNCONFIRMED_SET = bytes.fromhex("c1 01 81 0001 0000600100ff 02 00 0a 01 41".replace(" ", ""))
CONFIRMED_SET = UNCONFIRMED_SET[:2] + b"\xc1" + UNCONFIRMED_SET[3:]
NOTIFICATION = bytes.fromhex("0f 00000001 00 11 05".replace(" ", ""))


def _ui(link_sent: list[bytes]) -> HdlcFrame:
    (raw,) = link_sent
    return decode_frame(raw)


def _open_link(**kw) -> tuple[HdlcLink, LoopbackTransport]:
    transport = LoopbackTransport()
    transport.open()
    return HdlcLink(transport, timeout=0.05, **kw), transport


# --- HDLC UI send ----------------------------------------------------------------


def test_ui_frame_vector():
    """Hand-checked layout: flag, format A0 + length, server 1, client 16,
    UI with P=0, HCS, LLC E6 E6 00, the APDU, FCS, flag."""
    link, transport = _open_link()
    link.send_unconfirmed(UNCONFIRMED_SET)
    (raw,) = transport.sent
    length = 2 + 1 + 1 + 1 + 2 + 3 + len(UNCONFIRMED_SET) + 2
    header = bytes([0xA0, length, 0x03, 0x21, 0x03])
    info = b"\xe6\xe6\x00" + UNCONFIRMED_SET
    expected = (
        b"\x7e"
        + header
        + fcs_bytes(header)
        + info
        + fcs_bytes(header + fcs_bytes(header) + info)
        + b"\x7e"
    )
    assert raw == expected
    frame = decode_frame(raw)
    assert frame.kind == FrameType.UI and not frame.poll_final and not frame.segmented


def test_ui_without_connection_uses_default_max_info():
    link, transport = _open_link()
    assert link.state == HdlcState.DISCONNECTED
    link.send_unconfirmed(bytes(128 - 3))
    assert len(_ui(transport.sent).info) == 128
    with pytest.raises(ProtocolError, match="one UI frame"):
        link.send_unconfirmed(bytes(128 - 2))
    assert len(transport.sent) == 1  # nothing sent for the refused APDU


def test_ui_respects_negotiated_max_info():
    meter = UiMeter(max_info=32)
    link = make_link(meter)
    link.connect()
    link.send_unconfirmed(bytes(29))
    with pytest.raises(ProtocolError, match="one UI frame"):
        link.send_unconfirmed(bytes(30))
    assert meter.ui == [bytes(29)]


def test_ui_ignores_a_previous_sessions_negotiation():
    meter = UiMeter(max_info=32)
    link = make_link(meter)
    link.connect()
    link.disconnect()
    link.transport.open()
    link.send_unconfirmed(bytes(100))  # default 128 again, not the old 32
    assert meter.ui == [bytes(100)]


@pytest.mark.parametrize(
    "server,dest",
    [
        (HdlcAddress.server(1), b"\xff"),
        (HdlcAddress.server(1, 17), b"\xfe\xff"),
        (HdlcAddress(1, 1000, 4), b"\xfe\xfe\xfe\xff"),
    ],
)
def test_broadcast_goes_to_the_all_station_address(server, dest):
    link, transport = _open_link(server_address=server)
    link.send_unconfirmed(UNCONFIRMED_SET, broadcast=True)
    (raw,) = transport.sent
    assert raw[3 : 3 + len(dest)] == dest
    frame = decode_frame(raw)
    assert frame.dest.upper == (0x7F if server.size in (1, 2) else 0x3FFF)
    assert frame.src == HdlcAddress.client(16)
    assert frame.info == b"\xe6\xe6\x00" + UNCONFIRMED_SET


def test_unicast_ui_goes_to_the_server_address():
    link, transport = _open_link(server_address=HdlcAddress.server(1, 17))
    link.send_unconfirmed(UNCONFIRMED_SET)
    assert _ui(transport.sent).dest == HdlcAddress.server(1, 17)


class UiMeter(FakeMeter):
    """FakeMeter that records UI APDUs and answers a P=1 UI poll with
    ``pending`` UI frames."""

    def __init__(self, pending=(), **kw):
        super().__init__(**kw)
        self.ui: list[bytes] = []
        self.polls = 0
        self.pending = list(pending)

    def handle(self, f):
        if f.kind == FrameType.UI:
            if f.poll_final and not f.info:
                self.polls += 1
                out = b"".join(encode_frame(frame) for frame in self.pending)
                self.pending = []
                return out
            assert not f.poll_final
            assert f.info[:3] == b"\xe6\xe6\x00"
            self.ui.append(f.info[3:])
            return b""
        return super().handle(f)


def test_ui_send_leaves_the_sequence_state_alone():
    meter = UiMeter()
    link = make_link(meter)
    link.connect()
    assert link.request(b"\xc0\x01\x01") == b"\xc0\x01\x01"
    vs, vr = link.vs, link.vr
    link.send_unconfirmed(UNCONFIRMED_SET)
    assert (link.vs, link.vr) == (vs, vr)
    assert link.request(b"\xc0\x01\x02") == b"\xc0\x01\x02"
    assert meter.ui == [UNCONFIRMED_SET]


# --- push trigger --------------------------------------------------------------


def _push(apdu: bytes, final: bool, segmented: bool = False, info: bytes | None = None):
    control = FrameType.UI | (PF_BIT if final else 0)
    body = LLC_RESPONSE + apdu if info is None else info
    return HdlcFrame(HdlcAddress.client(16), HdlcAddress.server(1), control, body, segmented)


def test_trigger_pushes_queues_what_the_meter_sends():
    second = NOTIFICATION[:-1] + b"\x06"
    meter = UiMeter(pending=[_push(NOTIFICATION, False), _push(second, True)])
    link = make_link(meter)
    link.connect()
    assert link.trigger_pushes() == 2
    assert meter.polls == 1
    assert link.receive_push() == NOTIFICATION
    assert link.receive_push() == second


def test_trigger_pushes_reassembles_segmented_ui():
    body = LLC_RESPONSE + NOTIFICATION
    meter = UiMeter(
        pending=[
            _push(b"", False, segmented=True, info=body[:5]),
            _push(b"", True, info=body[5:]),
        ]
    )
    link = make_link(meter)
    link.connect()
    assert link.trigger_pushes() == 1
    assert link.receive_push() == NOTIFICATION


def test_trigger_pushes_frame_layout():
    link, transport = _open_link()
    link.trigger_pushes(timeout=0.01)
    frame = _ui(transport.sent)
    assert frame.kind == FrameType.UI and frame.poll_final and frame.info == b""
    assert frame.dest == HdlcAddress.server(1)


def test_trigger_pushes_without_answer_returns_zero():
    link, _ = _open_link()
    assert link.trigger_pushes(timeout=0.01) == 0


def test_trigger_pushes_empty_final_ui_means_nothing_pending():
    meter = UiMeter(pending=[_push(b"", True, info=b"")])
    link = make_link(meter)
    link.connect()
    assert link.trigger_pushes() == 0


def test_trigger_pushes_refused_while_a_response_is_outstanding():
    meter = UiMeter()
    link = make_link(meter)
    link.connect()
    link._awaiting = True
    with pytest.raises(ProtocolError, match="outstanding"):
        link.trigger_pushes()
    assert meter.polls == 0


def test_trigger_pushes_dm_on_a_connected_link_ends_it():
    meter = UiMeter(
        pending=[HdlcFrame(HdlcAddress.client(16), HdlcAddress.server(1), FrameType.DM | PF_BIT)]
    )
    link = make_link(meter)
    link.connect()
    with pytest.raises(ProtocolError, match="DM"):
        link.trigger_pushes()
    assert link.state == HdlcState.DISCONNECTED


# --- wrapper ---------------------------------------------------------------------


def test_wrapper_unconfirmed_goes_to_the_server_wport():
    transport = LoopbackTransport()
    link = WrapperLink(transport, client_wport=0x10, server_wport=0x01)
    link.send_unconfirmed(UNCONFIRMED_SET)
    pdu = decode_wrapper(transport.sent[0])
    assert (pdu.source, pdu.destination, pdu.apdu) == (0x10, 0x01, UNCONFIRMED_SET)


def test_wrapper_broadcast_goes_to_wport_0x7f():
    transport = LoopbackTransport()
    link = WrapperLink(transport, client_wport=0x10, server_wport=0x01)
    link.send_unconfirmed(UNCONFIRMED_SET, broadcast=True)
    assert transport.sent[0] == bytes.fromhex("0001 0010 007f 0010".replace(" ", "")) + (
        UNCONFIRMED_SET
    )
    assert decode_wrapper(transport.sent[0]).destination == WPORT_BROADCAST


def test_base_link_sends_without_awaiting_and_cannot_broadcast():
    link = ScriptedLink([])
    ApduLink.send_unconfirmed(link, UNCONFIRMED_SET)
    assert link.sent == [UNCONFIRMED_SET]
    with pytest.raises(ProtocolError, match="broadcast"):
        link.send_unconfirmed(UNCONFIRMED_SET, broadcast=True)


# --- association -----------------------------------------------------------------


def _associated() -> tuple[Association, ScriptedLink]:
    link = ScriptedLink([AARE_OK])
    assoc = Association(link)
    assoc.associate()
    return assoc, link


@pytest.mark.parametrize(
    "apdu",
    [
        UNCONFIRMED_SET,
        bytes.fromhex("c0 01 01 0003 0100010800ff 02 00".replace(" ", "")),  # GET, unconfirmed
        bytes.fromhex("c3 01 01 0046 0000600300ff 01 00".replace(" ", "")),  # ACTION
        bytes.fromhex("16 01 02 00 0200 0f 01".replace(" ", "")),  # SN unconfirmed write
        bytes.fromhex("d9 00000001 00 00 00".replace(" ", "")),  # ACCESS, unconfirmed
    ],
)
def test_association_sends_unconfirmed_services_without_waiting(apdu):
    assoc, link = _associated()
    assoc.send_unconfirmed(apdu)  # the script has no response: none is read
    assert link.sent[-1] == apdu


@pytest.mark.parametrize(
    "apdu",
    [
        CONFIRMED_SET,
        bytes.fromhex("c0 01 c1 0003 0100010800ff 02 00".replace(" ", "")),
        bytes.fromhex("d9 40000001 00 00 00".replace(" ", "")),  # ACCESS, confirmed
        bytes.fromhex("05 01 02 0200".replace(" ", "")),  # SN ReadRequest
        bytes.fromhex("c0 01".replace(" ", "")),  # too short to carry a service class
        bytes.fromhex("62 00".replace(" ", "")),  # RLRQ
        b"",
    ],
)
def test_association_refuses_confirmed_or_unknown_services(apdu):
    assoc, link = _associated()
    sent = len(link.sent)
    with pytest.raises(ProtocolError):
        assoc.send_unconfirmed(apdu)
    assert len(link.sent) == sent


def test_association_send_unconfirmed_needs_an_association():
    link = ScriptedLink([])
    assoc = Association(link)
    assert assoc.state == AssociationState.IDLE
    with pytest.raises(ProtocolError, match="not associated"):
        assoc.send_unconfirmed(UNCONFIRMED_SET)
    assert link.sent == []


def test_association_send_unconfirmed_respects_the_server_pdu_size():
    assoc, link = _associated()  # server max-receive-pdu-size 512
    big = UNCONFIRMED_SET[:-3] + b"\x09\x82\x02\x00" + bytes(512)
    with pytest.raises(ProtocolError, match="max-receive-pdu-size"):
        assoc.send_unconfirmed(big)


def test_association_send_unconfirmed_over_hdlc_ui():
    meter = UiMeter()
    link = make_link(meter, parameters=HdlcParameters())
    link.connect()
    assoc = Association(link)
    assoc.state = AssociationState.ASSOCIATED
    assoc.send_unconfirmed(UNCONFIRMED_SET)
    assert meter.ui == [UNCONFIRMED_SET]


def test_association_send_unconfirmed_protects_the_apdu():
    pytest.importorskip("cryptography")
    from pydlms.security.ciphering import unwrap
    from tests.test_association_security import associate, meter

    srv = meter()
    assoc, link = associate(srv)
    counter = assoc.security.invocation_counter
    assoc.send_unconfirmed(UNCONFIRMED_SET)
    protected = link.sent[-1]
    assert protected[0] == 0xC9  # glo-set-request
    assert unwrap(srv, protected).plaintext == UNCONFIRMED_SET
    assert assoc.security.invocation_counter == counter + 1


def test_unconfirmed_invoke_byte_matches_the_builder():
    assert UNCONFIRMED_SET[2] == xdlms.invoke_id_byte(1, confirmed=False)
