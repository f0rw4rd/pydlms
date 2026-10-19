"""Pushes on a shared connection.

A meter may send a DataNotification, EventNotification or InformationReport
on the association's own connection while the client waits for a response.
The association must queue it for ``read_push`` (as verified plaintext: the
inbound invocation counter has already advanced), keep waiting for the reply,
and still refuse everything that is neither a reply nor an authentic
notification.
"""

from __future__ import annotations

import time

import pytest

from pydlms.apdu import xdlms
from pydlms.apdu.tags import UNSOLICITED_TAGS, Tag
from pydlms.apdu.xdlms import AttributeDescriptor, DataNotification, EventNotificationRequest
from pydlms.association import MAX_STALE_RESPONSES, Association
from pydlms.cosem.data import DlmsData
from pydlms.exceptions import DlmsTimeoutError, ProtocolError
from pydlms.link import MAX_QUEUED_PUSHES, ApduLink
from pydlms.obis import ObisCode
from pydlms.transports.base import LoopbackTransport
from pydlms.wrapper import WrapperLink, encode_wrapper
from tests.test_association import AARE_OK, ScriptedLink

GET_REQUEST = bytes.fromhex("c0 01 c1 0003 0100010800ff 02 00")  # invoke-id 1
GET_RESPONSE = xdlms.GetResponseNormal(0xC1, xdlms.GetDataResult(data=DlmsData.uint8(1))).to_bytes()
ENERGY = ObisCode.parse("1.0.1.8.0.255")


def notification(long_invoke_id: int = 0x00C10000, value: int = 42) -> bytes:
    body = DlmsData.structure(
        [DlmsData.structure([DlmsData.octet_string(ENERGY.to_bytes()), DlmsData.uint32(value)])]
    )
    return DataNotification(long_invoke_id, body).to_bytes()


def event(value: int = 7) -> bytes:
    return EventNotificationRequest(
        AttributeDescriptor(3, ENERGY, 2), DlmsData.uint32(value)
    ).to_bytes()


def associated(*replies) -> tuple[Association, ScriptedLink]:
    link = ScriptedLink([AARE_OK, *replies])
    assoc = Association(link)
    assoc.associate()
    return assoc, link


# --- tag set ---------------------------------------------------------------------------


def test_unsolicited_tags_cover_every_form():
    assert {
        Tag.DATA_NOTIFICATION,
        Tag.EVENT_NOTIFICATION_REQUEST,
        Tag.INFORMATION_REPORT_REQUEST,
    } == UNSOLICITED_TAGS
    assert Tag.GET_RESPONSE not in UNSOLICITED_TAGS


# --- plaintext association -------------------------------------------------------------


def test_push_colliding_with_the_invoke_id_is_never_the_response():
    """Wave 0 defect 2: octet 2 of a DataNotification belongs to its long
    invoke id. With it equal to the request's invoke-id the push used to be
    returned as the GET response."""
    push = notification(long_invoke_id=0x00C10000)
    assert push[2] & 0x0F == GET_REQUEST[2] & 0x0F
    assoc, link = associated(push, GET_RESPONSE)
    assert assoc.request(GET_REQUEST) == GET_RESPONSE
    assert link.receive_push() == push
    with pytest.raises(AssertionError, match="script exhausted"):
        link.receive_push()  # readable exactly once


@pytest.mark.parametrize("push", [notification(), event()], ids=["data", "event"])
def test_plain_push_before_the_response_is_queued(push):
    assoc, link = associated(push, GET_RESPONSE)
    assert assoc.request(GET_REQUEST) == GET_RESPONSE
    entry = link.receive_queued_push()
    assert entry.apdu == push and entry.unwrapped is None


def test_pushes_and_stale_replies_share_one_bound():
    stale = bytearray(GET_RESPONSE)
    stale[2] = 0xC2  # invoke-id 2
    replies = [notification(), bytes(stale)] * MAX_STALE_RESPONSES
    assoc, _ = associated(*replies, GET_RESPONSE)
    with pytest.raises(ProtocolError, match="not the response"):
        assoc.request(GET_REQUEST)


def test_pushes_up_to_the_bound_are_accepted():
    pushes = [notification(value=n) for n in range(MAX_STALE_RESPONSES)]
    assoc, link = associated(*pushes, GET_RESPONSE)
    assert assoc.request(GET_REQUEST) == GET_RESPONSE
    assert [link.receive_push() for _ in pushes] == pushes


def test_other_non_replies_are_not_diverted():
    """Only notifications are diverted: a request-direction APDU is handed
    on exactly as before (the caller fails to decode it)."""
    assoc, _ = associated(GET_REQUEST)
    assert assoc.request(GET_REQUEST) == GET_REQUEST


# --- the queue itself ------------------------------------------------------------------


class _NoTraffic(ApduLink):
    def connect(self):
        pass

    def disconnect(self):
        pass

    def send_apdu(self, apdu):
        pass

    def receive_apdu(self, timeout=None):
        raise DlmsTimeoutError("nothing")


def test_queue_overflow_drops_the_oldest(caplog):
    link = _NoTraffic()
    for n in range(MAX_QUEUED_PUSHES + 2):
        link.queue_push(bytes([0x0F, n]))
    assert link.dropped_pushes == 2
    assert "push queue full" in caplog.text
    got = [link.receive_push() for _ in range(MAX_QUEUED_PUSHES)]
    assert got[0] == bytes([0x0F, 2]) and got[-1] == bytes([0x0F, MAX_QUEUED_PUSHES + 1])
    with pytest.raises(DlmsTimeoutError):
        link.receive_push(0)


def test_queued_push_repr_is_short():
    link = _NoTraffic()
    link.queue_push(b"\x0f" + bytes(range(1, 101)))
    text = repr(link.receive_queued_push())
    assert text.startswith("QueuedPush(0F ") and "+85 bytes" in text and "as received" in text


# --- wrapper push wPorts ---------------------------------------------------------------


def _wrapper(push_wports=frozenset()):
    transport = LoopbackTransport(timeout=0.2)
    link = WrapperLink(transport, 0x10, 1, timeout=0.2, push_wports=push_wports)
    link.connect()
    return link, transport


def test_wpdu_to_a_push_wport_is_queued():
    push = notification()
    link, transport = _wrapper(push_wports=frozenset({0x66}))
    transport.inject(encode_wrapper(1, 0x66, push) + encode_wrapper(1, 0x10, GET_RESPONSE))
    assert link.receive_apdu() == GET_RESPONSE
    assert link.queued_pushes == 1 and link.discarded == 0
    assert link.receive_push() == push


def test_wpdu_to_an_unlisted_wport_is_still_discarded():
    link, transport = _wrapper()
    transport.inject(
        encode_wrapper(1, 0x66, notification()) + encode_wrapper(1, 0x10, GET_RESPONSE)
    )
    assert link.receive_apdu() == GET_RESPONSE
    assert link.discarded == 1 and link.queued_pushes == 0
    with pytest.raises(DlmsTimeoutError):
        link.receive_push(0.05)


def test_receive_push_waits_on_the_push_wport():
    push = notification()
    link, transport = _wrapper(push_wports=frozenset({0x66}))
    transport.inject(encode_wrapper(1, 0x66, push))
    assert link.receive_push() == push
    assert link.queued_pushes == 0


# --- ciphered association --------------------------------------------------------------


@pytest.fixture
def ciphered():
    pytest.importorskip("cryptography")
    from tests.test_association_security import associate, meter

    srv = meter()
    return srv, associate


def test_general_glo_push_before_the_response(ciphered):
    from pydlms.push import PushDecoder
    from pydlms.security.ciphering import wrap, wrap_general_glo

    srv, associate = ciphered
    push = notification()
    assoc, link = associate(
        srv, lambda _: wrap_general_glo(srv, push), lambda _: wrap(srv, GET_RESPONSE)
    )
    assert assoc.request(GET_REQUEST) == GET_RESPONSE
    entry = link.receive_queued_push()
    assert entry.apdu == push  # plaintext, never deciphered twice
    assert entry.unwrapped.authenticated
    message = PushDecoder("raw", security=assoc.security).decode_queued(entry)
    assert message.authenticated and message.system_title == b"SERVER01"
    assert message.get("1.0.1.8.0.255") == 42


def test_glo_event_notification_push_is_queued(ciphered):
    from pydlms.security.ciphering import wrap

    srv, associate = ciphered
    push = event()
    assoc, link = associate(srv, lambda _: wrap(srv, push), lambda _: wrap(srv, GET_RESPONSE))
    assert assoc.request(GET_REQUEST) == GET_RESPONSE
    assert link.receive_push() == push


def test_forged_plaintext_push_in_a_protected_association_is_refused(ciphered):
    srv, associate = ciphered
    assoc, link = associate(srv, notification())
    with pytest.raises(ProtocolError, match="unprotected DATA_NOTIFICATION"):
        assoc.request(GET_REQUEST)
    assert not link.push_queue()


def test_unauthenticated_ciphered_push_is_refused(ciphered):
    from pydlms.exceptions import AuthenticationError
    from pydlms.security.ciphering import wrap_general_glo
    from pydlms.security.suites import SecurityControl

    srv, associate = ciphered
    sc = SecurityControl(encrypted=True)
    assoc, link = associate(srv, lambda _: wrap_general_glo(srv, notification(), sc))
    with pytest.raises(AuthenticationError, match="not authenticated"):
        assoc.request(GET_REQUEST)
    assert not link.push_queue()


@pytest.mark.parametrize("index", [-1, -13, 12])
def test_tampered_general_glo_push_is_refused(ciphered, index):
    from pydlms.exceptions import AuthenticationError
    from pydlms.security.ciphering import wrap_general_glo

    srv, associate = ciphered

    def tampered(_):
        apdu = bytearray(wrap_general_glo(srv, notification()))
        apdu[index] ^= 0x01
        return bytes(apdu)

    assoc, link = associate(srv, tampered)
    with pytest.raises(AuthenticationError):
        assoc.request(GET_REQUEST)
    assert not link.push_queue()


def test_general_glo_push_from_another_title_is_refused(ciphered):
    from pydlms.exceptions import AuthenticationError
    from pydlms.security.ciphering import wrap_general_glo
    from pydlms.security.context import SecurityContext
    from tests.test_association_security import AK, CLIENT, EK

    srv, associate = ciphered
    other = SecurityContext(EK, AK, client_system_title=b"OTHER001", server_system_title=CLIENT)
    assoc, link = associate(srv, lambda _: wrap_general_glo(other, notification()))
    with pytest.raises(AuthenticationError, match="system title"):
        assoc.request(GET_REQUEST)
    assert not link.push_queue()


def test_reply_envelope_relabelled_as_a_notification_is_refused(ciphered):
    """The glo- tag is outside the AAD: a glo-get-response retagged as
    glo-event-notification must not be queued as a push."""
    from pydlms.exceptions import AuthenticationError
    from pydlms.security.ciphering import wrap

    srv, associate = ciphered

    def retagged(_):
        apdu = bytearray(wrap(srv, GET_RESPONSE))
        apdu[0] = Tag.GLO_EVENT_NOTIFICATION_REQUEST
        return bytes(apdu)

    assoc, link = associate(srv, retagged)
    with pytest.raises(AuthenticationError, match="GET_RESPONSE"):
        assoc.request(GET_REQUEST)
    assert not link.push_queue()


def test_replayed_push_is_refused(ciphered):
    from pydlms.exceptions import ReplayError
    from pydlms.security.ciphering import wrap, wrap_general_glo

    srv, associate = ciphered
    sent: list[bytes] = []

    def push(_):  # wrapped once, after the AARE, then sent again verbatim
        if not sent:
            sent.append(wrap_general_glo(srv, notification()))
        return sent[0]

    assoc, link = associate(srv, push, lambda _: wrap(srv, GET_RESPONSE), push)
    assert assoc.request(GET_REQUEST) == GET_RESPONSE
    with pytest.raises(ReplayError):
        assoc.request(GET_REQUEST)
    assert len(link.push_queue()) == 1


# --- pushes the link queued by itself (HDLC UI, wrapper push wPorts) ---------------------


def test_link_queued_ciphered_push_is_opened_before_the_reply(ciphered):
    """Otherwise its counter, below the reply's, would fail at read_push."""
    from pydlms.push import PushDecoder
    from pydlms.security.ciphering import wrap, wrap_general_glo

    srv, associate = ciphered
    push = notification()

    def reply(_):
        link.queue_push(wrap_general_glo(srv, push))  # as a UI frame would be
        return wrap(srv, GET_RESPONSE)

    assoc, link = associate(srv, reply)
    assert assoc.request(GET_REQUEST) == GET_RESPONSE
    entry = link.receive_queued_push()
    assert entry.apdu == push and entry.checked and entry.unwrapped.authenticated
    assert PushDecoder("raw", security=assoc.security).decode_queued(entry).authenticated


def test_link_queued_plaintext_push_in_a_protected_association_is_refused(ciphered):
    from pydlms.security.ciphering import wrap, wrap_general_glo

    srv, associate = ciphered
    good = notification(value=1)

    def reply(_):
        link.queue_push(notification(value=666))  # forged, unprotected
        link.queue_push(wrap_general_glo(srv, good))
        return wrap(srv, GET_RESPONSE)

    assoc, link = associate(srv, reply)
    with pytest.raises(ProtocolError, match="unprotected DATA_NOTIFICATION"):
        assoc.request(GET_REQUEST)
    assert [p.checked for p in link.push_queue()] == [False]  # the forged one is gone


def test_link_queued_tampered_push_is_refused(ciphered):
    from pydlms.exceptions import AuthenticationError
    from pydlms.security.ciphering import wrap, wrap_general_glo

    srv, associate = ciphered

    def reply(_):
        apdu = bytearray(wrap_general_glo(srv, notification()))
        apdu[-1] ^= 0x80
        link.queue_push(bytes(apdu))
        return wrap(srv, GET_RESPONSE)

    assoc, link = associate(srv, reply)
    with pytest.raises(AuthenticationError):
        assoc.request(GET_REQUEST)
    assert not link.push_queue()


def test_link_queued_reply_is_not_a_push(ciphered):
    from pydlms.security.ciphering import wrap

    srv, associate = ciphered

    def reply(_):
        link.queue_push(wrap(srv, GET_RESPONSE))  # a reply sent to the push wPort
        return wrap(srv, GET_RESPONSE)

    assoc, link = associate(srv, reply)
    with pytest.raises(ProtocolError, match="not a notification"):
        assoc.request(GET_REQUEST)
    assert not link.push_queue()


def test_link_queued_plain_push_in_a_plain_association_is_kept():
    push = notification()
    assoc, link = associated(GET_RESPONSE)
    link.queue_push(push)
    assert assoc.request(GET_REQUEST) == GET_RESPONSE
    entry = link.receive_queued_push()
    assert entry.apdu == push and entry.checked and entry.unwrapped is None


# --- end to end against the simulator --------------------------------------------------


EK = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
AK = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")


@pytest.fixture
def sim():
    from pydlms.simulator import example_meter, serve

    meter = example_meter(encryption_key=EK, authentication_key=AK)
    servers = []

    def start(hdlc=False):
        server = serve(meter, hdlc=hdlc)
        servers.append(server)
        return server.server_address

    meter.start = start
    yield meter
    for server in servers:
        server.shutdown()
        server.server_close()


def _client(sim, hdlc=False, ciphered=False, **kw):
    from pydlms.client import DlmsClient
    from pydlms.simulator import ClientProfile

    if ciphered:
        pytest.importorskip("cryptography")
        from pydlms.security.context import SecurityContext

        sim.clients[16] = ClientProfile(ciphered=True)
        kw["security"] = SecurityContext(EK, AK, client_system_title=b"PYDCLNT1")
    host, port = sim.start(hdlc)
    return DlmsClient.tcp(host, port, hdlc=hdlc, timeout=2, **kw)


SCENARIOS = [
    pytest.param(False, False, None, "ui", id="wrapper-plain"),
    pytest.param(False, True, "general-glo", "ui", id="wrapper-general-glo"),
    pytest.param(True, False, None, "ui", id="hdlc-ui-plain"),
    pytest.param(True, False, None, "i", id="hdlc-i-plain"),
    pytest.param(True, True, "general-glo", "ui", id="hdlc-ui-general-glo"),
    pytest.param(True, True, "general-glo", "i", id="hdlc-i-general-glo"),
    pytest.param(True, True, "glo", "i", id="hdlc-i-glo-event"),
]


@pytest.mark.parametrize(("hdlc", "ciphered", "protection", "frame"), SCENARIOS)
def test_simulator_push_before_the_response(sim, hdlc, ciphered, protection, frame):
    push = event() if protection == "glo" else notification()
    with _client(sim, hdlc=hdlc, ciphered=ciphered) as m:
        sim.push_before_response(push, protection=protection, hdlc_frame=frame)
        started = time.monotonic()
        assert m.get_register("1.0.1.8.0.255").value == 12345678
        assert time.monotonic() - started < 1.5  # no timeout-driven recovery
        message = m.read_push(timeout=0.5)
        assert message.authenticated is ciphered
        assert message.get("1.0.1.8.0.255") == (7 if protection == "glo" else 42)
        with pytest.raises(DlmsTimeoutError):
            m.read_push(timeout=0.2)  # exactly once
        assert m.get_register("1.0.1.8.0.255").value == 12345678


@pytest.mark.parametrize("protection", [None, "general-glo"])
def test_simulator_push_to_a_push_wport(sim, protection):
    from pydlms.wrapper import WrapperLink

    with _client(sim, ciphered=protection is not None) as m:
        assert isinstance(m.link, WrapperLink)
        m.link.push_wports = frozenset({0x66})
        sim.push_before_response(notification(), protection=protection, wport=0x66)
        assert m.get_register("1.0.1.8.0.255").value == 12345678
        assert m.link.queued_pushes == 1
        message = m.read_push(timeout=0.5)
        assert message.get("1.0.1.8.0.255") == 42
        assert message.authenticated is (protection is not None)
