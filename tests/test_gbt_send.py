"""Requests sent in general-block-transfer, recovery and GBT pushes.

``Association.request`` protects first, then cuts a request longer than the
server's max PDU into GBT blocks when GBT was negotiated; the client prefers
GBT to SET / ACTION / SN blocks. Scripted peers pin the exchange bytes; the
in-process simulator runs it end to end (wrapper and HDLC, plain and
ciphered), with lost blocks in both directions.
"""

from __future__ import annotations

import pytest

from pydlms.apdu import xdlms
from pydlms.apdu.acse import AARE, ApplicationContext
from pydlms.apdu.gbt import GbtBlock, decode_gbt, encode_gbt, split_gbt
from pydlms.association import Association, AssociationSettings
from pydlms.client import DlmsClient
from pydlms.cosem.data import DlmsData
from pydlms.cosem.interface_classes import ClassId
from pydlms.exceptions import DlmsTimeoutError, ProtocolError
from pydlms.obis import ObisCode
from pydlms.simulator import example_meter, serve
from tests.test_association import ScriptedLink
from tests.test_gbt_transfer import _response_blocks, ack, blk

GBT = xdlms.Conformance.GENERAL_BLOCK_TRANSFER
X = ObisCode.parse("0.0.42.0.0.255")


# --- Association with a scripted peer --------------------------------------------------


def _initiate(conformance, pdu):
    return AARE(
        ApplicationContext.LN,
        0,
        user_information=xdlms.InitiateResponse(conformance, pdu).to_bytes(),
    ).to_bytes()


def gbt_association(responses, pdu=64, **settings):
    conformance = xdlms.Conformance.default_ln() | GBT
    link = ScriptedLink([_initiate(conformance, pdu), *responses])
    assoc = Association(link, AssociationSettings(propose_gbt=True, **settings))
    assoc.associate()
    return assoc, link


SET_LONG = xdlms.SetRequestNormal(
    0xC1, xdlms.AttributeDescriptor(1, X, 2), DlmsData.octet_string(bytes(150))
).to_bytes()
SET_OK = xdlms.SetResponseNormal(0xC1, 0).to_bytes()


def test_propose_gbt_sets_the_conformance_bit():
    link = ScriptedLink([_initiate(xdlms.Conformance.default_ln(), 64)])
    Association(link).associate()
    assert b"\x5f\x1f\x04\x00\x00\x7e\x1f" in link.sent[0]
    _, link = gbt_association([])
    assert b"\x5f\x1f\x04\x00\x20\x7e\x1f" in link.sent[0]


def test_long_request_is_split_into_gbt_blocks():
    assoc, link = gbt_association([ack(1, 1), ack(2, 2), SET_OK])
    assert assoc.uses_gbt and assoc.gbt_block_size() == 64 - 7
    assert assoc.request(SET_LONG) == SET_OK
    blocks = [blk(a) for a in link.sent[1:]]
    assert [(b.block_number, b.last, b.streaming) for b in blocks] == [
        (1, False, False),
        (2, False, False),
        (3, True, False),
    ]
    assert b"".join(b.data for b in blocks) == SET_LONG
    assert all(len(a) <= 64 for a in link.sent[1:])


def test_long_request_without_gbt_is_refused():
    link = ScriptedLink([_initiate(xdlms.Conformance.default_ln(), 64)])
    assoc = Association(link)
    assoc.associate()
    with pytest.raises(ProtocolError, match="general-block-transfer not negotiated"):
        assoc.request(SET_LONG)
    assoc, _ = gbt_association([], use_gbt=False)
    with pytest.raises(ProtocolError, match="max-receive-pdu-size 64$"):
        assoc.request(SET_LONG)


def test_low_ack_from_the_meter_retransmits():
    assoc, link = gbt_association([ack(1, 1, window=2), ack(2, 1, window=2), SET_OK])
    assert assoc.request(SET_LONG) == SET_OK
    numbers = [blk(a).block_number for a in link.sent[1:]]
    assert numbers == [1, 2, 3, 2, 3]


def test_retransmission_bound_raises():
    assoc, _ = gbt_association([ack(n, 0) for n in range(1, 6)], gbt_max_retransmissions=2)
    with pytest.raises(ProtocolError, match="giving up after 2"):
        assoc.request(SET_LONG)


def test_gbt_response_to_a_gbt_request():
    response = xdlms.SetResponseNormal(0xC1, 0).to_bytes()
    assoc, link = gbt_association(
        [ack(1, 1), ack(2, 2), encode_gbt(GbtBlock(True, False, 1, 3, 3, response))]
    )
    assert assoc.request(SET_LONG) == response


def test_review_f11_lost_block_is_recovered():
    """REVIEW F11 repro: blocks 1, 3 (2 lost) used to raise 'out of sequence'."""
    data = b"\xc4\x01\xc1\x00" + b"\x09\x81\x96" + bytes(150)
    b1, b2, b3, b4 = (encode_gbt(b) for b in _response_blocks(data, 50))
    link = ScriptedLink([_initiate(xdlms.Conformance.default_ln(), 512), b1, b3, b2, b3, b4])
    assoc = Association(link)
    assoc.associate()
    assert assoc.request(b"\xc0\x01\xc1") == data
    acks = [a.hex() for a in link.sent[2:]]
    assert acks == ["e0810002000100", "e0810003000100", "e0810004000200", "e0810005000300"]


def _timeout(_sent):
    raise DlmsTimeoutError("quiet")


def test_timeout_during_gbt_receive_sends_one_recovery_ack():
    data = b"\xc4\x01\xc1\x00" + b"\x09\x81\x96" + bytes(150)
    b1, b2, b3, b4 = (encode_gbt(b) for b in _response_blocks(data, 50))
    link = ScriptedLink([_initiate(xdlms.Conformance.default_ln(), 512), b1, _timeout, b2, b3, b4])
    assoc = Association(link)
    assoc.associate()
    assert assoc.request(b"\xc0\x01\xc1") == data
    assert [blk(a).block_number_ack for a in link.sent[2:]] == [1, 1, 2, 3]


def test_second_timeout_raises():
    data = bytes(150)
    b1, _, _ = (encode_gbt(b) for b in _response_blocks(data, 50))
    link = ScriptedLink([_initiate(xdlms.Conformance.default_ln(), 512), b1, _timeout, _timeout])
    assoc = Association(link)
    assoc.associate()
    with pytest.raises(DlmsTimeoutError):
        assoc.request(b"\xc0\x01\xc1")
    assert len(link.sent) == 4  # AARQ, request, ack of block 1, one recovery ack


def test_timeout_on_a_plain_exchange_is_not_retried():
    link = ScriptedLink([_initiate(xdlms.Conformance.default_ln(), 512), _timeout])
    assoc = Association(link)
    assoc.associate()
    with pytest.raises(DlmsTimeoutError):
        assoc.request(b"\xc0\x01\xc1")
    assert len(link.sent) == 2


GET = xdlms.GetRequestNormal(0xC1, xdlms.AttributeDescriptor(1, X, 2)).to_bytes()
GET_REPLY = xdlms.GetResponseNormal(
    0xC1, xdlms.GetDataResult(data=DlmsData.octet_string(bytes(100)))
).to_bytes()
PUSH = bytes.fromhex("0f00000001000902abcd")


def test_gbt_push_interleaved_with_the_response_is_queued():
    reply = _response_blocks(GET_REPLY, 40, streaming=[True, True, True])
    push = _response_blocks(PUSH, 6, streaming=[True, True], acked=0)
    order = [reply[0], push[0], reply[1], push[1], reply[2]]
    link = ScriptedLink([_initiate(xdlms.Conformance.default_ln(), 512)])
    link.responses += [encode_gbt(b) for b in order]
    assoc = Association(link)
    assoc.associate()
    assert assoc.request(GET) == GET_REPLY
    assert [p.apdu for p in link.push_queue()] == [PUSH]


def test_gbt_push_before_the_response_is_queued():
    push = [encode_gbt(b) for b in _response_blocks(PUSH, 6, streaming=[True, True])]
    link = ScriptedLink([_initiate(xdlms.Conformance.default_ln(), 512), *push, GET_REPLY])
    assoc = Association(link)
    assoc.associate()
    assert assoc.request(GET) == GET_REPLY
    assert [p.apdu for p in link.push_queue()] == [PUSH]


# --- end to end against the simulator --------------------------------------------------

EK = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
AK = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")


@pytest.fixture
def meter():
    sim = example_meter(encryption_key=EK, authentication_key=AK, max_pdu=128)
    sim.conformance |= GBT
    servers = []

    def start(hdlc=False):
        server = serve(sim, hdlc=hdlc)
        servers.append(server)
        return server.server_address

    sim.start = start
    yield sim
    for server in servers:
        server.shutdown()
        server.server_close()


def gbt_client(meter, hdlc=False, timeout=3, **kw) -> DlmsClient:
    host, port = meter.start(hdlc)
    kw.setdefault("propose_gbt", True)
    return DlmsClient.tcp(host, port, hdlc=hdlc, timeout=timeout, **kw)


def _set_requests(meter):
    return [r for r in meter.requests if r[:1] == b"\xe0"]


def ciphered(meter):
    pytest.importorskip("cryptography")
    from pydlms.security.context import SecurityContext
    from pydlms.security.hls import Mechanism
    from pydlms.simulator import ClientProfile

    meter.clients[16] = ClientProfile(Mechanism.HLS_GMAC, ciphered=True)
    return {
        "mechanism": Mechanism.HLS_GMAC,
        "security": SecurityContext(EK, AK, client_system_title=b"PYDCLNT1"),
    }


@pytest.mark.parametrize("protection", ["plain", "glo", "general-glo"])
def test_large_set_over_gbt(meter, protection):
    kw = {} if protection == "plain" else ciphered(meter)
    if protection == "general-glo":
        kw["protection"] = "general-glo"
    value = DlmsData.octet_string(bytes(range(256)) * 2)
    meter.add_object(ClassId.DATA, X, {2: DlmsData.octet_string(b"")})
    with gbt_client(meter, **kw) as m:
        assert m.association.uses_gbt
        m.set(X, ClassId.DATA, 2, value)
        assert m.get(X).value == value.value
    assert meter.objects[(1, X)][2] == value
    blocks = [decode_gbt(r) for r in _set_requests(meter)]
    assert blocks and max(len(r) for r in _set_requests(meter)) <= 128
    # GBT instead of datablocks: no Set-Request-With-First-Datablock was sent.
    assert not [r for r in meter.requests if r[:2] == b"\xc1\x02"]


def test_use_gbt_off_keeps_datablocks(meter):
    value = DlmsData.octet_string(bytes(300))
    meter.add_object(ClassId.DATA, X, {2: DlmsData.octet_string(b"")})
    with gbt_client(meter, use_gbt=False) as m:
        assert m.association.gbt_negotiated and not m.association.uses_gbt
        m.set(X, ClassId.DATA, 2, value)
    assert [r for r in meter.requests if r[:2] == b"\xc1\x02"]
    assert not _set_requests(meter)


PROFILE = ObisCode.parse("1.0.99.2.0.255")


def _big_profile(meter):
    rows = [
        DlmsData.structure([DlmsData.uint32(i), DlmsData.octet_string(bytes([i % 251]) * 26)])
        for i in range(2000)
    ]
    value = DlmsData.array(rows)
    meter.add_object(ClassId.PROFILE_GENERIC, PROFILE, {2: value})
    return value


@pytest.mark.parametrize("window", [1, 3])
def test_64k_profile_with_a_dropped_block(meter, window):
    value = _big_profile(meter)
    meter.drop_gbt_blocks = {5}
    meter.gbt_window = 2
    with gbt_client(meter, timeout=0.5, gbt_window=window, max_receive_pdu_size=1024) as m:
        got = m.get(PROFILE, ClassId.PROFILE_GENERIC, 2)
    assert got == value
    assert not meter.drop_gbt_blocks  # the block was lost once and sent again
    acks = [decode_gbt(r) for r in _set_requests(meter)]
    assert all(not a.data and a.window == window for a in acks)
    assert 4 in [a.block_number_ack for a in acks]  # the recovery ack names block 4


def test_lost_request_block_is_sent_again(meter):
    meter.gbt_window = 3
    meter.drop_gbt_requests = {3}
    value = DlmsData.octet_string(bytes(range(256)) * 3)
    meter.add_object(ClassId.DATA, X, {2: DlmsData.octet_string(b"")})
    with gbt_client(meter, timeout=0.5) as m:
        m.set(X, ClassId.DATA, 2, value)
    assert meter.objects[(1, X)][2] == value
    numbers = [decode_gbt(r).block_number for r in _set_requests(meter) if decode_gbt(r).data]
    assert numbers.count(3) == 2


def test_gbt_over_hdlc_window_1(meter):
    value = _big_profile(meter)
    meter.add_object(ClassId.DATA, X, {2: DlmsData.octet_string(b"")})
    with gbt_client(meter, hdlc=True, max_receive_pdu_size=4096) as m:
        assert m.get(PROFILE, ClassId.PROFILE_GENERIC, 2) == value
        m.set(X, ClassId.DATA, 2, DlmsData.octet_string(bytes(400)))
    assert meter.objects[(1, X)][2].value == bytes(400)


def test_not_negotiated_meter_answers_without_gbt(meter):
    meter.conformance &= ~GBT
    value = _big_profile(meter)
    with gbt_client(meter) as m:
        assert not m.association.gbt_negotiated
        assert m.get(PROFILE, ClassId.PROFILE_GENERIC, 2) == value
    assert not _set_requests(meter)


def test_simulator_handle_all_gbt_request():
    from pydlms.simulator import _Session

    sim = example_meter(max_pdu=64)
    sim.conformance |= GBT
    session = _Session()
    from pydlms.apdu.acse import AARQ

    initiate = xdlms.InitiateRequest(conformance=xdlms.Conformance.default_ln() | GBT)
    aarq = AARQ(ApplicationContext.LN, user_information=initiate.to_bytes()).to_bytes()
    assert sim.handle_all(aarq, session)[0][0] == 0x61
    assert session.gbt_negotiated
    request = xdlms.GetRequestNormal(0xC1, xdlms.AttributeDescriptor(1, X, 2)).to_bytes()
    first, second = split_gbt(request, 8)
    (got_ack,) = sim.handle_all(first, session)
    assert blk(got_ack) == GbtBlock(True, False, 1, 1, 1, b"")
    (reply,) = sim.handle_all(second, session)
    answer = blk(reply)
    assert answer.last and answer.block_number == 2 and answer.block_number_ack == 2
    assert answer.data[:1] == b"\xc4"


# --- GBT-wrapped pushes in a ciphered association -----------------------------------------


def _lazy_streams(srv, push_plain: bytes, wrap_push, reply_plain: bytes):
    """Callables for ScriptedLink: response block 1, push blocks, the rest
    of the response; both APDUs are protected on first use, push first
    (lower invocation counter), after the AARE."""
    from pydlms.security.ciphering import wrap

    cache: dict[str, list[bytes]] = {}

    def streams():
        if not cache:
            push = wrap_push(srv, push_plain)
            reply = wrap(srv, reply_plain)
            cache["push"] = [
                encode_gbt(b) for b in _response_blocks(push, 20, streaming=[True] * 9, acked=0)
            ]
            cache["reply"] = [
                encode_gbt(b) for b in _response_blocks(reply, 20, streaming=[True] * 9)
            ]
        return cache

    def item(kind, index):
        return lambda _: streams()[kind][index]

    return item


def test_ciphered_gbt_push_interleaved_with_a_ciphered_reply_is_queued():
    pytest.importorskip("cryptography")
    from pydlms.security.ciphering import wrap_general_glo
    from tests.test_association_security import GET_REQUEST, GET_RESPONSE, associate, meter
    from tests.test_push_routing import notification

    srv = meter()
    push = notification()
    item = _lazy_streams(srv, push, wrap_general_glo, GET_RESPONSE)
    # general-glo push (3 blocks of 20) inside the glo reply (2 blocks)
    script = [item("reply", 0), item("push", 0), item("push", 1), item("push", 2)]
    script += [item("reply", 1)]
    assoc, link = associate(srv, *script)
    assert assoc.request(GET_REQUEST) == GET_RESPONSE
    entry = link.receive_queued_push()
    assert entry.apdu == push and entry.unwrapped.authenticated


def test_plaintext_gbt_push_in_a_ciphered_association_is_refused():
    pytest.importorskip("cryptography")
    from tests.test_association_security import GET_REQUEST, associate, meter
    from tests.test_push_routing import notification

    srv = meter()
    blocks = [encode_gbt(b) for b in _response_blocks(notification(), 10, streaming=[True] * 9)]
    assoc, link = associate(srv, *blocks)
    with pytest.raises(ProtocolError, match="unprotected DATA_NOTIFICATION"):
        assoc.request(GET_REQUEST)
    assert not link.push_queue()


def test_meter_numbering_on_across_requests():
    """Repro (go-dlms server): after one GBT answer, the next answer goes
    on with block 3; it used to be taken as a gap after block 1 and the
    recovery ack made the server give up with an ExceptionResponse."""
    first = [encode_gbt(b) for b in _response_blocks(GET_REPLY, 60)]
    second = [encode_gbt(b) for b in _response_blocks(GET_REPLY, 60, first=3)]
    link = ScriptedLink([_initiate(xdlms.Conformance.default_ln(), 512), *first, *second])
    assoc = Association(link)
    assoc.associate()
    assert assoc.request(GET) == GET_REPLY
    assert assoc.request(GET) == GET_REPLY
    assert [blk(a).block_number_ack for a in link.sent if a[0] == 0xE0] == [1, 3]


def test_gbt_peer_state_is_reset_by_a_new_association():
    reply = [
        encode_gbt(GbtBlock(b.last, b.streaming, 0, b.block_number, 1, b.data))
        for b in _response_blocks(GET_REPLY, 60)
    ]
    aare = _initiate(xdlms.Conformance.default_ln(), 512)
    link = ScriptedLink([aare, ack(1, 1, window=4), SET_OK, *reply, aare, *reply])
    assoc = Association(link, AssociationSettings(propose_gbt=True))
    link.responses[0] = _initiate(xdlms.Conformance.default_ln() | GBT, 64)
    assoc.associate()
    assoc.request(SET_LONG)
    assoc.request(GET)
    assert (assoc._gbt_peer_window, assoc._gbt_peer_last) == (4, 2)
    assoc.associate()
    assert (assoc._gbt_peer_window, assoc._gbt_peer_last) == (1, 0)
