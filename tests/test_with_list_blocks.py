"""SET-/ACTION-with-list splitting and choice 5 (with-list and first block).

``set_many`` / ``action_many`` cut a list into requests that fit the
server's PDU; an item that still does not fit goes as
Set-Request-With-List-And-First-Datablock / Action-Request-With-List-And-
First-Pblock. No live server available for testing implements choice 5
(Gurux.DLMS.Net and GuruxDLMS.c have no handler for it, jDLMS only the
codec), so the exchange is pinned against scripted replies and the
in-process simulator; the codec is cross-checked by the jDLMS ``apdu``
oracle (``tests/interop/test_jdlms.py``).
"""

from __future__ import annotations

import pytest

from pydlms.apdu import xdlms
from pydlms.apdu.acse import AARE, ApplicationContext
from pydlms.client import DlmsClient
from pydlms.cosem.data import DlmsData
from pydlms.cosem.enums import ActionResult, DataAccessResult
from pydlms.cosem.interface_classes import ClassId
from pydlms.exceptions import ProtocolError, ServiceError
from pydlms.obis import ObisCode
from pydlms.simulator import example_meter, serve
from tests.test_association import ScriptedLink

PDU = 64
X = ObisCode.parse("0.0.42.0.0.255")
LONG = DlmsData.octet_string(bytes(range(120)))


def _client(responses, pdu=PDU, conformance=None) -> tuple[DlmsClient, ScriptedLink]:
    conformance = xdlms.Conformance.default_ln() if conformance is None else conformance
    initiate = xdlms.InitiateResponse(conformance, pdu).to_bytes()
    aare = AARE(ApplicationContext.LN, 0, user_information=initiate).to_bytes()
    link = ScriptedLink([aare, *responses])
    meter = DlmsClient(link, auto_associate=False)
    meter.association.associate()
    return meter, link


def _iid(request: bytes) -> int:
    return request[2]


def set_ack(n):
    return lambda req: xdlms.SetResponseDatablock(_iid(req), n).to_bytes()


def set_last(results, n):
    return lambda req: xdlms.SetResponseLastDatablockWithList(_iid(req), results, n).to_bytes()


def action_ack(n):
    return lambda req: xdlms.ActionResponseNextPblock(_iid(req), n).to_bytes()


def action_list(results):
    return lambda req: xdlms.ActionResponseWithList(_iid(req), results).to_bytes()


def _decoded(link):
    return [xdlms.decode_apdu(raw) for raw in link.sent[1:]]


# --- SET ------------------------------------------------------------------------------


def test_long_set_item_goes_as_choice_5():
    meter, link = _client([set_ack(1), set_ack(2), set_last([DataAccessResult.SUCCESS], 3)])
    assert meter.set_many([(X, 1, 2, LONG)]) == [DataAccessResult.SUCCESS]
    sent = _decoded(link)
    assert all(len(raw) <= PDU for raw in link.sent[1:])
    first, *rest = sent
    assert isinstance(first, xdlms.SetRequestWithListAndFirstDatablock)
    assert first.items == [(xdlms.AttributeDescriptor(1, X, 2), None)]
    assert all(isinstance(r, xdlms.SetRequestWithDatablock) for r in rest)
    assert [(r.block_number, r.last_block) for r in sent] == [(1, False), (2, False), (3, True)]
    assert len({r.invoke_id for r in sent}) == 1
    assert b"".join(r.raw_data for r in sent) == xdlms.encode_data_list([LONG])


def _set_server(count):
    """Acknowledge every block by its number; answer the last for ``count`` items."""

    def reply(req):
        block = xdlms.decode_apdu(req)
        if block.last_block:
            return set_last([DataAccessResult.SUCCESS] * count, block.block_number)(req)
        return set_ack(block.block_number)(req)

    return reply


def test_split_lists_false_sends_the_whole_list_in_blocks():
    small = DlmsData.octet_string(bytes(30))
    meter, link = _client([_set_server(3)] * 16)
    results = meter.set_many([(X, 1, 2, small)] * 3, split_lists=False)
    assert results == [DataAccessResult.SUCCESS] * 3
    first = _decoded(link)[0]
    assert isinstance(first, xdlms.SetRequestWithListAndFirstDatablock)
    assert len(first.items) == 3


def test_set_many_splits_to_fit_and_keeps_the_order():
    small = DlmsData.octet_string(bytes(30))
    replies = [
        lambda req: xdlms.SetResponseWithList(_iid(req), [DataAccessResult.SUCCESS]).to_bytes(),
        lambda req: xdlms.SetResponseWithList(
            _iid(req), [DataAccessResult.READ_WRITE_DENIED]
        ).to_bytes(),
        lambda req: xdlms.SetResponseWithList(_iid(req), [DataAccessResult.SUCCESS]).to_bytes(),
    ]
    meter, link = _client(replies)
    results = meter.set_many([(X, 1, 2, small)] * 3)
    assert results == [
        DataAccessResult.SUCCESS,
        DataAccessResult.READ_WRITE_DENIED,
        DataAccessResult.SUCCESS,
    ]
    assert [type(r).__name__ for r in _decoded(link)] == ["SetRequestWithList"] * 3
    assert all(len(raw) <= PDU for raw in link.sent[1:])


@pytest.mark.parametrize(
    ("replies", "error", "match"),
    [
        ([set_ack(2)], ProtocolError, "acknowledged as block 2"),
        ([set_ack(1), set_ack(1)], ProtocolError, "acknowledged as block 1"),
        (
            [set_last([DataAccessResult.TYPE_UNMATCHED], 1)],
            ServiceError,
            "block 1 refused: TYPE_UNMATCHED",
        ),
        (
            [
                set_ack(1),
                lambda req: xdlms.SetResponseNormal(
                    _iid(req), DataAccessResult.TEMPORARY_FAILURE
                ).to_bytes(),
            ],
            ServiceError,
            "block 2 refused",
        ),
        ([set_last([DataAccessResult.SUCCESS], 1)], ProtocolError, "unexpected reply"),
        (
            [set_ack(1), set_ack(2), set_last([DataAccessResult.SUCCESS] * 2, 3)],
            ProtocolError,
            "1 items, got 2 results",
        ),
        (
            [set_ack(1), set_ack(2), set_last([DataAccessResult.SUCCESS], 4)],
            ProtocolError,
            "answered as block 4",
        ),
        ([set_ack(1), set_ack(2), set_ack(3)], ProtocolError, "unexpected reply"),
    ],
    ids=[
        "wrong-ack",
        "repeated-ack",
        "error-mid",
        "normal-error-mid",
        "early-success",
        "result-count",
        "final-number",
        "final-ack",
    ],
)
def test_choice_5_set_replies_are_checked(replies, error, match):
    meter, _ = _client(replies)
    with pytest.raises(error, match=match):
        meter.set_many([(X, 1, 2, LONG)])


def test_choice_5_set_needs_block_transfer_with_set():
    conformance = (
        xdlms.Conformance.default_ln() & ~xdlms.Conformance.BLOCK_TRANSFER_WITH_SET_OR_WRITE
    )
    meter, link = _client([], conformance=conformance)
    with pytest.raises(ProtocolError, match="BLOCK_TRANSFER_WITH_SET_OR_WRITE"):
        meter.set_many([(X, 1, 2, LONG)])
    assert len(link.sent) == 1  # the AARQ only


# --- ACTION ---------------------------------------------------------------------------

M = xdlms.MethodDescriptor(70, ObisCode.parse("0.0.96.3.10.255"), 1)


def test_long_action_item_goes_as_choice_5():
    ok = (ActionResult.SUCCESS, xdlms.GetDataResult(data=DlmsData.uint8(9)))
    meter, link = _client([action_ack(1), action_ack(2), action_list([ok])])
    assert meter.action_many([(M.instance_id, 70, 1, LONG)]) == [DlmsData.uint8(9)]
    sent = _decoded(link)
    assert isinstance(sent[0], xdlms.ActionRequestWithListAndFirstPblock)
    assert sent[0].methods == [M]
    assert all(isinstance(r, xdlms.ActionRequestWithPblock) for r in sent[1:])
    assert all(len(raw) <= PDU for raw in link.sent[1:])
    assert b"".join(r.raw_data for r in sent) == xdlms.encode_data_list([LONG])


@pytest.mark.parametrize(
    ("replies", "error", "match"),
    [
        ([action_ack(3)], ProtocolError, "acknowledged as block 3"),
        (
            [
                lambda req: xdlms.ActionResponseNormal(
                    _iid(req), ActionResult.TYPE_UNMATCHED
                ).to_bytes()
            ],
            ServiceError,
            "block 1 refused",
        ),
        (
            [action_ack(1), action_ack(2), action_list([(ActionResult.SUCCESS, None)] * 2)],
            ProtocolError,
            "1 methods, got 2 results",
        ),
        ([action_ack(1), action_ack(2), action_ack(3)], ProtocolError, "unexpected reply"),
    ],
    ids=["wrong-ack", "error-mid", "result-count", "final-ack"],
)
def test_choice_5_action_replies_are_checked(replies, error, match):
    meter, _ = _client(replies)
    with pytest.raises(error, match=match):
        meter.action_many([(M.instance_id, 70, 1, LONG)])


def test_choice_5_action_needs_block_transfer_with_action():
    conformance = xdlms.Conformance.default_ln() & ~xdlms.Conformance.BLOCK_TRANSFER_WITH_ACTION
    meter, link = _client([], conformance=conformance)
    with pytest.raises(ProtocolError, match="BLOCK_TRANSFER_WITH_ACTION"):
        meter.action_many([(M.instance_id, 70, 1, LONG)])
    assert len(link.sent) == 1


def test_single_action_pblock_acks_are_checked():
    # The pblock sender is shared with action(): a wrong next-pblock number
    # was accepted before.
    meter, _ = _client([action_ack(2)])
    with pytest.raises(ProtocolError, match="acknowledged as block 2"):
        meter.action(M.instance_id, 70, 1, LONG)


# --- end to end against the simulator ---------------------------------------------------


@pytest.fixture
def sim():
    meter = example_meter()
    meter.max_pdu = 128
    server = serve(meter)
    meter.address = server.server_address
    yield meter
    server.shutdown()
    server.server_close()


def _connect(sim) -> DlmsClient:
    return DlmsClient.tcp(*sim.address, timeout=3)


def test_set_many_against_the_simulator_splits_and_uses_choice_5(sim):
    long_value = DlmsData.octet_string(bytes(i & 0xFF for i in range(400)))
    items = [
        ("0.0.42.0.0.255", ClassId.DATA, 2, DlmsData.octet_string(bytes(90))),
        ("9.9.9.9.9.9", ClassId.DATA, 2, DlmsData.uint8(1)),
        ("0.0.96.1.0.255", ClassId.DATA, 2, DlmsData.visible_string("LIST")),
        ("0.0.42.0.0.255", ClassId.DATA, 2, long_value),
    ]
    with _connect(sim) as m:
        limit = m.association.max_plain_request()
        start = len(sim.requests)
        results = m.set_many(items)
        sent = sim.requests[start:]
        assert m.get("0.0.42.0.0.255") == long_value
        assert m.get("0.0.96.1.0.255").value == "LIST"
    assert results == [
        DataAccessResult.SUCCESS,
        DataAccessResult.OBJECT_UNDEFINED,
        DataAccessResult.SUCCESS,
        DataAccessResult.SUCCESS,
    ]
    assert all(len(r) <= limit for r in sent)
    assert sum(r[:2] == b"\xc1\x04" for r in sent) >= 2
    assert sum(r[:2] == b"\xc1\x05" for r in sent) == 1


def test_action_many_against_the_simulator_uses_choice_5(sim):
    seen = []
    sim.add_method(
        ClassId.DATA, "0.0.42.0.0.255", 1, lambda s, p: seen.append(p) or DlmsData.uint16(len(seen))
    )
    long_params = DlmsData.octet_string(bytes(300))
    items = [
        ("0.0.42.0.0.255", ClassId.DATA, 1, DlmsData.uint8(1)),
        ("0.0.42.0.0.255", ClassId.DATA, 1, long_params),
        ("9.9.9.9.9.9", ClassId.DATA, 1, None),
    ]
    with _connect(sim) as m:
        limit = m.association.max_plain_request()
        start = len(sim.requests)
        out = m.action_many(items)
        sent = sim.requests[start:]
    assert out == [DlmsData.uint16(1), DlmsData.uint16(2), ActionResult.OBJECT_UNAVAILABLE]
    assert seen == [DlmsData.uint8(1), long_params]
    assert all(len(r) <= limit for r in sent)
    assert sum(r[:2] == b"\xc3\x05" for r in sent) == 1
